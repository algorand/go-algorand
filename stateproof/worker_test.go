// Copyright (C) 2019-2022 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package stateproof

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-deadlock"
)

type testWorkerStubs struct {
	t                         testing.TB
	mu                        deadlock.Mutex
	latest                    basics.Round
	waiters                   map[basics.Round]chan struct{}
	waitersCount              map[basics.Round]int
	blocks                    map[basics.Round]bookkeeping.BlockHeader
	keys                      []account.Participation
	keysForVoters             []account.Participation
	sigmsg                    chan []byte
	txmsg                     chan transactions.SignedTxn
	totalWeight               int
	deletedKeysBeforeRoundMap map[account.ParticipationID]basics.Round
	version                   protocol.ConsensusVersion
}

func newWorkerStubs(t testing.TB, keys []account.Participation, totalWeight int) *testWorkerStubs {
	return newWorkerStubsWithVersion(t, keys, protocol.ConsensusCurrentVersion, totalWeight)
}

func newWorkerStubsWithVersion(t testing.TB, keys []account.Participation, version protocol.ConsensusVersion, totalWeight int) *testWorkerStubs {
	proto := config.Consensus[version]
	s := &testWorkerStubs{
		t:                         nil,
		mu:                        deadlock.Mutex{},
		latest:                    0,
		waiters:                   make(map[basics.Round]chan struct{}),
		waitersCount:              make(map[basics.Round]int),
		blocks:                    make(map[basics.Round]bookkeeping.BlockHeader),
		keys:                      keys,
		keysForVoters:             keys,
		sigmsg:                    make(chan []byte, 1024*1024),
		txmsg:                     make(chan transactions.SignedTxn, 1024),
		totalWeight:               totalWeight,
		deletedKeysBeforeRoundMap: map[account.ParticipationID]basics.Round{},
		version:                   version,
	}
	s.latest--
	s.addBlock(2 * basics.Round(proto.StateProofInterval))
	return s
}

func (s *testWorkerStubs) addBlock(spNextRound basics.Round) {
	s.latest++

	hdr := bookkeeping.BlockHeader{}
	hdr.Round = s.latest
	hdr.CurrentProtocol = s.version

	var stateProofBasic = bookkeeping.StateProofTrackingData{
		StateProofVotersCommitment:  make([]byte, stateproof.HashSize),
		StateProofOnlineTotalWeight: basics.MicroAlgos{},
		StateProofNextRound:         0,
	}
	stateProofBasic.StateProofOnlineTotalWeight.Raw = uint64(s.totalWeight)

	if hdr.Round > 0 {
		// Just so it's not zero, since the signer logic checks for all-zeroes
		stateProofBasic.StateProofVotersCommitment[1] = 0x12
	}

	stateProofBasic.StateProofNextRound = spNextRound
	hdr.StateProofTracking = map[protocol.StateProofType]bookkeeping.StateProofTrackingData{
		protocol.StateProofBasic: stateProofBasic,
	}

	s.blocks[s.latest] = hdr

	if s.waiters[s.latest] != nil {
		close(s.waiters[s.latest])
	}
}
func (s *testWorkerStubs) StateProofKeys(rnd basics.Round) (out []account.StateProofSecretsForRound) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, part := range s.keys {
		partRecord := account.ParticipationRecord{
			ParticipationID:   part.ID(),
			Account:           part.Parent,
			FirstValid:        part.FirstValid,
			LastValid:         part.LastValid,
			KeyDilution:       part.KeyDilution,
			LastVote:          0,
			LastBlockProposal: 0,
			LastStateProof:    0,
			EffectiveFirst:    0,
			EffectiveLast:     0,
			VRF:               part.VRF,
			Voting:            part.Voting,
		}
		signerInRound := part.StateProofSecrets.GetSigner(uint64(rnd))
		if signerInRound == nil {
			continue
		}
		KeyInLifeTime, _ := signerInRound.FirstRoundInKeyLifetime()

		// simulate that the key was removed
		if basics.Round(KeyInLifeTime) < s.deletedKeysBeforeRoundMap[part.ID()] {
			continue
		}
		if part.LastValid < rnd {
			continue
		}
		partRecordForRound := account.StateProofSecretsForRound{
			ParticipationRecord: partRecord,
			StateProofSecrets:   signerInRound,
		}
		out = append(out, partRecordForRound)
	}
	return
}

func (s *testWorkerStubs) DeleteStateProofKeysForExpiredAccounts(currentRound basics.Round) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, part := range s.keys {
		if currentRound <= part.LastValid {
			continue
		}
		s.deletedKeysBeforeRoundMap[part.ID()] = currentRound
	}
}

func (s *testWorkerStubs) DeleteStateProofKey(id account.ParticipationID, round basics.Round) error {
	s.mu.Lock()
	s.deletedKeysBeforeRoundMap[id] = round
	s.mu.Unlock()

	return nil
}
func (s *testWorkerStubs) GetNumDeletedKeys() int {
	s.mu.Lock()
	numDeltedKeys := len(s.deletedKeysBeforeRoundMap)
	s.mu.Unlock()

	return numDeltedKeys
}

func (s *testWorkerStubs) BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hdr, ok := s.blocks[r]
	if !ok {
		return hdr, ledgercore.ErrNoEntry{
			Round:     r,
			Latest:    s.latest,
			Committed: s.latest,
		}
	}

	return hdr, nil
}

var errEmptyVoters = errors.New("ledger does not have voters")

func (s *testWorkerStubs) VotersForStateProof(r basics.Round) (*ledgercore.VotersForRound, error) {
	if len(s.keysForVoters) == 0 {
		return nil, errEmptyVoters
	}

	voters := &ledgercore.VotersForRound{
		Proto:       config.Consensus[protocol.ConsensusCurrentVersion],
		AddrToPos:   make(map[basics.Address]uint64),
		TotalWeight: basics.MicroAlgos{Raw: uint64(s.totalWeight)},
	}

	for i, k := range s.keysForVoters {
		voters.AddrToPos[k.Parent] = uint64(i)
		voters.Participants = append(voters.Participants, basics.Participant{
			PK:     *k.StateProofSecrets.GetVerifier(),
			Weight: 1,
		})
	}

	tree, err := merklearray.BuildVectorCommitmentTree(voters.Participants, crypto.HashFactory{HashType: stateproof.HashType})
	if err != nil {
		return nil, err
	}

	voters.Tree = tree
	return voters, nil
}

func (s *testWorkerStubs) GenesisHash() crypto.Digest {
	return crypto.Digest{0x01, 0x02, 0x03, 0x04}
}

func (s *testWorkerStubs) Latest() basics.Round {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest
}

func (s *testWorkerStubs) Wait(r basics.Round) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waiters[r] == nil {
		s.waiters[r] = make(chan struct{})
		s.waitersCount[r] = 0
		if r <= s.latest {
			close(s.waiters[r])
		}
	}
	s.waitersCount[r] = s.waitersCount[r] + 1
	return s.waiters[r]
}

func (s *testWorkerStubs) Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except network.Peer) error {
	require.Equal(s.t, tag, protocol.StateProofSigTag)
	s.sigmsg <- data
	return nil
}

func (s *testWorkerStubs) BroadcastInternalSignedTxGroup(tx []transactions.SignedTxn) error {
	require.Equal(s.t, len(tx), 1)
	s.txmsg <- tx[0]
	return nil
}

func (s *testWorkerStubs) RegisterHandlers([]network.TaggedMessageHandler) {
}

func (s *testWorkerStubs) advanceRoundsWithoutStateProof(delta uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for r := uint64(0); r < delta; r++ {
		s.addBlock(s.blocks[s.latest].StateProofTracking[protocol.StateProofBasic].StateProofNextRound)
	}
}

// used to simulate to workers that rounds have advanced, and stateproofs were created.
func (s *testWorkerStubs) advanceRoundsAndStateProofs(delta uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for r := uint64(0); r < delta; r++ {
		interval := basics.Round(config.Consensus[s.blocks[s.latest].CurrentProtocol].StateProofInterval)
		blk := s.blocks[s.latest]
		stateProofNextRound := s.blocks[s.latest].StateProofTracking[protocol.StateProofBasic].StateProofNextRound
		if blk.Round%interval == 0 && stateProofNextRound-interval < blk.Round {
			stateProofNextRound += interval
		}

		s.addBlock(stateProofNextRound)
	}
}

func (s *testWorkerStubs) waitOnSigWithTimeout(timeout time.Duration) ([]byte, error) {
	select {
	case sig := <-s.sigmsg:
		return sig, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting on sigmsg")
	}
}

func (s *testWorkerStubs) waitOnTxnWithTimeout(timeout time.Duration) (transactions.SignedTxn, error) {
	select {
	case signedTx := <-s.txmsg:
		return signedTx, nil
	case <-time.After(timeout):
		return transactions.SignedTxn{}, fmt.Errorf("timeout waiting on sigmsg")
	}
}

func newTestWorkerDB(t testing.TB, s *testWorkerStubs, dba db.Accessor) *Worker {
	return NewWorker(dba, logging.TestingLog(t), s, s, s, s)
}

func newTestWorker(t testing.TB, s *testWorkerStubs) *Worker {
	dbs, _ := dbOpenTest(t, true)
	return newTestWorkerDB(t, s, dbs.Wdb)
}

func newPartKey(t testing.TB, parent basics.Address) account.PersistedParticipation {
	version := config.Consensus[protocol.ConsensusCurrentVersion]
	return newPartKeyWithVersion(t, version, parent)
}

// You must call defer part.Close() after calling this function,
// since it creates a DB accessor but the caller must close it (required for mss)
func newPartKeyWithVersion(t testing.TB, protoParam config.ConsensusParams, parent basics.Address) account.PersistedParticipation {
	fn := fmt.Sprintf("%s.%d", strings.ReplaceAll(t.Name(), "/", "."), crypto.RandUint64())
	partDB, err := db.MakeAccessor(fn, false, true)
	require.NoError(t, err)

	part, err := account.FillDBWithParticipationKeys(partDB, parent, 0, basics.Round(15*protoParam.StateProofInterval), protoParam.DefaultKeyDilution)
	require.NoError(t, err)

	return part
}

func countBuildersInDB(store db.Accessor) (nrows int, err error) {
	err = store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		row := tx.QueryRow("SELECT COUNT(*) FROM builders")
		err := row.Scan(&nrows)
		if err != nil {
			return err
		}
		return nil
	})

	return
}

func TestWorkerAllSigs(t *testing.T) {
	partitiontest.PartitionTest(t)

	var keys []account.Participation
	for i := 0; i < 10; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, len(keys))
	w := newTestWorker(t, s)
	w.Start()
	defer w.Shutdown()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(proto.StateProofInterval + proto.StateProofInterval/2)

	// Go through several iterations, making sure that we get
	// the signatures and certs broadcast at each round.
	for iter := 0; iter < 5; iter++ {
		s.advanceRoundsWithoutStateProof(proto.StateProofInterval)

		for i := 0; i < len(keys); i++ {
			// Expect all signatures to be broadcast.
			_, err := s.waitOnSigWithTimeout(time.Second * 2)
			require.NoError(t, err)
		}

		// Expect a state proof to be formed.
		for {
			tx, err := s.waitOnTxnWithTimeout(time.Second * 5)
			require.NoError(t, err)

			lastAttestedRound := basics.Round(tx.Txn.Message.LastAttestedRound)
			require.Equal(t, tx.Txn.Type, protocol.StateProofTx)
			if lastAttestedRound < basics.Round(iter+2)*basics.Round(proto.StateProofInterval) {
				continue
			}

			require.Equal(t, lastAttestedRound, basics.Round(iter+2)*basics.Round(proto.StateProofInterval))

			stateProofLatestRound, err := s.BlockHdr(lastAttestedRound)
			require.NoError(t, err)

			votersRound := lastAttestedRound.SubSaturate(basics.Round(proto.StateProofInterval))

			msg, err := GenerateStateProofMessage(s, uint64(votersRound), stateProofLatestRound)
			require.NoError(t, err)
			require.Equal(t, msg, tx.Txn.Message)

			provenWeight, overflowed := basics.Muldiv(uint64(s.totalWeight), uint64(proto.StateProofWeightThreshold), 1<<32)
			require.False(t, overflowed)

			voters, err := s.VotersForStateProof(lastAttestedRound - basics.Round(proto.StateProofInterval) - basics.Round(proto.StateProofVotersLookback))
			require.NoError(t, err)

			verif, err := stateproof.MkVerifier(voters.Tree.Root(), provenWeight, proto.StateProofStrengthTarget)
			require.NoError(t, err)

			err = verif.Verify(uint64(lastAttestedRound), tx.Txn.Message.Hash(), &tx.Txn.StateProof)
			require.NoError(t, err)
			break
		}
	}
}

func TestWorkerPartialSigs(t *testing.T) {
	partitiontest.PartitionTest(t)

	var keys []account.Participation
	for i := 0; i < 7; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, 10)
	w := newTestWorker(t, s)
	w.Start()
	defer w.Shutdown()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(proto.StateProofInterval + proto.StateProofInterval/2)
	s.advanceRoundsWithoutStateProof(proto.StateProofInterval)

	for i := 0; i < len(keys); i++ {
		// Expect all signatures to be broadcast.
		_, err := s.waitOnSigWithTimeout(time.Second * 2)
		require.NoError(t, err)
	}

	// No state proof should be formed yet: not enough sigs for a stateproof this early.
	select {
	case <-s.txmsg:
		t.Fatal("state proof formed too early")
	case <-time.After(time.Second):
	}

	// Expect a state proof to be formed in the next StateProofInterval/2.
	s.advanceRoundsWithoutStateProof(proto.StateProofInterval / 2)

	tx, err := s.waitOnTxnWithTimeout(time.Second * 5)
	require.NoError(t, err)

	lastAttestedRound := basics.Round(tx.Txn.Message.LastAttestedRound)
	require.Equal(t, tx.Txn.Type, protocol.StateProofTx)
	require.Equal(t, lastAttestedRound, 2*basics.Round(proto.StateProofInterval))

	stateProofLatestRound, err := s.BlockHdr(lastAttestedRound)
	require.NoError(t, err)

	votersRound := lastAttestedRound.SubSaturate(basics.Round(proto.StateProofInterval))

	msg, err := GenerateStateProofMessage(s, uint64(votersRound), stateProofLatestRound)
	require.NoError(t, err)
	require.Equal(t, msg, tx.Txn.Message)

	provenWeight, overflowed := basics.Muldiv(uint64(s.totalWeight), uint64(proto.StateProofWeightThreshold), 1<<32)
	require.False(t, overflowed)

	voters, err := s.VotersForStateProof(lastAttestedRound - basics.Round(proto.StateProofInterval) - basics.Round(proto.StateProofVotersLookback))
	require.NoError(t, err)

	verif, err := stateproof.MkVerifier(voters.Tree.Root(), provenWeight, proto.StateProofStrengthTarget)
	require.NoError(t, err)
	err = verif.Verify(uint64(lastAttestedRound), msg.Hash(), &tx.Txn.StateProof)
	require.NoError(t, err)
}

func TestWorkerInsufficientSigs(t *testing.T) {
	partitiontest.PartitionTest(t)

	var keys []account.Participation
	for i := 0; i < 2; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, 10)
	w := newTestWorker(t, s)
	w.Start()
	defer w.Shutdown()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(3 * proto.StateProofInterval)

	for i := 0; i < len(keys); i++ {
		// Expect all signatures to be broadcast.
		_, err := s.waitOnSigWithTimeout(time.Second * 2)
		require.NoError(t, err)
	}

	// No state proof should be formed: not enough sigs.
	select {
	case <-s.txmsg:
		t.Fatal("state proof formed without enough sigs")
	case <-time.After(time.Second):
	}
}

func TestWorkerRestart(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var keys []account.Participation
	for i := 0; i < 10; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, 10)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(3*proto.StateProofInterval - 1)

	dbRand := crypto.RandUint64()

	formedAt := -1
	for i := 0; formedAt < 0 && i < len(keys); i++ {
		// Give one key at a time to the worker, and then shut it down,
		// to make sure that it will correctly save and restore these
		// signatures across restart.
		s.keys = keys[i : i+1]
		dbs, _ := dbOpenTestRand(t, true, dbRand)
		w := newTestWorkerDB(t, s, dbs.Wdb)
		w.Start()

		// Check if the cert formed
		select {
		case <-s.txmsg:
			formedAt = i
		case <-time.After(time.Second):
		}

		w.Shutdown()
	}

	a.Greater(formedAt, 1)
	a.Less(formedAt, 5)
}

func TestWorkerHandleSig(t *testing.T) {
	partitiontest.PartitionTest(t)

	var keys []account.Participation
	for i := 0; i < 2; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, 10)
	w := newTestWorker(t, s)
	w.Start()
	defer w.Shutdown()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(3 * proto.StateProofInterval)

	for i := 0; i < len(keys); i++ {
		// Expect all signatures to be broadcast.
		msg, err := s.waitOnSigWithTimeout(time.Second * 2)
		require.NoError(t, err)

		res := w.handleSigMessage(network.IncomingMessage{
			Data: msg,
		})

		// This should be a dup signature, so should not be broadcast
		// but also not disconnected.
		require.Equal(t, res.Action, network.Ignore)
	}
}

func createWorkerAndParticipants(t *testing.T, version protocol.ConsensusVersion, proto config.ConsensusParams) ([]account.Participation, *testWorkerStubs, *Worker) {
	var keys []account.Participation
	for i := 0; i < 2; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKeyWithVersion(t, proto, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubsWithVersion(t, keys, version, 10)
	dbs, _ := dbOpenTest(t, true)

	logger := logging.NewLogger()
	logger.SetOutput(io.Discard)

	w := NewWorker(dbs.Wdb, logger, s, s, s, s)
	w.Start()
	return keys, s, w
}

// threshold == 0 meaning nothing was deleted.
func requireDeletedKeysToBeDeletedBefore(t *testing.T, s *testWorkerStubs, threshold basics.Round) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, prt := range s.keys {
		if threshold == 0 {
			require.Equal(t, threshold, s.deletedKeysBeforeRoundMap[prt.ID()])
			continue
		}
		// minus one because we delete keys up to the round stated in the map but not including!
		require.Greater(t, threshold, s.deletedKeysBeforeRoundMap[prt.ID()]-1)
	}
}

func TestAllKeysRemovedAfterExpiration(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	firstExpectedStateproof := basics.Round(proto.StateProofInterval * 2)

	var keys []account.Participation
	for i := 0; i < 2; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKeyWithVersion(t, proto, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, 10)
	dbs, _ := dbOpenTest(t, true)

	logger := logging.NewLogger()
	logger.SetOutput(io.Discard)

	w := NewWorker(dbs.Wdb, logger, s, s, s, s)
	w.Start()
	defer w.Shutdown()

	advanceRoundsAndStateProofsSlowly(t, s, uint64(firstExpectedStateproof)+(12*proto.StateProofInterval))
	s.mu.Lock()
	for _, prt := range s.keys {
		require.Equal(t, uint64(prt.LastValid)-proto.StateProofInterval, uint64(s.deletedKeysBeforeRoundMap[prt.ID()]))
	}
	s.mu.Unlock()

	advanceRoundsAndStateProofsSlowly(t, s, proto.StateProofInterval)

	s.mu.Lock()
	for _, prt := range s.keys {
		require.Equal(t, prt.LastValid, s.deletedKeysBeforeRoundMap[prt.ID()])
	}
	s.mu.Unlock()

	advanceRoundsAndStateProofsSlowly(t, s, proto.StateProofInterval)

	s.mu.Lock()
	for _, prt := range s.keys {
		require.Less(t, prt.LastValid, s.deletedKeysBeforeRoundMap[prt.ID()])
	}
	s.mu.Unlock()
}

func TestKeysRemoveOnlyAfterStateProofAccepted(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	const expectedNumberOfStateProofs = uint64(3)
	firstExpectedStateproof := basics.Round(proto.StateProofInterval * 2)

	keys, s, w := createWorkerAndParticipants(t, protocol.ConsensusCurrentVersion, proto)
	defer w.Shutdown()

	s.advanceRoundsWithoutStateProof(uint64(firstExpectedStateproof) + expectedNumberOfStateProofs*proto.StateProofInterval)
	err := waitForBuilderAndSignerToWaitOnRound(s)
	require.NoError(t, err)

	// since no state proof was confirmed (i.e the next state proof round == firstExpectedStateproof), we expect a node
	// to keep its keys to sign the state proof firstExpectedStateproof. every participant should have keys for that round
	checkedKeys := s.StateProofKeys(firstExpectedStateproof)
	require.Equal(t, len(keys), len(checkedKeys))
	requireDeletedKeysToBeDeletedBefore(t, s, firstExpectedStateproof) // i should at this point have the keys to sign on round 512.... how come they were deleted?

	// confirm stateproof for firstExpectedStateproof
	advanceRoundsAndStateProofsSlowly(t, s, proto.StateProofInterval)

	// the first state proof was confirmed keys for that state proof can be removed
	// So we should have the not deleted keys for proto.StateProofInterval + firstExpectedStateproof
	requireDeletedKeysToBeDeletedBefore(t, s, firstExpectedStateproof+basics.Round(proto.StateProofInterval))
	checkedKeys = s.StateProofKeys(firstExpectedStateproof)
	require.Equal(t, 0, len(checkedKeys))
	checkedKeys = s.StateProofKeys(firstExpectedStateproof + basics.Round(proto.StateProofInterval))
	require.Equal(t, len(keys), len(checkedKeys))
}

func TestKeysRemoveOnlyAfterStateProofAcceptedSmallIntervals(t *testing.T) {
	partitiontest.PartitionTest(t)

	const stateProofIntervalForTest = 64
	const smallIntervalVersionName = "TestKeysRemoveOnlyAfterStateProofAcceptedSmallIntervals"
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	proto.StateProofInterval = stateProofIntervalForTest
	config.Consensus[smallIntervalVersionName] = proto
	defer func() {
		delete(config.Consensus, smallIntervalVersionName)
	}()

	partitiontest.PartitionTest(t)

	const expectedNumberOfStateProofs = uint64(3)
	firstExpectedStateproof := basics.Round(proto.StateProofInterval * 2)

	keys, s, w := createWorkerAndParticipants(t, smallIntervalVersionName, proto)
	defer w.Shutdown()

	s.advanceRoundsWithoutStateProof(uint64(firstExpectedStateproof) + expectedNumberOfStateProofs*proto.StateProofInterval)
	err := waitForBuilderAndSignerToWaitOnRound(s)
	require.NoError(t, err)

	// since no state proof was confirmed (i.e the next state proof round == firstExpectedStateproof), we expect a node
	// to keep its keys to sign the state proof firstExpectedStateproof. every participant should have keys for that round
	requireDeletedKeysToBeDeletedBefore(t, s, 0)
	checkedKeys := s.StateProofKeys(firstExpectedStateproof)
	require.Equal(t, len(keys), len(checkedKeys))

	// confirm stateproof for firstExpectedStateproof
	advanceRoundsAndStateProofsSlowly(t, s, proto.StateProofInterval)

	// the first state proof was confirmed. However, since keylifetime is greater than the state proof interval
	// the key for firstExpectedStateproof should be kept (since it is being reused on 3 * proto.StateProofInterval)
	requireDeletedKeysToBeDeletedBefore(t, s, 0)

	checkedKeys = s.StateProofKeys(firstExpectedStateproof)
	require.Equal(t, len(keys), len(checkedKeys))
	checkedKeys = s.StateProofKeys(firstExpectedStateproof + basics.Round(proto.StateProofInterval))
	require.Equal(t, len(keys), len(checkedKeys))
}

func TestKeysRemoveOnlyAfterStateProofAcceptedLargeIntervals(t *testing.T) {
	partitiontest.PartitionTest(t)

	const stateProofIntervalForTest = 260
	const smallIntervalVersionName = "TestKeysRemoveOnlyAfterStateProofAcceptedLargeIntervals"
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	proto.StateProofInterval = stateProofIntervalForTest
	config.Consensus[smallIntervalVersionName] = proto
	defer func() {
		delete(config.Consensus, smallIntervalVersionName)
	}()

	const expectedNumberOfStateProofs = uint64(3)
	firstExpectedStateproof := basics.Round(proto.StateProofInterval * 2)

	keys, s, w := createWorkerAndParticipants(t, protocol.ConsensusCurrentVersion, proto)
	defer w.Shutdown()

	s.advanceRoundsWithoutStateProof(uint64(firstExpectedStateproof) + expectedNumberOfStateProofs*proto.StateProofInterval)
	err := waitForBuilderAndSignerToWaitOnRound(s)
	require.NoError(t, err)

	// since no state proof was confirmed (i.e the next state proof round == firstExpectedStateproof), we expect a node
	// to keep its keys to sign the state proof firstExpectedStateproof. every participant should have keys for that round
	requireDeletedKeysToBeDeletedBefore(t, s, firstExpectedStateproof)
	checkedKeys := s.StateProofKeys(firstExpectedStateproof)
	require.Equal(t, len(keys), len(checkedKeys))

	// confirm stateproof for firstExpectedStateproof
	advanceRoundsAndStateProofsSlowly(t, s, proto.StateProofInterval)

	// the first state proof was confirmed keys for that state proof can be removed
	requireDeletedKeysToBeDeletedBefore(t, s, basics.Round(proto.StateProofInterval)+firstExpectedStateproof)

	checkedKeys = s.StateProofKeys(firstExpectedStateproof)
	require.Equal(t, 0, len(checkedKeys))
	checkedKeys = s.StateProofKeys(firstExpectedStateproof + basics.Round(proto.StateProofInterval))
	require.Equal(t, len(keys), len(checkedKeys))
}

func advanceRoundsAndStateProofsSlowly(t *testing.T, s *testWorkerStubs, numberOfRounds uint64) {
	// since adding blocks to our mock ledger happens very fast, the worker might
	// not iterate over the latest block. Hence, we add some blocks -> wait -> add one more -> wait
	s.advanceRoundsAndStateProofs(numberOfRounds - 1)
	err := waitForBuilderAndSignerToWaitOnRound(s)
	require.NoError(t, err)
	s.advanceRoundsAndStateProofs(1)
	err = waitForBuilderAndSignerToWaitOnRound(s)
	require.NoError(t, err)
}

func TestWorkerRemoveBuildersAndSignatures(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	const expectedStateProofs = 8
	var keys []account.Participation
	for i := 0; i < 10; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, len(keys))
	w := newTestWorker(t, s)
	w.Start()
	defer w.Shutdown()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(proto.StateProofInterval + proto.StateProofInterval/2)

	for iter := 0; iter < expectedStateProofs; iter++ {
		s.advanceRoundsWithoutStateProof(proto.StateProofInterval)
		tx := <-s.txmsg
		a.Equal(tx.Txn.Type, protocol.StateProofTx)
	}

	err := waitForBuilderAndSignerToWaitOnRound(s)
	a.NoError(err)
	a.Equal(expectedStateProofs, len(w.builders))
	countDB, err := countBuildersInDB(w.db)
	a.NoError(err)
	a.Equal(expectedStateProofs, countDB)

	var roundSigs map[basics.Round][]pendingSig
	err = w.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		roundSigs, err = getPendingSigs(tx)
		return
	})

	a.Equal(expectedStateProofs, len(roundSigs))

	// add block that confirm a state proof for interval: expectedStateProofs - 1
	s.mu.Lock()
	s.addBlock(basics.Round((expectedStateProofs - 1) * config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval))
	s.mu.Unlock()

	err = waitForBuilderAndSignerToWaitOnRound(s)
	a.NoError(err)
	a.Equal(3, len(w.builders))
	countDB, err = countBuildersInDB(w.db)
	a.NoError(err)
	a.Equal(3, countDB)

	err = w.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		roundSigs, err = getPendingSigs(tx)
		return
	})

	a.Equal(3, len(roundSigs))
}

func TestWorkerBuildersRecoveryIsNotLimited(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	var keys []account.Participation
	for i := 0; i < 10; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, len(keys))
	w := newTestWorker(t, s)
	w.Start()
	defer w.Shutdown()

	s.advanceRoundsWithoutStateProof(proto.StateProofInterval + proto.StateProofInterval/2)

	for iter := uint64(0); iter < proto.StateProofMaxRecoveryIntervals+1; iter++ {
		s.advanceRoundsWithoutStateProof(proto.StateProofInterval)
		tx := <-s.txmsg
		a.Equal(tx.Txn.Type, protocol.StateProofTx)
	}

	// since this test involves go routine, we would like to make sure that when
	// we sample the builder it already processed our current round.
	// in order to that, we wait for singer and the builder to wait.
	// then we push one more round so the builder could process it (since the builder might skip rounds)
	err := waitForBuilderAndSignerToWaitOnRound(s)
	a.NoError(err)
	s.mu.Lock()
	s.addBlock(basics.Round(proto.StateProofInterval * 2))
	s.mu.Unlock()
	err = waitForBuilderAndSignerToWaitOnRound(s)
	a.NoError(err)

	// should not give up on rounds
	a.Equal(proto.StateProofMaxRecoveryIntervals+1, uint64(len(w.builders)))
	countDB, err := countBuildersInDB(w.db)
	a.NoError(err)
	a.Equal(proto.StateProofMaxRecoveryIntervals+1, uint64(countDB))

	var roundSigs map[basics.Round][]pendingSig
	err = w.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		roundSigs, err = getPendingSigs(tx)
		return
	})
	a.Equal(proto.StateProofMaxRecoveryIntervals+1, uint64(len(roundSigs)))

	s.advanceRoundsWithoutStateProof(proto.StateProofInterval)
	tx := <-s.txmsg
	a.Equal(tx.Txn.Type, protocol.StateProofTx)

	err = waitForBuilderAndSignerToWaitOnRound(s)
	a.NoError(err)
	s.mu.Lock()
	s.addBlock(basics.Round(proto.StateProofInterval * 2))
	s.mu.Unlock()
	err = waitForBuilderAndSignerToWaitOnRound(s)
	a.NoError(err)

	// Although the max recovery has passed the worker will not delete
	// builder and signatures
	a.Equal(proto.StateProofMaxRecoveryIntervals+2, uint64(len(w.builders)))
	countDB, err = countBuildersInDB(w.db)
	a.NoError(err)
	a.Equal(proto.StateProofMaxRecoveryIntervals+2, uint64(countDB))

	roundSigs = make(map[basics.Round][]pendingSig)
	err = w.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		roundSigs, err = getPendingSigs(tx)
		return
	})
	a.Equal(proto.StateProofMaxRecoveryIntervals+2, uint64(len(roundSigs)))
}

func waitForBuilderAndSignerToWaitOnRound(s *testWorkerStubs) error {
	const maxRetries = 10000
	i := 0
	for {
		s.mu.Lock()
		r := s.latest + 1
		// in order to make sure the builder and the signer are waiting for a round we need to make sure
		// that round r has c channel and r +1 doesn't have.
		// we also want to make sure that the builder and the singer are waiting
		isWaitingForRound := s.waiters[r] != nil && s.waiters[r+1] == nil
		isWaitingForRound = isWaitingForRound && (s.waitersCount[r] == 2)
		s.mu.Unlock()
		if !isWaitingForRound {
			if i == maxRetries {
				return fmt.Errorf("timeout while waiting for round")
			}
			i++
			time.Sleep(time.Millisecond)
			continue
		}
		return nil
	}
}

type sigOrigin int

const (
	sigFromThisNode sigOrigin = iota
	sigNotFromThisNode
	sigAlternateOrigin
)

// getSignaturesInDatabase sets up the db with signatures. This function supports creating up to StateProofInterval/2 address.
func getSignaturesInDatabase(t *testing.T, numAddresses int, sigFrom sigOrigin) (
	signatureBcasted map[basics.Address]int, fromThisNode map[basics.Address]bool,
	tns *testWorkerStubs, spw *Worker) {

	// Some tests rely on having only one signature being broadcast at a single round.
	// for that we need to make sure that addresses won't fall into the same broadcast round.
	// For that same reason we can't have more than StateProofInterval / 2 address
	require.LessOrEqual(t, uint64(numAddresses), config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval/2)

	// Prepare the addresses and the keys
	signatureBcasted = make(map[basics.Address]int)
	fromThisNode = make(map[basics.Address]bool)
	var keys []account.Participation
	for i := 0; i < numAddresses; i++ {
		var parent basics.Address
		binary.LittleEndian.PutUint64(parent[:], uint64(i))
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
		signatureBcasted[parent] = 0
	}

	tns = newWorkerStubs(t, keys, len(keys))
	spw = newTestWorker(t, tns)

	// Prepare the database
	err := makeStateProofDB(spw.db)
	require.NoError(t, err)

	// All the keys are for round 255. This way, starting the period at 256,
	// there will be no disqualified signatures from broadcasting because they are
	// into the future.
	round := basics.Round(255)

	// Sign the message
	spRecords := tns.StateProofKeys(round)
	sigs := make([]sigFromAddr, 0, len(keys))
	stateproofMessage := stateproofmsg.Message{}
	hashedStateproofMessage := stateproofMessage.Hash()
	for _, key := range spRecords {
		sig, err := key.StateProofSecrets.SignBytes(hashedStateproofMessage[:])
		require.NoError(t, err)
		sigs = append(sigs, sigFromAddr{
			SignerAddress: key.Account,
			Round:         round,
			Sig:           sig,
		})
	}

	// Add the signatures to the database
	ftn := sigFrom == sigAlternateOrigin || sigFrom == sigFromThisNode
	for _, sfa := range sigs {
		err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			return addPendingSig(tx, sfa.Round, pendingSig{
				signer:       sfa.SignerAddress,
				sig:          sfa.Sig,
				fromThisNode: ftn,
			})
		})
		require.NoError(t, err)
		fromThisNode[sfa.SignerAddress] = ftn
		if sigFrom == sigAlternateOrigin {
			// alternate the fromThisNode argument between addresses
			ftn = !ftn
		}
	}
	return
}

// TestSigBroacastTwoPerSig checks if each signature is broadcasted twice per period
// It generates numAddresses and prepares a database with the account/signatures.
// Then, calls broadcastSigs with round numbers spanning periods and
// makes sure each account has 2 sigs sent per period if originated locally, and 1 sig
// if received from another relay.
func TestSigBroacastTwoPerSig(t *testing.T) {
	partitiontest.PartitionTest(t)
	signatureBcasted, fromThisNode, tns, spw := getSignaturesInDatabase(t, 10, sigAlternateOrigin)

	for periods := 1; periods < 10; periods += 3 {
		sendReceiveCountMessages(t, tns, signatureBcasted, fromThisNode, spw, periods)
		// reopen the channel
		tns.sigmsg = make(chan []byte, 1024)
		// reset the counters
		for addr := range signatureBcasted {
			signatureBcasted[addr] = 0
		}
	}
}

func sendReceiveCountMessages(t *testing.T, tns *testWorkerStubs, signatureBcasted map[basics.Address]int,
	fromThisNode map[basics.Address]bool, spw *Worker, periods int) {

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	// Collect the broadcast messages
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for bMsg := range tns.sigmsg {
			sfa := sigFromAddr{}
			err := protocol.Decode(bMsg, &sfa)
			require.NoError(t, err)
			signatureBcasted[sfa.SignerAddress]++
		}
	}()

	// Broadcast the messages
	for brnd := 257; brnd < 257+int(proto.StateProofInterval)*periods; brnd++ {
		spw.broadcastSigs(basics.Round(brnd), proto)
	}

	close(tns.sigmsg)
	wg.Wait()

	// Verify the number of times each signature was broadcast
	for addr, sb := range signatureBcasted {
		if fromThisNode[addr] {
			require.Equal(t, 2*periods, sb)
		} else {
			require.Equal(t, periods, sb)
		}
	}
}

func TestBuilderGeneratesValidStateProofTXN(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var keys []account.Participation
	for i := 0; i < 10; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, len(keys))
	w := newTestWorker(t, s)
	w.Start()
	defer w.Shutdown()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(proto.StateProofInterval + proto.StateProofInterval/2)

	s.advanceRoundsWithoutStateProof(proto.StateProofInterval)

	for i := 0; i < len(keys); i++ {
		// Expect all signatures to be broadcast.
		_, err := s.waitOnSigWithTimeout(time.Second * 2)
		require.NoError(t, err)
	}

	tx, err := s.waitOnTxnWithTimeout(time.Second * 5)
	require.NoError(t, err)

	a.NoError(tx.Txn.WellFormed(transactions.SpecialAddresses{}, proto))
}

// TestForwardNotFromThisNodeSecondHalf tests that relays forward
// signatures from other nodes only in the second half of the period
func TestForwardNotFromThisNodeSecondHalf(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, _, tns, spw := getSignaturesInDatabase(t, 10, sigNotFromThisNode)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	for brnd := 0; brnd < int(proto.StateProofInterval*10); brnd++ {
		spw.broadcastSigs(basics.Round(brnd), proto)
		select {
		case <-tns.sigmsg:
			// The message is broadcast in the second half of the period
			require.GreaterOrEqual(t, brnd%int(proto.StateProofInterval), int(proto.StateProofInterval)/2)
		default:
		}
	}
}

// TestForwardNotFromThisNodeFirstHalf tests that relays forward
// signatures in the first half of the period only if it is from this node
func TestForwardNotFromThisNodeFirstHalf(t *testing.T) {
	partitiontest.PartitionTest(t)

	signatureBcasted, fromThisNode, tns, spw := getSignaturesInDatabase(t, 10, sigAlternateOrigin)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	for brnd := 0; brnd < int(proto.StateProofInterval*10); brnd++ {
		spw.broadcastSigs(basics.Round(brnd), proto)
		select {
		case bMsg := <-tns.sigmsg:
			sfa := sigFromAddr{}
			err := protocol.Decode(bMsg, &sfa)
			require.NoError(t, err)

			// If it is in the first half, then it must be from this node
			if brnd%int(proto.StateProofInterval) < int(proto.StateProofInterval)/2 {
				require.True(t, fromThisNode[sfa.SignerAddress])
				signatureBcasted[sfa.SignerAddress]++
				continue
			}

			// The message is broadcast in the second half of the period, can be from this node or another node
			require.GreaterOrEqual(t, brnd%int(proto.StateProofInterval), int(proto.StateProofInterval)/2)
			if fromThisNode[sfa.SignerAddress] {
				// It must have already been broadcasted once in the first period
				require.Equal(t, brnd/int(proto.StateProofInterval), signatureBcasted[sfa.SignerAddress])
			}
		default:
		}
	}
}

func setBlocksAndMessage(t *testing.T, sigRound basics.Round) (s *testWorkerStubs, w *Worker, msg sigFromAddr, msgBytes []byte) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var address basics.Address
	crypto.RandBytes(address[:])
	p := newPartKey(t, address)
	defer p.Close()

	s = newWorkerStubs(t, []account.Participation{p.Participation}, 10)
	w = newTestWorker(t, s)

	for r := 0; r < int(proto.StateProofInterval)*2; r++ {
		s.addBlock(basics.Round(proto.StateProofInterval * 2))
	}

	msg = sigFromAddr{
		SignerAddress: address,
		Round:         sigRound,
		Sig:           merklesignature.Signature{},
	}
	msgBytes = protocol.Encode(&msg)
	return
}

// relays reject signatures for old rounds (before stateproofNext) not disconnect
func TestWorkerHandleSigOldRounds(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	intervalRound := basics.Round(proto.StateProofInterval)
	_, w, msg, msgBytes := setBlocksAndMessage(t, intervalRound)

	reply := w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, reply)

	fwd, err := w.handleSig(msg, msg.SignerAddress)
	require.Equal(t, network.Ignore, fwd)
	require.NoError(t, err)
}

// relays reject signatures for a round not in ledger
func TestWorkerHandleSigRoundNotInLedger(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	intervalRound := basics.Round(proto.StateProofInterval)
	_, w, msg, msgBytes := setBlocksAndMessage(t, intervalRound*10)
	defer w.Shutdown()

	reply := w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, reply)

	fwd, err := w.handleSig(msg, msg.SignerAddress)
	require.Equal(t, network.Ignore, fwd)
	require.ErrorContains(t, err, "latest round is smaller than given")
}

// relays reject signatures for wrong message (sig verification fails)
func TestWorkerHandleSigWrongSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	intervalRound := basics.Round(proto.StateProofInterval)
	_, w, msg, msgBytes := setBlocksAndMessage(t, intervalRound*2)
	err := makeStateProofDB(w.db)
	require.NoError(t, err)

	reply := w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Disconnect}, reply)

	fwd, err := w.handleSig(msg, msg.SignerAddress)
	require.Equal(t, network.Disconnect, fwd)
	expected2 := fmt.Errorf("%w: %v",
		merklesignature.ErrSignatureSchemeVerificationFailed,
		merklearray.ErrRootMismatch)
	require.Equal(t, expected2, err)
}

// relays reject signatures for address not in top N
func TestWorkerHandleSigAddrsNotInTopN(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	proto.StateProofTopVoters = 2

	addresses := make([]basics.Address, 0)
	var keys []account.Participation
	for i := 0; i < 4; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		addresses = append(addresses, parent)

		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys[0:proto.StateProofTopVoters], 10)
	w := newTestWorker(t, s)
	err := makeStateProofDB(w.db)
	require.NoError(t, err)

	for r := 0; r < int(proto.StateProofInterval)*2; r++ {
		s.addBlock(basics.Round(r))
	}

	msg := sigFromAddr{
		SignerAddress: addresses[3],
		Round:         basics.Round(proto.StateProofInterval * 2),
		Sig:           merklesignature.Signature{},
	}

	msgBytes := protocol.Encode(&msg)
	reply := w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Disconnect}, reply)

	fwd, err := w.handleSig(msg, msg.SignerAddress)
	require.Equal(t, network.Disconnect, fwd)
	expected3 := fmt.Errorf("handleSig: %v not in participants for %d",
		msg.SignerAddress, msg.Round)
	require.Equal(t, expected3, err)
}

// Signature already part of the builderForRound, ignore
func TestWorkerHandleSigAlreadyIn(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	lastRound := proto.StateProofInterval * 2
	s, w, msg, _ := setBlocksAndMessage(t, basics.Round(lastRound))

	latestBlockHeader, err := w.ledger.BlockHdr(basics.Round(lastRound))
	require.NoError(t, err)
	stateproofMessage, err := GenerateStateProofMessage(w.ledger, proto.StateProofInterval, latestBlockHeader)
	require.NoError(t, err)

	hashedStateproofMessage := stateproofMessage.Hash()
	spRecords := s.StateProofKeys(basics.Round(proto.StateProofInterval * 2))
	sig, err := spRecords[0].StateProofSecrets.SignBytes(hashedStateproofMessage[:])
	require.NoError(t, err)

	msg.Sig = sig
	// Create the database
	err = makeStateProofDB(w.db)
	require.NoError(t, err)

	msgBytes := protocol.Encode(&msg)
	// First call to add the sig
	reply := w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Broadcast}, reply)

	// The sig is already there. Shoud get error
	reply = w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, reply)

	fwd, err := w.handleSig(msg, msg.SignerAddress)
	require.Equal(t, network.Ignore, fwd)
	require.NoError(t, err)
}

// Ignore on db internal error and report error
func TestWorkerHandleSigExceptionsDbError(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	lastRound := proto.StateProofInterval * 2
	s, w, msg, _ := setBlocksAndMessage(t, basics.Round(lastRound))
	defer w.Shutdown()

	latestBlockHeader, err := w.ledger.BlockHdr(basics.Round(lastRound))
	require.NoError(t, err)

	stateproofMessage, err := GenerateStateProofMessage(w.ledger, proto.StateProofInterval, latestBlockHeader)
	require.NoError(t, err)

	hashedStateproofMessage := stateproofMessage.Hash()
	spRecords := s.StateProofKeys(basics.Round(proto.StateProofInterval * 2))
	sig, err := spRecords[0].StateProofSecrets.SignBytes(hashedStateproofMessage[:])
	require.NoError(t, err)
	msg.Sig = sig

	msgBytes := protocol.Encode(&msg)
	reply := w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, reply)

	fwd, err := w.handleSig(msg, msg.SignerAddress)
	require.Equal(t, network.Ignore, fwd)
	require.Contains(t, "no such table: sigs", err.Error())
}

// relays reject signatures when could not createBuilder
func TestWorkerHandleSigCantMakeBuilder(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	origProto := proto
	defer func() {
		config.Consensus[protocol.ConsensusCurrentVersion] = origProto
	}()
	proto.StateProofInterval = 512
	config.Consensus[protocol.ConsensusCurrentVersion] = proto

	var address basics.Address
	crypto.RandBytes(address[:])
	p := newPartKey(t, address)
	defer p.Close()

	s := newWorkerStubs(t, []account.Participation{p.Participation}, 10)
	w := newTestWorker(t, s)
	defer w.Shutdown()

	for r := 0; r < int(proto.StateProofInterval)*2; r++ {
		s.addBlock(basics.Round(512))
	}
	// remove the first block from the ledger
	delete(s.blocks, 0)

	msg := sigFromAddr{
		SignerAddress: address,
		Round:         basics.Round(proto.StateProofInterval),
		Sig:           merklesignature.Signature{},
	}

	msgBytes := protocol.Encode(&msg)
	reply := w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, reply)

	fwd, err := w.handleSig(msg, msg.SignerAddress)
	require.Equal(t, network.Ignore, fwd)
	expected := ledgercore.ErrNoEntry{
		Round:     0,
		Latest:    w.ledger.Latest(),
		Committed: w.ledger.Latest(),
	}
	require.Equal(t, expected, err)
}

// relays reject signiture for a round where StateProofInterval is 0
func TestWorkerHandleSigIntervalZero(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	origProto := proto
	defer func() {
		config.Consensus[protocol.ConsensusCurrentVersion] = origProto
	}()
	proto.StateProofInterval = 0
	config.Consensus[protocol.ConsensusCurrentVersion] = proto

	intervalRound := basics.Round(proto.StateProofInterval)
	_, w, msg, msgBytes := setBlocksAndMessage(t, intervalRound*2)

	reply := w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Disconnect}, reply)

	fwd, err := w.handleSig(msg, msg.SignerAddress)
	require.Equal(t, network.Disconnect, fwd)
	expected := fmt.Errorf("handleSig: StateProofInterval is 0 for round %d",
		uint64(msg.Round))
	require.Equal(t, expected, err)
}

// relays reject signiture for a round not multiple of StateProofInterval
func TestWorkerHandleSigNotOnInterval(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	_, w, msg, msgBytes := setBlocksAndMessage(t, basics.Round(600))

	reply := w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Disconnect}, reply)

	fwd, err := w.handleSig(msg, msg.SignerAddress)
	require.Equal(t, network.Disconnect, fwd)
	expected := fmt.Errorf("handleSig: round %d is not a multiple of SP interval %d",
		msg.Round, proto.StateProofInterval)
	require.Equal(t, expected, err)
}

// relays handle corrupt message
func TestWorkerHandleSigCorrupt(t *testing.T) {
	partitiontest.PartitionTest(t)

	var address basics.Address
	crypto.RandBytes(address[:])
	p := newPartKey(t, address)
	defer p.Close()

	s := newWorkerStubs(t, []account.Participation{p.Participation}, 10)
	w := newTestWorker(t, s)

	msg := sigFromAddr{}
	msgBytes := protocol.Encode(&msg)
	msgBytes[0] = 55 // arbitrary value to fail protocol.Decode

	reply := w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Disconnect}, reply)
}

func TestBuildersPersistenceAfterRestart(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var keys []account.Participation
	for i := 0; i < 2; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, 10)
	dbRand := crypto.RandUint64()
	dbs, _ := dbOpenTestRand(t, true, dbRand)
	w := newTestWorkerDB(t, s, dbs.Wdb)
	w.Start()

	const expectedStateproofs = 9
	const firstExpectedStateproof = 512

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof((expectedStateproofs+1)*proto.StateProofInterval + proto.StateProofInterval/2) // 512, 768, 1024, ... (9 StateProofs)

	err := waitForBuilderAndSignerToWaitOnRound(s)
	a.NoError(err)

	compareBuilders(a, expectedStateproofs, w, firstExpectedStateproof, proto)

	w.Shutdown()
	// we make sure that the worker will not be able to create a builder by disabling the mock ledger
	s.keysForVoters = []account.Participation{}

	dbs, _ = dbOpenTestRand(t, true, dbRand)
	w = newTestWorkerDB(t, s, dbs.Wdb)
	w.Start()
	defer w.Shutdown()

	compareBuilders(a, expectedStateproofs, w, firstExpectedStateproof, proto)
}

func TestWorkerInitOnlySignaturesInDatabase(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var keys []account.Participation
	for i := 0; i < 2; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	const expectedStateproofs = 9
	const firstExpectedStateproof = 512

	s := newWorkerStubs(t, keys, 10)
	dbRand := crypto.RandUint64()
	dbs, _ := dbOpenTestRand(t, true, dbRand)
	w := newTestWorkerDB(t, s, dbs.Wdb)
	w.Start()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof((expectedStateproofs+1)*proto.StateProofInterval + proto.StateProofInterval/2) // 512, 768, 1024, ... (9 StateProofs)

	err := waitForBuilderAndSignerToWaitOnRound(s)
	a.NoError(err)

	w.Shutdown()
	dbs, _ = dbOpenTestRand(t, true, dbRand)
	w = newTestWorkerDB(t, s, dbs.Wdb)

	// we now remove all builders from the table. This will cause the worker to create the builders from the ledger.
	a.NoError(w.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("DELETE  from builders")
		return err
	}))

	w.Start()
	defer w.Shutdown()

	compareBuilders(a, expectedStateproofs, w, firstExpectedStateproof, proto)

}

func compareBuilders(a *require.Assertions, expectedStateproofs int, w *Worker, firstExpectedStateproof int, proto config.ConsensusParams) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// In memory
	a.Equal(expectedStateproofs, len(w.builders))
	// In disk
	r := basics.Round(firstExpectedStateproof)
	for i := 0; i < expectedStateproofs; i++ {
		var builderFromDisk builder
		a.NoError(
			w.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
				var err error
				builderFromDisk, err = getBuilder(tx, r)
				return err
			}))
		a.Equal(w.builders[r].BuilderPersistingFields, builderFromDisk.BuilderPersistingFields)
		r += basics.Round(proto.StateProofInterval)
	}

	// verify the in-memory builder has signatures loaded
	for _, v := range w.builders {
		for j := 0; j < len(v.Participants); j++ {
			present, err := v.Present(uint64(j))
			a.NoError(err)
			a.True(present)
		}
	}
}

func TestWorkerLoadsBuilderAndSignatureUponMsgRecv(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	lastRound := proto.StateProofInterval * 2
	s, w, msg, _ := setBlocksAndMessage(t, basics.Round(lastRound))

	latestBlockHeader, err := w.ledger.BlockHdr(basics.Round(lastRound))
	require.NoError(t, err)
	stateproofMessage, err := GenerateStateProofMessage(w.ledger, proto.StateProofInterval, latestBlockHeader)
	require.NoError(t, err)

	hashedStateproofMessage := stateproofMessage.Hash()
	spRecords := s.StateProofKeys(basics.Round(proto.StateProofInterval * 2))
	sig, err := spRecords[0].StateProofSecrets.SignBytes(hashedStateproofMessage[:])
	require.NoError(t, err)

	msg.Sig = sig
	// Create the database
	err = makeStateProofDB(w.db)
	require.NoError(t, err)

	msgBytes := protocol.Encode(&msg)
	// add signature so  builder will get loaded
	reply := w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Broadcast}, reply)

	// we make sure that the worker will not be able to create a builder by disabling the mock ledger
	s.keysForVoters = []account.Participation{}

	// removing the builder from memory will force the worker to load it from disk
	w.builders = make(map[basics.Round]builder)
	_, exists := w.builders[msg.Round]
	require.False(t, exists)
	fwd, err := w.handleSig(msg, msg.SignerAddress)
	// we expect the handler to ignore the signature since the builder and the old signature were loaded
	require.Equal(t, network.Ignore, fwd)
	require.NoError(t, err)
	_, exists = w.builders[msg.Round]
	require.True(t, exists)

	// verify that builders can be loaded even if there are no signatures
	w.builders = make(map[basics.Round]builder)
	_, exists = w.builders[msg.Round]
	require.False(t, exists)
	require.NoError(t, w.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("DELETE  from sigs")
		return err
	}))
	fwd, err = w.handleSig(msg, msg.SignerAddress)
	require.Equal(t, network.Broadcast, fwd)
	require.NoError(t, err)
	_, exists = w.builders[msg.Round]
	require.True(t, exists)

	// remove builder from disk and memory we fail the builder creation (since the ledger also returns error)
	require.NoError(t, w.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("DELETE  from builders")
		return err
	}))
	w.builders = make(map[basics.Round]builder)
	_, err = w.handleSig(msg, msg.SignerAddress)
	require.ErrorIs(t, err, errEmptyVoters)
	_, exists = w.builders[msg.Round]
	require.False(t, exists)
}
