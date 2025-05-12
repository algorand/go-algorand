// Copyright (C) 2019-2025 Algorand, Inc.
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
	"os"
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
	listenerMu                deadlock.RWMutex
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
	commitListener            ledgercore.VotersCommitListener
}

func newWorkerStubs(t *testing.T, keys []account.Participation, totalWeight int) *testWorkerStubs {
	return newWorkerStubsWithVersion(t, keys, protocol.ConsensusCurrentVersion, totalWeight)
}

func newWorkerStubsWithChannel(t *testing.T, keys []account.Participation, totalWeight int) *testWorkerStubs {
	worker := newWorkerStubsWithVersion(t, keys, protocol.ConsensusCurrentVersion, totalWeight)
	worker.sigmsg = make(chan []byte, 1024*1024)
	worker.txmsg = make(chan transactions.SignedTxn, 1024)
	return worker
}

func newWorkerStubAtGenesis(t *testing.T, keys []account.Participation, totalWeight int) *testWorkerStubs {
	s := &testWorkerStubs{
		t:                         t,
		mu:                        deadlock.Mutex{},
		listenerMu:                deadlock.RWMutex{},
		latest:                    0,
		waiters:                   make(map[basics.Round]chan struct{}),
		waitersCount:              make(map[basics.Round]int),
		blocks:                    make(map[basics.Round]bookkeeping.BlockHeader),
		keys:                      keys,
		keysForVoters:             keys,
		sigmsg:                    nil,
		txmsg:                     nil,
		totalWeight:               totalWeight,
		deletedKeysBeforeRoundMap: map[account.ParticipationID]basics.Round{},
		version:                   protocol.ConsensusCurrentVersion,
	}
	s.latest--
	s.addBlock(2 * basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval))
	return s
}

func newWorkerStubsWithVersion(t *testing.T, keys []account.Participation, version protocol.ConsensusVersion, totalWeight int) *testWorkerStubs {
	proto := config.Consensus[version]
	s := &testWorkerStubs{
		t:                         t,
		mu:                        deadlock.Mutex{},
		listenerMu:                deadlock.RWMutex{},
		latest:                    0,
		waiters:                   make(map[basics.Round]chan struct{}),
		waitersCount:              make(map[basics.Round]int),
		blocks:                    make(map[basics.Round]bookkeeping.BlockHeader),
		keys:                      keys,
		keysForVoters:             keys,
		sigmsg:                    nil,
		txmsg:                     nil,
		totalWeight:               totalWeight,
		deletedKeysBeforeRoundMap: map[account.ParticipationID]basics.Round{},
		version:                   version,
	}
	s.latest--
	s.addBlock(2 * basics.Round(proto.StateProofInterval))
	s.advanceRoundsBeforeFirstStateProof(&proto)
	return s
}

func (s *testWorkerStubs) notifyPrepareVoterCommit(oldBase, newBase basics.Round) {
	s.listenerMu.RLock()
	defer s.listenerMu.RUnlock()

	if s.commitListener == nil {
		return
	}

	s.commitListener.OnPrepareVoterCommit(oldBase, newBase, s)
}

func (s *testWorkerStubs) addBlock(spNextRound basics.Round) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.latest++

	hdr := bookkeeping.BlockHeader{}
	hdr.Round = s.latest
	hdr.CurrentProtocol = s.version
	var stateProofBasic = bookkeeping.StateProofTrackingData{
		StateProofVotersCommitment:  make([]byte, stateproof.HashSize),
		StateProofOnlineTotalWeight: basics.MicroAlgos{},
		StateProofNextRound:         0,
	}

	spInterval := config.Consensus[s.version].StateProofInterval
	if spInterval != 0 && (hdr.Round > 0 && uint64(hdr.Round)%spInterval == 0) {
		vt, _ := s.VotersForStateProof(hdr.Round)
		stateProofBasic.StateProofOnlineTotalWeight = vt.TotalWeight
		stateProofBasic.StateProofVotersCommitment = vt.Tree.Root()
	}

	stateProofBasic.StateProofNextRound = spNextRound
	hdr.StateProofTracking = map[protocol.StateProofType]bookkeeping.StateProofTrackingData{
		protocol.StateProofBasic: stateProofBasic,
	}

	s.blocks[s.latest] = hdr

	s.waitersCount[s.latest] = 0
	if s.waiters[s.latest] != nil {
		close(s.waiters[s.latest])
		s.waiters[s.latest] = nil
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

func (s *testWorkerStubs) RegisterVotersCommitListener(listener ledgercore.VotersCommitListener) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	if s.commitListener != nil {
		panic("re-register commit Listener")
	}
	s.commitListener = listener
}

func (s *testWorkerStubs) UnregisterVotersCommitListener() {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	s.commitListener = nil
}

func (s *testWorkerStubs) VotersForStateProof(r basics.Round) (*ledgercore.VotersForRound, error) {
	if r == 0 {
		return nil, nil
	}

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

func (s *testWorkerStubs) StateProofVerificationContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	dummyContext := ledgercore.StateProofVerificationContext{
		LastAttestedRound: stateProofLastAttestedRound,
		VotersCommitment:  crypto.GenericDigest{0x1},
		OnlineTotalWeight: basics.MicroAlgos{},
		Version:           protocol.ConsensusCurrentVersion,
	}

	return &dummyContext, nil
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
	}

	if r <= s.latest {
		s.waitersCount[r] = 0
		close(s.waiters[r])
		retChan := s.waiters[r]
		s.waiters[r] = nil
		return retChan
	}
	s.waitersCount[r]++
	return s.waiters[r]
}

func (s *testWorkerStubs) Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except network.Peer) error {
	require.Equal(s.t, tag, protocol.StateProofSigTag)
	if s.sigmsg == nil {
		return nil
	}
	s.sigmsg <- data
	return nil
}

func (s *testWorkerStubs) BroadcastInternalSignedTxGroup(tx []transactions.SignedTxn) error {
	require.Equal(s.t, len(tx), 1)
	if s.txmsg == nil {
		return nil
	}
	s.txmsg <- tx[0]
	return nil
}

func (s *testWorkerStubs) RegisterHandlers([]network.TaggedMessageHandler) {
}

func (s *testWorkerStubs) waitForSignerAndBuilder(t *testing.T) {
	const maxRetries = 1000000
	i := 0
	for {
		numberOfWaiters := 0
		s.mu.Lock()
		for _, v := range s.waitersCount {
			numberOfWaiters += v
		}
		s.mu.Unlock()
		if numberOfWaiters == 2 {
			break
		}
		if numberOfWaiters > 2 {
			t.Error("found numberOfWaiters > 2. Might be bug in the test")
		}
		if i == maxRetries {
			t.Error("timeout waiting for builder and signer")
		}
		i++
		time.Sleep(time.Millisecond)
	}
}

func (s *testWorkerStubs) advanceRoundsBeforeFirstStateProof(proto *config.ConsensusParams) {
	if proto.StateProofInterval*2 <= 1 {
		return
	}

	for r := uint64(0); r < proto.StateProofInterval*2-1; r++ {
		s.addBlock(s.blocks[s.latest].StateProofTracking[protocol.StateProofBasic].StateProofNextRound)
	}
}

func (s *testWorkerStubs) advanceRoundsWithoutStateProof(t *testing.T, delta uint64) {
	for r := uint64(0); r < delta; r++ {
		s.addBlock(s.blocks[s.latest].StateProofTracking[protocol.StateProofBasic].StateProofNextRound)
		s.waitForSignerAndBuilder(t)
	}
}

// used to simulate to workers that rounds have advanced, and stateproofs were created.
func (s *testWorkerStubs) advanceRoundsAndCreateStateProofs(t *testing.T, delta uint64) {
	for r := uint64(0); r < delta; r++ {
		s.mu.Lock()
		interval := basics.Round(config.Consensus[s.blocks[s.latest].CurrentProtocol].StateProofInterval)
		blk := s.blocks[s.latest]
		stateProofNextRound := s.blocks[s.latest].StateProofTracking[protocol.StateProofBasic].StateProofNextRound
		if blk.Round%interval == 0 && stateProofNextRound-interval < blk.Round {
			stateProofNextRound += interval
		}
		s.mu.Unlock()
		s.addBlock(stateProofNextRound)
		s.waitForSignerAndBuilder(t)
	}
}

func (s *testWorkerStubs) mockCommit(upTo basics.Round) {
	startRound := upTo

	s.mu.Lock()
	for round := range s.blocks {
		if round < startRound {
			startRound = round
		}
	}
	s.mu.Unlock()
	s.notifyPrepareVoterCommit(startRound, upTo)

	for round := startRound; round <= upTo; round++ {
		s.mu.Lock()
		delete(s.blocks, round)
		s.mu.Unlock()
	}
}

func (s *testWorkerStubs) waitOnSigWithTimeout(timeout time.Duration) ([]byte, error) {
	select {
	case sig := <-s.sigmsg:
		return sig, nil
	case <-time.After(timeout):
		return nil, errors.New("timeout waiting on sigmsg")
	}
}

func (s *testWorkerStubs) waitOnTxnWithTimeout(timeout time.Duration) (transactions.SignedTxn, error) {
	select {
	case signedTx := <-s.txmsg:
		return signedTx, nil
	case <-time.After(timeout):
		return transactions.SignedTxn{}, errors.New("timeout waiting on stateproof txn")
	}
}

func (s *testWorkerStubs) isRoundSigned(a *require.Assertions, w *Worker, round basics.Round) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range s.keys {
		var accountSigExists bool
		err := w.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
			accountSigExists, err = sigExistsInDB(tx, round, key.Parent)
			return err
		})
		a.NoError(err)
		if accountSigExists {
			return true
		}
	}

	return false
}

func newTestWorkerOnDiskDb(t testing.TB, s *testWorkerStubs) *Worker {
	fn := fmt.Sprintf("%s.%d", strings.ReplaceAll(t.Name(), "/", "."), crypto.RandUint64())

	ctx, cancel := context.WithCancel(context.Background())
	return &Worker{
		spDbFileName: fn,
		log:          logging.TestingLog(t),
		accts:        s,
		ledger:       s,
		net:          s,
		txnSender:    s,
		provers:      make(map[basics.Round]spProver),
		ctx:          ctx,
		shutdown:     cancel,
		signedCh:     make(chan struct{}, 1),
	}

}

func newTestWorker(t testing.TB, s *testWorkerStubs) *Worker {
	worker := newTestWorkerOnDiskDb(t, s)
	worker.inMemory = true
	return worker
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

func countProversInDB(store db.Accessor) (nrows int, err error) {
	err = store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		row := tx.QueryRow("SELECT COUNT(*) FROM provers")
		err := row.Scan(&nrows)
		if err != nil {
			return err
		}
		return nil
	})

	return
}

func expectedNumberOfProvers(stateproofInterval uint64, atRound basics.Round, nextStateProof basics.Round) int {
	if nextStateProof > atRound {
		return 0
	}

	return int((atRound-nextStateProof)/basics.Round(stateproofInterval) + 1)
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
	w := newTestWorker(t, s)
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

	s := newWorkerStubsWithChannel(t, keys, len(keys))
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	// at this point the ledger is at round 511 - we add 2 blocks to pass the state proof interval
	s.advanceRoundsWithoutStateProof(t, 2)
	// Go through several iterations, making sure that we get
	// the signatures and certs broadcast at each round.
	for iter := 0; iter < 5; iter++ {
		s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval-1)
		for i := 0; i < 2*len(keys); i++ {
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

			msg, err := GenerateStateProofMessage(s, lastAttestedRound)
			require.NoError(t, err)
			require.Equal(t, msg, tx.Txn.Message)

			provenWeight, overflowed := basics.Muldiv(uint64(s.totalWeight), uint64(proto.StateProofWeightThreshold), 1<<32)
			require.False(t, overflowed)

			voters, err := s.VotersForStateProof(lastAttestedRound - basics.Round(proto.StateProofInterval) - basics.Round(proto.StateProofVotersLookback))
			require.NoError(t, err)

			verif, err := stateproof.MkVerifier(voters.Tree.Root(), provenWeight, proto.StateProofStrengthTarget)
			require.NoError(t, err)

			err = verif.Verify(lastAttestedRound, tx.Txn.Message.Hash(), &tx.Txn.StateProof)
			require.NoError(t, err)
			break
		}
		s.advanceRoundsAndCreateStateProofs(t, 1)
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

	s := newWorkerStubsWithChannel(t, keys, 10)
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	// at this point the ledger is at round 511 - we push add one block, so it will start to create state proofs
	s.advanceRoundsWithoutStateProof(t, 1)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval/2+1)

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
	s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval/2)

	tx, err := s.waitOnTxnWithTimeout(time.Second * 5)
	require.NoError(t, err)

	lastAttestedRound := basics.Round(tx.Txn.Message.LastAttestedRound)
	require.Equal(t, tx.Txn.Type, protocol.StateProofTx)
	require.Equal(t, lastAttestedRound, 2*basics.Round(proto.StateProofInterval))

	msg, err := GenerateStateProofMessage(s, lastAttestedRound)
	require.NoError(t, err)
	require.Equal(t, msg, tx.Txn.Message)

	provenWeight, overflowed := basics.Muldiv(uint64(s.totalWeight), uint64(proto.StateProofWeightThreshold), 1<<32)
	require.False(t, overflowed)

	voters, err := s.VotersForStateProof(lastAttestedRound - basics.Round(proto.StateProofInterval) - basics.Round(proto.StateProofVotersLookback))
	require.NoError(t, err)

	verif, err := stateproof.MkVerifier(voters.Tree.Root(), provenWeight, proto.StateProofStrengthTarget)
	require.NoError(t, err)
	err = verif.Verify(lastAttestedRound, msg.Hash(), &tx.Txn.StateProof)
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

	s := newWorkerStubsWithChannel(t, keys, 10)
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(t, 3*proto.StateProofInterval)

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
	const expectedStateProofs = 5

	var keys []account.Participation
	for i := 0; i < 10; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubsWithChannel(t, keys, len(keys))
	s.sigmsg = nil
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(t, 1)
	lastRound := basics.Round(0)
	for i := 0; i < expectedStateProofs; i++ {
		s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval/2-1)
		w.Stop()
		w.Start()
		s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval/2)

		var tx transactions.SignedTxn
		// there will be several state proof txn. we extract them
		for {
			var err error
			tx, err = s.waitOnTxnWithTimeout(time.Second * 5)
			a.NoError(err)
			if lastRound == 0 || lastRound < tx.Txn.Message.LastAttestedRound {
				break
			}

		}

		// since a state proof txn was created, we update the header with the next state proof round
		// i.e network has accepted the state proof.
		s.addBlock(tx.Txn.Message.LastAttestedRound + basics.Round(proto.StateProofInterval))
		lastRound = tx.Txn.Message.LastAttestedRound
	}
	a.EqualValues(expectedStateProofs+1, lastRound/basics.Round(proto.StateProofInterval))
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

	s := newWorkerStubsWithChannel(t, keys, 10)
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(t, 3*proto.StateProofInterval)

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

func TestWorkerIgnoresSignatureForNonCacheProvers(t *testing.T) {
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
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	targetRound := (proversCacheLength + 1) * proto.StateProofInterval

	s.advanceRoundsWithoutStateProof(t, targetRound)

	// clean up the cache and clean up the signatures database so the handler will accept our signatures.
	s.mu.Lock()
	w.provers = make(map[basics.Round]spProver)
	a.NoError(w.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("DELETE  from sigs")
		return err
	}))
	s.mu.Unlock()

	// rounds [2*proto.StateProofInterval, 3*proto.StateProofInterval, ... (proversCacheLength - 1)*proto.StateProofInterval] should be
	// accepted by handleSig
	i := uint64(0)
	for ; i < (proversCacheLength - 1); i++ {
		fwd, err := sendSigToHandler(proto, i, w, a, s)
		a.Equal(network.Broadcast, fwd)
		a.NoError(err)
	}

	// signature for (proversCacheLength)*proto.StateProofInterval should be rejected - due to cache limit
	fwd, err := sendSigToHandler(proto, i, w, a, s)
	a.Equal(network.Ignore, fwd)
	a.NoError(err)
	i++

	// newest signature should be accepted
	fwd, err = sendSigToHandler(proto, i, w, a, s)
	a.Equal(network.Broadcast, fwd)
	a.NoError(err)

}

func sendSigToHandler(proto config.ConsensusParams, i uint64, w *Worker, a *require.Assertions, s *testWorkerStubs) (network.ForwardingPolicy, error) {
	rnd := basics.Round(2*proto.StateProofInterval + i*proto.StateProofInterval)
	stateproofMessage, err := GenerateStateProofMessage(w.ledger, rnd)
	a.NoError(err)

	hashedStateproofMessage := stateproofMessage.Hash()
	spRecords := s.StateProofKeys(rnd)
	sig, err := spRecords[0].StateProofSecrets.SignBytes(hashedStateproofMessage[:])
	a.NoError(err)

	msg := sigFromAddr{
		SignerAddress: spRecords[0].Account,
		Round:         rnd,
		Sig:           sig,
	}

	fwd, err := w.handleSig(msg, msg.SignerAddress)
	return fwd, err
}

func TestKeysRemoveOnlyAfterStateProofAccepted(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	const expectedNumberOfStateProofs = uint64(3)
	firstExpectedStateproof := basics.Round(proto.StateProofInterval * 2)

	keys, s, w := createWorkerAndParticipants(t, protocol.ConsensusCurrentVersion, proto)
	defer w.Stop()

	s.advanceRoundsWithoutStateProof(t, expectedNumberOfStateProofs*proto.StateProofInterval)

	// since no state proof was confirmed (i.e the next state proof round == firstExpectedStateproof), we expect a node
	// to keep its keys to sign the state proof firstExpectedStateproof. every participant should have keys for that round
	checkedKeys := s.StateProofKeys(firstExpectedStateproof)
	require.Equal(t, len(keys), len(checkedKeys))
	requireDeletedKeysToBeDeletedBefore(t, s, firstExpectedStateproof) // i should at this point have the keys to sign on round 512.... how come they were deleted?

	s.advanceRoundsAndCreateStateProofs(t, proto.StateProofInterval)

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
	defer w.Stop()

	s.advanceRoundsWithoutStateProof(t, expectedNumberOfStateProofs*proto.StateProofInterval)

	// since no state proof was confirmed (i.e the next state proof round == firstExpectedStateproof), we expect a node
	// to keep its keys to sign the state proof firstExpectedStateproof. every participant should have keys for that round
	requireDeletedKeysToBeDeletedBefore(t, s, 0)
	checkedKeys := s.StateProofKeys(firstExpectedStateproof)
	require.Equal(t, len(keys), len(checkedKeys))

	// confirm stateproof for firstExpectedStateproof
	s.advanceRoundsAndCreateStateProofs(t, proto.StateProofInterval)

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
	defer w.Stop()

	s.advanceRoundsWithoutStateProof(t, expectedNumberOfStateProofs*proto.StateProofInterval)
	// since no state proof was confirmed (i.e the next state proof round == firstExpectedStateproof), we expect a node
	// to keep its keys to sign the state proof firstExpectedStateproof. every participant should have keys for that round
	requireDeletedKeysToBeDeletedBefore(t, s, firstExpectedStateproof)
	checkedKeys := s.StateProofKeys(firstExpectedStateproof)
	require.Equal(t, len(keys), len(checkedKeys))

	// confirm stateproof for firstExpectedStateproof
	s.advanceRoundsAndCreateStateProofs(t, proto.StateProofInterval)

	// the first state proof was confirmed keys for that state proof can be removed
	requireDeletedKeysToBeDeletedBefore(t, s, basics.Round(proto.StateProofInterval)+firstExpectedStateproof)

	checkedKeys = s.StateProofKeys(firstExpectedStateproof)
	require.Equal(t, 0, len(checkedKeys))
	checkedKeys = s.StateProofKeys(firstExpectedStateproof + basics.Round(proto.StateProofInterval))
	require.Equal(t, len(keys), len(checkedKeys))
}

func TestWorkersProversCacheAndSignatures(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	const expectedStateProofs = proversCacheLength + 2
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
	defer w.Stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	// we break the loop into two part since we don't want to add a state proof round (Round % 256 == 0)
	for iter := 0; iter < expectedStateProofs-1; iter++ {
		s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval)
	}
	s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval/2)

	a.Equal(proversCacheLength, len(w.provers))
	verifyProverCache(proto, w, a, expectedStateProofs)

	countDB, err := countProversInDB(w.db)
	a.NoError(err)
	a.Equal(expectedStateProofs, countDB)

	threshold := onlineProversThreshold(&proto, 512) // 512 since no StateProofs are confirmed yet (512 is the first, commitment at 256)
	var roundSigs map[basics.Round][]pendingSig
	err = w.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		roundSigs, err = getPendingSigs(tx, threshold, basics.Round(256+proto.StateProofInterval*expectedStateProofs), false)
		return
	})
	a.NoError(err)
	a.Equal(proversCacheLength, len(roundSigs)) // Number of broadcasted sigs should be the same as number of (online) cached provers.

	/*
		add block that confirm a state proof for interval: expectedStateProofs
	*/
	s.addBlock(basics.Round((expectedStateProofs) * config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval))
	s.waitForSignerAndBuilder(t)

	count := expectedNumberOfProvers(proto.StateProofInterval, s.latest, basics.Round((expectedStateProofs)*config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval))
	countDB, err = countProversInDB(w.db)
	a.NoError(err)
	a.Equal(count, countDB)

	threshold = onlineProversThreshold(&proto, s.blocks[s.latest].StateProofTracking[protocol.StateProofBasic].StateProofNextRound)
	maxStateProofRnd := s.latest.RoundDownToMultipleOf(basics.Round(proto.StateProofInterval))
	err = w.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		roundSigs, err = getPendingSigs(tx, threshold, maxStateProofRnd, false)
		return
	})
	a.NoError(err)
	a.Equal(count, len(roundSigs))
}

func verifyProverCache(proto config.ConsensusParams, w *Worker, a *require.Assertions, expectedStateProofs uint64) {
	for i := uint64(0); i < proversCacheLength-1; i++ {
		rnd := proto.StateProofInterval*2 + proto.StateProofInterval*i
		_, exists := w.provers[basics.Round(rnd)]
		a.True(exists)
	}
	_, exists := w.provers[basics.Round(proto.StateProofInterval*(expectedStateProofs+1))]
	a.True(exists)
}

// TestSignatureBroadcastPolicy makes sure that during half of a state proof interval, every online account
// will broadcast only proversCacheLength amount of signatures
func TestSignatureBroadcastPolicy(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	const numberOfParticipants = 5
	const expectedStateProofs = proversCacheLength + 2
	var keys []account.Participation
	for i := 0; i < numberOfParticipants; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, len(keys))
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	for iter := 0; iter < expectedStateProofs-1; iter++ {
		s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval)
	}
	// set the latest block to be at round r, where r % 256 == 0
	s.advanceRoundsWithoutStateProof(t, 1)

	checkSignatureBroadcastHalfInterval(t, proto, expectedStateProofs, s, numberOfParticipants, a)
	checkSignatureBroadcastHalfInterval(t, proto, expectedStateProofs, s, numberOfParticipants, a)
}

func checkSignatureBroadcastHalfInterval(t *testing.T, proto config.ConsensusParams, expectedStateProofs uint64, s *testWorkerStubs, numberOfParticipants int, a *require.Assertions) {
	roundSigs := make(map[basics.Round]int)
	for i := uint64(2); i < proversCacheLength; i++ {
		roundSigs[basics.Round(i*proto.StateProofInterval)] = 0
	}
	roundSigs[basics.Round((expectedStateProofs+1)*proto.StateProofInterval)] = 0

	// empty all pending sigs
	s.sigmsg = make(chan []byte, 1024*1024)

	s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval/2)
	for i := 0; i < numberOfParticipants*proversCacheLength; i++ {
		sigMessage := sigFromAddr{}
		sigMessageBytes, err := s.waitOnSigWithTimeout(time.Second * 2)
		a.NoError(err)

		err = protocol.Decode(sigMessageBytes, &sigMessage)
		a.NoError(err)

		roundSigs[sigMessage.Round]++
	}

	a.Equal(proversCacheLength, len(roundSigs))
	for _, numOfSignatures := range roundSigs {
		a.Equal(numberOfParticipants, numOfSignatures)
	}
}

func TestWorkerDoesNotLimitProversAndSignaturesOnDisk(t *testing.T) {
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
	defer w.Stop()

	for iter := uint64(0); iter < proto.StateProofMaxRecoveryIntervals+1; iter++ {
		s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval)
	}

	// should not give up on rounds
	a.Equal(proversCacheLength, len(w.provers))
	countDB, err := countProversInDB(w.db)
	a.NoError(err)
	a.Equal(proto.StateProofMaxRecoveryIntervals+1, uint64(countDB))

	sigsCount := countAllSignaturesInDB(t, w.db)
	a.Equal(proto.StateProofMaxRecoveryIntervals+1, sigsCount)
}

func countAllSignaturesInDB(t *testing.T, accessor db.Accessor) uint64 {
	var roundSigs map[basics.Round][]pendingSig
	err := accessor.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		query := "SELECT sprnd, signer, sig, from_this_node FROM sigs "
		rows, err := tx.Query(query)
		if err != nil {
			return err
		}
		defer rows.Close()
		roundSigs, err = rowsToPendingSigs(rows)
		if err != nil {
			return err
		}
		return nil
	})
	require.NoError(t, err)
	return uint64(len(roundSigs))
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

	tns = newWorkerStubsWithChannel(t, keys, len(keys))
	spw = newTestWorkerOnDiskDb(t, tns)

	// we don't need go routines to run so just create the db
	spw.initDb(false)

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
	defer os.Remove(spw.spDbFileName)
	defer spw.db.Close()

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
		spw.broadcastSigs(basics.Round(brnd), basics.Round(512), proto)
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

func TestProverGeneratesValidStateProofTXN(t *testing.T) {
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

	s := newWorkerStubsWithChannel(t, keys, len(keys))
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval)

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
	defer os.Remove(spw.spDbFileName)
	defer spw.db.Close()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	for brnd := 0; brnd < int(proto.StateProofInterval*10); brnd++ {
		stateProofNextRound := basics.Round(brnd).RoundDownToMultipleOf(basics.Round(proto.StateProofInterval))
		spw.broadcastSigs(basics.Round(brnd), stateProofNextRound, proto)
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
	defer os.Remove(spw.spDbFileName)
	defer spw.db.Close()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	for brnd := 0; brnd < int(proto.StateProofInterval*10); brnd++ {
		stateProofNextRound := basics.Round(brnd).RoundDownToMultipleOf(basics.Round(proto.StateProofInterval))
		spw.broadcastSigs(basics.Round(brnd), stateProofNextRound, proto)
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
	w.initDb(w.inMemory)

	s.addBlock(basics.Round(proto.StateProofInterval * 2))

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

	reply := w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Disconnect}, reply)

	fwd, err := w.handleSig(msg, msg.SignerAddress)
	require.Equal(t, network.Disconnect, fwd)
	require.ErrorIs(t, err, errSignatureVerification)
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

	s := newWorkerStubsWithChannel(t, keys[0:proto.StateProofTopVoters], 10)
	w := newTestWorker(t, s)
	w.initDb(w.inMemory)

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
	require.ErrorIs(t, err, errAddressNotInVoters)
}

// Signature already part of the proverForRound, ignore
func TestWorkerHandleSigAlreadyIn(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	lastRound := proto.StateProofInterval * 2
	s, w, msg, _ := setBlocksAndMessage(t, basics.Round(lastRound))

	stateproofMessage, err := GenerateStateProofMessage(w.ledger, basics.Round(lastRound))
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

	// The sig is already there. Should get error
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

	require.NoError(t, w.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("drop table sigs ")
		return err
	}))

	stateproofMessage, err := GenerateStateProofMessage(w.ledger, basics.Round(lastRound))
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

// relays reject signatures when could not createAndPersistProver
func TestWorkerHandleSigCantMakeProver(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var address basics.Address
	crypto.RandBytes(address[:])
	p := newPartKey(t, address)
	defer p.Close()

	s := newWorkerStubs(t, []account.Participation{p.Participation}, 10)
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	s.addBlock(basics.Round(proto.StateProofInterval * 2))

	s.mu.Lock()
	// remove the first block from the ledger
	delete(s.blocks, 256)
	s.mu.Unlock()

	msg := sigFromAddr{
		SignerAddress: address,
		Round:         basics.Round(proto.StateProofInterval * 2),
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
		Round:     256,
		Latest:    w.ledger.Latest(),
		Committed: w.ledger.Latest(),
	}
	require.Equal(t, expected, err)
}

// relays reject signature for a round where StateProofInterval is 0
func TestWorkerHandleSigIntervalZero(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	origProto := proto
	defer func() {
		config.Consensus[protocol.ConsensusCurrentVersion] = origProto
	}()
	proto.StateProofInterval = 0
	config.Consensus[protocol.ConsensusCurrentVersion] = proto

	_, w, msg, msgBytes := setBlocksAndMessage(t, 1)

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

// relays reject signature for a round not multiple of StateProofInterval
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

func verifyPersistedProvers(a *require.Assertions, w *Worker) {
	w.mu.Lock()

	defer w.mu.Unlock()
	for k, v := range w.provers {
		var proverFromDisk spProver
		a.NoError(
			w.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
				var err error
				proverFromDisk, err = getProver(tx, k)
				return err
			}))
		a.Equal(v.ProverPersistedFields, proverFromDisk.ProverPersistedFields)
	}
}

func TestWorkerCacheAndDiskAfterRestart(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	const expectedStateProofs = proversCacheLength + 1
	var keys []account.Participation
	for i := 0; i < 10; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, len(keys))
	w := newTestWorkerOnDiskDb(t, s)
	defer os.Remove(w.spDbFileName)
	w.Start()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	// we break the loop into two part since we don't want to add a state proof round (Round % 256 == 0)
	for iter := 0; iter < expectedStateProofs-1; iter++ {
		s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval)
	}
	s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval/2)

	// at this point we expect the number of provers in memory to be equal to proversCacheLength
	a.Equal(proversCacheLength, len(w.provers))
	countDB, err := countProversInDB(w.db)
	a.NoError(err)
	a.Equal(expectedStateProofs, countDB)

	threshold := onlineProversThreshold(&proto, 512) // 512 since no StateProofs are confirmed yet (512 is the first, commitment at 256)
	var roundSigs map[basics.Round][]pendingSig
	err = w.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		roundSigs, err = getPendingSigs(tx, threshold, basics.Round(256+proto.StateProofInterval*expectedStateProofs), false)
		return
	})
	a.NoError(err)
	a.Equal(proversCacheLength, len(roundSigs)) // Number of broadcasted sigs should be the same as number of (online) cached provers.

	// restart worker
	w.Stop()
	// we make sure that the worker will not be able to create a prover by disabling the mock ledger
	s.keysForVoters = []account.Participation{}

	w.Start()
	defer w.Stop()

	a.Equal(proversCacheLength, len(w.provers))
	countDB, err = countProversInDB(w.db)
	a.NoError(err)
	a.Equal(expectedStateProofs, countDB)

	verifyPersistedProvers(a, w)
}

func TestWorkerInitOnlySignaturesInDatabase(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	const expectedStateProofs = proversCacheLength + 1
	var keys []account.Participation
	for i := 0; i < 10; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, len(keys))
	w := newTestWorkerOnDiskDb(t, s)
	defer os.Remove(w.spDbFileName)
	w.Start()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	// we break the loop into two part since we don't want to add a state proof round (Round % 256 == 0)
	for iter := 0; iter < expectedStateProofs-1; iter++ {
		s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval)
	}
	s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval/2)

	// at this point we expect the number of provers in memory to be bound with proversCacheLength
	a.Equal(proversCacheLength, len(w.provers))
	countDB, err := countProversInDB(w.db)
	a.NoError(err)
	a.Equal(expectedStateProofs, countDB)

	threshold := onlineProversThreshold(&proto, 512) // 512 since no StateProofs are confirmed yet (512 is the first, commitment at 256)
	var roundSigs map[basics.Round][]pendingSig
	err = w.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		roundSigs, err = getPendingSigs(tx, threshold, basics.Round(256+proto.StateProofInterval*expectedStateProofs), false)
		return
	})
	a.NoError(err)
	a.Equal(proversCacheLength, len(roundSigs)) // Number of broadcasted sigs should be the same as number of (online) cached provers.

	w.Stop()

	accessor, err := db.MakeAccessor(w.spDbFileName, false, false)
	a.NoError(err)
	// we now remove all provers from the table. This will cause the worker to create the provers from the ledger.
	a.NoError(accessor.Atomic(func(_ context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("DELETE  from provers")
		return err
	}))
	accessor.Close()

	w.Start()
	defer w.Stop()

	a.Equal(proversCacheLength, len(w.provers))
	countDB, err = countProversInDB(w.db)
	a.NoError(err)
	a.Equal(proversCacheLength, countDB)

	verifyPersistedProvers(a, w)
}

func TestWorkerLoadsProverAndSignatureUponMsgRecv(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	lastRound := proto.StateProofInterval * 2
	s, w, msg, _ := setBlocksAndMessage(t, basics.Round(lastRound))

	stateproofMessage, err := GenerateStateProofMessage(w.ledger, basics.Round(lastRound))
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
	// add signature so  prover will get loaded
	reply := w.handleSigMessage(network.IncomingMessage{
		Data: msgBytes,
	})
	require.Equal(t, network.OutgoingMessage{Action: network.Broadcast}, reply)

	// we make sure that the worker will not be able to create a prover by disabling the mock ledger
	s.keysForVoters = []account.Participation{}

	// removing the prover from memory will force the worker to load it from disk
	w.provers = make(map[basics.Round]spProver)
	_, exists := w.provers[msg.Round]
	require.False(t, exists)
	fwd, err := w.handleSig(msg, msg.SignerAddress)
	// we expect the handler to ignore the signature since the prover and the old signature were loaded
	require.Equal(t, network.Ignore, fwd)
	require.NoError(t, err)
	_, exists = w.provers[msg.Round]
	require.True(t, exists)

	// verify that provers can be loaded even if there are no signatures
	w.provers = make(map[basics.Round]spProver)
	_, exists = w.provers[msg.Round]
	require.False(t, exists)
	require.NoError(t, w.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("DELETE  from sigs")
		return err
	}))
	fwd, err = w.handleSig(msg, msg.SignerAddress)
	require.Equal(t, network.Broadcast, fwd)
	require.NoError(t, err)
	_, exists = w.provers[msg.Round]
	require.True(t, exists)

	// remove prover from disk and memory we fail the prover creation (since the ledger also returns error)
	require.NoError(t, w.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("DELETE  from provers")
		return err
	}))
	w.provers = make(map[basics.Round]spProver)
	_, err = w.handleSig(msg, msg.SignerAddress)
	require.ErrorIs(t, err, errEmptyVoters)
	_, exists = w.provers[msg.Round]
	require.False(t, exists)
}

func TestWorkerCreatesProversOnCommit(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	_, s, w := createWorkerAndParticipants(t, protocol.ConsensusCurrentVersion, proto)
	defer w.Stop()

	// We remove the signer's keys to stop it from generating provers.
	s.keys = []account.Participation{}

	ProverRound := basics.Round(proto.StateProofInterval * 2)

	// We start on round 511, so the callback should be called when committing the next round.
	s.advanceRoundsWithoutStateProof(t, 2)

	var proverExists bool
	err := w.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		proverExists, err = proverExistInDB(tx, ProverRound)
		return err
	})
	a.NoError(err)
	a.False(proverExists)

	// We leave one round uncommitted to be able to easily discern the stateProofNextRound.
	s.mockCommit(ProverRound)

	proverExists = false
	err = w.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		proverExists, err = proverExistInDB(tx, ProverRound)
		return err
	})
	a.NoError(err)
	a.True(proverExists)
}

func TestSignerUsesPersistedProverLatestProto(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var keys []account.Participation
	for i := 0; i < 2; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, 10)
	w := newTestWorkerOnDiskDb(t, s)
	defer os.Remove(w.spDbFileName)
	w.Start()

	// We remove the signer's keys to stop it from generating provers and signing.
	prevKeys := s.keys
	s.keys = []account.Participation{}

	firstProverRound := basics.Round(proto.StateProofInterval * 2)

	// We start on round 511, so the callback should be called on the next round.
	s.advanceRoundsWithoutStateProof(t, 2)
	s.mockCommit(firstProverRound)
	s.waitForSignerAndBuilder(t)

	a.False(s.isRoundSigned(a, w, firstProverRound))

	// We restart the signing process.
	s.keys = prevKeys
	w.Stop()

	w.Start()
	defer w.Stop()

	// We advance another round to allow us to wait for the signer, allowing it time to finish signing.
	s.advanceRoundsWithoutStateProof(t, 1)
	s.waitForSignerAndBuilder(t)

	a.True(s.isRoundSigned(a, w, firstProverRound))
}

func TestRegisterCommitListener(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	const expectedStateProofs = 3
	var keys []account.Participation
	for i := 0; i < 10; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, len(keys))
	a.Nil(s.commitListener)

	w := newTestWorker(t, s)
	w.Start()

	a.NotNil(s.commitListener)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	// we break the loop into two part since we don't want to add a state proof round (Round % 256 == 0)
	for iter := 0; iter < expectedStateProofs-1; iter++ {
		s.advanceRoundsAndCreateStateProofs(t, proto.StateProofInterval)
	}
	s.advanceRoundsAndCreateStateProofs(t, proto.StateProofInterval/2)

	w.Stop()

	a.Nil(s.commitListener)
}
