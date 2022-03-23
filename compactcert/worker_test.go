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

package compactcert

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
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
	t                     testing.TB
	mu                    deadlock.Mutex
	latest                basics.Round
	waiters               map[basics.Round]chan struct{}
	blocks                map[basics.Round]bookkeeping.BlockHeader
	keys                  []account.Participation
	keysForVoters         []account.Participation
	sigmsg                chan []byte
	txmsg                 chan transactions.SignedTxn
	totalWeight           int
	deletedStateProofKeys map[account.ParticipationID]basics.Round
}

func newWorkerStubs(t testing.TB, keys []account.Participation, totalWeight int) *testWorkerStubs {
	s := &testWorkerStubs{
		t:                     nil,
		mu:                    deadlock.Mutex{},
		latest:                0,
		waiters:               make(map[basics.Round]chan struct{}),
		blocks:                make(map[basics.Round]bookkeeping.BlockHeader),
		keys:                  keys,
		keysForVoters:         keys,
		sigmsg:                make(chan []byte, 1024),
		txmsg:                 make(chan transactions.SignedTxn, 1024),
		totalWeight:           totalWeight,
		deletedStateProofKeys: map[account.ParticipationID]basics.Round{},
	}
	s.latest--
	s.addBlock(2 * basics.Round(config.Consensus[protocol.ConsensusFuture].CompactCertRounds))
	return s
}

func (s *testWorkerStubs) addBlock(ccNextRound basics.Round) {
	s.latest++

	hdr := bookkeeping.BlockHeader{}
	hdr.Round = s.latest
	hdr.CurrentProtocol = protocol.ConsensusFuture

	var ccBasic = bookkeeping.CompactCertState{
		CompactCertVoters:      make([]byte, compactcert.HashSize),
		CompactCertVotersTotal: basics.MicroAlgos{},
		CompactCertNextRound:   0,
	}
	ccBasic.CompactCertVotersTotal.Raw = uint64(s.totalWeight)

	if hdr.Round > 0 {
		// Just so it's not zero, since the signer logic checks for all-zeroes
		ccBasic.CompactCertVoters[1] = 0x12
	}

	ccBasic.CompactCertNextRound = ccNextRound
	hdr.CompactCert = map[protocol.CompactCertType]bookkeeping.CompactCertState{
		protocol.CompactCertBasic: ccBasic,
	}

	s.blocks[s.latest] = hdr
	if s.waiters[s.latest] != nil {
		close(s.waiters[s.latest])
	}
}

func (s *testWorkerStubs) StateProofKeys(rnd basics.Round) (out []account.StateProofRecordForRound) {
	for _, part := range s.keys {
		if part.OverlapsInterval(rnd, rnd) {
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
			partRecordForRound := account.StateProofRecordForRound{
				ParticipationRecord: partRecord,
				StateProofSecrets:   signerInRound,
			}
			out = append(out, partRecordForRound)
		}
	}
	return
}

func (s *testWorkerStubs) DeleteStateProofKey(id account.ParticipationID, round basics.Round) error {
	s.deletedStateProofKeys[id] = round
	return nil
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

func (s *testWorkerStubs) CompactCertVoters(r basics.Round) (*ledgercore.VotersForRound, error) {
	voters := &ledgercore.VotersForRound{
		Proto:       config.Consensus[protocol.ConsensusFuture],
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

	tree, err := merklearray.BuildVectorCommitmentTree(voters.Participants, crypto.HashFactory{HashType: compactcert.HashType})
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
		if r <= s.latest {
			close(s.waiters[r])
		}
	}
	return s.waiters[r]
}

func (s *testWorkerStubs) Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except network.Peer) error {
	require.Equal(s.t, tag, protocol.CompactCertSigTag)
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

func (s *testWorkerStubs) advanceLatest(delta uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for r := uint64(0); r < delta; r++ {
		s.addBlock(s.blocks[s.latest].CompactCert[protocol.CompactCertBasic].CompactCertNextRound)
	}
}

func newTestWorkerDB(t testing.TB, s *testWorkerStubs, dba db.Accessor) *Worker {
	return NewWorker(dba, logging.TestingLog(t), s, s, s, s)
}

func newTestWorker(t testing.TB, s *testWorkerStubs) *Worker {
	dbs, _ := dbOpenTest(t, true)
	return newTestWorkerDB(t, s, dbs.Wdb)
}

// You must call defer part.Close() after calling this function,
// since it creates a DB accessor but the caller must close it (required for mss)
func newPartKey(t testing.TB, parent basics.Address) account.PersistedParticipation {
	fn := fmt.Sprintf("%s.%d", strings.ReplaceAll(t.Name(), "/", "."), crypto.RandUint64())
	partDB, err := db.MakeAccessor(fn, false, true)
	require.NoError(t, err)

	part, err := account.FillDBWithParticipationKeys(partDB, parent, 0, basics.Round(10*config.Consensus[protocol.ConsensusFuture].CompactCertRounds), config.Consensus[protocol.ConsensusFuture].DefaultKeyDilution)
	require.NoError(t, err)

	return part
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

	proto := config.Consensus[protocol.ConsensusFuture]
	s.advanceLatest(proto.CompactCertRounds + proto.CompactCertRounds/2)

	// Go through several iterations, making sure that we get
	// the signatures and certs broadcast at each round.
	for iter := 0; iter < 5; iter++ {
		s.advanceLatest(proto.CompactCertRounds)

		for i := 0; i < len(keys); i++ {
			// Expect all signatures to be broadcast.
			_ = <-s.sigmsg
		}

		// Expect a compact cert to be formed.
		for {
			tx := <-s.txmsg
			require.Equal(t, tx.Txn.Type, protocol.CompactCertTx)
			if tx.Txn.CertIntervalLatestRound < basics.Round(iter+2)*basics.Round(proto.CompactCertRounds) {
				continue
			}

			require.Equal(t, tx.Txn.CertIntervalLatestRound, basics.Round(iter+2)*basics.Round(proto.CompactCertRounds))

			msg, err := GenerateStateProofMessage(s, tx.Txn.CertIntervalLatestRound, proto.CompactCertRounds)
			require.NoError(t, err)
			require.Equal(t, msg, tx.Txn.CertMsg)

			provenWeight, overflowed := basics.Muldiv(uint64(s.totalWeight), uint64(proto.CompactCertWeightThreshold), 1<<32)
			require.False(t, overflowed)

			ccparams := compactcert.Params{
				StateProofMessageHash: tx.Txn.CertMsg.IntoStateProofMessageHash(),
				ProvenWeight:          provenWeight,
				SigRound:              tx.Txn.CertIntervalLatestRound,
				SecKQ:                 proto.CompactCertSecKQ,
			}

			voters, err := s.CompactCertVoters(tx.Txn.CertIntervalLatestRound - basics.Round(proto.CompactCertRounds) - basics.Round(proto.CompactCertVotersLookback))
			require.NoError(t, err)

			verif := compactcert.MkVerifier(ccparams, voters.Tree.Root())
			err = verif.Verify(&tx.Txn.Cert)
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

	proto := config.Consensus[protocol.ConsensusFuture]
	s.advanceLatest(proto.CompactCertRounds + proto.CompactCertRounds/2)
	s.advanceLatest(proto.CompactCertRounds)

	for i := 0; i < len(keys); i++ {
		// Expect all signatures to be broadcast.
		_ = <-s.sigmsg
	}

	// No compact cert should be formed yet: not enough sigs for a cert this early.
	select {
	case <-s.txmsg:
		t.Fatal("compact cert formed too early")
	case <-time.After(time.Second):
	}

	// Expect a compact cert to be formed in the next CompactCertRounds/2.
	s.advanceLatest(proto.CompactCertRounds / 2)
	tx := <-s.txmsg
	require.Equal(t, tx.Txn.Type, protocol.CompactCertTx)
	require.Equal(t, tx.Txn.CertIntervalLatestRound, 2*basics.Round(proto.CompactCertRounds))

	msg, err := GenerateStateProofMessage(s, tx.Txn.CertIntervalLatestRound, proto.CompactCertRounds)
	require.NoError(t, err)
	require.Equal(t, msg, tx.Txn.CertMsg)

	provenWeight, overflowed := basics.Muldiv(uint64(s.totalWeight), uint64(proto.CompactCertWeightThreshold), 1<<32)
	require.False(t, overflowed)

	ccparams := compactcert.Params{
		StateProofMessageHash: msg.IntoStateProofMessageHash(),
		ProvenWeight:          provenWeight,
		SigRound:              basics.Round(tx.Txn.CertIntervalLatestRound),
		SecKQ:                 proto.CompactCertSecKQ,
	}

	voters, err := s.CompactCertVoters(tx.Txn.CertIntervalLatestRound - basics.Round(proto.CompactCertRounds) - basics.Round(proto.CompactCertVotersLookback))
	require.NoError(t, err)

	verif := compactcert.MkVerifier(ccparams, voters.Tree.Root())
	err = verif.Verify(&tx.Txn.Cert)
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

	proto := config.Consensus[protocol.ConsensusFuture]
	s.advanceLatest(3 * proto.CompactCertRounds)

	for i := 0; i < len(keys); i++ {
		// Expect all signatures to be broadcast.
		_ = <-s.sigmsg
	}

	// No compact cert should be formed: not enough sigs.
	select {
	case <-s.txmsg:
		t.Fatal("compact cert formed without enough sigs")
	case <-time.After(time.Second):
	}
}

func TestWorkerRestart(t *testing.T) {
	partitiontest.PartitionTest(t)

	var keys []account.Participation
	for i := 0; i < 10; i++ {
		var parent basics.Address
		crypto.RandBytes(parent[:])
		p := newPartKey(t, parent)
		defer p.Close()
		keys = append(keys, p.Participation)
	}

	s := newWorkerStubs(t, keys, 10)

	proto := config.Consensus[protocol.ConsensusFuture]
	s.advanceLatest(3*proto.CompactCertRounds - 1)

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

	require.True(t, formedAt > 1)
	require.True(t, formedAt < 5)
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

	proto := config.Consensus[protocol.ConsensusFuture]
	s.advanceLatest(3 * proto.CompactCertRounds)

	for i := 0; i < len(keys); i++ {
		// Expect all signatures to be broadcast.
		msg := <-s.sigmsg
		res := w.handleSigMessage(network.IncomingMessage{
			Data: msg,
		})

		// This should be a dup signature, so should not be broadcast
		// but also not disconnected.
		require.Equal(t, res.Action, network.Ignore)
	}
}

func TestSignerDeletesUnneededStateProofKeys(t *testing.T) {
	partitiontest.PartitionTest(t)

	var keys []account.Participation
	nParticipants := 2
	for i := 0; i < nParticipants; i++ {
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

	proto := config.Consensus[protocol.ConsensusFuture]
	s.advanceLatest(3 * proto.CompactCertRounds)
	// Expect all signatures to be broadcast.

	require.Zero(t, len(s.deletedStateProofKeys))
	w.signBlock(s.blocks[basics.Round(proto.CompactCertRounds)])
	require.Equal(t, len(s.deletedStateProofKeys), nParticipants)
}

func TestSignerDoesntDeleteKeysWhenDBDoesntStoreSigs(t *testing.T) {
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
	proto := config.Consensus[protocol.ConsensusFuture]
	s.advanceLatest(3 * proto.CompactCertRounds)
	// Expect all signatures to be broadcast.

	require.NoError(t, w.db.Atomic(
		func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.Exec("DROP TABLE sigs")
			return err
		}),
	)

	s.deletedStateProofKeys = map[account.ParticipationID]basics.Round{}
	w.signBlock(s.blocks[3*basics.Round(proto.CompactCertRounds)])
	require.Zero(t, len(s.deletedStateProofKeys))
}
