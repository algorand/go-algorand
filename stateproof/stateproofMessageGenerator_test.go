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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
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
)

type workerForStateProofMessageTests struct {
	w *testWorkerStubs
}

func (s *workerForStateProofMessageTests) StateProofKeys(round basics.Round) []account.StateProofRecordForRound {
	return s.w.StateProofKeys(round)
}

func (s *workerForStateProofMessageTests) DeleteStateProofKey(id account.ParticipationID, round basics.Round) error {
	return s.w.DeleteStateProofKey(id, round)
}

func (s *workerForStateProofMessageTests) Latest() basics.Round {
	return s.w.Latest()
}

func (s *workerForStateProofMessageTests) Wait(round basics.Round) chan struct{} {
	return s.w.Wait(round)
}

func (s *workerForStateProofMessageTests) GenesisHash() crypto.Digest {
	return s.w.GenesisHash()
}

func (s *workerForStateProofMessageTests) BlockHdr(round basics.Round) (bookkeeping.BlockHeader, error) {
	s.w.mu.Lock()
	defer s.w.mu.Unlock()

	element, ok := s.w.blocks[round]
	if !ok {
		return bookkeeping.BlockHeader{}, ledgercore.ErrNoEntry{Round: round}
	}
	return element, nil
}

func (s *workerForStateProofMessageTests) VotersForStateProof(round basics.Round) (*ledgercore.VotersForRound, error) {
	voters := &ledgercore.VotersForRound{
		Proto:     config.Consensus[protocol.ConsensusFuture],
		AddrToPos: make(map[basics.Address]uint64),
	}

	wt := uint64(0)
	for i, k := range s.w.keysForVoters {
		partWe := uint64((len(s.w.keysForVoters) + int(round) - i) * 10000)
		voters.AddrToPos[k.Parent] = uint64(i)
		voters.Participants = append(voters.Participants, basics.Participant{
			PK:     *k.StateProofSecrets.GetVerifier(),
			Weight: partWe,
		})
		wt += partWe
	}

	tree, err := merklearray.BuildVectorCommitmentTree(voters.Participants, crypto.HashFactory{HashType: stateproof.HashType})
	if err != nil {
		return nil, err
	}

	voters.Tree = tree
	voters.TotalWeight = basics.MicroAlgos{Raw: wt}
	return voters, nil
}

func (s *workerForStateProofMessageTests) Broadcast(ctx context.Context, tag protocol.Tag, bytes []byte, b bool, peer network.Peer) error {
	return s.w.Broadcast(ctx, tag, bytes, b, peer)
}

func (s *workerForStateProofMessageTests) RegisterHandlers(handlers []network.TaggedMessageHandler) {
	s.w.RegisterHandlers(handlers)
}

func (s *workerForStateProofMessageTests) BroadcastInternalSignedTxGroup(txns []transactions.SignedTxn) error {
	return s.w.BroadcastInternalSignedTxGroup(txns)
}

func (s *workerForStateProofMessageTests) addBlockWithStateProofHeaders(ccNextRound basics.Round) {

	s.w.latest++

	hdr := bookkeeping.BlockHeader{}
	hdr.Round = s.w.latest
	hdr.CurrentProtocol = protocol.ConsensusFuture

	var ccBasic = bookkeeping.StateProofTrackingData{
		StateProofVotersCommitment:  make([]byte, stateproof.HashSize),
		StateProofVotersTotalWeight: basics.MicroAlgos{},
		StateProofNextRound:         0,
	}

	if uint64(hdr.Round)%config.Consensus[hdr.CurrentProtocol].StateProofInterval == 0 {
		voters, _ := s.VotersForStateProof(hdr.Round.SubSaturate(basics.Round(config.Consensus[hdr.CurrentProtocol].StateProofVotersLookback)))
		ccBasic.StateProofVotersCommitment = voters.Tree.Root()
		ccBasic.StateProofVotersTotalWeight = voters.TotalWeight

	}

	ccBasic.StateProofNextRound = ccNextRound
	hdr.StateProofTracking = map[protocol.StateProofType]bookkeeping.StateProofTrackingData{
		protocol.StateProofBasic: ccBasic,
	}

	s.w.blocks[s.w.latest] = hdr
	if s.w.waiters[s.w.latest] != nil {
		close(s.w.waiters[s.w.latest])
	}
}

func newWorkerForStateProofMessageStubs(keys []account.Participation, totalWeight int) *workerForStateProofMessageTests {
	s := &testWorkerStubs{
		t:                     nil,
		mu:                    deadlock.Mutex{},
		latest:                0,
		waiters:               make(map[basics.Round]chan struct{}),
		waitersCount:          make(map[basics.Round]int),
		blocks:                make(map[basics.Round]bookkeeping.BlockHeader),
		keys:                  keys,
		keysForVoters:         keys,
		sigmsg:                make(chan []byte, 1024),
		txmsg:                 make(chan transactions.SignedTxn, 1024),
		totalWeight:           totalWeight,
		deletedStateProofKeys: map[account.ParticipationID]basics.Round{},
	}
	sm := workerForStateProofMessageTests{w: s}
	return &sm
}

func (s *workerForStateProofMessageTests) advanceLatest(delta uint64) {
	s.w.mu.Lock()
	defer s.w.mu.Unlock()

	for r := uint64(0); r < delta; r++ {
		s.addBlockWithStateProofHeaders(s.w.blocks[s.w.latest].StateProofTracking[protocol.StateProofBasic].StateProofNextRound)
	}
}

func TestStateProofMessage(t *testing.T) {
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

	s := newWorkerForStateProofMessageStubs(keys, len(keys))
	dbs, _ := dbOpenTest(t, true)
	w := NewWorker(dbs.Wdb, logging.TestingLog(t), s, s, s, s)

	s.w.latest--
	s.addBlockWithStateProofHeaders(2 * basics.Round(config.Consensus[protocol.ConsensusFuture].StateProofInterval))

	w.Start()
	defer w.Shutdown()

	proto := config.Consensus[protocol.ConsensusFuture]
	s.advanceLatest(proto.StateProofInterval + proto.StateProofInterval/2)

	var lastMessage stateproofmsg.Message

	for iter := uint64(0); iter < 5; iter++ {
		s.advanceLatest(proto.StateProofInterval)

		for {
			tx, err := s.w.waitOnTxnWithTimeout(time.Second * 5)
			a.NoError(err)

			a.Equal(tx.Txn.Type, protocol.StateProofTx)
			if tx.Txn.StateProofIntervalLastRound < basics.Round(iter+2)*basics.Round(proto.StateProofInterval) {
				continue
			}

			a.Equal(tx.Txn.StateProofIntervalLastRound, basics.Round(iter+2)*basics.Round(proto.StateProofInterval))
			a.Equal(tx.Txn.Message.LastAttestedRound, (iter+2)*proto.StateProofInterval)
			a.Equal(tx.Txn.Message.FirstAttestedRound, (iter+1)*proto.StateProofInterval+1)

			verifySha256BlockHeadersCommitments(a, tx.Txn.Message, s.w.blocks)

			if !lastMessage.MsgIsZero() {
				verifier := stateproof.MkVerifierWithLnProvenWeight(lastMessage.VotersCommitment, lastMessage.LnProvenWeight, proto.StateProofStrengthTarget)

				err := verifier.Verify(uint64(tx.Txn.StateProofIntervalLastRound), tx.Txn.Message.Hash(), &tx.Txn.StateProof)
				a.NoError(err)

			}

			lastMessage = tx.Txn.Message
			break
		}
	}
}

func verifySha256BlockHeadersCommitments(a *require.Assertions, message stateproofmsg.Message, blocks map[basics.Round]bookkeeping.BlockHeader) {
	blkHdrArr := make(lightBlockHeaders, message.LastAttestedRound-message.FirstAttestedRound+1)
	for i := uint64(0); i < message.LastAttestedRound-message.FirstAttestedRound+1; i++ {
		hdr := blocks[basics.Round(message.FirstAttestedRound+i)]
		blkHdrArr[i] = hdr.ToLightBlockHeader()
	}

	tree, err := merklearray.BuildVectorCommitmentTree(blkHdrArr, crypto.HashFactory{HashType: crypto.Sha256})
	a.NoError(err)

	a.Equal(tree.Root(), crypto.GenericDigest(message.BlockHeadersCommitment))
}

func TestGenerateStateProofMessageForSmallRound(t *testing.T) {
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

	s := newWorkerForStateProofMessageStubs(keys[:], len(keys))
	s.w.latest--
	s.addBlockWithStateProofHeaders(2 * basics.Round(config.Consensus[protocol.ConsensusFuture].StateProofInterval))

	_, err := GenerateStateProofMessage(s, 240, s.w.blocks[s.w.latest])
	a.ErrorIs(err, errInvalidParams)
}

func TestMessageLnApproxError(t *testing.T) {
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

	s := newWorkerForStateProofMessageStubs(keys[:], len(keys))
	s.w.latest--
	s.addBlockWithStateProofHeaders(2 * basics.Round(config.Consensus[protocol.ConsensusFuture].StateProofInterval))

	s.advanceLatest(2*config.Consensus[protocol.ConsensusFuture].StateProofInterval + config.Consensus[protocol.ConsensusFuture].StateProofInterval/2)
	tracking := s.w.blocks[512].StateProofTracking[protocol.StateProofBasic]
	tracking.StateProofVotersTotalWeight = basics.MicroAlgos{}
	newtracking := tracking
	s.w.blocks[512].StateProofTracking[protocol.StateProofBasic] = newtracking

	_, err := GenerateStateProofMessage(s, 256, s.w.blocks[512])
	a.ErrorIs(err, stateproof.ErrIllegalInputForLnApprox)
}

func TestMessageMissingHeaderOnInterval(t *testing.T) {
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

	s := newWorkerForStateProofMessageStubs(keys[:], len(keys))
	s.w.latest--
	s.addBlockWithStateProofHeaders(2 * basics.Round(config.Consensus[protocol.ConsensusFuture].StateProofInterval))

	s.advanceLatest(2*config.Consensus[protocol.ConsensusFuture].StateProofInterval + config.Consensus[protocol.ConsensusFuture].StateProofInterval/2)
	delete(s.w.blocks, 510)

	_, err := GenerateStateProofMessage(s, 256, s.w.blocks[512])
	a.ErrorIs(err, ledgercore.ErrNoEntry{Round: 510})
}

func TestGenerateBlockProof(t *testing.T) {
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

	s := newWorkerForStateProofMessageStubs(keys, len(keys))
	dbs, _ := dbOpenTest(t, true)
	w := NewWorker(dbs.Wdb, logging.TestingLog(t), s, s, s, s)

	s.w.latest--
	s.addBlockWithStateProofHeaders(2 * basics.Round(config.Consensus[protocol.ConsensusFuture].StateProofInterval))

	w.Start()
	defer w.Shutdown()

	proto := config.Consensus[protocol.ConsensusFuture]
	s.advanceLatest(proto.StateProofInterval + proto.StateProofInterval/2)

	for iter := uint64(0); iter < 5; iter++ {
		s.advanceLatest(proto.StateProofInterval)

		tx := <-s.w.txmsg
		// we have a new tx. now attempt to fetch a block proof.
		firstAttestedRound := tx.Txn.Message.FirstAttestedRound
		lastAttestedRound := tx.Txn.Message.LastAttestedRound

		headers, err := FetchLightHeaders(s, proto.StateProofInterval, basics.Round(lastAttestedRound))
		a.NoError(err)
		a.Equal(proto.StateProofInterval, uint64(len(headers)))

		// attempting to get block proof for every block in the interval
		for i := firstAttestedRound; i < lastAttestedRound; i++ {
			headerIndex := i - firstAttestedRound
			proof, err := GenerateProofOfLightBlockHeaders(proto.StateProofInterval, headers, headerIndex)
			a.NoError(err)
			a.NotNil(proof)

			lightheader := headers[headerIndex]
			err = merklearray.VerifyVectorCommitment(
				tx.Txn.Message.BlockHeadersCommitment,
				map[uint64]crypto.Hashable{headerIndex: &lightheader},
				proof.ToProof())

			a.NoError(err)
		}
	}
}

func TestGenerateBlockProofOnSmallArray(t *testing.T) {
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

	s := newWorkerForStateProofMessageStubs(keys, len(keys))
	s.w.latest--
	s.addBlockWithStateProofHeaders(2 * basics.Round(config.Consensus[protocol.ConsensusFuture].StateProofInterval))

	proto := config.Consensus[protocol.ConsensusFuture]
	s.advanceLatest(2 * proto.StateProofInterval)
	headers, err := FetchLightHeaders(s, proto.StateProofInterval, basics.Round(2*proto.StateProofInterval))
	a.NoError(err)
	headers = headers[1:]

	_, err = GenerateProofOfLightBlockHeaders(proto.StateProofInterval, headers, 1)
	a.ErrorIs(err, errInvalidParams)
}
