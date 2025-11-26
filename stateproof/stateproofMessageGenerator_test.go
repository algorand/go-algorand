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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

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

	s := newWorkerStubsWithChannel(t, keys, len(keys))
	s.sigmsg = nil
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(t, 1)
	var lastMessage stateproofmsg.Message
	for i := 0; i < 5; i++ {
		s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval-1)

		var tx transactions.SignedTxn
		// there will be several state proof txn. we extract them
		for {
			var err error
			tx, err = s.waitOnTxnWithTimeout(time.Second * 5)
			a.NoError(err)
			if lastMessage.LastAttestedRound == 0 || lastMessage.LastAttestedRound < tx.Txn.Message.LastAttestedRound {
				break
			}

		}

		verifySha256BlockHeadersCommitments(a, tx.Txn.Message, s.blocks)
		if !lastMessage.MsgIsZero() {
			verifier := stateproof.MkVerifierWithLnProvenWeight(lastMessage.VotersCommitment, lastMessage.LnProvenWeight, proto.StateProofStrengthTarget)

			err := verifier.Verify(tx.Txn.Message.LastAttestedRound, tx.Txn.Message.Hash(), &tx.Txn.StateProof)
			a.NoError(err)
		}
		// since a state proof txn was created, we update the header with the next state proof round
		// i.e network has accepted the state proof.
		s.addBlock(tx.Txn.Message.LastAttestedRound + basics.Round(proto.StateProofInterval))
		lastMessage = tx.Txn.Message
	}
}

func verifySha256BlockHeadersCommitments(a *require.Assertions, message stateproofmsg.Message, blocks map[basics.Round]bookkeeping.BlockHeader) {
	blkHdrArr := make(lightBlockHeaders, message.LastAttestedRound-message.FirstAttestedRound+1)
	for i := range message.LastAttestedRound - message.FirstAttestedRound + 1 {
		hdr := blocks[message.FirstAttestedRound+i]
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

	s := newWorkerStubAtGenesis(t, keys[:], len(keys))
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.addBlock(2 * basics.Round(proto.StateProofInterval))

	_, err := GenerateStateProofMessage(s, s.latest)
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

	s := newWorkerStubs(t, keys[:], len(keys))
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval)
	tracking := s.blocks[512].StateProofTracking[protocol.StateProofBasic]
	tracking.StateProofOnlineTotalWeight = basics.MicroAlgos{}
	newtracking := tracking
	s.blocks[512].StateProofTracking[protocol.StateProofBasic] = newtracking

	_, err := GenerateStateProofMessage(s, basics.Round(2*proto.StateProofInterval))
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

	s := newWorkerStubs(t, keys[:], len(keys))
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval)
	delete(s.blocks, 510)

	_, err := GenerateStateProofMessage(s, basics.Round(2*proto.StateProofInterval))
	a.ErrorIs(err, ledgercore.ErrNoEntry{Round: 510, Latest: s.latest, Committed: s.latest})
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

	s := newWorkerStubsWithChannel(t, keys, len(keys))
	s.sigmsg = nil
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(t, 1)
	var lastAttestedRound basics.Round
	for i := 0; i < 5; i++ {
		s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval-1)

		var tx transactions.SignedTxn
		// there will be several state proof txn. we extract them
		for {
			var err error
			tx, err = s.waitOnTxnWithTimeout(time.Second * 5)
			a.NoError(err)
			if lastAttestedRound == 0 || lastAttestedRound < basics.Round(tx.Txn.Message.LastAttestedRound) {
				break
			}

		}
		headers, err := FetchLightHeaders(s, proto.StateProofInterval, basics.Round(tx.Txn.Message.LastAttestedRound))
		a.NoError(err)
		a.Equal(proto.StateProofInterval, uint64(len(headers)))

		verifyLightBlockHeaderProof(&tx, &proto, headers, a)

		s.addBlock(tx.Txn.Message.LastAttestedRound + basics.Round(proto.StateProofInterval))
		lastAttestedRound = basics.Round(tx.Txn.Message.LastAttestedRound)
	}
}

func verifyLightBlockHeaderProof(tx *transactions.SignedTxn, proto *config.ConsensusParams, headers []bookkeeping.LightBlockHeader, a *require.Assertions) {
	// attempting to get block proof for every block in the interval
	for j := tx.Txn.Message.FirstAttestedRound; j < tx.Txn.Message.LastAttestedRound; j++ {
		headerIndex := j - tx.Txn.Message.FirstAttestedRound
		proof, err := GenerateProofOfLightBlockHeaders(proto.StateProofInterval, headers, headerIndex)
		a.NoError(err)
		a.NotNil(proof)

		lightheader := headers[headerIndex]
		err = merklearray.VerifyVectorCommitment(
			tx.Txn.Message.BlockHeadersCommitment,
			map[uint64]crypto.Hashable{uint64(headerIndex): &lightheader},
			proof.ToProof())

		a.NoError(err)
	}
}

func TestGenerateBlockProofOnSmallArray(t *testing.T) {
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

	s := newWorkerStubs(t, keys[:], len(keys))
	w := newTestWorker(t, s)
	w.Start()
	defer w.Stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	s.advanceRoundsWithoutStateProof(t, proto.StateProofInterval)
	headers, err := FetchLightHeaders(s, proto.StateProofInterval, basics.Round(2*proto.StateProofInterval))
	a.NoError(err)
	headers = headers[1:]

	_, err = GenerateProofOfLightBlockHeaders(proto.StateProofInterval, headers, 1)
	a.ErrorIs(err, errInvalidParams)
}
