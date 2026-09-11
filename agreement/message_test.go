// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package agreement

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config/bounds"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func TestProposalCarriesMalformedStateProofPath(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genesisHash := crypto.Hash([]byte("state-proof-path-proposal-check"))
	block := bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{
		GenesisHash:  genesisHash,
		UpgradeState: bookkeeping.UpgradeState{CurrentProtocol: protocol.ConsensusCurrentVersion},
	}}
	txn := transactions.Transaction{
		Type: protocol.StateProofTx,
		Header: transactions.Header{
			GenesisHash: genesisHash,
		},
		StateProofTxnFields: transactions.StateProofTxnFields{
			StateProof: stateproof.StateProof{
				SigCommit: make(crypto.GenericDigest, stateproof.HashSize),
				SigProofs: merklearray.Proof{
					HashFactory: crypto.HashFactory{HashType: stateproof.HashType},
				},
				PartProofs: merklearray.Proof{
					Path:        []crypto.GenericDigest{make(crypto.GenericDigest, 2*stateproof.HashSize)},
					HashFactory: crypto.HashFactory{HashType: stateproof.HashType},
					TreeDepth:   1,
				},
			},
		},
	}

	stib, err := block.EncodeSignedTxn(transactions.SignedTxn{Txn: txn}, transactions.ApplyData{})
	require.NoError(t, err)
	block.Payset = append(block.Payset, stib)
	require.True(t, proposalCarriesInvalidTxn(unauthenticatedProposal{Block: block}),
		"a proposal carrying a malformed Merkle path must be dropped")

	// A path using the wrong algorithm is outside the StateProofBasic suite.
	txn.StateProof.PartProofs.HashFactory.HashType = crypto.Sha256
	txn.StateProof.PartProofs.Path[0] = make(crypto.GenericDigest, crypto.Sha256Size)
	stib, err = block.EncodeSignedTxn(transactions.SignedTxn{Txn: txn}, transactions.ApplyData{})
	require.NoError(t, err)
	block.Payset = []transactions.SignedTxnInBlock{stib}
	require.True(t, proposalCarriesInvalidTxn(unauthenticatedProposal{Block: block}))

	// StateProofBasic parameters remain accepted.
	txn.StateProof.PartProofs.HashFactory.HashType = stateproof.HashType
	txn.StateProof.PartProofs.Path[0] = make(crypto.GenericDigest, stateproof.HashSize)
	stib, err = block.EncodeSignedTxn(transactions.SignedTxn{Txn: txn}, transactions.ApplyData{})
	require.NoError(t, err)
	block.Payset = []transactions.SignedTxnInBlock{stib}
	require.False(t, proposalCarriesInvalidTxn(unauthenticatedProposal{Block: block}))
}

func TestProposalCarriesInvalidTxnGroupOrder(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genesisHash := crypto.Hash([]byte("proposal-check"))
	block := bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{
		GenesisHash: genesisHash,
		UpgradeState: bookkeeping.UpgradeState{
			CurrentProtocol: protocol.ConsensusCurrentVersion,
		},
	}}

	txns := []transactions.Transaction{
		{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      basics.Address{1},
				GenesisHash: genesisHash,
			},
		},
		{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      basics.Address{2},
				GenesisHash: genesisHash,
			},
		},
	}
	txgroup := transactions.TxGroup{TxGroupHashes: []crypto.Digest{
		crypto.Digest(txns[0].ID()),
		crypto.Digest(txns[1].ID()),
	}}
	groupID := crypto.HashObj(txgroup)
	for i := range txns {
		txns[i].Group = groupID
		stib, err := block.EncodeSignedTxn(transactions.SignedTxn{Txn: txns[i]}, transactions.ApplyData{})
		require.NoError(t, err)
		block.Payset = append(block.Payset, stib)
	}

	require.False(t, proposalCarriesInvalidTxn(unauthenticatedProposal{Block: block}), "valid group order must pass the check")

	block.Payset[0], block.Payset[1] = block.Payset[1], block.Payset[0]
	require.True(t, proposalCarriesInvalidTxn(unauthenticatedProposal{Block: block}), "invalid group order must fail")
}

func TestProposalCarriesOversizedTxnGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genesisHash := crypto.Hash([]byte("oversized-txn-group-proposal-check"))
	block := bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{
		GenesisHash: genesisHash,
		UpgradeState: bookkeeping.UpgradeState{
			CurrentProtocol: protocol.ConsensusCurrentVersion,
		},
	}}

	maxGroupSize := bounds.MaxTxGroupSize
	txns := make([]transactions.Transaction, maxGroupSize+1)
	txgroup := transactions.TxGroup{TxGroupHashes: make([]crypto.Digest, len(txns))}
	for i := range txns {
		txns[i] = transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      basics.Address{byte(i + 1)},
				GenesisHash: genesisHash,
			},
		}
		txgroup.TxGroupHashes[i] = crypto.Digest(txns[i].ID())
	}
	groupID := crypto.HashObj(txgroup)
	for i := range txns {
		txns[i].Group = groupID
		stib, err := block.EncodeSignedTxn(transactions.SignedTxn{Txn: txns[i]}, transactions.ApplyData{})
		require.NoError(t, err)
		block.Payset = append(block.Payset, stib)
	}

	encoded := protocol.Encode(&transmittedPayload{unauthenticatedProposal: unauthenticatedProposal{Block: block}})
	decoded, err := decodeProposal(encoded)
	require.NoError(t, err)
	proposal := decoded.(compoundMessage).Proposal
	require.True(t, proposalCarriesInvalidTxn(proposal), "oversized group must be rejected before proposal validation")
}

func TestDecodeRejectsStepAboveDown(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tests := []struct {
		name     string
		step     step
		rejected bool
	}{
		{name: "propose", step: propose},
		{name: "soft", step: soft},
		{name: "cert", step: cert},
		{name: "next", step: next},
		{name: "next+1", step: next + 1},
		{name: "late-1", step: late - 1},
		{name: "late", step: late},
		{name: "redo", step: redo},
		{name: "down", step: down},
		{name: "down+1", step: down + 1, rejected: true},
		{name: "maxuint64", step: step(math.MaxUint64), rejected: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uv := unauthenticatedVote{R: rawVote{Sender: poolAddr, Round: basics.Round(1), Period: period(1), Step: tc.step}}
			_, voteErr := decodeVote(protocol.Encode(&uv))

			ub := unauthenticatedBundle{Round: basics.Round(1), Period: period(1), Step: tc.step}
			_, bundleErr := decodeBundle(protocol.Encode(&ub))

			tp := transmittedPayload{PriorVote: uv}
			_, proposalErr := decodeProposal(protocol.Encode(&tp))

			if tc.rejected {
				require.ErrorContains(t, voteErr, "exceeds max step")
				require.ErrorContains(t, bundleErr, "exceeds max step")
				require.ErrorContains(t, proposalErr, "exceeds max step")
			} else {
				require.NoError(t, voteErr)
				require.NoError(t, bundleErr)
				require.NoError(t, proposalErr)
			}
		})
	}
}

func BenchmarkVoteDecoding(b *testing.B) {
	oneTimeSecrets := crypto.GenerateOneTimeSignatureSecrets(300, 1000)
	id := crypto.OneTimeSignatureIdentifier{
		Batch: 1000,

		// Avoid generating the last few offsets (in a batch size of 256), so we can increment correctly
		Offset: crypto.RandUint64() % 250,
	}
	proposal := unauthenticatedProposal{
		OriginalPeriod: period(crypto.RandUint64() % 250),
	}

	var vrfProof crypto.VRFProof
	crypto.SystemRNG.RandBytes(vrfProof[:])

	var sendAddr basics.Address
	crypto.SystemRNG.RandBytes(sendAddr[:])

	uv := unauthenticatedVote{
		R: rawVote{
			Sender: sendAddr,
			Round:  basics.Round(356),
			Period: period(4),
			Step:   step(3),
			Proposal: proposalValue{
				OriginalPeriod:   period(3),
				OriginalProposer: poolAddr,
				BlockDigest:      crypto.Hash([]byte{1, 2, 3}),
				EncodingDigest:   crypto.Hash([]byte{5, 6, 7}),
			},
		},
		Cred: committee.UnauthenticatedCredential{
			Proof: vrfProof,
		},
		Sig: oneTimeSecrets.Sign(id, proposal),
	}

	msgBytes := protocol.Encode(&uv)

	// make sure we know how to decode this correctly.
	iVote, err := decodeVote(msgBytes)
	require.Nil(b, err)
	decodedVote := iVote.(unauthenticatedVote)
	require.Equal(b, uv.R.Period, decodedVote.R.Period)

	// and now, let's measure the performance.
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decodeVote(msgBytes)
	}
}
