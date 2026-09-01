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

package transactions

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func stateProofPathForCheck(hashType crypto.HashType, elementSize int) merklearray.Proof {
	return merklearray.Proof{
		Path:        []crypto.GenericDigest{make(crypto.GenericDigest, elementSize), nil},
		HashFactory: crypto.HashFactory{HashType: hashType},
		TreeDepth:   1,
	}
}

func stateProofTxnForCheck() Transaction {
	return Transaction{
		Type: protocol.StateProofTx,
		StateProofTxnFields: StateProofTxnFields{
			StateProof: stateproof.StateProof{
				SigCommit:  make(crypto.GenericDigest, stateproof.HashSize),
				SigProofs:  stateProofPathForCheck(stateproof.HashType, stateproof.HashSize),
				PartProofs: stateProofPathForCheck(stateproof.HashType, stateproof.HashSize),
			},
		},
	}
}

func TestCheckTxnGroupStateProofBasicSuite(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	valid := stateProofTxnForCheck()
	require.NoError(t, CheckTxnGroup([]SignedTxn{{Txn: valid}}))
	require.NoError(t, CheckPaysetGroup([]SignedTxnWithAD{SignedTxn{Txn: valid}.WithAD()}))

	t.Run("unsupported state proof type", func(t *testing.T) {
		t.Parallel()
		malformed := stateProofTxnForCheck()
		malformed.StateProofType = protocol.StateProofType(1)
		require.ErrorIs(t, CheckTxnGroup([]SignedTxn{{Txn: malformed}}), errMalformedStateProofType)
	})

	t.Run("signature commitment proof hash", func(t *testing.T) {
		t.Parallel()
		malformed := stateProofTxnForCheck()
		malformed.StateProof.SigProofs = stateProofPathForCheck(crypto.Sha256, crypto.Sha256Size)
		require.ErrorIs(t, CheckTxnGroup([]SignedTxn{{Txn: malformed}}), errMalformedStateProofHash)
	})

	t.Run("participant commitment proof hash", func(t *testing.T) {
		t.Parallel()
		malformed := stateProofTxnForCheck()
		malformed.StateProof.PartProofs = stateProofPathForCheck(crypto.Sha256, crypto.Sha256Size)
		require.ErrorIs(t, CheckPaysetGroup([]SignedTxnWithAD{SignedTxn{Txn: malformed}.WithAD()}), errMalformedStateProofHash)
	})

	t.Run("path element size", func(t *testing.T) {
		t.Parallel()
		malformed := stateProofTxnForCheck()
		malformed.StateProof.PartProofs.Path[0] = make(crypto.GenericDigest, crypto.Sha256Size)
		require.ErrorIs(t, CheckTxnGroup([]SignedTxn{{Txn: malformed}}), errMalformedStateProofPath)
	})

	t.Run("signature commitment size", func(t *testing.T) {
		t.Parallel()
		malformed := stateProofTxnForCheck()
		malformed.StateProof.SigCommit = make(crypto.GenericDigest, crypto.Sha256Size)
		require.ErrorIs(t, CheckTxnGroup([]SignedTxn{{Txn: malformed}}), errMalformedStateProofCommit)
	})

	t.Run("nested Merkle signature proof hash", func(t *testing.T) {
		t.Parallel()
		malformed := stateProofTxnForCheck()
		reveal := stateproof.Reveal{}
		reveal.SigSlot.Sig.Signature = crypto.FalconSignature{1, 2}
		reveal.SigSlot.Sig.Proof = merklearray.SingleLeafProof{
			Proof: stateProofPathForCheck(crypto.Sha256, crypto.Sha256Size),
		}
		malformed.StateProof.Reveals = map[uint64]stateproof.Reveal{0: reveal}
		require.ErrorIs(t, CheckTxnGroup([]SignedTxn{{Txn: malformed}}), errMalformedStateProofHash)
	})

	t.Run("nested Merkle signature proof path size", func(t *testing.T) {
		t.Parallel()
		malformed := stateProofTxnForCheck()
		reveal := stateproof.Reveal{}
		reveal.SigSlot.Sig.Signature = crypto.FalconSignature{1, 2}
		reveal.SigSlot.Sig.Proof = merklearray.SingleLeafProof{
			Proof: stateProofPathForCheck(stateproof.HashType, crypto.Sha256Size),
		}
		malformed.StateProof.Reveals = map[uint64]stateproof.Reveal{0: reveal}
		require.ErrorIs(t, CheckTxnGroup([]SignedTxn{{Txn: malformed}}), errMalformedStateProofPath)
	})

	t.Run("nested Basic Merkle signature proof", func(t *testing.T) {
		t.Parallel()
		valid := stateProofTxnForCheck()
		reveal := stateproof.Reveal{}
		reveal.SigSlot.Sig.Signature = crypto.FalconSignature{1, 2}
		reveal.SigSlot.Sig.Proof = merklearray.SingleLeafProof{
			Proof: stateProofPathForCheck(stateproof.HashType, stateproof.HashSize),
		}
		valid.StateProof.Reveals = map[uint64]stateproof.Reveal{0: reveal}
		require.NoError(t, CheckTxnGroup([]SignedTxn{{Txn: valid}}))
	})
}

func TestCheckTxnGroupApplicationBoxIndex(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	malformed := Transaction{
		Type: protocol.ApplicationCallTx,
		ApplicationCallTxnFields: ApplicationCallTxnFields{
			Boxes: []BoxRef{{Index: 1}},
		},
	}
	require.ErrorIs(t, CheckTxnGroup([]SignedTxn{{Txn: malformed}}), errMalformedApplicationBoxIndex)

	currentApp := Transaction{
		Type: protocol.ApplicationCallTx,
		ApplicationCallTxnFields: ApplicationCallTxnFields{
			Boxes: []BoxRef{{Index: 0}},
		},
	}
	require.NoError(t, CheckTxnGroup([]SignedTxn{{Txn: currentApp}}))

	foreignApp := Transaction{
		Type: protocol.ApplicationCallTx,
		ApplicationCallTxnFields: ApplicationCallTxnFields{
			ForeignApps: []basics.AppIndex{1},
			Boxes:       []BoxRef{{Index: 1}},
		},
	}
	require.NoError(t, CheckTxnGroup([]SignedTxn{{Txn: foreignApp}}))
}

func TestCheckPaysetGroupApplicationBoxIndex(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	malformed := Transaction{
		Type: protocol.ApplicationCallTx,
		ApplicationCallTxnFields: ApplicationCallTxnFields{
			Boxes: []BoxRef{{Index: 1}},
		},
	}
	group := []SignedTxnWithAD{SignedTxn{Txn: malformed}.WithAD()}
	require.ErrorIs(t, CheckPaysetGroup(group), errMalformedApplicationBoxIndex)
}

func TestCheckPaysetGroupID(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	txns := []Transaction{
		{Type: protocol.PaymentTx, Header: Header{Sender: basics.Address{1}}},
		{Type: protocol.PaymentTx, Header: Header{Sender: basics.Address{2}}},
	}
	group := TxGroup{TxGroupHashes: []crypto.Digest{
		crypto.Digest(txns[0].ID()),
		crypto.Digest(txns[1].ID()),
	}}
	groupID := crypto.HashObj(group)
	for i := range txns {
		txns[i].Group = groupID
	}
	valid := []SignedTxnWithAD{
		SignedTxn{Txn: txns[0]}.WithAD(),
		SignedTxn{Txn: txns[1]}.WithAD(),
	}

	require.NoError(t, CheckPaysetGroup(valid))
	ungrouped := SignedTxn{Txn: Transaction{Type: protocol.PaymentTx}}.WithAD()
	require.NoError(t, CheckPaysetGroup([]SignedTxnWithAD{ungrouped}))

	err := CheckPaysetGroup([]SignedTxnWithAD{ungrouped, ungrouped})
	require.ErrorContains(t, err, "had zero Group")
	var malformed *TxGroupMalformedError
	require.ErrorAs(t, err, &malformed)
	require.Equal(t, TxGroupMalformedErrorReasonEmptyGroupID, malformed.Reason)
	require.Equal(t, 0, malformed.GroupIndex)

	inconsistent := append([]SignedTxnWithAD(nil), valid...)
	inconsistent[1].SignedTxn.Txn.Group = crypto.Digest{1}
	err = CheckPaysetGroup(inconsistent)
	require.ErrorContains(t, err, "inconsistent group values")
	require.ErrorAs(t, err, &malformed)
	require.Equal(t, TxGroupMalformedErrorReasonInconsistentGroupID, malformed.Reason)
	require.Equal(t, 1, malformed.GroupIndex)

	err = CheckPaysetGroup([]SignedTxnWithAD{valid[1], valid[0]})
	require.ErrorContains(t, err, "incomplete group")
	require.ErrorAs(t, err, &malformed)
	require.Equal(t, TxGroupMalformedErrorReasonIncompleteGroup, malformed.Reason)
	require.Equal(t, -1, malformed.GroupIndex)

	err = CheckPaysetGroup([]SignedTxnWithAD{valid[0]})
	require.ErrorContains(t, err, "incomplete group")
}

// TestHashTxGroupMatchesHashObj pins the pooled-buffer group hash used by
// checkTxnGroupID to the canonical crypto.HashObj encoding. Group IDs are
// computed with crypto.HashObj by proposers and by the block evaluator, so any
// divergence here would reject valid groups or accept invalid ones across the
// consensus boundary.
func TestHashTxGroupMatchesHashObj(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	groups := []TxGroup{
		{},
		{TxGroupHashes: []crypto.Digest{}},
		{TxGroupHashes: []crypto.Digest{{}}},
		{TxGroupHashes: []crypto.Digest{{1}, {2}}},
		{TxGroupHashes: []crypto.Digest{crypto.Hash([]byte("a")), crypto.Hash([]byte("b")), crypto.Hash([]byte("c"))}},
	}
	var maxGroup TxGroup
	for i := range 16 {
		maxGroup.TxGroupHashes = append(maxGroup.TxGroupHashes, crypto.Hash([]byte{byte(i)}))
	}
	groups = append(groups, maxGroup)

	for i, g := range groups {
		require.Equal(t, crypto.HashObj(g), hashTxGroup(g), "group %d", i)
	}
}

func TestCheckTxnGroupUnknownType(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// A lone unknown transaction type does NOT crash today: nothing triggers the group-wide
	// computeAvailability, so resources.fill is never called on it (WellFormed / applyTransaction's
	// default reject it). The screen rejects it anyway, since an unknown type is always invalid.
	bogus := Transaction{Type: protocol.TxType("bogus")}
	require.ErrorIs(t, CheckTxnGroup([]SignedTxn{{Txn: bogus}}), errMalformedTxType)

	// The crash case: the unknown type grouped *after* an app call. The app call triggers the
	// whole-group computeAvailability, whose fill walks the unknown member before its WellFormed
	// runs (and outside the eval() recover) and hits resources.fill's default. Caught as a group
	// and after block decoding.
	appcall := Transaction{Type: protocol.ApplicationCallTx}
	require.ErrorIs(t, CheckTxnGroup([]SignedTxn{{Txn: appcall}, {Txn: bogus}}), errMalformedTxType)
	require.ErrorIs(t, CheckPaysetGroup([]SignedTxnWithAD{
		SignedTxn{Txn: appcall}.WithAD(),
		SignedTxn{Txn: bogus}.WithAD(),
	}), errMalformedTxType)

	// Every known type that fill handles must still be accepted (guard against over-rejection).
	// Heartbeat is excluded here because it independently requires its fields (tested elsewhere).
	for _, tt := range []protocol.TxType{
		protocol.PaymentTx, protocol.KeyRegistrationTx, protocol.AssetConfigTx,
		protocol.AssetTransferTx, protocol.AssetFreezeTx, protocol.ApplicationCallTx,
	} {
		require.NoError(t, CheckTxnGroup([]SignedTxn{{Txn: Transaction{Type: tt}}}), "type %q must be accepted", tt)
	}
	require.NoError(t, CheckTxnGroup([]SignedTxn{{Txn: stateProofTxnForCheck()}}),
		"type %q must be accepted", protocol.StateProofTx)
}
