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
	"errors"
	"fmt"
	"slices"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errMalformedStateProofSignature = errors.New("state proof reveal has an empty or too-short signature")
	errMalformedStateProofProof     = errors.New("state proof reveal has an invalid Merkle proof depth")
	errMalformedStateProofPath      = errors.New("state proof has a Merkle path element with an unexpected size")
	errMalformedStateProofType      = errors.New("state proof has an unsupported type")
	errMalformedStateProofHash      = errors.New("state proof uses an unexpected hash algorithm")
	errMalformedStateProofCommit    = errors.New("state proof has an unexpected signature commitment size")
)

// TxGroupMalformedErrorReasonCode is a reason code for TxGroupMalformedError.
//
//msgp:ignore TxGroupMalformedErrorReasonCode
type TxGroupMalformedErrorReasonCode int

const (
	// TxGroupMalformedErrorReasonGeneric is a generic (not specific) reason code.
	TxGroupMalformedErrorReasonGeneric TxGroupMalformedErrorReasonCode = iota
	// TxGroupMalformedErrorReasonExceedMaxSize indicates a transaction group that is too large.
	TxGroupMalformedErrorReasonExceedMaxSize
	// TxGroupMalformedErrorReasonInconsistentGroupID indicates different group IDs in a transaction group.
	TxGroupMalformedErrorReasonInconsistentGroupID
	// TxGroupMalformedErrorReasonEmptyGroupID indicates an empty group ID in a multi-transaction group.
	TxGroupMalformedErrorReasonEmptyGroupID
	// TxGroupMalformedErrorReasonIncompleteGroup indicates that the group ID does not commit to the provided transactions.
	TxGroupMalformedErrorReasonIncompleteGroup
	// TxGroupErrorReasonInvalidFee indicates a group with improper fees.
	TxGroupErrorReasonInvalidFee
	// TxGroupMalformedErrorReasonDuplicateTxn indicates a group that contains the same transaction twice.
	TxGroupMalformedErrorReasonDuplicateTxn
)

// TxGroupMalformedError indicates a transaction group that violates a group-wide rule.
type TxGroupMalformedError struct {
	Msg    string
	Reason TxGroupMalformedErrorReasonCode
	// GroupIndex identifies the transaction associated with errors from CheckTxnGroup.
	// It is -1 when a CheckTxnGroup failure cannot be attributed to one transaction.
	GroupIndex int
}

// Error returns the transaction group validation failure message.
func (e *TxGroupMalformedError) Error() string {
	return e.Msg
}

// checkBasicStateProofPath enforces the Merkle proof parameters fixed by the
// StateProofBasic cryptographic suite.
func checkBasicStateProofPath(proof *merklearray.Proof, expectedHash crypto.HashType, digestSize int) error {
	if proof.HashFactory.HashType != expectedHash {
		return fmt.Errorf("%w: uses %d, expected %d",
			errMalformedStateProofHash, proof.HashFactory.HashType, expectedHash)
	}

	for i := range proof.Path {
		// An empty path element represents a missing sibling. Every present
		// sibling must be one complete Sumhash digest.
		if len(proof.Path[i]) != 0 && len(proof.Path[i]) != digestSize {
			return fmt.Errorf("%w: element %d has length %d, expected %d",
				errMalformedStateProofPath, i, len(proof.Path[i]), digestSize)
		}
	}
	return nil
}

func checkBasicStateProof(sp *stateproof.StateProof) error {
	if len(sp.SigCommit) != stateproof.HashSize {
		return fmt.Errorf("%w: has length %d, expected %d",
			errMalformedStateProofCommit, len(sp.SigCommit), stateproof.HashSize)
	}
	if err := checkBasicStateProofPath(&sp.SigProofs, stateproof.HashType, stateproof.HashSize); err != nil {
		return err
	}
	if err := checkBasicStateProofPath(&sp.PartProofs, stateproof.HashType, stateproof.HashSize); err != nil {
		return err
	}

	for _, r := range sp.Reveals {
		sig := r.SigSlot.Sig
		if sig.MsgIsZero() {
			continue
		}
		if len(sig.Signature) < 2 {
			return errMalformedStateProofSignature
		}
		if int(sig.Proof.TreeDepth) > len(sig.Proof.Path) ||
			sig.Proof.TreeDepth > merklearray.MaxEncodedTreeDepth {
			return errMalformedStateProofProof
		}
		if err := checkBasicStateProofPath(sig.Proof.ToProof(), merklesignature.MerkleSignatureSchemeHashFunction, merklesignature.MerkleSignatureSchemeRootSize); err != nil {
			return err
		}
	}
	return nil
}

func checkStateProof(spType protocol.StateProofType, sp *stateproof.StateProof) error {
	switch spType {
	case protocol.StateProofBasic:
		return checkBasicStateProof(sp)
	default:
		return fmt.Errorf("%w: %d", errMalformedStateProofType, spType)
	}
}

// checkTxnGroup screens a group on behalf of the agreement proposal filter,
// which is the only caller: it validates proposal payloads without ever
// calling WellFormed, so any check it needs must be repeated here.
func checkTxnGroup(n int, txn func(i int) *Transaction) error {
	for i := range n {
		tx := txn(i)
		if tx.Type == protocol.StateProofTx {
			if err := checkStateProof(tx.StateProofType, &tx.StateProof); err != nil {
				return err
			}
		}
	}
	return checkTxnGroupID(n, txn)
}

// checkTxnGroupID verifies that a group's nonzero group ID commits to the
// provided transaction order, and that no transaction appears twice within the
// group.
//
// Both must run before the caller consults the VerifiedTransactionCache, which
// keys entries by transaction ID: a full-group hit means the group itself was
// verified only if the ID commits to this group and the transaction IDs within
// it are distinct.
func checkTxnGroupID(n int, txn func(i int) *Transaction) error {
	if n == 0 {
		return nil
	}

	groupID := txn(0).Group
	if groupID.IsZero() {
		if n == 1 {
			return nil
		}
		return &TxGroupMalformedError{
			Msg:        fmt.Sprintf("transactionGroup: [0] had zero Group but was submitted in a group of %d", n),
			Reason:     TxGroupMalformedErrorReasonEmptyGroupID,
			GroupIndex: 0,
		}
	}

	computed := TxGroup{
		TxGroupHashes: make([]crypto.Digest, 0, n),
	}
	for i := range n {
		tx := txn(i)
		if tx.Group != groupID {
			return &TxGroupMalformedError{
				Msg:        fmt.Sprintf("transactionGroup: inconsistent group values: %v != %v", tx.Group, groupID),
				Reason:     TxGroupMalformedErrorReasonInconsistentGroupID,
				GroupIndex: i,
			}
		}

		current := *tx
		current.Group = crypto.Digest{}
		// Within a group every transaction carries the same Group value, so
		// these group-zeroed IDs are equal exactly when the real transaction
		// IDs are.
		txid := crypto.Digest(current.ID())
		if j := slices.Index(computed.TxGroupHashes, txid); j >= 0 {
			return &TxGroupMalformedError{
				Msg:        fmt.Sprintf("transactionGroup: duplicate transaction: [%d] repeats [%d]", i, j),
				Reason:     TxGroupMalformedErrorReasonDuplicateTxn,
				GroupIndex: i,
			}
		}
		computed.TxGroupHashes = append(computed.TxGroupHashes, txid)
	}

	computedID := hashTxGroup(computed)
	if groupID != computedID {
		return &TxGroupMalformedError{
			Msg:        fmt.Sprintf("transactionGroup: incomplete group: %v != %v (%v)", groupID, computedID, computed),
			Reason:     TxGroupMalformedErrorReasonIncompleteGroup,
			GroupIndex: -1,
		}
	}
	return nil
}

// hashTxGroup computes the canonical group hash using a pooled encoding buffer.
func hashTxGroup(group TxGroup) crypto.Digest {
	buf := protocol.GetEncodingBuf()
	encoded := append(buf.Bytes(), protocol.TxGroup...)
	encoded = group.MarshalMsg(encoded)
	digest := crypto.Hash(encoded)
	protocol.PutEncodingBuf(buf.Update(encoded))
	return digest
}

// CheckTxnGroupID verifies a group's ID and transaction-ID uniqueness. Callers
// must establish both before consulting the VerifiedTransactionCache -- see
// checkTxnGroupID.
func CheckTxnGroupID(group []SignedTxn) error {
	return checkTxnGroupID(len(group), func(i int) *Transaction { return &group[i].Txn })
}

// CheckPaysetGroup screens a decoded block payset group for invalid transactions and
// verifies that its nonzero group ID commits to the provided transaction order.
func CheckPaysetGroup(group []SignedTxnWithAD) error {
	return checkTxnGroup(len(group), func(i int) *Transaction { return &group[i].SignedTxn.Txn })
}
