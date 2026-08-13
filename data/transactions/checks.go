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

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errMissingHeartbeatFields       = errors.New("heartbeat transaction is missing its heartbeat fields")
	errHeartbeatInResourceGroup     = errors.New("heartbeat transaction may not be grouped with an application call or asset creation")
	errMalformedTxType              = errors.New("transaction has an unknown type")
	errMalformedApplicationBoxIndex = errors.New("application transaction box index exceeds foreign apps")
	errMalformedStateProofSignature = errors.New("state proof reveal has an empty or too-short signature")
	errMalformedStateProofProof     = errors.New("state proof reveal has an invalid Merkle proof depth")
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

func triggersResourceAvailability(tx *Transaction) bool {
	return tx.Type == protocol.ApplicationCallTx ||
		(tx.Type == protocol.AssetConfigTx && tx.ConfigAsset == 0)
}

func checkStateProofReveals(sp *stateproof.StateProof) error {
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
	}
	return nil
}

func checkApplicationCallBoxes(tx *Transaction) error {
	if tx.Access != nil {
		return nil
	}
	for i := range tx.Boxes {
		if tx.Boxes[i].Index > uint64(len(tx.ForeignApps)) {
			return errMalformedApplicationBoxIndex
		}
	}
	return nil
}

func checkTxnGroup(n int, txn func(i int) *Transaction) error {
	heartbeat, availTrigger := false, false
	for i := range n {
		tx := txn(i)
		switch tx.Type {
		case protocol.HeartbeatTx:
			heartbeat = true
			if tx.HeartbeatTxnFields == nil {
				return errMissingHeartbeatFields
			}
		case protocol.StateProofTx:
			if err := checkStateProofReveals(&tx.StateProof); err != nil {
				return err
			}
		case protocol.ApplicationCallTx:
			availTrigger = true
			if err := checkApplicationCallBoxes(tx); err != nil {
				return err
			}
		case protocol.PaymentTx, protocol.KeyRegistrationTx, protocol.AssetConfigTx, protocol.AssetTransferTx, protocol.AssetFreezeTx:
			if triggersResourceAvailability(tx) {
				availTrigger = true
			}
		default:
			return errMalformedTxType
		}
	}
	if heartbeat && availTrigger {
		return errHeartbeatInResourceGroup
	}
	return checkTxnGroupID(n, txn)
}

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
		computed.TxGroupHashes = append(computed.TxGroupHashes, crypto.Digest(current.ID()))
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

// CheckTxnGroup screens a transaction group for invalid transactions and
// verifies that its nonzero group ID commits to the provided transaction order.
func CheckTxnGroup(group []SignedTxn) error {
	return checkTxnGroup(len(group), func(i int) *Transaction { return &group[i].Txn })
}

// CheckPaysetGroup screens a decoded block payset group for invalid transactions and
// verifies that its nonzero group ID commits to the provided transaction order.
func CheckPaysetGroup(group []SignedTxnWithAD) error {
	return checkTxnGroup(len(group), func(i int) *Transaction { return &group[i].SignedTxn.Txn })
}
