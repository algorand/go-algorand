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

	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errMissingHeartbeatFields       = errors.New("heartbeat transaction is missing its heartbeat fields")
	errHeartbeatInResourceGroup     = errors.New("heartbeat transaction may not be grouped with an application call or asset creation")
	errMalformedStateProofSignature = errors.New("state proof reveal has an empty or too-short signature")
	errMalformedStateProofProof     = errors.New("state proof reveal has an invalid Merkle proof depth")
)

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

func checkTxnGroup(n int, txn func(i int) *Transaction) error {
	heartbeat, availTrigger := false, false
	for i := 0; i < n; i++ {
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
		default:
			if triggersResourceAvailability(tx) {
				availTrigger = true
			}
		}
	}
	if heartbeat && availTrigger {
		return errHeartbeatInResourceGroup
	}
	return nil
}

// CheckTxnGroup screens a transaction group for invalid transactions.
func CheckTxnGroup(group []SignedTxn) error {
	return checkTxnGroup(len(group), func(i int) *Transaction { return &group[i].Txn })
}

// CheckPayset screens a block's payset for invalid transactions.
func CheckPayset(payset Payset) error {
	groupStart := 0
	for i := 1; i < len(payset); i++ {
		firstGroup := payset[groupStart].SignedTxn.Txn.Group
		if firstGroup.IsZero() || firstGroup != payset[i].SignedTxn.Txn.Group {
			if err := checkPaysetGroup(payset[groupStart:i]); err != nil {
				return err
			}
			groupStart = i
		}
	}
	if groupStart < len(payset) {
		if err := checkPaysetGroup(payset[groupStart:]); err != nil {
			return err
		}
	}
	return nil
}

func checkPaysetGroup(group Payset) error {
	return checkTxnGroup(len(group), func(i int) *Transaction { return &group[i].SignedTxn.Txn })
}
