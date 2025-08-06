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

package txntest

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

// Txn exists to simplify writing tests where transaction.Transaction might be unwieldy.
// Txn simplifies testing in these ways:
// * Provides a flat structure to simplify object construction.
// * Defines convenience methods to help setup test state.
type Txn struct {
	Type protocol.TxType

	Sender      basics.Address
	Fee         interface{} // basics.MicroAlgos, uint64, int, or nil
	FirstValid  basics.Round
	LastValid   basics.Round
	Note        []byte
	GenesisID   string
	GenesisHash crypto.Digest
	Group       crypto.Digest
	Lease       [32]byte
	RekeyTo     basics.Address

	VotePK           crypto.OneTimeSignatureVerifier
	SelectionPK      crypto.VRFVerifier
	VoteFirst        basics.Round
	VoteLast         basics.Round
	VoteKeyDilution  uint64
	Nonparticipation bool
	StateProofPK     merklesignature.Commitment

	Receiver         basics.Address
	Amount           uint64
	CloseRemainderTo basics.Address

	ConfigAsset basics.AssetIndex
	AssetParams basics.AssetParams

	XferAsset     basics.AssetIndex
	AssetAmount   uint64
	AssetSender   basics.Address
	AssetReceiver basics.Address
	AssetCloseTo  basics.Address

	FreezeAccount basics.Address
	FreezeAsset   basics.AssetIndex
	AssetFrozen   bool

	ApplicationID     basics.AppIndex
	OnCompletion      transactions.OnCompletion
	ApplicationArgs   [][]byte
	Accounts          []basics.Address
	ForeignApps       []basics.AppIndex
	ForeignAssets     []basics.AssetIndex
	Boxes             []transactions.BoxRef
	Access            []transactions.ResourceRef
	LocalStateSchema  basics.StateSchema
	GlobalStateSchema basics.StateSchema
	ApprovalProgram   interface{} // string, nil, or []bytes if already compiled
	ClearStateProgram interface{} // string, nil or []bytes if already compiled
	ExtraProgramPages uint32

	StateProofType protocol.StateProofType
	StateProof     stateproof.StateProof
	StateProofMsg  stateproofmsg.Message

	HbAddress     basics.Address
	HbProof       crypto.HeartbeatProof
	HbSeed        committee.Seed
	HbVoteID      crypto.OneTimeSignatureVerifier
	HbKeyDilution uint64
}

// internalCopy "finishes" a shallow copy done by a simple Go assignment by
// copying all of the slice fields
func (tx *Txn) internalCopy() {
	tx.Note = append([]byte(nil), tx.Note...)
	if tx.ApplicationArgs != nil {
		tx.ApplicationArgs = append([][]byte(nil), tx.ApplicationArgs...)
		for i := range tx.ApplicationArgs {
			tx.ApplicationArgs[i] = append([]byte(nil), tx.ApplicationArgs[i]...)
		}
	}
	tx.Accounts = append([]basics.Address(nil), tx.Accounts...)
	tx.ForeignApps = append([]basics.AppIndex(nil), tx.ForeignApps...)
	tx.ForeignAssets = append([]basics.AssetIndex(nil), tx.ForeignAssets...)
	tx.Boxes = append([]transactions.BoxRef(nil), tx.Boxes...)
	for i := 0; i < len(tx.Boxes); i++ {
		tx.Boxes[i].Name = append([]byte(nil), tx.Boxes[i].Name...)
	}
	tx.Access = append([]transactions.ResourceRef(nil), tx.Access...)
	for i := 0; i < len(tx.Access); i++ {
		tx.Access[i].Box.Name = append([]byte(nil), tx.Access[i].Box.Name...)
	}

	// Programs may or may not actually be byte slices.  The other
	// possibilitiues don't require copies.
	if program, ok := tx.ApprovalProgram.([]byte); ok {
		tx.ApprovalProgram = append([]byte(nil), program...)
	}
	if program, ok := tx.ClearStateProgram.([]byte); ok {
		tx.ClearStateProgram = append([]byte(nil), program...)
	}
}

// Noted returns a new Txn with the given note field.
func (tx Txn) Noted(note string) *Txn {
	tx.internalCopy()
	tx.Note = []byte(note)
	return &tx
}

// Args returns a new Txn with the given strings as app args
func (tx Txn) Args(strings ...string) *Txn {
	tx.internalCopy()
	bytes := make([][]byte, len(strings))
	for i, s := range strings {
		bytes[i] = []byte(s)
	}
	tx.ApplicationArgs = bytes
	return &tx
}

// FillDefaults populates some obvious defaults from config params,
// unless they have already been set.
func (tx *Txn) FillDefaults(params config.ConsensusParams) {
	if tx.Fee == nil {
		tx.Fee = params.MinTxnFee
	}
	if tx.LastValid == 0 {
		tx.LastValid = tx.FirstValid + basics.Round(params.MaxTxnLife)
	}

	switch tx.Type {
	case protocol.KeyRegistrationTx:
		if !tx.VotePK.MsgIsZero() && !tx.SelectionPK.MsgIsZero() {
			if tx.VoteLast == 0 {
				tx.VoteLast = tx.VoteFirst + 1_000_000
			}
		}
	case protocol.ApplicationCallTx:
		// fill in empty programs
		if tx.ApplicationID == 0 || tx.OnCompletion == transactions.UpdateApplicationOC {
			switch program := tx.ApprovalProgram.(type) {
			case nil:
				tx.ApprovalProgram = fmt.Sprintf("#pragma version %d\nint 1", params.LogicSigVersion)
			case string:
				if program != "" && !strings.Contains(program, "#pragma version") {
					pragma := fmt.Sprintf("#pragma version %d\n", params.LogicSigVersion)
					tx.ApprovalProgram = pragma + program
				}
			case []byte:
			}

			switch program := tx.ClearStateProgram.(type) {
			case nil:
				tx.ClearStateProgram = tx.ApprovalProgram
			case string:
				if program != "" && !strings.Contains(program, "#pragma version") {
					pragma := fmt.Sprintf("#pragma version %d\n", params.LogicSigVersion)
					tx.ClearStateProgram = pragma + program
				}
			case []byte:
			}
		}

	}
}

func assemble(source interface{}) []byte {
	switch program := source.(type) {
	case string:
		if program == "" {
			return nil
		}
		ops, err := logic.AssembleString(program)
		if err != nil {
			panic(fmt.Sprintf("Bad program %v", ops.Errors))
		}
		return ops.Program
	case []byte:
		return program
	case nil:
		return nil
	}
	panic(reflect.TypeOf(source))
}

// Txn produces a transactions.Transaction from the fields in this Txn
func (tx Txn) Txn() transactions.Transaction {
	switch fee := tx.Fee.(type) {
	case basics.MicroAlgos:
		// nothing, already have MicroAlgos
	case uint64:
		tx.Fee = basics.MicroAlgos{Raw: fee}
	case int:
		if fee >= 0 {
			tx.Fee = basics.MicroAlgos{Raw: uint64(fee)}
		}
	case nil:
		tx.Fee = basics.MicroAlgos{}
	}

	hb := &transactions.HeartbeatTxnFields{
		HbAddress:     tx.HbAddress,
		HbProof:       tx.HbProof,
		HbSeed:        tx.HbSeed,
		HbVoteID:      tx.HbVoteID,
		HbKeyDilution: tx.HbKeyDilution,
	}
	if hb.MsgIsZero() {
		hb = nil
	}
	return transactions.Transaction{
		Type: tx.Type,
		Header: transactions.Header{
			Sender:      tx.Sender,
			Fee:         tx.Fee.(basics.MicroAlgos),
			FirstValid:  tx.FirstValid,
			LastValid:   tx.LastValid,
			Note:        tx.Note,
			GenesisID:   tx.GenesisID,
			GenesisHash: tx.GenesisHash,
			Group:       tx.Group,
			Lease:       tx.Lease,
			RekeyTo:     tx.RekeyTo,
		},
		KeyregTxnFields: transactions.KeyregTxnFields{
			VotePK:           tx.VotePK,
			SelectionPK:      tx.SelectionPK,
			VoteFirst:        tx.VoteFirst,
			VoteLast:         tx.VoteLast,
			VoteKeyDilution:  tx.VoteKeyDilution,
			Nonparticipation: tx.Nonparticipation,
			StateProofPK:     tx.StateProofPK,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         tx.Receiver,
			Amount:           basics.MicroAlgos{Raw: tx.Amount},
			CloseRemainderTo: tx.CloseRemainderTo,
		},
		AssetConfigTxnFields: transactions.AssetConfigTxnFields{
			ConfigAsset: tx.ConfigAsset,
			AssetParams: tx.AssetParams,
		},
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     tx.XferAsset,
			AssetAmount:   tx.AssetAmount,
			AssetSender:   tx.AssetSender,
			AssetReceiver: tx.AssetReceiver,
			AssetCloseTo:  tx.AssetCloseTo,
		},
		AssetFreezeTxnFields: transactions.AssetFreezeTxnFields{
			FreezeAccount: tx.FreezeAccount,
			FreezeAsset:   tx.FreezeAsset,
			AssetFrozen:   tx.AssetFrozen,
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID:     tx.ApplicationID,
			OnCompletion:      tx.OnCompletion,
			ApplicationArgs:   tx.ApplicationArgs,
			Accounts:          tx.Accounts,
			ForeignApps:       append([]basics.AppIndex(nil), tx.ForeignApps...),
			ForeignAssets:     append([]basics.AssetIndex(nil), tx.ForeignAssets...),
			Boxes:             tx.Boxes,
			Access:            tx.Access,
			LocalStateSchema:  tx.LocalStateSchema,
			GlobalStateSchema: tx.GlobalStateSchema,
			ApprovalProgram:   assemble(tx.ApprovalProgram),
			ClearStateProgram: assemble(tx.ClearStateProgram),
			ExtraProgramPages: tx.ExtraProgramPages,
		},
		StateProofTxnFields: transactions.StateProofTxnFields{
			StateProofType: tx.StateProofType,
			StateProof:     tx.StateProof,
			Message:        tx.StateProofMsg,
		},
		HeartbeatTxnFields: hb,
	}
}

// SignedTxn produces a unsigned, transactions.SignedTransaction from
// the fields in this Txn.  This seemingly pointless operation exists,
// again, for convenience when driving tests.
func (tx Txn) SignedTxn() transactions.SignedTxn {
	return transactions.SignedTxn{Txn: tx.Txn()}
}

// SignedTxnWithAD produces unsigned, transactions.SignedTxnWithAD
// from the fields in this Txn.  This seemingly pointless operation
// exists, again, for convenience when driving tests.
func (tx Txn) SignedTxnWithAD() transactions.SignedTxnWithAD {
	return transactions.SignedTxnWithAD{SignedTxn: tx.SignedTxn()}
}

// Group turns a list of Txns into a slice of SignedTxns with
// GroupIDs set properly to make them a transaction group. The input
// Txns are modified with the calculated GroupID.
func Group(txns ...*Txn) []transactions.SignedTxn {
	txgroup := transactions.TxGroup{
		TxGroupHashes: make([]crypto.Digest, len(txns)),
	}
	stxns := make([]transactions.SignedTxn, len(txns))
	for i, txn := range txns {
		stxns[i] = txn.SignedTxn()
	}
	for i, txn := range stxns {
		txn.Txn.Group = crypto.Digest{}
		txgroup.TxGroupHashes[i] = crypto.Digest(txn.ID())
	}
	group := crypto.HashObj(txgroup)
	for i, txn := range txns {
		txn.Group = group
		stxns[i].Txn.Group = group
	}

	return stxns

}
