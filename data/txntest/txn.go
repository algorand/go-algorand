// Copyright (C) 2019-2021 Algorand, Inc.
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

// Copyright (C) 2021 Algorand, Inc.
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
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

// Txn exists purely to make it easier to write a
// transaction.Transaction in Go source.
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
	LocalStateSchema  basics.StateSchema
	GlobalStateSchema basics.StateSchema
	ApprovalProgram   string
	ClearStateProgram string
	ExtraProgramPages uint32

	CertRound basics.Round
	CertType  protocol.CompactCertType
	Cert      compactcert.Cert
}

// Noted returns a new Txn with the given note field.
func (tx *Txn) Noted(note string) *Txn {
	copy := &Txn{}
	*copy = *tx
	copy.Note = []byte(note)
	return copy
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
	if tx.ApprovalProgram != "" && !strings.Contains(tx.ApprovalProgram, "#pragma version") {
		pragma := fmt.Sprintf("#pragma version %d\n", params.LogicSigVersion)
		tx.ApprovalProgram = pragma + tx.ApprovalProgram
	}
	if tx.ApprovalProgram != "" && tx.ClearStateProgram == "" {
		tx.ClearStateProgram = "int 0"
	}
	if tx.ClearStateProgram != "" && !strings.Contains(tx.ClearStateProgram, "#pragma version") {
		pragma := fmt.Sprintf("#pragma version %d\n", params.LogicSigVersion)
		tx.ClearStateProgram = pragma + tx.ClearStateProgram
	}
}

func assemble(source string) []byte {
	if source == "" {
		return nil
	}
	ops, err := logic.AssembleString(source)
	if err != nil {
		fmt.Printf("Bad program %v", ops.Errors)
		panic(ops.Errors)
	}
	return ops.Program
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
			ForeignApps:       tx.ForeignApps,
			ForeignAssets:     tx.ForeignAssets,
			LocalStateSchema:  tx.LocalStateSchema,
			GlobalStateSchema: tx.GlobalStateSchema,
			ApprovalProgram:   assemble(tx.ApprovalProgram),
			ClearStateProgram: assemble(tx.ClearStateProgram),
			ExtraProgramPages: tx.ExtraProgramPages,
		},
		CompactCertTxnFields: transactions.CompactCertTxnFields{
			CertRound: tx.CertRound,
			CertType:  tx.CertType,
			Cert:      tx.Cert,
		},
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

// SignedTxns turns a list of Txns into a slice of SignedTxns with
// GroupIDs set properly to make them a transaction group. Maybe
// another name is more approrpriate
func SignedTxns(txns ...*Txn) []transactions.SignedTxn {
	txgroup := transactions.TxGroup{
		TxGroupHashes: make([]crypto.Digest, len(txns)),
	}
	for i, txn := range txns {
		txn.Group = crypto.Digest{}
		txgroup.TxGroupHashes[i] = crypto.HashObj(txn.Txn())
	}
	group := crypto.HashObj(txgroup)
	for _, txn := range txns {
		txn.Group = group
	}

	stxns := make([]transactions.SignedTxn, len(txns))
	for i, txn := range txns {
		stxns[i] = txn.SignedTxn()
	}
	return stxns

}
