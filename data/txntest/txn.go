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
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// Txn exists purely to make it easier to write a
// transaction.Transaction in Go source.
type Txn struct {
	Type protocol.TxType

	Sender      basics.Address
	Fee         basics.MicroAlgos
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
	Amount           basics.MicroAlgos
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
	ApprovalProgram   []byte
	ClearStateProgram []byte
	ExtraProgramPages uint32

	CertRound basics.Round
	CertType  protocol.CompactCertType
	Cert      compactcert.Cert
}

// FillDefaults populates some obvious defaults from config params,
// unless they have already been set.
func (tx *Txn) FillDefaults(params config.ConsensusParams) {
	if tx.Fee.IsZero() {
		tx.Fee = basics.MicroAlgos{Raw: params.MinTxnFee}
	}
	if tx.LastValid == 0 {
		tx.LastValid = tx.FirstValid + basics.Round(params.MaxTxnLife)
	}
}

// Txn produces a transactions.Transaction from the fields in this Txn
func (tx Txn) Txn() transactions.Transaction {
	return transactions.Transaction{
		Type: tx.Type,
		Header: transactions.Header{
			Sender:      tx.Sender,
			Fee:         tx.Fee,
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
			Amount:           tx.Amount,
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
			ApprovalProgram:   tx.ApprovalProgram,
			ClearStateProgram: tx.ClearStateProgram,
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
