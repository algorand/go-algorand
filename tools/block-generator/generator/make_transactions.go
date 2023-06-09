// Copyright (C) 2019-2023 Algorand, Inc.
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

package generator

import (
	"encoding/binary"

	"github.com/algorand/go-algorand/data/basics"
	txn "github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
)

// ---- header / boilerplate ----

func (g *generator) makeTxnHeader(sender basics.Address, round, intra uint64) txn.Header {
	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, uint64(g.txnCounter+intra))

	return txn.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: g.params.MinTxnFee},
		FirstValid:  basics.Round(round),
		LastValid:   basics.Round(round + 1000),
		GenesisID:   g.genesisID,
		GenesisHash: g.genesisHash,
		Note:        note,
	}
}

// makeTestTxn creates and populates the flat txntest.Txn structure with the given values.
func (g *generator) makeTestTxn(sender basics.Address, round, intra uint64) txntest.Txn {
	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, uint64(g.txnCounter+intra))

	return txntest.Txn{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: g.params.MinTxnFee},
		FirstValid:  basics.Round(round),
		LastValid:   basics.Round(round + 1000),
		GenesisID:   g.genesisID,
		GenesisHash: g.genesisHash,
		Note:        note,
	}
}

// ---- payments ----

func (g *generator) makePaymentTxn(header txn.Header, receiver basics.Address, amount uint64, closeRemainderTo basics.Address) txn.Transaction {
	return txn.Transaction{
		Type:   protocol.PaymentTx,
		Header: header,
		PaymentTxnFields: txn.PaymentTxnFields{
			Receiver:         receiver,
			Amount:           basics.MicroAlgos{Raw: amount},
			CloseRemainderTo: closeRemainderTo,
		},
	}
}

// ---- asset transactions ----

func (g *generator) makeAssetCreateTxn(header txn.Header, total uint64, defaultFrozen bool, assetName string) txn.Transaction {
	return txn.Transaction{
		Type:   protocol.AssetConfigTx,
		Header: header,
		AssetConfigTxnFields: txn.AssetConfigTxnFields{
			AssetParams: basics.AssetParams{
				Total:         total,
				DefaultFrozen: defaultFrozen,
				AssetName:     assetName,
				Manager:       header.Sender,
				Freeze:        header.Sender,
				Clawback:      header.Sender,
				Reserve:       header.Sender,
			},
		},
	}
}

func (g *generator) makeAssetDestroyTxn(header txn.Header, index uint64) txn.Transaction {
	return txn.Transaction{
		Type:   protocol.AssetConfigTx,
		Header: header,
		AssetConfigTxnFields: txn.AssetConfigTxnFields{
			ConfigAsset: basics.AssetIndex(index),
		},
	}
}

func (g *generator) makeAssetTransferTxn(header txn.Header, receiver basics.Address, amount uint64, closeAssetsTo basics.Address, index uint64) txn.Transaction {
	return txn.Transaction{
		Type:   protocol.AssetTransferTx,
		Header: header,
		AssetTransferTxnFields: txn.AssetTransferTxnFields{
			XferAsset:     basics.AssetIndex(index),
			AssetAmount:   amount,
			AssetReceiver: receiver,
			AssetCloseTo:  closeAssetsTo,
		},
	}
}

func (g *generator) makeAssetAcceptanceTxn(header txn.Header, index uint64) txn.Transaction {
	return g.makeAssetTransferTxn(header, header.Sender, 0, basics.Address{}, index)
}

// ---- application transactions ----

func (g *generator) makeAppCreateTxn(sender basics.Address, round, intra uint64, approval, clear string) txn.Transaction {

	createTxn := g.makeTestTxn(sender, round, intra)

	/* all 0 values but keep around for reference
	createTxn.ApplicationID = 0
	createTxn.ApplicationArgs = nil
	createTxn.Accounts = nil
	createTxn.ForeignApps = nil
	createTxn.ForeignAssets = nil
	createTxn.Boxes = nil
	createTxn.ExtraProgramPages = 0
	*/

	createTxn.Type = protocol.ApplicationCallTx
	createTxn.ApprovalProgram = approval
	createTxn.ClearStateProgram = clear

	// sender opts-in to their own created app
	createTxn.OnCompletion = txn.OptInOC

	// max out local/global state usage but split
	// 50% between bytes/uint64
	createTxn.LocalStateSchema = basics.StateSchema{
		NumUint:      8,
		NumByteSlice: 8,
	}
	createTxn.GlobalStateSchema = basics.StateSchema{
		NumUint:      32,
		NumByteSlice: 32,
	}

	return createTxn.Txn()
}
