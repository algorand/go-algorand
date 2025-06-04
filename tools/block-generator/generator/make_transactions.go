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

package generator

import (
	"encoding/binary"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	txn "github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
)

// ---- header / boilerplate ----

func (g *generator) makeTxnHeader(sender basics.Address, round basics.Round, intra uint64) txn.Header {
	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, g.txnCounter+intra)

	return txn.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: g.params.MinTxnFee},
		FirstValid:  round,
		LastValid:   round + 1000,
		GenesisID:   g.genesisID,
		GenesisHash: g.genesisHash,
		Note:        note,
	}
}

// makeTestTxn creates and populates the flat txntest.Txn structure with the given values.
func (g *generator) makeTestTxn(sender basics.Address, round basics.Round, intra uint64) txntest.Txn {
	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, g.txnCounter+intra)

	return txntest.Txn{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: g.params.MinTxnFee},
		FirstValid:  round,
		LastValid:   round + 1000,
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

func (g *generator) makeAssetDestroyTxn(header txn.Header, index basics.AssetIndex) txn.Transaction {
	return txn.Transaction{
		Type:   protocol.AssetConfigTx,
		Header: header,
		AssetConfigTxnFields: txn.AssetConfigTxnFields{
			ConfigAsset: index,
		},
	}
}

func (g *generator) makeAssetTransferTxn(header txn.Header, receiver basics.Address, amount uint64, closeAssetsTo basics.Address, index basics.AssetIndex) txn.Transaction {
	return txn.Transaction{
		Type:   protocol.AssetTransferTx,
		Header: header,
		AssetTransferTxnFields: txn.AssetTransferTxnFields{
			XferAsset:     index,
			AssetAmount:   amount,
			AssetReceiver: receiver,
			AssetCloseTo:  closeAssetsTo,
		},
	}
}

func (g *generator) makeAssetAcceptanceTxn(header txn.Header, index basics.AssetIndex) txn.Transaction {
	return g.makeAssetTransferTxn(header, header.Sender, 0, basics.Address{}, index)
}

// ---- application transactions ----

func (g *generator) makeAppCreateTxn(kind appKind, sender basics.Address, round basics.Round, intra uint64, futureAppId basics.AppIndex) []txn.SignedTxn {
	var approval, clear interface{}
	if kind == appKindSwap {
		approval, clear = approvalSwapBytes, clearSwapBytes
	} else {
		approval, clear = approvalBoxesBytes, clearBoxesBytes
	}

	createTxn := g.makeTestTxn(sender, round, intra)

	createTxn.Type = protocol.ApplicationCallTx
	createTxn.ApprovalProgram = approval
	createTxn.ClearStateProgram = clear

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

	createTxFee := g.params.MinTxnFee
	senderIndex := accountToIndex(sender)

	// TODO: should check for min balance
	g.balances[senderIndex] -= createTxFee
	if kind != appKindBoxes {
		return txntest.Group(&createTxn)
	}

	// also group in a pay txn to fund the app
	pstFee := uint64(1_000)
	pstAmt := uint64(2_000_000)

	paySibTxn := g.makeTestTxn(sender, round, intra)
	paySibTxn.Type = protocol.PaymentTx
	paySibTxn.Receiver = futureAppId.Address()
	paySibTxn.Fee = basics.MicroAlgos{Raw: pstFee}
	paySibTxn.Amount = uint64(pstAmt)

	// TODO: should check for min balance}
	g.balances[senderIndex] -= (pstFee + pstAmt)

	return txntest.Group(&createTxn, &paySibTxn)
}

// makeAppOptinTxn currently only works for the boxes app
func (g *generator) makeAppOptinTxn(sender basics.Address, round basics.Round, intra uint64, kind appKind, appIndex basics.AppIndex) []txn.SignedTxn {
	if kind != appKindBoxes {
		panic("makeAppOptinTxn only works for the boxes app currently")
	}

	optInTxn := g.makeTestTxn(sender, round, intra)
	/* all 0 values but keep around for reference
	optInTxn.ApplicationArgs = nil
	optInTxn.ForeignApps = nil
	optInTxn.ForeignAssets = nil
	optInTxn.ExtraProgramPages = 0
	*/

	optInTxn.Type = protocol.ApplicationCallTx
	optInTxn.ApplicationID = appIndex
	optInTxn.OnCompletion = txn.OptInOC
	// the first inner sends some algo to the creator:
	optInTxn.Accounts = []basics.Address{indexToAccount(g.appMap[kind][appIndex].sender)}
	optInTxn.Boxes = []txn.BoxRef{
		{Name: crypto.Digest(sender).ToSlice()},
	}

	// TODO: these may not make sense for the swap optin

	pstFee := uint64(2_000)
	pstAmt := uint64(2_000_000)

	paySibTxn := g.makeTestTxn(sender, round, intra)
	paySibTxn.Type = protocol.PaymentTx
	paySibTxn.Receiver = appIndex.Address()
	paySibTxn.Fee = basics.MicroAlgos{Raw: pstFee}
	paySibTxn.Amount = uint64(pstAmt)

	senderIndex := accountToIndex(sender)
	// TODO: should check for min balance}
	// TODO: for the case of boxes, should refund 0.76 algo
	g.balances[senderIndex] -= (pstFee + pstAmt)

	return txntest.Group(&optInTxn, &paySibTxn)
}

// makeAppCallTxn currently only works for the boxes app
func (g *generator) makeAppCallTxn(sender basics.Address, round basics.Round, intra uint64, appIndex basics.AppIndex) txn.Transaction {
	callTxn := g.makeTestTxn(sender, round, intra)
	callTxn.Type = protocol.ApplicationCallTx
	callTxn.ApplicationID = appIndex
	callTxn.OnCompletion = txn.NoOpOC // redundant for clarity
	callTxn.ApplicationArgs = [][]byte{
		{0xe1, 0xf9, 0x3f, 0x1d}, // the method selector for getting a box
	}

	callTxn.Boxes = []txn.BoxRef{
		{Name: crypto.Digest(sender).ToSlice()},
	}

	// TODO: should check for min balance
	appCallTxFee := g.params.MinTxnFee
	senderIndex := accountToIndex(sender)
	g.balances[senderIndex] -= appCallTxFee

	return callTxn.Txn()
}
