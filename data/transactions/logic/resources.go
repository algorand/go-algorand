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

package logic

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// resources contains a catalog of available resources. It's used to track the
// apps, assets, and boxes that are available to a transaction, outside the
// direct foreign array mechanism.
type resources struct {
	// These resources were created previously in the group, so they can be used
	// by later transactions.
	createdAsas []basics.AssetIndex
	createdApps []basics.AppIndex

	// These resources have been mentioned by some txn in the group, so they are
	// available. But only their "main" data is available. For example, if an
	// account is mentioned, its algo balance is available, but not necessarily
	// its asset balance for any old ASA.
	sharedAccounts map[basics.Address]struct{}
	sharedAsas     map[basics.AssetIndex]struct{}
	sharedApps     map[basics.AppIndex]struct{}
	// We need to carefully track the "cross-product" availability, because if
	// tx0 mentions an account A, and tx1 mentions an ASA X, that does _not_
	// make the holding AX available
	sharedHoldings map[ledgercore.AccountAsset]struct{}
	sharedLocals   map[ledgercore.AccountApp]struct{}

	// boxes are all of the top-level box refs from the txgroup. Most are added
	// during NewEvalParams(). refs using 0 on an appl create are resolved and
	// added when the appl executes. The boolean value indicates the "dirtiness"
	// of the box - has it been modified in this txngroup? If yes, the size of
	// the box counts against the group writeBudget. So delete is NOT a dirtying
	// operation.
	boxes map[boxRef]bool

	// dirtyBytes maintains a running count of the number of dirty bytes in `boxes`
	dirtyBytes uint64
}

func (r *resources) shareHolding(addr basics.Address, id basics.AssetIndex) {
	r.sharedHoldings[ledgercore.AccountAsset{Address: addr, Asset: id}] = struct{}{}
}

func (r *resources) shareAccountAndHolding(addr basics.Address, id basics.AssetIndex) {
	r.sharedAccounts[addr] = struct{}{}
	if id != 0 {
		r.sharedHoldings[ledgercore.AccountAsset{Address: addr, Asset: id}] = struct{}{}
	}
}

func (r *resources) shareLocal(addr basics.Address, id basics.AppIndex) {
	r.sharedLocals[ledgercore.AccountApp{Address: addr, App: id}] = struct{}{}
}

// In the fill* routines, we pass the header and the fields in separately, even
// though they are pointers into the same structure. That prevents dumb attempts
// to use other fields from the transaction.

func (r *resources) fill(tx *transactions.Transaction, ep *EvalParams) {
	switch tx.Type {
	case protocol.PaymentTx:
		r.fillPayment(&tx.Header, &tx.PaymentTxnFields)
	case protocol.KeyRegistrationTx:
		r.fillKeyRegistration(&tx.Header)
	case protocol.AssetConfigTx:
		r.fillAssetConfig(&tx.Header, &tx.AssetConfigTxnFields)
	case protocol.AssetTransferTx:
		r.fillAssetTransfer(&tx.Header, &tx.AssetTransferTxnFields)
	case protocol.AssetFreezeTx:
		r.fillAssetFreeze(&tx.Header, &tx.AssetFreezeTxnFields)
	case protocol.ApplicationCallTx:
		r.fillApplicationCall(ep, &tx.Header, &tx.ApplicationCallTxnFields)
	}
}

func (r *resources) fillKeyRegistration(hdr *transactions.Header) {
	r.sharedAccounts[hdr.Sender] = struct{}{}
}

func (r *resources) fillPayment(hdr *transactions.Header, tx *transactions.PaymentTxnFields) {
	r.sharedAccounts[hdr.Sender] = struct{}{}
	r.sharedAccounts[tx.Receiver] = struct{}{}
	if !tx.CloseRemainderTo.IsZero() {
		r.sharedAccounts[tx.CloseRemainderTo] = struct{}{}
	}
}

func (r *resources) fillAssetConfig(hdr *transactions.Header, tx *transactions.AssetConfigTxnFields) {
	r.shareAccountAndHolding(hdr.Sender, tx.ConfigAsset)
	if id := tx.ConfigAsset; id != 0 {
		r.sharedAsas[id] = struct{}{}
	}
	// We don't need to read the special addresses, so they don't go in.
}

func (r *resources) fillAssetTransfer(hdr *transactions.Header, tx *transactions.AssetTransferTxnFields) {
	id := tx.XferAsset
	r.sharedAsas[id] = struct{}{}
	r.shareAccountAndHolding(hdr.Sender, id)
	r.shareAccountAndHolding(tx.AssetReceiver, id)

	if !tx.AssetSender.IsZero() {
		r.shareAccountAndHolding(tx.AssetSender, id)
	}

	if !tx.AssetCloseTo.IsZero() {
		r.shareAccountAndHolding(tx.AssetCloseTo, id)
	}
}

func (r *resources) fillAssetFreeze(hdr *transactions.Header, tx *transactions.AssetFreezeTxnFields) {
	r.sharedAccounts[hdr.Sender] = struct{}{}
	id := tx.FreezeAsset
	r.sharedAsas[id] = struct{}{}
	r.shareAccountAndHolding(tx.FreezeAccount, id)
}

func (r *resources) fillApplicationCall(ep *EvalParams, hdr *transactions.Header, tx *transactions.ApplicationCallTxnFields) {
	txAccounts := make([]basics.Address, 0, 2+len(tx.Accounts)+len(tx.ForeignApps))
	txAccounts = append(txAccounts, hdr.Sender)
	txAccounts = append(txAccounts, tx.Accounts...)
	for _, id := range tx.ForeignAssets {
		r.sharedAsas[id] = struct{}{}
	}
	// Make the app account associated with app calls available. We
	// don't have to add code to make the accounts of freshly created
	// apps available, because that is already handled by looking at
	// `createdApps`.
	if id := tx.ApplicationID; id != 0 {
		txAccounts = append(txAccounts, ep.getApplicationAddress(id))
		r.sharedApps[id] = struct{}{}
	}
	for _, id := range tx.ForeignApps {
		txAccounts = append(txAccounts, ep.getApplicationAddress(id))
		r.sharedApps[id] = struct{}{}
	}
	for _, address := range txAccounts {
		r.sharedAccounts[address] = struct{}{}

		for _, id := range tx.ForeignAssets {
			r.shareHolding(address, id)
		}
		// Similar to note about app accounts, availableLocals allows
		// all createdApps holdings, so we don't care if id == 0 here.
		if id := tx.ApplicationID; id != 0 {
			r.shareLocal(address, id)
		}
		for _, id := range tx.ForeignApps {
			r.shareLocal(address, id)
		}
	}

	for _, br := range tx.Boxes {
		var app basics.AppIndex
		if br.Index == 0 {
			// "current app": Ignore if this is a create, else use ApplicationID
			if tx.ApplicationID == 0 {
				// When the create actually happens, and we learn the appID, we'll add it.
				continue
			}
			app = tx.ApplicationID
		} else {
			// Bounds check will already have been done by
			// WellFormed. For testing purposes, it's better to panic
			// now than after returning a nil.
			app = tx.ForeignApps[br.Index-1] // shift for the 0=this convention
		}
		r.boxes[boxRef{app, string(br.Name)}] = false
	}
}
