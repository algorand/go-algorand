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

package logic

import (
	"fmt"

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
	createdAsas map[basics.AssetIndex]struct{}
	createdApps map[basics.AppIndex]struct{}

	// These resources have been used by some txn in the group, so they are
	// available. These maps track the availability of the basic objects (often
	// called "params"), not the "cross-product" objects (which are tracked
	// below)
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
	boxes map[basics.BoxRef]bool

	// unnamedAccess is the number of times that a newly created app may access
	// a box that was not named.  It is decremented for each box accessed this way.
	unnamedAccess int

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

func (r *resources) shareBox(br basics.BoxRef, current basics.AppIndex) {
	if br.App == 0 {
		// "current app": Ignore if this is a create, else use ApplicationID
		if current == 0 {
			// When the create actually happens, and we learn the appID, we'll add it.
			return
		}
		br.App = current
	}
	r.boxes[br] = false
}

// In the fill* and allows* routines, we pass the header and the fields in
// separately, even though they are pointers into the same structure. That
// prevents dumb attempts to use other fields from the transaction.

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
	case protocol.StateProofTx:
		// state proof txns add nothing to availability (they can't even appear
		// in a group with an appl. but still.)
	default:
		panic(tx.Type)
	}
}

func (cx *EvalContext) allows(tx *transactions.Transaction, calleeVer uint64) error {
	// if the caller is pre-sharing, it can't prepare transactions with
	// resources that are not available, so `tx` is surely legal.
	if cx.version < sharedResourcesVersion {
		// this is just an optimization, from the perspective of properly
		// evaluating transactions in "normal" mode.  However, it is an
		// important short-circuit for simulation.  Simulation does not
		// understand how to handle missing cross-products in non-sharing
		// program versions.
		return nil
	}
	switch tx.Type {
	case protocol.PaymentTx, protocol.KeyRegistrationTx, protocol.AssetConfigTx:
		// these transactions don't touch cross-product resources, so no error is possible
		return nil
	case protocol.AssetTransferTx:
		return cx.allowsAssetTransfer(&tx.Header, &tx.AssetTransferTxnFields)
	case protocol.AssetFreezeTx:
		return cx.allowsAssetFreeze(&tx.Header, &tx.AssetFreezeTxnFields)
	case protocol.ApplicationCallTx:
		return cx.allowsApplicationCall(&tx.Header, &tx.ApplicationCallTxnFields, calleeVer)
	default:
		return fmt.Errorf("unknown inner transaction type %s", tx.Type)
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
	r.sharedAccounts[hdr.Sender] = struct{}{}
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

// allowsHolding checks if a holding is available under the txgroup sharing rules
func (cx *EvalContext) allowsHolding(addr basics.Address, ai basics.AssetIndex) bool {
	r := cx.available
	if _, ok := r.sharedHoldings[ledgercore.AccountAsset{Address: addr, Asset: ai}]; ok {
		return true
	}
	// If an ASA was created in this group, then allow holding access for any allowed account.
	if _, ok := r.createdAsas[ai]; ok {
		return cx.availableAccount(addr)
	}
	// If the address was "created" by making its app in this group, then allow for available assets.
	for created := range r.createdApps {
		if cx.GetApplicationAddress(created) == addr {
			return cx.availableAsset(ai)
		}
	}

	if cx.UnnamedResources != nil {
		// Ensure that the account and asset are available before consulting cx.UnnamedResources.AllowsHolding.
		// This way cx.UnnamedResources.AllowsHolding only needs to make a decision about the asset holding
		// being available, not about the component resources.
		return cx.availableAccount(addr) && cx.availableAsset(ai) && cx.UnnamedResources.AllowsHolding(addr, ai)
	}
	return false
}

// allowsLocals checks if a local state is available under the txgroup sharing rules
func (cx *EvalContext) allowsLocals(addr basics.Address, ai basics.AppIndex) bool {
	r := cx.available
	if _, ok := r.sharedLocals[ledgercore.AccountApp{Address: addr, App: ai}]; ok {
		return true
	}
	// All locals of created apps are available
	if _, ok := r.createdApps[ai]; ok {
		return cx.availableAccount(addr)
	}

	// All locals of created app accounts are available
	for created := range r.createdApps {
		if cx.GetApplicationAddress(created) == addr {
			return cx.availableApp(ai)
		}
	}

	if cx.UnnamedResources != nil {
		// Ensure that the account and app are available before consulting cx.UnnamedResources.AllowsLocal.
		// This way cx.UnnamedResources.AllowsLocal only needs to make a decision about the app local
		// being available, not about the component resources.
		return cx.availableApp(ai) && cx.availableAccount(addr) && cx.UnnamedResources.AllowsLocal(addr, ai)
	}
	return false
}

func (cx *EvalContext) requireHolding(acct basics.Address, id basics.AssetIndex) error {
	/* Previous versions allowed inner appls with zeros in "required" places,
	   even if that 0 resource should have be inaccessible, because the check
	   was done at itxn_field time, and maybe the app simply didn't set the
	   field. */
	if id == 0 || acct.IsZero() {
		return nil
	}
	if !cx.allowsHolding(acct, id) {
		return fmt.Errorf("unavailable Holding %d+%s would be accessible", id, acct)
	}
	return nil
}

func (cx *EvalContext) requireLocals(acct basics.Address, id basics.AppIndex) error {
	if !cx.allowsLocals(acct, id) {
		return fmt.Errorf("unavailable Local State %d+%s would be accessible", id, acct)
	}
	return nil
}

func (cx *EvalContext) allowsAssetTransfer(hdr *transactions.Header, tx *transactions.AssetTransferTxnFields) error {
	// After EnableInnerClawbackWithoutSenderHolding appears in a consensus
	// update, we should remove it from consensus params and assume it's true in
	// the next release. It only needs to be in there so that it gates the
	// behavior change in the release it first appears.
	if !cx.Proto.EnableInnerClawbackWithoutSenderHolding || tx.AssetSender.IsZero() {
		err := cx.requireHolding(hdr.Sender, tx.XferAsset)
		if err != nil {
			return fmt.Errorf("axfer Sender: %w", err)
		}
	}
	err := cx.requireHolding(tx.AssetReceiver, tx.XferAsset)
	if err != nil {
		return fmt.Errorf("axfer AssetReceiver: %w", err)
	}
	err = cx.requireHolding(tx.AssetSender, tx.XferAsset)
	if err != nil {
		return fmt.Errorf("axfer AssetSender: %w", err)
	}
	err = cx.requireHolding(tx.AssetCloseTo, tx.XferAsset)
	if err != nil {
		return fmt.Errorf("axfer AssetCloseTo: %w", err)
	}
	return nil
}

func (r *resources) fillAssetFreeze(hdr *transactions.Header, tx *transactions.AssetFreezeTxnFields) {
	r.sharedAccounts[hdr.Sender] = struct{}{}
	id := tx.FreezeAsset
	r.sharedAsas[id] = struct{}{}
	r.shareAccountAndHolding(tx.FreezeAccount, id)
}

func (cx *EvalContext) allowsAssetFreeze(hdr *transactions.Header, tx *transactions.AssetFreezeTxnFields) error {
	err := cx.requireHolding(tx.FreezeAccount, tx.FreezeAsset)
	if err != nil {
		return fmt.Errorf("afrz FreezeAccount: %w", err)
	}
	return nil
}

func (r *resources) fillApplicationCall(ep *EvalParams, hdr *transactions.Header, tx *transactions.ApplicationCallTxnFields) {
	if tx.Access != nil {
		r.fillApplicationCallAccess(ep, hdr, tx)
	} else {
		r.fillApplicationCallForeign(ep, hdr, tx)
	}
}

func (r *resources) fillApplicationCallAccess(ep *EvalParams, hdr *transactions.Header, tx *transactions.ApplicationCallTxnFields) {
	// The only implicitly available things are the sender, the app, and the sender's locals
	r.sharedAccounts[hdr.Sender] = struct{}{}
	if tx.ApplicationID != 0 {
		r.sharedApps[tx.ApplicationID] = struct{}{}
		r.shareLocal(hdr.Sender, tx.ApplicationID)
	}

	// Access is a explicit list of resources that should be made "available"
	for _, rr := range tx.Access {
		switch {
		case !rr.Address.IsZero():
			r.sharedAccounts[rr.Address] = struct{}{}
		case rr.Asset != 0:
			r.sharedAsas[rr.Asset] = struct{}{}
		case rr.App != 0:
			r.sharedApps[rr.App] = struct{}{}
		case !rr.Holding.Empty():
			// ApplicationCallTxnFields.wellFormed ensures no error here.
			address, asset, _ := rr.Holding.Resolve(tx.Access, hdr.Sender)
			r.shareHolding(address, asset)
		case !rr.Locals.Empty():
			// ApplicationCallTxnFields.wellFormed ensures no error here.
			address, app, _ := rr.Locals.Resolve(tx.Access, hdr.Sender)
			r.shareLocal(address, app)
		case !rr.Box.Empty():
			// ApplicationCallTxnFields.wellFormed ensures no error here.
			app, name, _ := rr.Box.Resolve(tx.Access)
			r.shareBox(basics.BoxRef{App: app, Name: name}, tx.ApplicationID)
		default:
			// all empty equals an "empty boxref" which allows one unnamed access
			if ep.Proto.EnableUnnamedBoxAccessInNewApps {
				r.unnamedAccess++
			}
		}
	}
}

func (r *resources) fillApplicationCallForeign(ep *EvalParams, hdr *transactions.Header, tx *transactions.ApplicationCallTxnFields) {
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
		txAccounts = append(txAccounts, ep.GetApplicationAddress(id))
		r.sharedApps[id] = struct{}{}
	}
	for _, id := range tx.ForeignApps {
		txAccounts = append(txAccounts, ep.GetApplicationAddress(id))
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
		if ep.Proto.EnableUnnamedBoxAccessInNewApps && br.Empty() {
			r.unnamedAccess++
		}
		var app basics.AppIndex
		if br.Index > 0 {
			// Bounds check will already have been done by
			// WellFormed. For testing purposes, it's better to panic
			// now than after returning a nil.
			app = tx.ForeignApps[br.Index-1] // shift for the 0=current convention
		}
		r.shareBox(basics.BoxRef{App: app, Name: string(br.Name)}, tx.ApplicationID)
	}
}

func (cx *EvalContext) allowsApplicationCall(hdr *transactions.Header, tx *transactions.ApplicationCallTxnFields, calleeVer uint64) error {
	// If the callee is at least sharedResourcesVersion, then it will check
	// availability properly itself.
	if calleeVer >= sharedResourcesVersion {
		return nil
	}

	// This should closely match the `fillApplicationCall` routine, as the idea
	// is to find all of the cross product resources this attempted call will
	// have access to, and check that they are already available.
	txAccounts := make([]basics.Address, 0, 2+len(tx.Accounts)+len(tx.ForeignApps))
	txAccounts = append(txAccounts, hdr.Sender)
	txAccounts = append(txAccounts, tx.Accounts...)
	if id := tx.ApplicationID; id != 0 {
		txAccounts = append(txAccounts, cx.GetApplicationAddress(id))
	}
	for _, id := range tx.ForeignApps {
		txAccounts = append(txAccounts, cx.GetApplicationAddress(id))
	}
	for _, address := range txAccounts {
		for _, id := range tx.ForeignAssets {
			err := cx.requireHolding(address, id)
			if err != nil {
				return fmt.Errorf("appl ForeignAssets: %w", err)
			}
		}
		if id := tx.ApplicationID; id != 0 {
			err := cx.requireLocals(address, id)
			if err != nil {
				return fmt.Errorf("appl ApplicationID: %w", err)
			}
		}
		for _, id := range tx.ForeignApps {
			err := cx.requireLocals(address, id)
			if err != nil {
				return fmt.Errorf("appl ForeignApps: %w", err)
			}
		}
	}
	return nil
}
