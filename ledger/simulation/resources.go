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

package simulation

import (
	"cmp"
	"fmt"
	"math"
	"slices"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// ResourceTracker calculates the additional resources that a transaction or group could use, and
// it tracks any referenced unnamed resources that fit within those limits.
type ResourceTracker struct {
	Accounts    map[basics.Address]struct{}
	MaxAccounts int

	Assets    map[basics.AssetIndex]struct{}
	MaxAssets int

	Apps    map[basics.AppIndex]struct{}
	MaxApps int

	// The map value is the size of the box loaded from the ledger prior to any writes. This is used
	// to track the box read budget.
	Boxes           map[logic.BoxRef]uint64
	MaxBoxes        int
	NumEmptyBoxRefs int
	maxWriteBudget  uint64

	MaxTotalRefs int

	AssetHoldings             map[ledgercore.AccountAsset]struct{}
	AppLocals                 map[ledgercore.AccountApp]struct{}
	MaxCrossProductReferences int
}

func makeTxnResourceTracker(txn *transactions.Transaction, proto *config.ConsensusParams) ResourceTracker {
	if txn.Type != protocol.ApplicationCallTx {
		return ResourceTracker{}
	}
	return ResourceTracker{
		// Use MaxAppTxnAccounts + MaxAppTxnForeignApps for the account limit because app references
		// also make their accounts available, and since we can't know if an unknown account is an
		// app account, we assume it is.
		MaxAccounts:  proto.MaxAppTxnAccounts + proto.MaxAppTxnForeignApps - len(txn.Accounts) - len(txn.ForeignApps),
		MaxAssets:    proto.MaxAppTxnForeignAssets - len(txn.ForeignAssets),
		MaxApps:      proto.MaxAppTxnForeignApps - len(txn.ForeignApps),
		MaxBoxes:     proto.MaxAppBoxReferences - len(txn.Boxes),
		MaxTotalRefs: proto.MaxAppTotalTxnReferences - len(txn.Accounts) - len(txn.ForeignAssets) - len(txn.ForeignApps) - len(txn.Boxes),
	}
}

func makeGlobalResourceTracker(perTxnResources []ResourceTracker, nonAppCalls int, proto *config.ConsensusParams) ResourceTracker {
	// Calculate the maximum number of cross-product resources that can be accessed by one app call
	// under normal circumstances. This is calculated using the case of an app call with a full set
	// of foreign apps. Including the app being called, there are (MaxAppTxnForeignApps + 1) apps,
	// crossed with (MaxAppTxnForeignAssets + 2) accounts (the called app's account, the sender's
	// account, and the foreign app accounts). We then subtract out the app local of sender's
	// account and the called app, and each app local of an app and its own account, or
	// (MaxAppTxnForeignApps + 2) references. So we end up with:
	//
	// (MaxAppTxnForeignApps + 1) * (MaxAppTxnForeignApps + 2) - (MaxAppTxnForeignApps + 2)
	// <=> MaxAppTxnForeignApps^2 + 3*MaxAppTxnForeignApps + 2 - MaxAppTxnForeignApps - 2
	// <=> MaxAppTxnForeignApps^2 + 2*MaxAppTxnForeignApps
	// <=> MaxAppTxnForeignApps * (MaxAppTxnForeignApps + 2)
	maxCrossProductsPerAppCall := proto.MaxAppTxnForeignApps * (proto.MaxAppTxnForeignApps + 2)
	unusedTxns := proto.MaxTxGroupSize - len(perTxnResources)
	globalResources := ResourceTracker{
		MaxCrossProductReferences: maxCrossProductsPerAppCall * (proto.MaxTxGroupSize - nonAppCalls),
		// If there are fewer than MaxTxGroupSize transactions, then we can make more resources
		// available as if the remaining transactions were empty app calls.
		MaxAccounts:  unusedTxns * (proto.MaxAppTxnAccounts + proto.MaxAppTxnForeignApps),
		MaxAssets:    unusedTxns * proto.MaxAppTxnForeignAssets,
		MaxApps:      unusedTxns * proto.MaxAppTxnForeignApps,
		MaxBoxes:     unusedTxns * proto.MaxAppBoxReferences,
		MaxTotalRefs: unusedTxns * proto.MaxAppTotalTxnReferences,
	}
	for i := range perTxnResources {
		globalResources.MaxAccounts += perTxnResources[i].MaxAccounts
		globalResources.MaxAssets += perTxnResources[i].MaxAssets
		globalResources.MaxApps += perTxnResources[i].MaxApps
		globalResources.MaxBoxes += perTxnResources[i].MaxBoxes
		globalResources.MaxTotalRefs += perTxnResources[i].MaxTotalRefs
	}
	return globalResources
}

func (a *ResourceTracker) removePrivateFields() {
	a.maxWriteBudget = 0
}

// HasResources returns true if the tracker has any resources.
func (a *ResourceTracker) HasResources() bool {
	return len(a.Accounts) != 0 || len(a.Assets) != 0 || len(a.Apps) != 0 || len(a.Boxes) != 0 || len(a.AssetHoldings) != 0 || len(a.AppLocals) != 0
}

func (a *ResourceTracker) hasAccount(addr basics.Address, ep *logic.EvalParams, programVersion uint64) bool {
	// nil map lookup is ok
	_, ok := a.Accounts[addr]
	if ok {
		return true
	}
	if programVersion >= 7 { // appAddressAvailableVersion
		for app := range a.Apps {
			if ep.GetApplicationAddress(app) == addr {
				return true
			}
		}
	}
	return false
}

func (a *ResourceTracker) addAccount(addr basics.Address) bool {
	if len(a.Accounts) >= a.MaxAccounts || len(a.Accounts)+len(a.Assets)+len(a.Apps)+len(a.Boxes)+a.NumEmptyBoxRefs >= a.MaxTotalRefs {
		return false
	}
	if a.Accounts == nil {
		a.Accounts = make(map[basics.Address]struct{})
	}
	a.Accounts[addr] = struct{}{}
	return true
}

func (a *ResourceTracker) removeAccountSlot() bool {
	if len(a.Accounts) >= a.MaxAccounts || len(a.Accounts)+len(a.Assets)+len(a.Apps)+len(a.Boxes)+a.NumEmptyBoxRefs >= a.MaxTotalRefs {
		return false
	}
	a.MaxAccounts--
	a.MaxTotalRefs--
	return true
}

func (a *ResourceTracker) hasAsset(aid basics.AssetIndex) bool {
	// nil map lookup is ok
	_, ok := a.Assets[aid]
	return ok
}

func (a *ResourceTracker) addAsset(aid basics.AssetIndex) bool {
	if len(a.Assets) >= a.MaxAssets || len(a.Accounts)+len(a.Assets)+len(a.Apps)+len(a.Boxes)+a.NumEmptyBoxRefs >= a.MaxTotalRefs {
		return false
	}
	if a.Assets == nil {
		a.Assets = make(map[basics.AssetIndex]struct{})
	}
	a.Assets[aid] = struct{}{}
	return true
}

func (a *ResourceTracker) removeAssetSlot() bool {
	if len(a.Assets) >= a.MaxAssets || len(a.Accounts)+len(a.Assets)+len(a.Apps)+len(a.Boxes)+a.NumEmptyBoxRefs >= a.MaxTotalRefs {
		return false
	}
	a.MaxAssets--
	a.MaxTotalRefs--
	return true
}

func (a *ResourceTracker) hasApp(aid basics.AppIndex) bool {
	// nil map lookup is ok
	_, ok := a.Apps[aid]
	return ok
}

func (a *ResourceTracker) addApp(aid basics.AppIndex, ep *logic.EvalParams, programVersion uint64) bool {
	if len(a.Apps) >= a.MaxApps {
		return false
	}

	if programVersion >= 7 { // appAddressAvailableVersion
		appAddr := ep.GetApplicationAddress(aid)
		// nil map lookup is ok
		_, ok := a.Accounts[appAddr]
		if ok {
			// remove the account reference, since it will be made available by this app reference
			delete(a.Accounts, appAddr)
			if len(a.Accounts) == 0 {
				a.Accounts = nil
			}
		}
	}

	if len(a.Accounts)+len(a.Assets)+len(a.Apps)+len(a.Boxes)+a.NumEmptyBoxRefs >= a.MaxTotalRefs {
		return false
	}
	if a.Apps == nil {
		a.Apps = make(map[basics.AppIndex]struct{})
	}
	a.Apps[aid] = struct{}{}
	return true
}

func (a *ResourceTracker) removeAppSlot() bool {
	if len(a.Apps) >= a.MaxApps || len(a.Accounts)+len(a.Assets)+len(a.Apps)+len(a.Boxes)+a.NumEmptyBoxRefs >= a.MaxTotalRefs {
		return false
	}
	a.MaxApps--
	a.MaxTotalRefs--
	if a.MaxAccounts > 0 {
		a.MaxAccounts--
	}
	return true
}

func (a *ResourceTracker) hasBox(app basics.AppIndex, name string) bool {
	// nil map lookup is ok
	_, ok := a.Boxes[logic.BoxRef{App: app, Name: name}]
	return ok
}

func (a *ResourceTracker) addBox(app basics.AppIndex, name string, readSize, additionalReadBudget, bytesPerBoxRef uint64) bool {
	usedReadBudget := basics.AddSaturate(a.usedBoxReadBudget(), readSize)
	// Adding bytesPerBoxRef to account for the new IO budget from adding an additional box ref
	readBudget := additionalReadBudget + a.boxIOBudget(bytesPerBoxRef) + bytesPerBoxRef

	var emptyRefs int
	if usedReadBudget > readBudget {
		// We need to allocate more empty box refs to increase the read budget
		neededBudget := usedReadBudget - readBudget
		emptyRefsU64 := basics.DivCeil(neededBudget, bytesPerBoxRef)
		if emptyRefsU64 > math.MaxInt {
			// This should never happen, but if we overflow an int with the number of extra pages
			// needed, we can't support this request.
			return false
		}
		emptyRefs = int(emptyRefsU64)
	} else if a.NumEmptyBoxRefs != 0 {
		surplusBudget := readBudget - usedReadBudget
		if surplusBudget >= bytesPerBoxRef && readBudget-bytesPerBoxRef >= a.maxWriteBudget {
			// If we already have enough read budget, remove one empty ref to be replaced by the new
			// named box ref.
			emptyRefs = -1
		}
	}

	if emptyRefs >= a.MaxBoxes-len(a.Boxes)-a.NumEmptyBoxRefs || emptyRefs >= a.MaxTotalRefs-len(a.Accounts)-len(a.Assets)-len(a.Apps)-len(a.Boxes)-a.NumEmptyBoxRefs {
		return false
	}
	if a.Boxes == nil {
		a.Boxes = make(map[logic.BoxRef]uint64)
	}
	a.Boxes[logic.BoxRef{App: app, Name: name}] = readSize
	a.NumEmptyBoxRefs += emptyRefs
	return true
}

func (a *ResourceTracker) addEmptyBoxRefsForWriteBudget(usedWriteBudget, additionalWriteBudget, bytesPerBoxRef uint64) bool {
	writeBudget := additionalWriteBudget + a.boxIOBudget(bytesPerBoxRef)
	if usedWriteBudget > writeBudget {
		// Need to allocate more empty box refs
		overspend := usedWriteBudget - writeBudget
		extraRefsU64 := basics.DivCeil(overspend, bytesPerBoxRef)
		if extraRefsU64 > math.MaxInt {
			// This should never happen, but if we overflow an int with the number of extra pages
			// needed, we can't support this request.
			return false
		}
		extraRefs := int(extraRefsU64)
		if extraRefs > a.MaxBoxes-len(a.Boxes)-a.NumEmptyBoxRefs || extraRefs > a.MaxTotalRefs-len(a.Accounts)-len(a.Assets)-len(a.Apps)-len(a.Boxes)-a.NumEmptyBoxRefs {
			return false
		}
		a.NumEmptyBoxRefs += extraRefs
	}
	if a.maxWriteBudget < usedWriteBudget {
		a.maxWriteBudget = usedWriteBudget
	}
	return true
}

func (a *ResourceTracker) boxIOBudget(bytesPerBoxRef uint64) uint64 {
	return uint64(len(a.Boxes)+a.NumEmptyBoxRefs) * bytesPerBoxRef
}

func (a *ResourceTracker) usedBoxReadBudget() uint64 {
	var budget uint64
	for _, readSize := range a.Boxes {
		budget += readSize
	}
	return budget
}

func (a *ResourceTracker) maxPossibleUnnamedBoxes() int {
	numBoxes := a.MaxTotalRefs - len(a.Accounts) - len(a.Assets) - len(a.Apps)
	if a.MaxBoxes < numBoxes {
		numBoxes = a.MaxBoxes
	}
	return numBoxes
}

func (a *ResourceTracker) hasHolding(addr basics.Address, aid basics.AssetIndex) bool {
	// nil map lookup is ok
	_, ok := a.AssetHoldings[ledgercore.AccountAsset{Address: addr, Asset: aid}]
	return ok
}

func (a *ResourceTracker) addHolding(addr basics.Address, aid basics.AssetIndex) bool {
	if len(a.AssetHoldings)+len(a.AppLocals) >= a.MaxCrossProductReferences {
		return false
	}
	if a.AssetHoldings == nil {
		a.AssetHoldings = make(map[ledgercore.AccountAsset]struct{})
	}
	a.AssetHoldings[ledgercore.AccountAsset{Address: addr, Asset: aid}] = struct{}{}
	return true
}

func (a *ResourceTracker) hasLocal(addr basics.Address, aid basics.AppIndex, ep *logic.EvalParams) bool {
	if ep.GetApplicationAddress(aid) == addr {
		// The app local of an app and its own account is always available, so don't bother recording it.
		return true
	}
	// nil map lookup is ok
	_, ok := a.AppLocals[ledgercore.AccountApp{Address: addr, App: aid}]
	return ok
}

func (a *ResourceTracker) addLocal(addr basics.Address, aid basics.AppIndex) bool {
	if len(a.AssetHoldings)+len(a.AppLocals) >= a.MaxCrossProductReferences {
		return false
	}
	if a.AppLocals == nil {
		a.AppLocals = make(map[ledgercore.AccountApp]struct{})
	}
	a.AppLocals[ledgercore.AccountApp{Address: addr, App: aid}] = struct{}{}
	return true
}

// groupResourceTracker calculates the additional resources that a transaction group could use,
// and it tracks any referenced unnamed resources that fit within those limits.
type groupResourceTracker struct {
	// globalResources specifies global resources for the entire group.
	globalResources ResourceTracker

	// localTxnResources specifies local resources for each transaction in the group. This will only
	// be populated if a top-level transaction executes AVM programs prior to v9 (when resource
	// sharing was added).
	localTxnResources []ResourceTracker

	startingBoxes int
}

func makeGroupResourceTracker(txns []transactions.SignedTxnWithAD, proto *config.ConsensusParams) groupResourceTracker {
	var startingBoxes int
	var nonAppCalls int
	localTxnResources := make([]ResourceTracker, len(txns))
	for i := range txns {
		localTxnResources[i] = makeTxnResourceTracker(&txns[i].Txn, proto)
		startingBoxes += len(txns[i].Txn.Boxes)
		if txns[i].Txn.Type != protocol.ApplicationCallTx {
			nonAppCalls++
		}
	}
	return groupResourceTracker{
		globalResources:   makeGlobalResourceTracker(localTxnResources, nonAppCalls, proto),
		localTxnResources: localTxnResources,
		startingBoxes:     startingBoxes,
	}
}

func (a *groupResourceTracker) hasAccount(addr basics.Address, ep *logic.EvalParams, programVersion uint64, globalSharing bool, gi int) bool {
	if globalSharing {
		for i := range a.localTxnResources {
			if a.localTxnResources[i].hasAccount(addr, ep, programVersion) {
				return true
			}
		}
		return a.globalResources.hasAccount(addr, ep, programVersion)
	}
	return a.localTxnResources[gi].hasAccount(addr, ep, programVersion)
}

func (a *groupResourceTracker) addAccount(addr basics.Address, globalSharing bool, gi int) bool {
	if globalSharing {
		return a.globalResources.addAccount(addr)
	}
	if !a.localTxnResources[gi].addAccount(addr) {
		return false
	}
	if a.globalResources.hasAccount(addr, nil, 0) {
		// It's redundant to list a resources in both the global and local tracker, so remove it
		// from global. The below call to a.globalResources.removeAccountSlot() will revert the
		// changes to a.globalResources.MaxAccounts and a.globalResources.MaxTotalRefs.
		delete(a.globalResources.Accounts, addr)
		a.globalResources.MaxAccounts++
		a.globalResources.MaxTotalRefs++
	}
	// This ensures that the global tracker reduces in size if a resource is assigned locally.
	if a.globalResources.removeAccountSlot() {
		return true
	}
	// Undo the local assignment if global is full.
	delete(a.localTxnResources[gi].Accounts, addr)
	return false
}

func (a *groupResourceTracker) hasAsset(aid basics.AssetIndex, globalSharing bool, gi int) bool {
	if globalSharing {
		for i := range a.localTxnResources {
			if a.localTxnResources[i].hasAsset(aid) {
				return true
			}
		}
		return a.globalResources.hasAsset(aid)
	}
	return a.localTxnResources[gi].hasAsset(aid)
}

func (a *groupResourceTracker) addAsset(aid basics.AssetIndex, globalSharing bool, gi int) bool {
	if globalSharing {
		return a.globalResources.addAsset(aid)
	}
	if !a.localTxnResources[gi].addAsset(aid) {
		return false
	}
	if a.globalResources.hasAsset(aid) {
		// It's redundant to list a resources in both the global and local tracker, so remove it
		// from global. The below call to a.globalResources.removeAssetSlot() will revert the
		// changes to a.globalResources.MaxAssets and a.globalResources.MaxTotalRefs.
		delete(a.globalResources.Assets, aid)
		a.globalResources.MaxAssets++
		a.globalResources.MaxTotalRefs++
	}
	// This ensures that the global tracker reduces in size if a resource is assigned locally.
	if a.globalResources.removeAssetSlot() {
		return true
	}
	// Undo the local assignment if global is full.
	delete(a.localTxnResources[gi].Assets, aid)
	return false
}

func (a *groupResourceTracker) hasApp(aid basics.AppIndex, globalSharing bool, gi int) bool {
	if globalSharing {
		for i := range a.localTxnResources {
			if a.localTxnResources[i].hasApp(aid) {
				return true
			}
		}
		return a.globalResources.hasApp(aid)
	}
	return a.localTxnResources[gi].hasApp(aid)
}

func (a *groupResourceTracker) addApp(aid basics.AppIndex, ep *logic.EvalParams, programVersion uint64, globalSharing bool, gi int) bool {
	if globalSharing {
		return a.globalResources.addApp(aid, ep, programVersion)
	}
	if !a.localTxnResources[gi].addApp(aid, ep, programVersion) {
		return false
	}
	if a.globalResources.hasApp(aid) {
		// It's redundant to list a resources in both the global and local tracker, so remove it
		// from global. The below call to a.globalResources.removeAppSlot() will revert the changes
		// to a.globalResources.MaxApps and a.globalResources.MaxTotalRefs.
		delete(a.globalResources.Apps, aid)
		a.globalResources.MaxApps++
		a.globalResources.MaxTotalRefs++
	}
	// This ensures that the global tracker reduces in size if a resource is assigned locally.
	if a.globalResources.removeAppSlot() {
		return true
	}
	// Undo the local assignment if global is full.
	delete(a.localTxnResources[gi].Apps, aid)
	return false
}

func (a *groupResourceTracker) hasBox(app basics.AppIndex, name string) bool {
	// All boxes are global, never consult localTxnResources
	return a.globalResources.hasBox(app, name)
}

func (a *groupResourceTracker) addBox(app basics.AppIndex, name string, readSize, additionalReadBudget, bytesPerBoxRef uint64) bool {
	// All boxes are global, never consult localTxnResources
	return a.globalResources.addBox(app, name, readSize, additionalReadBudget, bytesPerBoxRef)
}

func (a *groupResourceTracker) reconcileBoxWriteBudget(used uint64, bytesPerBoxRef uint64) error {
	if !a.globalResources.addEmptyBoxRefsForWriteBudget(used, uint64(a.startingBoxes)*bytesPerBoxRef, bytesPerBoxRef) {
		return fmt.Errorf("cannot add extra box refs to satisfy write budget of %d bytes", used)
	}
	return nil
}

func (a *groupResourceTracker) maxPossibleBoxIOBudget(bytesPerBoxRef uint64) uint64 {
	return basics.MulSaturate(
		uint64(a.startingBoxes+a.globalResources.maxPossibleUnnamedBoxes()),
		bytesPerBoxRef,
	)
}

func (a *groupResourceTracker) hasHolding(addr basics.Address, aid basics.AssetIndex) bool {
	// All cross-products are global, never consult localTxnResources
	return a.globalResources.hasHolding(addr, aid)
}

func (a *groupResourceTracker) addHolding(addr basics.Address, aid basics.AssetIndex) bool {
	// All cross-products are global, never consult localTxnResources
	return a.globalResources.addHolding(addr, aid)
}

func (a *groupResourceTracker) hasLocal(addr basics.Address, aid basics.AppIndex, ep *logic.EvalParams) bool {
	// All cross-products are global, never consult localTxnResources
	return a.globalResources.hasLocal(addr, aid, ep)
}

func (a *groupResourceTracker) addLocal(addr basics.Address, aid basics.AppIndex) bool {
	// All cross-products are global, never consult localTxnResources
	return a.globalResources.addLocal(addr, aid)
}

type resourcePolicy struct {
	tracker                     groupResourceTracker
	ep                          *logic.EvalParams
	initialBoxSurplusReadBudget *uint64

	txnRootIndex   int
	programVersion uint64
	globalSharing  bool
}

func newResourcePolicy(ep *logic.EvalParams, groupResult *TxnGroupResult) *resourcePolicy {
	policy := resourcePolicy{
		tracker: makeGroupResourceTracker(ep.TxnGroup, ep.Proto),
		ep:      ep,
	}
	groupResult.UnnamedResourcesAccessed = &policy.tracker.globalResources
	for i := range groupResult.Txns {
		groupResult.Txns[i].UnnamedResourcesAccessed = &policy.tracker.localTxnResources[i]
	}
	return &policy
}

func (p *resourcePolicy) AvailableAccount(addr basics.Address) bool {
	if p.tracker.hasAccount(addr, p.ep, p.programVersion, p.globalSharing, p.txnRootIndex) {
		return true
	}
	return p.tracker.addAccount(addr, p.globalSharing, p.txnRootIndex)
}

func (p *resourcePolicy) AvailableAsset(aid basics.AssetIndex) bool {
	if p.tracker.hasAsset(aid, p.globalSharing, p.txnRootIndex) {
		return true
	}
	return p.tracker.addAsset(aid, p.globalSharing, p.txnRootIndex)
}

func (p *resourcePolicy) AvailableApp(aid basics.AppIndex) bool {
	if p.tracker.hasApp(aid, p.globalSharing, p.txnRootIndex) {
		return true
	}
	return p.tracker.addApp(aid, p.ep, p.programVersion, p.globalSharing, p.txnRootIndex)
}

func (p *resourcePolicy) AllowsHolding(addr basics.Address, aid basics.AssetIndex) bool {
	// holdings are only checked if globalSharing is true
	if p.tracker.hasHolding(addr, aid) {
		return true
	}
	return p.tracker.addHolding(addr, aid)
}

func (p *resourcePolicy) AllowsLocal(addr basics.Address, aid basics.AppIndex) bool {
	// locals are only checked if globalSharing is true
	if p.tracker.hasLocal(addr, aid, p.ep) {
		return true
	}
	return p.tracker.addLocal(addr, aid)
}

func (p *resourcePolicy) AvailableBox(app basics.AppIndex, name string, operation logic.BoxOperation, createSize uint64) bool {
	if p.tracker.hasBox(app, name) {
		// We actually never expect this to happen, since the EvalContext remembers each box in
		// order to track their dirty bytes, and it won't invoke this method if it's already seen
		// the box.
		return true
	}
	box, ok, err := p.ep.Ledger.GetBox(app, name)
	if err != nil {
		panic(err.Error())
	}
	var readSize uint64
	if ok {
		readSize = uint64(len(box))
	}
	return p.tracker.addBox(app, name, readSize, *p.initialBoxSurplusReadBudget, p.ep.Proto.BytesPerBoxReference)
}

// txnResources tracks the resources being added to a transaction during resource population
type txnResources struct {
	// The prefilled resources are resources that were given in the txn group and thus cannot be removed
	// The assumption is that these are prefilled because of one of the following reasons:
	//   - This transaction has already been signed
	//   - One of the foreign resources is accessed on-chain
	prefilledAssets   []basics.AssetIndex
	prefilledApps     []basics.AppIndex
	prefilledAccounts []basics.Address
	prefilledBoxes    []logic.BoxRef

	// The following fields are resources that are available to the transaction group because they were used in a transaction field (like `Sender`) rather than a foreign array.
	assetFromField     basics.AssetIndex
	appFromField       basics.AppIndex
	accountsFromFields map[basics.Address]struct{}

	// These are the fields currently being populated, thus we can mutate them however we'd like
	assets   []basics.AssetIndex
	apps     []basics.AppIndex
	boxes    []logic.BoxRef
	accounts []basics.Address

	maxTotalRefs int
	maxAccounts  int
	maxBoxes     int
	maxApps      int
	maxAssets    int
}

func (r *txnResources) getTotalRefs() int {
	return len(r.accounts) + len(r.assets) + len(r.apps) + len(r.boxes) + len(r.prefilledAccounts) + len(r.prefilledAssets) + len(r.prefilledApps) + len(r.prefilledBoxes)
}

// Methods for determining room for specific references

func (r *txnResources) hasRoom(numRefs int) bool {
	return r.getTotalRefs() < r.maxTotalRefs-numRefs+1
}

func (r *txnResources) hasRoomForApp() bool {
	return r.hasRoom(1) && (len(r.apps)+len(r.prefilledApps)) < r.maxApps
}

func (r *txnResources) hasRoomForAsset() bool {
	return r.hasRoom(1) && (len(r.assets)+len(r.prefilledAssets)) < r.maxAssets
}

func (r *txnResources) hasRoomForBox() bool {
	return r.hasRoom(1) && (len(r.boxes)+len(r.prefilledBoxes)) < r.maxBoxes
}

func (r *txnResources) hasRoomForAccount() bool {
	return r.hasRoom(1) && (len(r.accounts)+len(r.prefilledAccounts)) < r.maxAccounts
}

func (r *txnResources) hasRoomForHolding() bool {
	return r.hasRoom(2) && r.hasRoomForAccount() && r.hasRoomForAsset()
}

func (r *txnResources) hasRoomForAppLocal() bool {
	return r.hasRoom(2) && r.hasRoomForAccount() && r.hasRoomForApp()
}

func (r *txnResources) hasRoomForBoxWithApp() bool {
	return r.hasRoom(2) && r.hasRoomForBox() && r.hasRoomForApp()
}

// Methods for determining if a resource is available

func (r *txnResources) hasApp(app basics.AppIndex) bool {
	if r.appFromField == app {
		return true
	}

	if slices.Contains(slices.Concat(r.prefilledApps, r.apps), app) {
		return true
	}
	return false
}

func (r *txnResources) hasAsset(aid basics.AssetIndex) bool {
	if slices.Contains(slices.Concat(r.prefilledAssets, r.assets), aid) {
		return true
	}
	return r.assetFromField == aid
}

func (r *txnResources) hasAccount(addr basics.Address) bool {
	if r.appFromField.Address() == addr {
		return true
	}

	for _, app := range r.apps {
		if app.Address() == addr {
			return true
		}
	}

	for _, app := range r.prefilledApps {
		if app.Address() == addr {
			return true
		}
	}

	if _, hasField := r.accountsFromFields[addr]; hasField {
		return true
	}

	if slices.Contains(slices.Concat(r.prefilledAccounts, r.accounts), addr) {
		return true
	}

	return false
}

func (r *txnResources) addAccount(addr basics.Address) error {
	// The resource tracker *should* not have duplicates like this, but we check here just to be safe
	if r.hasAccount(addr) {
		return nil
	}

	if !r.hasRoomForAccount() {
		return fmt.Errorf("no room for account: %s", addr.String())
	}

	r.accounts = append(r.accounts, addr)
	return nil
}

func (r *txnResources) addAsset(aid basics.AssetIndex) error {
	// The resource tracker *should* not have duplicates like this, but we check here just to be safe
	if r.hasAsset(aid) {
		return nil
	}

	if !r.hasRoomForAsset() {
		return fmt.Errorf("no room for asset: %d", aid)
	}
	r.assets = append(r.assets, aid)
	return nil
}

func (r *txnResources) addApp(aid basics.AppIndex) error {
	// The resource tracker *should* not have duplicates like this, but we check here just to be safe
	if r.hasApp(aid) {
		return nil
	}

	if !r.hasRoomForApp() {
		return fmt.Errorf("no room for app: %d", aid)
	}
	r.apps = append(r.apps, aid)
	return nil
}

// addBox adds a box to the box array. It does NOT add the app to the app array.
func (r *txnResources) addBox(app basics.AppIndex, name string) error {
	if !r.hasRoomForBox() {
		return fmt.Errorf("no room for box %d : %s", app, name)
	}
	r.boxes = append(r.boxes, logic.BoxRef{App: app, Name: name})
	return nil
}

// addBoxWithApp adds a box to the box array. It also adds the app to the app array.
func (r *txnResources) addBoxWithApp(app basics.AppIndex, name string) error {
	if !r.hasRoomForBoxWithApp() {
		return fmt.Errorf("no room for box %d : %s", app, name)
	}
	r.boxes = append(r.boxes, logic.BoxRef{App: app, Name: name})
	r.apps = append(r.apps, app)
	return nil
}

func (r *txnResources) addAppLocal(app basics.AppIndex, addr basics.Address) error {
	if !r.hasRoomForAppLocal() {
		return fmt.Errorf("no room for app local %d : %s", app, addr.String())
	}

	r.apps = append(r.apps, app)
	r.accounts = append(r.accounts, addr)
	return nil
}

func (r *txnResources) addAssetHolding(addr basics.Address, aid basics.AssetIndex) error {
	if !r.hasRoomForHolding() {
		return fmt.Errorf("no room for asset holding %d : %s", aid, addr.String())
	}

	r.accounts = append(r.accounts, addr)
	r.assets = append(r.assets, aid)
	return nil
}

func (r *txnResources) addAddressFromField(addr basics.Address) {
	if !addr.IsZero() {
		r.accountsFromFields[addr] = struct{}{}
	}
}

// PopulatedResourceArrays is a struct that contains all the populated arrays for a txn
type PopulatedResourceArrays struct {
	Accounts []basics.Address
	Assets   []basics.AssetIndex
	Apps     []basics.AppIndex
	Boxes    []logic.BoxRef
}

func (r *txnResources) getPopulatedArrays() PopulatedResourceArrays {
	return PopulatedResourceArrays{
		Accounts: slices.Concat(r.prefilledAccounts, r.accounts),
		Assets:   slices.Concat(r.prefilledAssets, r.assets),
		Apps:     slices.Concat(r.prefilledApps, r.apps),
		Boxes:    slices.Concat(r.prefilledBoxes, r.boxes),
	}
}

// resourcePopulator is used to populate app resources for a transaction group
type resourcePopulator struct {
	txnResources   map[int]*txnResources
	appCallIndexes []int
	groupSize      int
}

func (p *resourcePopulator) addTransaction(txn transactions.Transaction, groupIndex int, consensusParams config.ConsensusParams) {
	p.txnResources[groupIndex] = &txnResources{
		prefilledAssets:    []basics.AssetIndex{},
		prefilledApps:      []basics.AppIndex{},
		prefilledAccounts:  []basics.Address{},
		prefilledBoxes:     []logic.BoxRef{},
		accountsFromFields: make(map[basics.Address]struct{}),

		assets:       []basics.AssetIndex{},
		apps:         []basics.AppIndex{},
		accounts:     []basics.Address{},
		boxes:        []logic.BoxRef{},
		maxTotalRefs: consensusParams.MaxAppTotalTxnReferences,
		maxAccounts:  consensusParams.MaxAppTxnAccounts,
		maxBoxes:     consensusParams.MaxAppBoxReferences,
		maxApps:      consensusParams.MaxAppTxnForeignApps,
		maxAssets:    consensusParams.MaxAppTxnForeignAssets,
	}

	// The Sender will always be implicitly available for every transaction type
	p.txnResources[groupIndex].addAddressFromField(txn.Sender)

	switch txn.Type {
	case protocol.ApplicationCallTx:
		for _, asset := range txn.ForeignAssets {
			p.txnResources[groupIndex].prefilledAssets = append(p.txnResources[groupIndex].prefilledAssets, asset)

		}

		for _, app := range txn.ForeignApps {
			p.txnResources[groupIndex].prefilledApps = append(p.txnResources[groupIndex].prefilledApps, app)
		}

		for _, account := range txn.Accounts {
			p.txnResources[groupIndex].prefilledAccounts = append(p.txnResources[groupIndex].prefilledAccounts, account)
		}

		for _, box := range txn.Boxes {
			ref := logic.BoxRef{App: txn.ForeignApps[box.Index], Name: string(box.Name)}
			p.txnResources[groupIndex].prefilledBoxes = append(p.txnResources[groupIndex].prefilledBoxes, ref)
		}

		p.txnResources[groupIndex].appFromField = txn.ApplicationID

	case protocol.AssetTransferTx:
		p.txnResources[groupIndex].assetFromField = txn.XferAsset
		p.txnResources[groupIndex].addAddressFromField(txn.AssetReceiver)
		p.txnResources[groupIndex].addAddressFromField(txn.AssetCloseTo)
		p.txnResources[groupIndex].addAddressFromField(txn.AssetSender)

	case protocol.PaymentTx:
		p.txnResources[groupIndex].addAddressFromField(txn.Receiver)
		p.txnResources[groupIndex].addAddressFromField(txn.CloseRemainderTo)

	case protocol.AssetConfigTx:
		p.txnResources[groupIndex].assetFromField = txn.ConfigAsset

	case protocol.AssetFreezeTx:
		p.txnResources[groupIndex].assetFromField = txn.FreezeAsset
		p.txnResources[groupIndex].addAddressFromField(txn.FreezeAccount)
	}
}

func (p *resourcePopulator) addAccount(addr basics.Address) error {
	var err error

	// If another txn has the account, do nothing
	// This should never happen because the logic in EvalContext should
	// prevent duplicate resources in the tracker, but we check here just to be safe
	for _, txn := range p.txnResources {
		if txn.hasAccount(addr) {
			return nil
		}
	}

	for _, i := range p.appCallIndexes {
		err = p.txnResources[i].addAccount(addr)
		if err == nil {
			return nil
		}
	}

	return err
}

func (p *resourcePopulator) addAsset(asset basics.AssetIndex) error {
	var err error

	// If another txn has the asset, do nothing
	// This should never happen because the logic in EvalContext should
	// prevent duplicate resources in the tracker, but we check here just to be safe
	for _, txn := range p.txnResources {
		if txn.hasAsset(asset) {
			return nil
		}
	}

	for _, i := range p.appCallIndexes {
		err = p.txnResources[i].addAsset(asset)
		if err == nil {
			return nil
		}
	}

	return err
}

func (p *resourcePopulator) addApp(app basics.AppIndex) error {
	var err error

	// If another txn has the app, do nothing
	// This should never happen because the logic in EvalContext should
	// prevent duplicate resources in the tracker, but we check here just to be safe
	for _, txn := range p.txnResources {
		if txn.hasApp(app) {
			return nil
		}
	}

	for _, i := range p.appCallIndexes {
		err = p.txnResources[i].addApp(app)
		if err == nil {
			return nil
		}
	}
	return err
}

func (p *resourcePopulator) addBox(app basics.AppIndex, name string) error {
	var err error

	// First try to find txn with app already available
	for _, i := range p.appCallIndexes {
		if app == basics.AppIndex(0) || p.txnResources[i].hasApp(app) {
			err = p.txnResources[i].addBox(app, name)
			if err == nil {
				return nil
			}
		}
	}

	// Then try to find txn with room for both app and box
	for _, i := range p.appCallIndexes {
		err = p.txnResources[i].addBoxWithApp(app, name)
		if err == nil {
			return nil
		}
	}

	return err
}

func (p *resourcePopulator) addHolding(addr basics.Address, aid basics.AssetIndex) error {
	var err error

	// First try to find txn with account already available
	for _, i := range p.appCallIndexes {
		if p.txnResources[i].hasAccount(addr) {
			err = p.txnResources[i].addAsset(aid)
			if err == nil {
				return nil
			}
		}
	}

	// Then try to find txn with asset already available
	for _, i := range p.appCallIndexes {
		if p.txnResources[i].hasAsset(aid) {
			err = p.txnResources[i].addAccount(addr)
			if err == nil {
				return nil
			}
		}
	}

	// Finally try to find txn with room for both account and holding
	for _, i := range p.appCallIndexes {
		err = p.txnResources[i].addAssetHolding(addr, aid)
		if err == nil {
			return nil
		}
	}

	return err
}

func (p *resourcePopulator) addLocal(addr basics.Address, aid basics.AppIndex) error {
	var err error

	// First try to find txn with account already available
	for _, i := range p.appCallIndexes {
		if p.txnResources[i].hasAccount(addr) {
			err = p.txnResources[i].addApp(aid)
			if err == nil {
				return nil
			}
		}
	}

	// Then try to find txn with app already available
	for _, i := range p.appCallIndexes {
		if p.txnResources[i].hasApp(aid) {
			err = p.txnResources[i].addAccount(addr)
			if err == nil {
				return nil
			}
		}
	}

	// Finally try to find txn with room for both account and app
	for _, i := range p.appCallIndexes {
		err = p.txnResources[i].addAppLocal(aid, addr)
		if err == nil {
			return nil
		}
	}

	return err
}

func (p *resourcePopulator) populateResources(groupResourceTracker ResourceTracker, txnResources []ResourceTracker) error {
	// We don't want to mutate the groupResourceTracker because it is used later in simulate for UnnamedResourcesAccessed
	groupResources := struct {
		Assets        []basics.AssetIndex
		Apps          []basics.AppIndex
		Accounts      []basics.Address
		Boxes         []logic.BoxRef
		AssetHoldings []ledgercore.AccountAsset
		AppLocals     []ledgercore.AccountApp
	}{
		Apps:          []basics.AppIndex{},
		Accounts:      []basics.Address{},
		Boxes:         []logic.BoxRef{},
		AssetHoldings: []ledgercore.AccountAsset{},
		AppLocals:     []ledgercore.AccountApp{},
	}

	// Sort assets
	for asset := range groupResourceTracker.Assets {
		groupResources.Assets = append(groupResources.Assets, asset)
	}
	slices.SortFunc(groupResources.Assets, func(a, b basics.AssetIndex) int {
		return cmp.Compare(a, b)
	})

	// Sort apps
	for app := range groupResourceTracker.Apps {
		groupResources.Apps = append(groupResources.Apps, app)
	}
	slices.SortFunc(groupResources.Apps, func(a, b basics.AppIndex) int {
		return cmp.Compare(a, b)
	})

	// Sort accounts
	for account := range groupResourceTracker.Accounts {
		groupResources.Accounts = append(groupResources.Accounts, account)
	}
	slices.SortFunc(groupResources.Accounts, func(a, b basics.Address) int {
		return cmp.Compare(a.GetUserAddress(), b.GetUserAddress())
	})

	// Sort boxes
	// To sort boxes, we turn the app into a string, concat with the name, and then sort
	for box := range groupResourceTracker.Boxes {
		groupResources.Boxes = append(groupResources.Boxes, box)
	}
	slices.SortFunc(groupResources.Boxes, func(a, b logic.BoxRef) int {
		return cmp.Compare(fmt.Sprintf("%d:%s", a.App, a.Name), fmt.Sprintf("%d:%s", b.App, b.Name))
	})

	// Sort assets holdings
	// To sort asset holdings, we turn the asset into a string, concat with the address, and then sort
	for holding := range groupResourceTracker.AssetHoldings {
		groupResources.AssetHoldings = append(groupResources.AssetHoldings, holding)
	}
	slices.SortFunc(groupResources.AssetHoldings, func(a, b ledgercore.AccountAsset) int {
		return cmp.Compare(fmt.Sprintf("%d:%s", a.Asset, a.Address), fmt.Sprintf("%d:%s", b.Asset, b.Address.GetUserAddress()))
	})

	// Sort app locals
	// To sort app locals, we turn the app into a string, concat with the address, and then sort
	for local := range groupResourceTracker.AppLocals {
		groupResources.AppLocals = append(groupResources.AppLocals, local)
	}
	slices.SortFunc(groupResources.AppLocals, func(a, b ledgercore.AccountApp) int {
		return cmp.Compare(fmt.Sprintf("%d:%s", a.App, a.Address), fmt.Sprintf("%d:%s", b.App, b.Address.GetUserAddress()))
	})

	// First populate resources that HAVE to be assigned to a specific transaction
	for i, tracker := range txnResources {
		// Sort assets
		sortedAssets := make([]basics.AssetIndex, 0, len(tracker.Assets))
		for asset := range tracker.Assets {
			sortedAssets = append(sortedAssets, asset)
		}
		slices.SortFunc(sortedAssets, func(a, b basics.AssetIndex) int {
			return cmp.Compare(a, b)
		})

		// Sort apps
		sortedApps := make([]basics.AppIndex, 0, len(tracker.Apps))
		for app := range tracker.Apps {
			sortedApps = append(sortedApps, app)
		}
		slices.SortFunc(sortedApps, func(a, b basics.AppIndex) int {
			return cmp.Compare(a, b)
		})

		// Sort accounts
		sortedAccounts := make([]basics.Address, 0, len(tracker.Accounts))
		for account := range tracker.Accounts {
			sortedAccounts = append(sortedAccounts, account)
		}
		slices.SortFunc(sortedAccounts, func(a, b basics.Address) int {
			return cmp.Compare(a.GetUserAddress(), b.GetUserAddress())
		})

		for _, asset := range sortedAssets {
			err := p.txnResources[i].addAsset(asset)
			if err != nil {
				return err
			}
		}

		for _, app := range sortedApps {
			err := p.txnResources[i].addApp(app)
			if err != nil {
				return err
			}
		}

		for _, account := range sortedAccounts {
			err := p.txnResources[i].addAccount(account)
			if err != nil {
				return err
			}
		}
	}

	// Then assign cross-reference resources because they have the most strict requirements (one account and another resource)
	for _, holding := range groupResources.AssetHoldings {
		err := p.addHolding(holding.Address, holding.Asset)
		if err != nil {
			return err
		}

		// Remove the resources from the global tracker in case they were added separately
		groupResources.Assets = slices.DeleteFunc(groupResources.Assets, func(a basics.AssetIndex) bool {
			return a == holding.Asset
		})
		groupResources.Accounts = slices.DeleteFunc(groupResources.Accounts, func(a basics.Address) bool {
			return a == holding.Address
		})
	}

	for _, local := range groupResources.AppLocals {
		err := p.addLocal(local.Address, local.App)
		if err != nil {
			return err
		}

		// Remove the resources from the global tracker in case they were added separately
		groupResources.Apps = slices.DeleteFunc(groupResources.Apps, func(a basics.AppIndex) bool {
			return a == local.App
		})
		groupResources.Accounts = slices.DeleteFunc(groupResources.Accounts, func(a basics.Address) bool {
			return a == local.Address
		})
	}

	// Then assign boxes because they can take up to two slots
	for _, box := range groupResources.Boxes {
		err := p.addBox(box.App, box.Name)
		if err != nil {
			return err
		}

		// Remove the app from the global tracker in case it was added separately
		groupResources.Apps = slices.DeleteFunc(groupResources.Apps, func(a basics.AppIndex) bool {
			return a == box.App
		})
	}

	// Then assign accounts because they have a lower limit than other resources
	for _, account := range groupResources.Accounts {
		err := p.addAccount(account)
		if err != nil {
			return err
		}
	}

	// Finally assign the remaining resources which just require one slot
	for _, app := range groupResources.Apps {
		err := p.addApp(app)
		if err != nil {
			return err
		}
	}

	for _, asset := range groupResources.Assets {
		err := p.addAsset(asset)
		if err != nil {
			return err
		}
	}

	for i := 0; i < groupResourceTracker.NumEmptyBoxRefs; i++ {
		err := p.addBox(0, "")
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *resourcePopulator) getPopulatedArrays() map[int]PopulatedResourceArrays {
	populatedArrays := map[int]PopulatedResourceArrays{}
	for _, i := range p.appCallIndexes {
		resources := p.txnResources[i]
		if resources == nil {
			continue
		}

		pop := resources.getPopulatedArrays()
		if i >= p.groupSize && len(pop.Accounts)+len(pop.Assets)+len(pop.Apps)+len(pop.Boxes) == 0 {
			break
		}
		populatedArrays[i] = resources.getPopulatedArrays()
	}
	return populatedArrays
}

// makeResourcePopulator creates a ResourcePopulator from a transaction group
func makeResourcePopulator(txnGroup []transactions.SignedTxn, consensusParams config.ConsensusParams) resourcePopulator {
	populator := resourcePopulator{
		txnResources:   map[int]*txnResources{},
		appCallIndexes: []int{},
		groupSize:      len(txnGroup),
	}

	for i, txn := range txnGroup {
		populator.addTransaction(txn.Txn, i, consensusParams)
		if txn.Txn.Type == protocol.ApplicationCallTx {
			populator.appCallIndexes = append(populator.appCallIndexes, i)
		}
	}

	for i := len(txnGroup); i < consensusParams.MaxTxGroupSize; i++ {
		populator.appCallIndexes = append(populator.appCallIndexes, i)
		populator.txnResources[i] = &txnResources{
			prefilledAssets:    []basics.AssetIndex{},
			prefilledApps:      []basics.AppIndex{},
			prefilledAccounts:  []basics.Address{},
			prefilledBoxes:     []logic.BoxRef{},
			accountsFromFields: make(map[basics.Address]struct{}),
			assets:             []basics.AssetIndex{},
			apps:               []basics.AppIndex{},
			accounts:           []basics.Address{},
			boxes:              []logic.BoxRef{},
			maxTotalRefs:       consensusParams.MaxAppTotalTxnReferences,
			maxAccounts:        consensusParams.MaxAppTxnAccounts,
			maxBoxes:           consensusParams.MaxAppBoxReferences,
			maxAssets:          consensusParams.MaxAppTxnForeignAssets,
			maxApps:            consensusParams.MaxAppTxnForeignApps,
		}
	}

	return populator
}
