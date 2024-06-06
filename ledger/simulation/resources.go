// Copyright (C) 2019-2024 Algorand, Inc.
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
	"fmt"
	"math"

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

type TxnResources struct {
	// The static fields are resource arrays that were given in the transaciton group and thus cannot be removed
	// The assumption is that these are prefilled because of one of the following reaons:
	//   - This transaction has already been signed
	//   - One of the foreign arrays is accessed on-chain
	StaticAssets   map[basics.AssetIndex]struct{}
	StaticApps     map[basics.AppIndex]struct{}
	StaticAccounts map[basics.Address]struct{}
	StaticBoxes    []logic.BoxRef

	// The following fields are fields that are implicitly available to the transaction group from transaction fields
	AssetFromField     basics.AssetIndex
	AppFromField       basics.AppIndex
	AccountsFromFields map[basics.Address]struct{}

	// These are the fields currently being populated, thus we can mutate them however we'd like
	Assets   map[basics.AssetIndex]struct{}
	Apps     map[basics.AppIndex]struct{}
	Boxes    []logic.BoxRef
	Accounts map[basics.Address]struct{}

	MaxTotalRefs int
	MaxAccounts  int
}

func (r *TxnResources) getTotalRefs() int {
	return len(r.Accounts) + len(r.Assets) + len(r.Apps) + len(r.Boxes) + len(r.StaticAccounts) + len(r.StaticAssets) + len(r.StaticApps) + len(r.StaticBoxes)
}

// Methods for determining room for specific references

func (r *TxnResources) hasRoom() bool {
	return r.getTotalRefs() < r.MaxTotalRefs
}

func (r *TxnResources) hasRoomForAccount() bool {
	return r.hasRoom() && (len(r.Accounts)+len(r.StaticAccounts)) < r.MaxAccounts
}

func (r *TxnResources) hasRoomForCrossRef() bool {
	return r.hasRoomForAccount() && r.getTotalRefs() < r.MaxTotalRefs-1
}

func (r *TxnResources) hasRoomForBoxWithApp() bool {
	return r.getTotalRefs() < r.MaxTotalRefs-1
}

// Methods for determining if a resource is available

func (r *TxnResources) hasApp(app basics.AppIndex) bool {
	_, hasStatic := r.StaticApps[app]
	_, hasRef := r.Apps[app]
	return r.AppFromField == app || hasStatic || hasRef
}

func (r *TxnResources) hasAsset(aid basics.AssetIndex) bool {
	_, hasStatic := r.StaticAssets[aid]
	_, hasRef := r.Assets[aid]
	return r.AssetFromField == aid || hasStatic || hasRef
}

func (r *TxnResources) hasAccount(addr basics.Address) bool {
	_, hasStatic := r.StaticAccounts[addr]
	_, hasRef := r.Accounts[addr]
	_, hasField := r.AccountsFromFields[addr]

	if r.AppFromField.Address() == addr {
		return true
	}

	for app := range r.Apps {
		if app.Address() == addr {
			return true
		}
	}

	for app := range r.StaticApps {
		if app.Address() == addr {
			return true
		}
	}

	return hasField || hasStatic || hasRef
}

func (r *TxnResources) addAccount(addr basics.Address) {
	r.Accounts[addr] = struct{}{}
}

func (r *TxnResources) addAsset(aid basics.AssetIndex) {
	r.Assets[aid] = struct{}{}
}

func (r *TxnResources) addApp(aid basics.AppIndex) {
	r.Apps[aid] = struct{}{}
}

func (r *TxnResources) addBox(app basics.AppIndex, name string) {
	r.Boxes = append(r.Boxes, logic.BoxRef{App: app, Name: name})
}

func (r *TxnResources) addAddressFromField(addr basics.Address) {
	if !addr.IsZero() {
		r.AccountsFromFields[addr] = struct{}{}
	}
}

type PopulatedArrays struct {
	Accounts []basics.Address
	Assets   []basics.AssetIndex
	Apps     []basics.AppIndex
	Boxes    []logic.BoxRef
}

func (r *TxnResources) getPopulatedArrays() PopulatedArrays {
	accounts := make([]basics.Address, 0, len(r.Accounts)+len(r.StaticAccounts))
	for account := range r.Accounts {
		accounts = append(accounts, account)
	}
	for account := range r.StaticAccounts {
		accounts = append(accounts, account)
	}

	assets := make([]basics.AssetIndex, 0, len(r.Assets)+len(r.StaticAssets))
	for asset := range r.Assets {
		assets = append(assets, asset)
	}
	for asset := range r.StaticAssets {
		assets = append(assets, asset)
	}

	apps := make([]basics.AppIndex, 0, len(r.Apps)+len(r.StaticApps))
	for app := range r.Apps {
		apps = append(apps, app)
	}
	for app := range r.StaticApps {
		apps = append(apps, app)
	}

	boxes := make([]logic.BoxRef, 0, len(r.Boxes)+len(r.StaticBoxes))
	for _, box := range r.Boxes {
		boxes = append(boxes, box)
	}
	for _, box := range r.StaticBoxes {
		boxes = append(boxes, box)
	}

	return PopulatedArrays{
		Accounts: accounts,
		Assets:   assets,
		Apps:     apps,
		Boxes:    boxes,
	}
}

type ResourcePopulator struct {
	TxnResources []TxnResources
}

func (p *ResourcePopulator) addTransaction(txn transactions.Transaction, groupIndex int, consensusParams config.ConsensusParams) {
	p.TxnResources[groupIndex] = TxnResources{
		StaticAssets:       make(map[basics.AssetIndex]struct{}),
		StaticApps:         make(map[basics.AppIndex]struct{}),
		StaticAccounts:     make(map[basics.Address]struct{}),
		StaticBoxes:        []logic.BoxRef{},
		AccountsFromFields: make(map[basics.Address]struct{}),
		Assets:             make(map[basics.AssetIndex]struct{}),
		Apps:               make(map[basics.AppIndex]struct{}),
		Accounts:           make(map[basics.Address]struct{}),
		Boxes:              []logic.BoxRef{},
		MaxTotalRefs:       consensusParams.MaxAppTotalTxnReferences,
		MaxAccounts:        consensusParams.MaxAppTxnAccounts,
	}

	// The Sender and RekeyTo will always be implicitly available for every transaction type
	p.TxnResources[groupIndex].addAddressFromField(txn.Sender)
	p.TxnResources[groupIndex].addAddressFromField(txn.RekeyTo)

	if txn.Type == protocol.ApplicationCallTx {
		for _, asset := range txn.ForeignAssets {
			p.TxnResources[groupIndex].StaticAssets[asset] = struct{}{}
		}

		for _, app := range txn.ForeignApps {
			p.TxnResources[groupIndex].StaticApps[app] = struct{}{}
		}

		for _, account := range txn.Accounts {
			p.TxnResources[groupIndex].StaticAccounts[account] = struct{}{}
		}

		for _, box := range txn.Boxes {
			ref := logic.BoxRef{App: txn.ForeignApps[box.Index], Name: string(box.Name)}
			p.TxnResources[groupIndex].StaticBoxes = append(p.TxnResources[groupIndex].StaticBoxes, ref)
		}

		p.TxnResources[groupIndex].AppFromField = txn.ApplicationID

		return
	}

	if txn.Type == protocol.AssetTransferTx {
		p.TxnResources[groupIndex].AssetFromField = txn.XferAsset
		p.TxnResources[groupIndex].addAddressFromField(txn.AssetReceiver)
		p.TxnResources[groupIndex].addAddressFromField(txn.AssetCloseTo)
		p.TxnResources[groupIndex].addAddressFromField(txn.AssetSender)

		return
	}

	if txn.Type == protocol.PaymentTx {
		p.TxnResources[groupIndex].addAddressFromField(txn.Receiver)
		p.TxnResources[groupIndex].addAddressFromField(txn.CloseRemainderTo)

		return
	}

	if txn.Type == protocol.AssetConfigTx {
		p.TxnResources[groupIndex].AssetFromField = txn.ConfigAsset

		return
	}

	if txn.Type == protocol.AssetFreezeTx {
		p.TxnResources[groupIndex].AssetFromField = txn.FreezeAsset
		p.TxnResources[groupIndex].addAddressFromField(txn.FreezeAccount)

		return
	}
}

func (p *ResourcePopulator) addAccount(addr basics.Address) error {
	for i := range p.TxnResources {
		if p.TxnResources[i].hasRoomForAccount() {
			p.TxnResources[i].addAccount(addr)
			return nil
		}
	}
	return fmt.Errorf("no room for account")
}

func (p *ResourcePopulator) addAsset(asset basics.AssetIndex) error {
	for i := range p.TxnResources {
		if p.TxnResources[i].hasRoom() {
			p.TxnResources[i].addAsset(asset)
			return nil
		}
	}
	return fmt.Errorf("no room for asset")
}

func (p *ResourcePopulator) addApp(app basics.AppIndex) error {
	for i := range p.TxnResources {
		if p.TxnResources[i].hasRoom() {
			p.TxnResources[i].addApp(app)
			return nil
		}
	}
	return fmt.Errorf("no room for app")
}

func (p *ResourcePopulator) addBox(app basics.AppIndex, name string) error {
	// First try to find txn with app already available
	for i := range p.TxnResources {
		if app == basics.AppIndex(0) || p.TxnResources[i].hasApp(app) {
			if p.TxnResources[i].hasRoom() {
				p.TxnResources[i].addBox(app, name)
				return nil
			}
		}
	}

	// Then try to find txn with room for both app and box
	for i := range p.TxnResources {
		if p.TxnResources[i].hasRoomForBoxWithApp() {
			p.TxnResources[i].addApp(app)
			p.TxnResources[i].addBox(app, name)
			return nil
		}
	}

	return fmt.Errorf("no room for box")
}

func (p *ResourcePopulator) addHolding(addr basics.Address, aid basics.AssetIndex) error {
	// First try to find txn with account already available
	for i := range p.TxnResources {
		if p.TxnResources[i].hasAccount(addr) {
			if p.TxnResources[i].hasRoom() {
				p.TxnResources[i].addAsset(aid)
				return nil
			}
		}
	}

	// Then try to find txn with asset already available
	for i := range p.TxnResources {
		if p.TxnResources[i].hasAsset(aid) {
			if p.TxnResources[i].hasRoomForAccount() {
				p.TxnResources[i].addAccount(addr)
				return nil
			}
		}
	}

	// Finally try to find txn with room for both account and holding
	for i := range p.TxnResources {
		if p.TxnResources[i].hasRoomForCrossRef() {
			p.TxnResources[i].addAccount(addr)
			p.TxnResources[i].addAsset(aid)
			return nil
		}
	}
	return fmt.Errorf("no room for holding")
}

func (p *ResourcePopulator) addLocal(addr basics.Address, aid basics.AppIndex) error {
	// First try to find txn with account already available
	for i := range p.TxnResources {
		if p.TxnResources[i].hasAccount(addr) {
			if p.TxnResources[i].hasRoom() {
				p.TxnResources[i].addApp(aid)
				return nil
			}
		}
	}

	// Then try to find txn with app already available
	for i := range p.TxnResources {
		if p.TxnResources[i].hasApp(aid) {
			if p.TxnResources[i].hasRoomForAccount() {
				p.TxnResources[i].addAccount(addr)
				return nil
			}
		}
	}

	// Finally try to find txn with room for both account and app
	for i := range p.TxnResources {
		if p.TxnResources[i].hasRoomForCrossRef() {
			p.TxnResources[i].addApp(aid)
			p.TxnResources[i].addAccount(addr)
			return nil
		}
	}
	return fmt.Errorf("no room for local")
}

func (p *ResourcePopulator) populateResources(groupResourceTracker groupResourceTracker) error {
	// First populate resources that HAVE to be assigned to a specific transaction
	for i, tracker := range groupResourceTracker.localTxnResources {
		for asset := range tracker.Assets {
			p.TxnResources[i].addAsset(asset)
		}

		for app := range tracker.Apps {
			p.TxnResources[i].addApp(app)
		}

		for account := range tracker.Accounts {
			p.TxnResources[i].addAccount(account)
		}
	}

	// Then assign cross-reference resources because they have the most strict requirements (one account and another resource)
	for holding := range groupResourceTracker.globalResources.AssetHoldings {
		err := p.addHolding(holding.Address, holding.Asset)
		if err != nil {
			return err
		}

		// Remove the resources from the global tracker in case they were added seperately
		delete(groupResourceTracker.globalResources.Assets, holding.Asset)
		delete(groupResourceTracker.globalResources.Accounts, holding.Address)
	}

	for local := range groupResourceTracker.globalResources.AppLocals {
		err := p.addLocal(local.Address, local.App)
		if err != nil {
			return err
		}

		// Remove the resources from the global tracker in case they were added seperately
		delete(groupResourceTracker.globalResources.Apps, local.App)
		delete(groupResourceTracker.globalResources.Accounts, local.Address)
	}

	// Then assign boxes because they can take up to two slots
	for box := range groupResourceTracker.globalResources.Boxes {
		err := p.addBox(box.App, box.Name)
		if err != nil {
			return err
		}

		// Remove the app from the global tracker in case it was added seperately
		delete(groupResourceTracker.globalResources.Apps, box.App)
	}

	// Then assign accounts because they have a lower limit than other resources
	for account := range groupResourceTracker.globalResources.Accounts {
		err := p.addAccount(account)
		if err != nil {
			return err
		}
	}

	// Finally assign the remaining resources which just require one slot
	for app := range groupResourceTracker.globalResources.Apps {
		err := p.addApp(app)
		if err != nil {
			return err
		}
	}

	for asset := range groupResourceTracker.globalResources.Assets {
		err := p.addAsset(asset)
		if err != nil {
			return err
		}
	}

	for i := 0; i <= groupResourceTracker.globalResources.NumEmptyBoxRefs; i++ {
		err := p.addBox(0, "")
		if err != nil {
			return err
		}
	}

	return nil
}

func MakeResourcePopulator(txnGroup []transactions.SignedTxnWithAD, consensusParams config.ConsensusParams) ResourcePopulator {
	populator := ResourcePopulator{
		TxnResources: make([]TxnResources, consensusParams.MaxTxGroupSize),
	}

	for i, txn := range txnGroup {
		populator.addTransaction(txn.Txn, i, consensusParams)
	}

	for i := len(txnGroup); i < consensusParams.MaxTxGroupSize; i++ {
		populator.TxnResources[i] = TxnResources{
			StaticAssets:       make(map[basics.AssetIndex]struct{}),
			StaticApps:         make(map[basics.AppIndex]struct{}),
			StaticAccounts:     make(map[basics.Address]struct{}),
			StaticBoxes:        []logic.BoxRef{},
			AccountsFromFields: make(map[basics.Address]struct{}),
			Assets:             make(map[basics.AssetIndex]struct{}),
			Apps:               make(map[basics.AppIndex]struct{}),
			Accounts:           make(map[basics.Address]struct{}),
			Boxes:              []logic.BoxRef{},
			MaxTotalRefs:       consensusParams.MaxAppTotalTxnReferences,
			MaxAccounts:        consensusParams.MaxAppTxnAccounts,
		}
	}

	return populator
}
