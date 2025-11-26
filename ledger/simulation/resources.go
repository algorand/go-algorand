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
	Accounts map[basics.Address]struct{}
	// MaxAccounts is the largest number of new accounts that could possibly be
	// referenced by the thing being tracked (txn or group) beyond what is
	// already listed.
	MaxAccounts int

	Assets map[basics.AssetIndex]struct{}
	// MaxAssets is the largest number of new assets that could possibly be
	// referenced by the thing being tracked (txn or group) beyond what is
	// already listed.
	MaxAssets int

	Apps map[basics.AppIndex]struct{}
	// MaxApps is the largest number of new apps that could possibly be
	// referenced by the thing being tracked (txn or group) beyond what is
	// already listed.
	MaxApps int

	// The map value is the size of the box loaded from the ledger prior to any writes. This is used
	// to track the box read budget.
	Boxes    map[basics.BoxRef]BoxStat
	MaxBoxes int

	// NumEmptyBoxRefs tracks the number of additional BoxRefs that will be
	// required to handle the boxes this tracker has observed (for i/o budget,
	// or to allow access to boxes in new apps).
	NumEmptyBoxRefs int

	// maxWriteBudget is the "high-water mark" for dirty box writes. A group
	// must have enough write budget during its entire execution to accommodate
	// writing its dirty boxes. This is maintained after each opcode.
	maxWriteBudget uint64

	// initialReadSurplus is the I/O surplus available based on the submitted
	// group, so it takes into account the number of box refs supplied, and the
	// size of the boxes named. It can be negative!
	initialReadSurplus int64

	// MaxTotalRefs is the largest number of new refs of any kind that could
	// possibly be added tp the thing being tracked (txn or group) beyond what
	// it began with.
	MaxTotalRefs int

	AssetHoldings             map[ledgercore.AccountAsset]struct{}
	AppLocals                 map[ledgercore.AccountApp]struct{}
	MaxCrossProductReferences int
}

// BoxStat is what needs to be tracked in order to figure out need resources (especially empty refs)
type BoxStat struct {
	ReadSize uint64 // how much read quota did this access consume?
	NewApp   bool   // was the box accessed by an app created in this group?
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

// makeGlobalResourceTracker populates a tracker so that it knows what are the
// bounds on how many new references of various types that could potentially be
// allowed for the group.
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
	a.initialReadSurplus = 0
}

// HasResources returns true if the tracker has any resources.
func (a ResourceTracker) HasResources() bool {
	return len(a.Accounts) != 0 || len(a.Assets) != 0 || len(a.Apps) != 0 || len(a.Boxes) != 0 || len(a.AssetHoldings) != 0 || len(a.AppLocals) != 0 || a.NumEmptyBoxRefs != 0
}

// refCount returns the number of references this tracker has.
func (a ResourceTracker) refCount() int {
	return len(a.Accounts) + len(a.Assets) + len(a.Apps) + a.boxCount()
}

// boxCount returns the number of box references this tracker has.
func (a ResourceTracker) boxCount() int {
	return len(a.Boxes) + a.NumEmptyBoxRefs
}

func (a *ResourceTracker) hasAccount(addr basics.Address, ep *logic.EvalParams, programVersion uint64) bool {
	// nil map lookup is ok
	if _, ok := a.Accounts[addr]; ok {
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
	if len(a.Accounts) >= a.MaxAccounts || a.refCount() >= a.MaxTotalRefs {
		return false
	}
	if a.Accounts == nil {
		a.Accounts = make(map[basics.Address]struct{})
	}
	a.Accounts[addr] = struct{}{}
	return true
}

// removeAccountSlot notes that there is one less account slot available for
// referencing new assets. It's used to tell the global tracker that a local
// slot is used.
func (a *ResourceTracker) removeAccountSlot() bool {
	if len(a.Accounts) >= a.MaxAccounts || a.refCount() >= a.MaxTotalRefs {
		return false
	}
	a.MaxAccounts--
	a.MaxTotalRefs--
	return true
}

func (a ResourceTracker) hasAsset(aid basics.AssetIndex) bool {
	// nil map lookup is ok
	_, ok := a.Assets[aid]
	return ok
}

// addAsset records that an asset reference must be added. It return false if
// that is known to be impossible.
func (a *ResourceTracker) addAsset(aid basics.AssetIndex) bool {
	if len(a.Assets) >= a.MaxAssets || a.refCount() >= a.MaxTotalRefs {
		return false
	}
	if a.Assets == nil {
		a.Assets = make(map[basics.AssetIndex]struct{})
	}
	a.Assets[aid] = struct{}{}
	return true
}

// removeAssetSlot notes that there is one less asset slot available for
// referencing new assets. It's used to tell the global tracker that a local
// slot is used.
func (a *ResourceTracker) removeAssetSlot() bool {
	if len(a.Assets) >= a.MaxAssets || a.refCount() >= a.MaxTotalRefs {
		return false
	}
	a.MaxAssets--
	a.MaxTotalRefs--
	return true
}

func (a ResourceTracker) hasApp(aid basics.AppIndex) bool {
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

	if a.refCount() >= a.MaxTotalRefs {
		return false
	}
	if a.Apps == nil {
		a.Apps = make(map[basics.AppIndex]struct{})
	}
	a.Apps[aid] = struct{}{}
	return true
}

func (a *ResourceTracker) removeAppSlot() bool {
	if len(a.Apps) >= a.MaxApps || a.refCount() >= a.MaxTotalRefs {
		return false
	}
	a.MaxApps--
	a.MaxTotalRefs--
	if a.MaxAccounts > 0 {
		a.MaxAccounts--
	}
	return true
}

func (a ResourceTracker) hasBox(app basics.AppIndex, name string) bool {
	// nil map lookup is ok
	_, ok := a.Boxes[basics.BoxRef{App: app, Name: name}]
	return ok
}

func (a *ResourceTracker) addBox(app basics.AppIndex, name string, newApp bool, readSize uint64, bytesPerBoxRef uint64) bool {
	usedReadBudget := basics.AddSaturate(a.usedBoxReadBudget(), readSize)
	// Adding bytesPerBoxRef to account for the new IO budget from adding an additional box ref
	ioBudget := a.boxIOBudget(bytesPerBoxRef) + bytesPerBoxRef
	if a.initialReadSurplus > 0 {
		ioBudget += uint64(a.initialReadSurplus)
	} else {
		ioBudget -= uint64(-a.initialReadSurplus)
	}

	var emptyRefs int
	if usedReadBudget > ioBudget {
		// We need to allocate more empty box refs to increase the read budget
		neededBudget := usedReadBudget - ioBudget
		emptyRefsU64 := basics.DivCeil(neededBudget, bytesPerBoxRef)
		if emptyRefsU64 > math.MaxInt {
			// This should never happen, but if we overflow an int with the number of extra pages
			// needed, we can't support this request.
			return false
		}
		emptyRefs = int(emptyRefsU64)
	} else if a.NumEmptyBoxRefs > 0 { // If there are empties added for quota, we may not need as many.
		surplusReadBudget := basics.SubSaturate(ioBudget, usedReadBudget)
		surplusWriteBudget := basics.SubSaturate(ioBudget, a.maxWriteBudget)
		if surplusReadBudget >= bytesPerBoxRef && surplusWriteBudget >= bytesPerBoxRef {
			// By adding this box, we may no longer need an empty ref we previously added for quota.
			emptyRefs = -1
		}
	}

	if emptyRefs >= a.MaxBoxes-a.boxCount() || emptyRefs >= a.MaxTotalRefs-a.refCount() {
		return false
	}
	if a.Boxes == nil {
		a.Boxes = make(map[basics.BoxRef]BoxStat)
	}
	a.Boxes[basics.BoxRef{App: app, Name: name}] = BoxStat{readSize, newApp}
	a.NumEmptyBoxRefs += emptyRefs
	return true
}

// ioSurplus notes whether extra bytes can be read because of the initially
// supplied box refs.  If not, it ensures that empty box refs can be added to
// account for the deficit.
func (a *ResourceTracker) ioSurplus(amount int64, bytesPerBoxRef uint64) bool {
	a.initialReadSurplus = amount
	if amount > 0 {
		return true
	}
	neededBudget := uint64(-amount)
	emptyRefsU64 := basics.DivCeil(neededBudget, bytesPerBoxRef)
	if emptyRefsU64 > math.MaxInt {
		// This should never happen, but if we overflow an int with the number of extra pages
		// needed, we can't support this request.
		return false
	}
	emptyRefs := int(emptyRefsU64)
	if emptyRefs >= a.MaxBoxes-a.boxCount() || emptyRefs >= a.MaxTotalRefs-a.refCount() {
		return false
	}
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
		if extraRefs > a.MaxBoxes-a.boxCount() || extraRefs > a.MaxTotalRefs-a.refCount() {
			return false
		}
		a.NumEmptyBoxRefs += extraRefs
	}
	if a.maxWriteBudget < usedWriteBudget {
		a.maxWriteBudget = usedWriteBudget
	}
	return true
}

func (a ResourceTracker) boxIOBudget(bytesPerBoxRef uint64) uint64 {
	return uint64(a.boxCount()) * bytesPerBoxRef
}

func (a *ResourceTracker) usedBoxReadBudget() uint64 {
	var budget uint64
	for _, bs := range a.Boxes {
		budget += bs.ReadSize
	}
	return budget
}

func (a *ResourceTracker) maxPossibleUnnamedBoxes() int {
	return min(a.MaxBoxes, a.MaxTotalRefs-len(a.Accounts)-len(a.Assets)-len(a.Apps))
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

// Simplify makes the ResourceTracker easier to consume for callers.  It avoids
// returning boxes "named" by a newly created app.  Those app IDs would not be
// usable in a later submission. An empty ref can stand in. Once Simplified, the
// tracker should not be used to for further tracking.
func (a *ResourceTracker) Simplify() {
	for name, stat := range a.Boxes {
		if stat.NewApp {
			a.NumEmptyBoxRefs++
			delete(a.Boxes, name)
		}
	}
	if len(a.Boxes) == 0 {
		a.Boxes = nil
	}
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

	// startingBoxes is the total number of box references in the group, as submitted
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

func (a *groupResourceTracker) addBox(app basics.AppIndex, name string, newApp bool, readSize uint64, bytesPerBoxRef uint64) bool {
	// All boxes are global, never consult localTxnResources
	return a.globalResources.addBox(app, name, newApp, readSize, bytesPerBoxRef)
}

func (a *groupResourceTracker) ioSurplus(readSize int64, bytesPerBoxRef uint64) bool {
	// All boxes are global, never consult localTxnResources
	return a.globalResources.ioSurplus(readSize, bytesPerBoxRef)
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
	initialBoxSurplusReadBudget *int64

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

func (p *resourcePolicy) AvailableBox(app basics.AppIndex, name string, newApp bool, createSize uint64) bool {
	if p.tracker.hasBox(app, name) {
		// We never expect this to happen. The EvalContext remembers each box in
		// order to track their dirty bytes, and it won't invoke this method if
		// it's already seen the box.
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

	return p.tracker.addBox(app, name, newApp, readSize, p.ep.Proto.BytesPerBoxReference)
}

func (p *resourcePolicy) IOSurplus(size int64) bool {
	return p.tracker.ioSurplus(size, p.ep.Proto.BytesPerBoxReference)
}
