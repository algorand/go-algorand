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

package simulation

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// ResourceAssignment calculates the additional resources that a transaction or group could use, and
// it tracks any referenced unnamed resources that fit within those limits.
type ResourceAssignment struct {
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
}

func makeTxnResourceAssignment(txn *transactions.Transaction, proto *config.ConsensusParams) ResourceAssignment {
	if txn.Type != protocol.ApplicationCallTx {
		return ResourceAssignment{}
	}
	return ResourceAssignment{
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

func makeGlobalResourceAssignment(perTxnResources []ResourceAssignment, proto *config.ConsensusParams) ResourceAssignment {
	unusedTxns := proto.MaxTxGroupSize - len(perTxnResources)
	globalResources := ResourceAssignment{
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

func (a *ResourceAssignment) removePrivateFields() {
	a.maxWriteBudget = 0
}

// HasResources returns true if the assignment has any resources.
func (a *ResourceAssignment) HasResources() bool {
	return len(a.Accounts) != 0 || len(a.Assets) != 0 || len(a.Apps) != 0 || len(a.Boxes) != 0
}

func (a *ResourceAssignment) hasAccount(addr basics.Address, ep *logic.EvalParams, programVersion uint64) bool {
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

func (a *ResourceAssignment) addAccount(addr basics.Address) bool {
	if len(a.Accounts) >= a.MaxAccounts || len(a.Accounts)+len(a.Assets)+len(a.Apps)+len(a.Boxes)+a.NumEmptyBoxRefs >= a.MaxTotalRefs {
		return false
	}
	if a.Accounts == nil {
		a.Accounts = make(map[basics.Address]struct{})
	}
	a.Accounts[addr] = struct{}{}
	return true
}

func (a *ResourceAssignment) removeAccountSlot() bool {
	if len(a.Accounts) >= a.MaxAccounts || len(a.Accounts)+len(a.Assets)+len(a.Apps)+len(a.Boxes)+a.NumEmptyBoxRefs >= a.MaxTotalRefs {
		return false
	}
	a.MaxAccounts--
	a.MaxTotalRefs--
	return true
}

func (a *ResourceAssignment) hasAsset(aid basics.AssetIndex) bool {
	// nil map lookup is ok
	_, ok := a.Assets[aid]
	return ok
}

func (a *ResourceAssignment) addAsset(aid basics.AssetIndex) bool {
	if len(a.Assets) >= a.MaxAssets || len(a.Accounts)+len(a.Assets)+len(a.Apps)+len(a.Boxes)+a.NumEmptyBoxRefs >= a.MaxTotalRefs {
		return false
	}
	if a.Assets == nil {
		a.Assets = make(map[basics.AssetIndex]struct{})
	}
	a.Assets[aid] = struct{}{}
	return true
}

func (a *ResourceAssignment) removeAssetSlot() bool {
	if len(a.Assets) >= a.MaxAssets || len(a.Accounts)+len(a.Assets)+len(a.Apps)+len(a.Boxes)+a.NumEmptyBoxRefs >= a.MaxTotalRefs {
		return false
	}
	a.MaxAssets--
	a.MaxTotalRefs--
	return true
}

func (a *ResourceAssignment) hasApp(aid basics.AppIndex) bool {
	// nil map lookup is ok
	_, ok := a.Apps[aid]
	return ok
}

func (a *ResourceAssignment) addApp(aid basics.AppIndex, ep *logic.EvalParams, programVersion uint64) bool {
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

func (a *ResourceAssignment) removeAppSlot() bool {
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

func (a *ResourceAssignment) hasBox(app basics.AppIndex, name string) bool {
	// nil map lookup is ok
	_, ok := a.Boxes[logic.BoxRef{App: app, Name: name}]
	return ok
}

func (a *ResourceAssignment) addBox(app basics.AppIndex, name string, readSize, additionalReadBudget, bytesPerBoxRef uint64) bool {
	usedReadBudget := basics.AddSaturate(a.usedBoxReadBudget(), readSize)
	// Adding bytesPerBoxRef to account for the new IO budget from adding an additional box ref
	readBudget := additionalReadBudget + a.boxIOBudget(bytesPerBoxRef) + bytesPerBoxRef

	var emptyRefs int
	if usedReadBudget > readBudget {
		// We need to allocate more empty box refs to increase the read budget
		neededBudget := usedReadBudget - readBudget
		// Adding (bytesPerBoxRef - 1) to round up
		emptyRefs = int((neededBudget + bytesPerBoxRef - 1) / bytesPerBoxRef)
	} else if a.NumEmptyBoxRefs != 0 {
		surplusBudget := readBudget - usedReadBudget
		if surplusBudget >= bytesPerBoxRef && readBudget-bytesPerBoxRef >= a.maxWriteBudget {
			// If we already have enough read budget, remove one empty ref to be replaced by the new
			// named box ref.
			emptyRefs = -1
		}
	}

	if len(a.Boxes)+a.NumEmptyBoxRefs+emptyRefs >= a.MaxBoxes || len(a.Accounts)+len(a.Assets)+len(a.Apps)+len(a.Boxes)+a.NumEmptyBoxRefs+emptyRefs >= a.MaxTotalRefs {
		return false
	}
	if a.Boxes == nil {
		a.Boxes = make(map[logic.BoxRef]uint64)
	}
	a.Boxes[logic.BoxRef{App: app, Name: name}] = readSize
	a.NumEmptyBoxRefs += emptyRefs
	return true
}

func (a *ResourceAssignment) addEmptyBoxRefsForWriteBudget(usedWriteBudget, additionalWriteBudget, bytesPerBoxRef uint64) bool {
	writeBudget := additionalWriteBudget + a.boxIOBudget(bytesPerBoxRef)
	if usedWriteBudget > writeBudget {
		// Need to allocate more empty box refs
		overspend := usedWriteBudget - writeBudget
		extraRefs := int((overspend + bytesPerBoxRef - 1) / bytesPerBoxRef) // adding (bytesPerBoxRef - 1) to round up
		if len(a.Boxes)+a.NumEmptyBoxRefs+extraRefs > a.MaxBoxes || len(a.Accounts)+len(a.Assets)+len(a.Apps)+len(a.Boxes)+a.NumEmptyBoxRefs+extraRefs > a.MaxTotalRefs {
			return false
		}
		a.NumEmptyBoxRefs += extraRefs
	}
	if a.maxWriteBudget < usedWriteBudget {
		a.maxWriteBudget = usedWriteBudget
	}
	return true
}

func (a *ResourceAssignment) boxIOBudget(bytesPerBoxRef uint64) uint64 {
	return uint64(len(a.Boxes)+a.NumEmptyBoxRefs) * bytesPerBoxRef
}

func (a *ResourceAssignment) usedBoxReadBudget() uint64 {
	var budget uint64
	for _, readSize := range a.Boxes {
		budget += readSize
	}
	return budget
}

func (a *ResourceAssignment) maxPossibleUnnamedBoxes() int {
	numBoxes := a.MaxTotalRefs - len(a.Accounts) - len(a.Assets) - len(a.Apps)
	if a.MaxBoxes < numBoxes {
		numBoxes = a.MaxBoxes
	}
	return numBoxes
}

// GroupResourceAssignment calculates the additional resources that a transaction group could use,
// and it tracks any referenced unnamed resources that fit within those limits.
type GroupResourceAssignment struct {
	// Resources specifies global resources for the entire group.
	Resources ResourceAssignment

	AssetHoldings             map[ledgercore.AccountAsset]struct{}
	AppLocals                 map[ledgercore.AccountApp]struct{}
	MaxCrossProductReferences int

	// localTxnResources specifies local resources for each transaction in the group. This will only
	// be populated if a top-level transaction executes AVM programs prior to v9 (when resource
	// sharing was added).
	localTxnResources []ResourceAssignment

	startingBoxes int
}

func makeGroupResourceAssignment(txns []transactions.SignedTxnWithAD, proto *config.ConsensusParams) GroupResourceAssignment {
	var startingBoxes int
	var nonAppCalls int
	localTxnResources := make([]ResourceAssignment, len(txns))
	for i := range txns {
		localTxnResources[i] = makeTxnResourceAssignment(&txns[i].Txn, proto)
		startingBoxes += len(txns[i].Txn.Boxes)
		if txns[i].Txn.Type != protocol.ApplicationCallTx {
			nonAppCalls++
		}
	}
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
	return GroupResourceAssignment{
		Resources:                 makeGlobalResourceAssignment(localTxnResources, proto),
		MaxCrossProductReferences: maxCrossProductsPerAppCall * (proto.MaxTxGroupSize - nonAppCalls),
		localTxnResources:         localTxnResources,
		startingBoxes:             startingBoxes,
	}
}

func (a *GroupResourceAssignment) removePrivateFields() {
	a.startingBoxes = 0
	a.Resources.removePrivateFields()
	for i := range a.localTxnResources {
		a.localTxnResources[i].removePrivateFields()
	}
	a.localTxnResources = nil
}

func (a *GroupResourceAssignment) hasAccount(addr basics.Address, ep *logic.EvalParams, programVersion uint64, globalSharing bool, txnIndex int) bool {
	if globalSharing {
		for i := range a.localTxnResources {
			if a.localTxnResources[i].hasAccount(addr, ep, programVersion) {
				return true
			}
		}
		return a.Resources.hasAccount(addr, ep, programVersion)
	}
	return a.localTxnResources[txnIndex].hasAccount(addr, ep, programVersion)
}

func (a *GroupResourceAssignment) addAccount(addr basics.Address, globalSharing bool, txnIndex int) bool {
	if globalSharing {
		return a.Resources.addAccount(addr)
	}
	if !a.localTxnResources[txnIndex].addAccount(addr) {
		return false
	}
	if a.Resources.hasAccount(addr, nil, 0) {
		// It's redundant to list a resources in both the global and local assignment, so remove it
		// from global. The below call to a.Resources.removeAccountSlot() will revert the changes to
		// a.Resources.MaxAccounts and a.Resources.MaxTotalRefs.
		delete(a.Resources.Accounts, addr)
		a.Resources.MaxAccounts++
		a.Resources.MaxTotalRefs++
	}
	// This ensures that the global assignment reduces in size if a resource is assigned locally.
	if a.Resources.removeAccountSlot() {
		return true
	}
	// Undo the local assignment if global is full.
	delete(a.localTxnResources[txnIndex].Accounts, addr)
	return false
}

func (a *GroupResourceAssignment) hasAsset(aid basics.AssetIndex, globalSharing bool, txnIndex int) bool {
	if globalSharing {
		for i := range a.localTxnResources {
			if a.localTxnResources[i].hasAsset(aid) {
				return true
			}
		}
		return a.Resources.hasAsset(aid)
	}
	return a.localTxnResources[txnIndex].hasAsset(aid)
}

func (a *GroupResourceAssignment) addAsset(aid basics.AssetIndex, globalSharing bool, txnIndex int) bool {
	if globalSharing {
		return a.Resources.addAsset(aid)
	}
	if !a.localTxnResources[txnIndex].addAsset(aid) {
		return false
	}
	if a.Resources.hasAsset(aid) {
		// It's redundant to list a resources in both the global and local assignment, so remove it
		// from global. The below call to a.Resources.removeAssetSlot() will revert the changes to
		// a.Resources.MaxAssets and a.Resources.MaxTotalRefs.
		delete(a.Resources.Assets, aid)
		a.Resources.MaxAssets++
		a.Resources.MaxTotalRefs++
	}
	// This ensures that the global assignment reduces in size if a resource is assigned locally.
	if a.Resources.removeAssetSlot() {
		return true
	}
	// Undo the local assignment if global is full.
	delete(a.localTxnResources[txnIndex].Assets, aid)
	return false
}

func (a *GroupResourceAssignment) hasApp(aid basics.AppIndex, globalSharing bool, txnIndex int) bool {
	if globalSharing {
		for i := range a.localTxnResources {
			if a.localTxnResources[i].hasApp(aid) {
				return true
			}
		}
		return a.Resources.hasApp(aid)
	}
	return a.localTxnResources[txnIndex].hasApp(aid)
}

func (a *GroupResourceAssignment) addApp(aid basics.AppIndex, ep *logic.EvalParams, programVersion uint64, globalSharing bool, txnIndex int) bool {
	if globalSharing {
		return a.Resources.addApp(aid, ep, programVersion)
	}
	if !a.localTxnResources[txnIndex].addApp(aid, ep, programVersion) {
		return false
	}
	if a.Resources.hasApp(aid) {
		// It's redundant to list a resources in both the global and local assignment, so remove it
		// from global. The below call to a.Resources.removeAppSlot() will revert the changes to
		// a.Resources.MaxApps and a.Resources.MaxTotalRefs.
		delete(a.Resources.Apps, aid)
		a.Resources.MaxApps++
		a.Resources.MaxTotalRefs++
	}
	// This ensures that the global assignment reduces in size if a resource is assigned locally.
	if a.Resources.removeAppSlot() {
		return true
	}
	// Undo the local assignment if global is full.
	delete(a.localTxnResources[txnIndex].Apps, aid)
	return false
}

func (a *GroupResourceAssignment) hasBox(app basics.AppIndex, name string) bool {
	// All boxes are global, never consult localTxnResources
	return a.Resources.hasBox(app, name)
}

func (a *GroupResourceAssignment) addBox(app basics.AppIndex, name string, readSize, additionalReadBudget, bytesPerBoxRef uint64) bool {
	// All boxes are global, never consult localTxnResources
	return a.Resources.addBox(app, name, readSize, additionalReadBudget, bytesPerBoxRef)
}

func (a *GroupResourceAssignment) reconcileBoxWriteBudget(used uint64, bytesPerBoxRef uint64) error {
	if !a.Resources.addEmptyBoxRefsForWriteBudget(used, uint64(a.startingBoxes)*bytesPerBoxRef, bytesPerBoxRef) {
		return fmt.Errorf("cannot add extra box refs to satisfy write budget of %d bytes", used)
	}
	return nil
}

func (a *GroupResourceAssignment) maxPossibleBoxIOBudget(bytesPerBoxRef uint64) uint64 {
	return basics.MulSaturate(
		uint64(a.startingBoxes+a.Resources.maxPossibleUnnamedBoxes()),
		bytesPerBoxRef,
	)
}

func (a *GroupResourceAssignment) hasHolding(addr basics.Address, aid basics.AssetIndex) bool {
	// nil map lookup is ok
	_, ok := a.AssetHoldings[ledgercore.AccountAsset{Address: addr, Asset: aid}]
	return ok
}

func (a *GroupResourceAssignment) addHolding(addr basics.Address, aid basics.AssetIndex) bool {
	if len(a.AssetHoldings)+len(a.AppLocals) >= a.MaxCrossProductReferences {
		return false
	}
	if a.AssetHoldings == nil {
		a.AssetHoldings = make(map[ledgercore.AccountAsset]struct{})
	}
	a.AssetHoldings[ledgercore.AccountAsset{Address: addr, Asset: aid}] = struct{}{}
	return true
}

func (a *GroupResourceAssignment) hasLocal(addr basics.Address, aid basics.AppIndex, ep *logic.EvalParams) bool {
	if ep.GetApplicationAddress(aid) == addr {
		// The app local of an app and its own account is always available, so don't bother recording it.
		return true
	}
	// nil map lookup is ok
	_, ok := a.AppLocals[ledgercore.AccountApp{Address: addr, App: aid}]
	return ok
}

func (a *GroupResourceAssignment) addLocal(addr basics.Address, aid basics.AppIndex) bool {
	if len(a.AssetHoldings)+len(a.AppLocals) >= a.MaxCrossProductReferences {
		return false
	}
	if a.AppLocals == nil {
		a.AppLocals = make(map[ledgercore.AccountApp]struct{})
	}
	a.AppLocals[ledgercore.AccountApp{Address: addr, App: aid}] = struct{}{}
	return true
}

type resourcePolicy struct {
	assignment                  GroupResourceAssignment
	ep                          *logic.EvalParams
	initialBoxSurplusReadBudget *uint64

	txnRootIndex   int
	programVersion uint64
	globalSharing  bool
}

func newResourcePolicy(ep *logic.EvalParams, groupResult *TxnGroupResult) *resourcePolicy {
	policy := resourcePolicy{
		assignment: makeGroupResourceAssignment(ep.TxnGroup, ep.Proto),
		ep:         ep,
	}
	groupResult.UnnamedResourcesAccessed = &policy.assignment
	for i := range groupResult.Txns {
		groupResult.Txns[i].UnnamedResourcesAccessed = &policy.assignment.localTxnResources[i]
	}
	return &policy
}

func (p *resourcePolicy) AvailableAccount(addr basics.Address) bool {
	if p.assignment.hasAccount(addr, p.ep, p.programVersion, p.globalSharing, p.txnRootIndex) {
		return true
	}
	return p.assignment.addAccount(addr, p.globalSharing, p.txnRootIndex)
}

func (p *resourcePolicy) AvailableAsset(aid basics.AssetIndex) bool {
	if p.assignment.hasAsset(aid, p.globalSharing, p.txnRootIndex) {
		return true
	}
	return p.assignment.addAsset(aid, p.globalSharing, p.txnRootIndex)
}

func (p *resourcePolicy) AvailableApp(aid basics.AppIndex) bool {
	if p.assignment.hasApp(aid, p.globalSharing, p.txnRootIndex) {
		return true
	}
	return p.assignment.addApp(aid, p.ep, p.programVersion, p.globalSharing, p.txnRootIndex)
}

func (p *resourcePolicy) AllowsHolding(addr basics.Address, aid basics.AssetIndex) bool {
	// holdings are only checked if globalSharing is true
	if p.assignment.hasHolding(addr, aid) {
		return true
	}
	return p.assignment.addHolding(addr, aid)
}

func (p *resourcePolicy) AllowsLocal(addr basics.Address, aid basics.AppIndex) bool {
	// locals are only checked if globalSharing is true
	if p.assignment.hasLocal(addr, aid, p.ep) {
		return true
	}
	return p.assignment.addLocal(addr, aid)
}

func (p *resourcePolicy) AvailableBox(app basics.AppIndex, name string, operation logic.BoxOperation, createSize uint64) bool {
	if p.assignment.hasBox(app, name) {
		// We actually never expect this to happen, since the EvalContext remembers each box in
		// order to track their dirty bytes, and it won't invoke this method if it's already seen
		// the box.
		return true
	}
	box, ok, err := p.ep.Ledger.GetBox(app, name)
	if err != nil {
		panic(err)
	}
	var readSize uint64
	if ok {
		readSize = uint64(len(box))
	}
	return p.assignment.addBox(app, name, readSize, *p.initialBoxSurplusReadBudget, p.ep.Proto.BytesPerBoxReference)
}
