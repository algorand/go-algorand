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

package ledger

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

//   ___________________
// < cow = Copy On Write >
//   -------------------
//          \   ^__^
//           \  (oo)\_______
//              (__)\       )\/\
//                  ||----w |
//                  ||     ||

type roundCowParent interface {
	// lookout with rewards
	lookup(basics.Address) (ledgercore.PersistedAccountData, error)
	lookupCreatableData(basics.Address, []creatableDataLocator) (ledgercore.PersistedAccountData, error)
	checkDup(basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error
	txnCounter() uint64
	getCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error)
	compactCertNext() basics.Round
	blockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error)
	getStorageCounts(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error)
	// note: getStorageLimits is redundant with the other methods
	// and is provided to optimize state schema lookups
	getStorageLimits(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error)
	allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error)
	getKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) (basics.TealValue, bool, error)
}

type roundCowState struct {
	lookupParent roundCowParent
	commitParent *roundCowState
	proto        config.ConsensusParams
	mods         ledgercore.StateDelta

	// storage deltas populated as side effects of AppCall transaction
	// 1. Opt-in/Close actions (see Allocate/Deallocate)
	// 2. Stateful TEAL evaluation (see SetKey/DelKey)
	// must be incorporated into mods.accts before passing deltas forward
	sdeltas map[basics.Address]map[storagePtr]*storageDelta

	// getPadCache provides compatibility between mods that uses PersistedAccountData
	// and balances interface implementation (Get, GetEx, Put, PutWithCreatable)
	// that work with AccountData view to PersistedAccountData.
	// The idea is Getters populate getPadCache and return AccountData portion,
	// and Putters find corresponding PersistedAccountData there without looking into DB
	getPadCache map[basics.Address]ledgercore.PersistedAccountData

	// either or not maintain compatibility with original app refactoring behavior
	// this is needed for generating old eval delta in new code
	compatibilityMode bool
	// cache mainaining accountIdx used in getKey for local keys access
	compatibilityGetKeyCache map[basics.Address]map[storagePtr]uint64
}

func makeRoundCowState(b roundCowParent, hdr bookkeeping.BlockHeader, prevTimestamp int64, hint int) *roundCowState {
	cb := roundCowState{
		lookupParent: b,
		commitParent: nil,
		proto:        config.Consensus[hdr.CurrentProtocol],
		mods:         ledgercore.MakeStateDelta(&hdr, prevTimestamp, hint, 0),
		sdeltas:      make(map[basics.Address]map[storagePtr]*storageDelta),
		getPadCache:  make(map[basics.Address]ledgercore.PersistedAccountData),
	}

	// compatibilityMode retains producing application' eval deltas under the following rule:
	// local delta has account index as it specified in TEAL either in set/del key or prior get key calls.
	// The predicate is that complex in order to cover all the block seen on testnet and mainnet.
	compatibilityMode := (hdr.CurrentProtocol == protocol.ConsensusV24) &&
		(hdr.NextProtocol != protocol.ConsensusV26 || (hdr.UpgradePropose == "" && hdr.UpgradeApprove == false && hdr.Round < hdr.UpgradeState.NextProtocolVoteBefore))
	if compatibilityMode {
		cb.compatibilityMode = true
		cb.compatibilityGetKeyCache = make(map[basics.Address]map[storagePtr]uint64)
	}
	return &cb
}

func (cb *roundCowState) deltas() ledgercore.StateDelta {
	var err error
	if len(cb.sdeltas) == 0 {
		return cb.mods
	}

	// Apply storage deltas to account deltas
	// 1. Ensure all addresses from sdeltas have entries in accts because
	//    SetKey/DelKey work only with sdeltas, so need to pull missing accounts
	// 2. Call applyStorageDelta for every delta per account
	for addr, smap := range cb.sdeltas {
		var pad ledgercore.PersistedAccountData
		var exist bool
		if pad, exist = cb.mods.Accts.Get(addr); !exist {
			pad, err = cb.lookup(addr)
			if err != nil {
				panic(fmt.Sprintf("fetching account data failed for addr %s: %s", addr.String(), err.Error()))
			}
		}
		for aapp, storeDelta := range smap {
			if pad.AccountData, err = applyStorageDelta(pad.AccountData, aapp, storeDelta); err != nil {
				panic(fmt.Sprintf("applying storage delta failed for addr %s app %d: %s", addr.String(), aapp.aidx, err.Error()))
			}
		}
		cb.mods.Accts.Upsert(addr, pad)
	}
	return cb.mods
}

func (cb *roundCowState) rewardsLevel() uint64 {
	return cb.mods.Hdr.RewardsLevel
}

func (cb *roundCowState) round() basics.Round {
	return cb.mods.Hdr.Round
}

func (cb *roundCowState) prevTimestamp() int64 {
	return cb.mods.PrevTimestamp
}

func (cb *roundCowState) getCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (creator basics.Address, ok bool, err error) {
	delta, ok := cb.mods.Creatables[cidx]
	if ok {
		if delta.Created && delta.Ctype == ctype {
			return delta.Creator, true, nil
		}
		return basics.Address{}, false, nil
	}
	return cb.lookupParent.getCreator(cidx, ctype)
}

func (cb *roundCowState) lookup(addr basics.Address) (pad ledgercore.PersistedAccountData, err error) {
	pad, ok := cb.mods.Accts.Get(addr)
	if ok {
		return pad, nil
	}

	pad, err = cb.lookupParent.lookup(addr)
	if err != nil {
		return
	}

	// save PersistentAccountData for later usage in put
	cb.getPadCache[addr] = pad
	return
}

// lookupWithHolding is gets account data but also fetches asset holding or app local data for a specified creatable
func (cb *roundCowState) lookupCreatableData(addr basics.Address, locators []creatableDataLocator) (data ledgercore.PersistedAccountData, err error) {
	pad, modified := cb.mods.Accts.Get(addr)
	if modified {
		foundInModified := make([]bool, 0, len(locators))
		for _, loc := range locators {
			globalExist := false
			localExist := false
			if loc.ctype == basics.AssetCreatable {
				if loc.global {
					_, globalExist = pad.AccountData.AssetParams[basics.AssetIndex(loc.cidx)]
				}
				if loc.local {
					_, localExist = pad.AccountData.Assets[basics.AssetIndex(loc.cidx)]
				}
			} else {
				if loc.global {
					_, globalExist = pad.AccountData.AppParams[basics.AppIndex(loc.cidx)]
				}
				if loc.local {
					_, localExist = pad.AccountData.AppLocalStates[basics.AppIndex(loc.cidx)]
				}
			}

			onlyGlobal := loc.global && globalExist && !loc.local
			onlyLocal := loc.local && localExist && !loc.global
			bothGlobalLocal := loc.global && globalExist && loc.local && localExist
			found := onlyGlobal || onlyLocal || bothGlobalLocal
			foundInModified = append(foundInModified, found)
		}
		found := 0
		for _, val := range foundInModified {
			if !val {
				break
			}
			found++
		}
		// all requested items were found in modified data => return
		if found == len(locators) {
			return pad, nil
		}
	}

	parentPad, err := cb.lookupParent.lookupCreatableData(addr, locators)
	if !modified {
		cb.getPadCache[addr] = parentPad
		return parentPad, err
	}

	// data from cb.mods.Accts is newer than from lookupParent -> lookupHolding/lookupParams
	// so add assets if they do not exist in new
	for _, loc := range locators {
		if loc.ctype == basics.AssetCreatable {
			if loc.global {
				params, parentOk := parentPad.AccountData.AssetParams[basics.AssetIndex(loc.cidx)]
				if _, ok := pad.AccountData.AssetParams[basics.AssetIndex(loc.cidx)]; !ok && parentOk {
					pad.AccountData.AssetParams[basics.AssetIndex(loc.cidx)] = params
				}
			}
			if loc.local {
				holding, parentOk := parentPad.AccountData.Assets[basics.AssetIndex(loc.cidx)]
				if _, ok := pad.AccountData.Assets[basics.AssetIndex(loc.cidx)]; !ok && parentOk {
					pad.AccountData.Assets[basics.AssetIndex(loc.cidx)] = holding
				}
			}
		} else {
			if loc.global {
				params, parentOk := parentPad.AccountData.AppParams[basics.AppIndex(loc.cidx)]
				if _, ok := pad.AccountData.AppParams[basics.AppIndex(loc.cidx)]; !ok && parentOk {
					pad.AccountData.AppParams[basics.AppIndex(loc.cidx)] = params
				}
			}
			if loc.local {
				states, parentOk := parentPad.AccountData.AppLocalStates[basics.AppIndex(loc.cidx)]
				if _, ok := pad.AccountData.AppLocalStates[basics.AppIndex(loc.cidx)]; !ok && parentOk {
					pad.AccountData.AppLocalStates[basics.AppIndex(loc.cidx)] = states
				}
			}
		}
	}

	cb.getPadCache[addr] = pad
	return pad, nil
}

func (cb *roundCowState) checkDup(firstValid, lastValid basics.Round, txid transactions.Txid, txl ledgercore.Txlease) error {
	_, present := cb.mods.Txids[txid]
	if present {
		return &ledgercore.TransactionInLedgerError{Txid: txid}
	}

	if cb.proto.SupportTransactionLeases && (txl.Lease != [32]byte{}) {
		expires, ok := cb.mods.Txleases[txl]
		if ok && cb.mods.Hdr.Round <= expires {
			return ledgercore.MakeLeaseInLedgerError(txid, txl)
		}
	}

	return cb.lookupParent.checkDup(firstValid, lastValid, txid, txl)
}

func (cb *roundCowState) txnCounter() uint64 {
	return cb.lookupParent.txnCounter() + uint64(len(cb.mods.Txids))
}

func (cb *roundCowState) compactCertNext() basics.Round {
	if cb.mods.CompactCertNext != 0 {
		return cb.mods.CompactCertNext
	}
	return cb.lookupParent.compactCertNext()
}

func (cb *roundCowState) blockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	return cb.lookupParent.blockHdr(r)
}

func (cb *roundCowState) put(addr basics.Address, new basics.AccountData, newCreatable *basics.CreatableLocator, deletedCreatable *basics.CreatableLocator) {
	// convert AccountData to PersistentAccountData by using getPadCache
	// that is must be filled in lookup* methods
	if pad, ok := cb.getPadCache[addr]; ok {
		pad.AccountData = new
		cb.mods.Accts.Upsert(addr, pad)
	} else {
		logging.Base().Errorf("address %s does not have entry in getPadCache", addr.String())

		// Try to recover.
		// Problem: getPadCache have to keep AccountData with the asset/app used in lookupCreatableData call,
		// and put() has no idea what the client needed (that's why getPadCache exists).
		// So need to preload all elements that makes sense:
		// - for asset params they are either newCreatable or deletedCreatable
		// - for asset holdings it is more complicated and need to load all data from new.Assets
		pad, err := cb.lookup(addr)
		if err != nil {
			// well, seems like something really wrong, panic
			panic(fmt.Sprintf("Recovering attempt after %s missing in getPadCache failed: %s", addr.String(), err.Error()))
		}

		if pad.ExtendedAssetParams.Count != 0 {
			var target basics.CreatableIndex
			if newCreatable != nil && newCreatable.Type == basics.AssetCreatable {
				target = newCreatable.Index
			}
			if deletedCreatable != nil && deletedCreatable.Type == basics.AssetCreatable {
				target = deletedCreatable.Index
			}
			if target != 0 {
				pad2, err := cb.lookupCreatableData(addr, []creatableDataLocator{{cidx: target, ctype: basics.AssetCreatable, global: true, local: false}})
				if err != nil {
					// well, seems like something really wrong, panic
					panic(fmt.Sprintf("Recovering attempt after %s missing in getPadCache and asset params %d failed: %s", addr.String(), target, err.Error()))
				}
				pad2.AccountData = new
				cb.mods.Accts.Upsert(addr, pad2)
			}
		}

		if pad.ExtendedAssetHolding.Count != 0 {
			// There are some extension records, need to fetch all holdings that are in new
			// to ensure underlying code has all needed data
			locators := make([]creatableDataLocator, 0, len(new.Assets))
			for aidx := range new.Assets {
				locators = append(locators, creatableDataLocator{cidx: basics.CreatableIndex(aidx), ctype: basics.AssetCreatable, global: false, local: true})
			}

			pad2, err := cb.lookupCreatableData(addr, locators)
			if err != nil {
				// well, seems like something really wrong, panic
				panic(fmt.Sprintf("Recovering attempt after %s missing in getPadCache and asset holdings failed: %s", addr.String(), err.Error()))
			}
			for i, g := range pad2.ExtendedAssetHolding.Groups {
				if g.Loaded() {
					pad.ExtendedAssetHolding.Groups[i] = g
				}
			}
			pad.AccountData = new
			cb.mods.Accts.Upsert(addr, pad)
		}

		if pad.ExtendedAssetParams.Count == 0 && pad.ExtendedAssetHolding.Count == 0 {
			// if no extension records, store a value from regular lookup
			pad.AccountData = new
			cb.mods.Accts.Upsert(addr, pad)
		}
	}

	if newCreatable != nil {
		cb.mods.Creatables[newCreatable.Index] = ledgercore.ModifiedCreatable{
			Ctype:   newCreatable.Type,
			Creator: newCreatable.Creator,
			Created: true,
		}
	}
	if deletedCreatable != nil {
		cb.mods.Creatables[deletedCreatable.Index] = ledgercore.ModifiedCreatable{
			Ctype:   deletedCreatable.Type,
			Creator: deletedCreatable.Creator,
			Created: false,
		}
	}
}

func (cb *roundCowState) addTx(txn transactions.Transaction, txid transactions.Txid) {
	cb.mods.Txids[txid] = txn.LastValid
	cb.mods.Txleases[ledgercore.Txlease{Sender: txn.Sender, Lease: txn.Lease}] = txn.LastValid
}

func (cb *roundCowState) setCompactCertNext(rnd basics.Round) {
	cb.mods.CompactCertNext = rnd
}

func (cb *roundCowState) child(hint int) *roundCowState {
	ch := roundCowState{
		lookupParent: cb,
		commitParent: cb,
		proto:        cb.proto,
		mods:         ledgercore.MakeStateDelta(cb.mods.Hdr, cb.mods.PrevTimestamp, hint, cb.mods.CompactCertNext),
		sdeltas:      make(map[basics.Address]map[storagePtr]*storageDelta),
		getPadCache:  make(map[basics.Address]ledgercore.PersistedAccountData),
	}

	if cb.compatibilityMode {
		ch.compatibilityMode = cb.compatibilityMode
		ch.compatibilityGetKeyCache = make(map[basics.Address]map[storagePtr]uint64)
	}
	return &ch
}

func (cb *roundCowState) commitToParent() {
	cb.commitParent.mods.Accts.MergeAccounts(cb.mods.Accts)

	for txid, lv := range cb.mods.Txids {
		cb.commitParent.mods.Txids[txid] = lv
	}
	for txl, expires := range cb.mods.Txleases {
		cb.commitParent.mods.Txleases[txl] = expires
	}
	for cidx, delta := range cb.mods.Creatables {
		cb.commitParent.mods.Creatables[cidx] = delta
	}
	for addr, smod := range cb.sdeltas {
		for aapp, nsd := range smod {
			lsd, ok := cb.commitParent.sdeltas[addr][aapp]
			if ok {
				lsd.applyChild(nsd)
			} else {
				_, ok = cb.commitParent.sdeltas[addr]
				if !ok {
					cb.commitParent.sdeltas[addr] = make(map[storagePtr]*storageDelta)
				}
				cb.commitParent.sdeltas[addr][aapp] = nsd
			}
		}
	}
	cb.commitParent.mods.CompactCertNext = cb.mods.CompactCertNext

	for addr, pad := range cb.getPadCache {
		cb.commitParent.getPadCache[addr] = pad
	}
}

func (cb *roundCowState) modifiedAccounts() []basics.Address {
	return cb.mods.Accts.ModifiedAccounts()
}
