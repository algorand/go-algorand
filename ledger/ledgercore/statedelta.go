// Copyright (C) 2019-2022 Algorand, Inc.
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

package ledgercore

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
)

const (
	accountArrayEntrySize                 = uint64(232) // Measured by BenchmarkBalanceRecord
	accountMapCacheEntrySize              = uint64(64)  // Measured by BenchmarkAcctCache
	txleasesEntrySize                     = uint64(112) // Measured by BenchmarkTxLeases
	creatablesEntrySize                   = uint64(100) // Measured by BenchmarkCreatables
	stateDeltaTargetOptimizationThreshold = uint64(50000000)
)

// ModifiedCreatable defines the changes to a single single creatable state
type ModifiedCreatable struct {
	// Type of the creatable: app or asset
	Ctype basics.CreatableType

	// Created if true, deleted if false
	Created bool

	// creator of the app/asset
	Creator basics.Address

	// Keeps track of how many times this app/asset appears in
	// accountUpdates.creatableDeltas
	Ndeltas int
}

// AccountAsset is used as a map key.
type AccountAsset struct {
	Address basics.Address
	Asset   basics.AssetIndex
}

// AccountApp is used as a map key.
type AccountApp struct {
	Address basics.Address
	App     basics.AppIndex
}

// A Txlease is a transaction (sender, lease) pair which uniquely specifies a
// transaction lease.
type Txlease struct {
	Sender basics.Address
	Lease  [32]byte
}

// StateDelta describes the delta between a given round to the previous round
type StateDelta struct {
	// modified accounts
	// Accts AccountDeltas

	// modified new accounts
	Accts AccountDeltas

	// modified kv pairs (nil == delete)
	KvMods map[string]*string

	// new Txids for the txtail and TxnCounter, mapped to txn.LastValid
	Txids map[transactions.Txid]basics.Round

	// new txleases for the txtail mapped to expiration
	Txleases map[Txlease]basics.Round

	// new creatables creator lookup table
	Creatables map[basics.CreatableIndex]ModifiedCreatable

	// new block header; read-only
	Hdr *bookkeeping.BlockHeader

	// next round for which we expect a compact cert.
	// zero if no compact cert is expected.
	CompactCertNext basics.Round

	// previous block timestamp
	PrevTimestamp int64

	// initial hint for allocating data structures for StateDelta
	initialTransactionsCount int

	// The account totals reflecting the changes in this StateDelta object.
	Totals AccountTotals
}

// NewBalanceRecord is similar to basics.BalanceRecord but with decoupled base and voting data
type NewBalanceRecord struct {
	Addr basics.Address
	AccountData
}

// AssetHoldingDelta records a changed AssetHolding, and whether it was deleted
type AssetHoldingDelta struct {
	Holding *basics.AssetHolding
	Deleted bool
}

// AssetParamsDelta tracks a changed AssetParams, and whether it was deleted
type AssetParamsDelta struct {
	Params  *basics.AssetParams
	Deleted bool
}

// AppLocalStateDelta tracks a changed AppLocalState, and whether it was deleted
type AppLocalStateDelta struct {
	LocalState *basics.AppLocalState
	Deleted    bool
}

// AppParamsDelta tracks a changed AppParams, and whether it was deleted
type AppParamsDelta struct {
	Params  *basics.AppParams
	Deleted bool
}

// AppResourceRecord represents AppParams and AppLocalState in deltas
type AppResourceRecord struct {
	Aidx   basics.AppIndex
	Addr   basics.Address
	Params AppParamsDelta
	State  AppLocalStateDelta
}

// AssetResourceRecord represents AssetParams and AssetHolding in deltas
type AssetResourceRecord struct {
	Aidx    basics.AssetIndex
	Addr    basics.Address
	Params  AssetParamsDelta
	Holding AssetHoldingDelta
}

// AccountDeltas stores ordered accounts and allows fast lookup by address
// One key design aspect here was to ensure that we're able to access the written
// deltas in a deterministic order, while maintaining O(1) lookup. In order to
// do that, each of the arrays here is constructed as a pair of (slice, map).
// The map would point the address/address+creatable id onto the index of the
// element within the slice.
type AccountDeltas struct {
	// Actual data. If an account is deleted, `accts` contains the NewBalanceRecord
	// with an empty `AccountData` and a populated `Addr`.
	accts []NewBalanceRecord
	// cache for addr to deltas index resolution
	acctsCache map[basics.Address]int

	// AppResources deltas. If app params or local state is deleted, there is a nil value in appResources.Params or appResources.State and Deleted flag set
	appResources []AppResourceRecord
	// caches for {addr, app id} to app params delta resolution
	appResourcesCache map[AccountApp]int

	assetResources      []AssetResourceRecord
	assetResourcesCache map[AccountAsset]int
}

// MakeStateDelta creates a new instance of StateDelta.
// hint is amount of transactions for evaluation, 2 * hint is for sender and receiver balance records.
// This does not play well for AssetConfig and ApplicationCall transactions on scale
func MakeStateDelta(hdr *bookkeeping.BlockHeader, prevTimestamp int64, hint int, compactCertNext basics.Round) StateDelta {
	return StateDelta{
		Accts:    MakeAccountDeltas(hint),
		KvMods:   make(map[string]*string),
		Txids:    make(map[transactions.Txid]basics.Round, hint),
		Txleases: make(map[Txlease]basics.Round, hint),
		// asset or application creation are considered as rare events so do not pre-allocate space for them
		Creatables:               make(map[basics.CreatableIndex]ModifiedCreatable),
		Hdr:                      hdr,
		CompactCertNext:          compactCertNext,
		PrevTimestamp:            prevTimestamp,
		initialTransactionsCount: hint,
	}
}

// MakeAccountDeltas creates account delta
func MakeAccountDeltas(hint int) AccountDeltas {
	return AccountDeltas{
		accts:      make([]NewBalanceRecord, 0, hint*2),
		acctsCache: make(map[basics.Address]int, hint*2),

		appResourcesCache:   make(map[AccountApp]int),
		assetResourcesCache: make(map[AccountAsset]int),
	}
}

// GetData lookups AccountData by address
func (ad AccountDeltas) GetData(addr basics.Address) (AccountData, bool) {
	idx, ok := ad.acctsCache[addr]
	if !ok {
		return AccountData{}, false
	}
	return ad.accts[idx].AccountData, true
}

// GetAppParams returns app params delta value
func (ad AccountDeltas) GetAppParams(addr basics.Address, aidx basics.AppIndex) (AppParamsDelta, bool) {
	if idx, ok := ad.appResourcesCache[AccountApp{addr, aidx}]; ok {
		result := ad.appResources[idx].Params
		return result, result.Deleted || result.Params != nil
	}
	return AppParamsDelta{}, false
}

// GetAssetParams returns asset params delta value
func (ad AccountDeltas) GetAssetParams(addr basics.Address, aidx basics.AssetIndex) (AssetParamsDelta, bool) {
	if idx, ok := ad.assetResourcesCache[AccountAsset{addr, aidx}]; ok {
		result := ad.assetResources[idx].Params
		return result, result.Deleted || result.Params != nil
	}
	return AssetParamsDelta{}, false
}

// GetAppLocalState returns app local state delta value
func (ad AccountDeltas) GetAppLocalState(addr basics.Address, aidx basics.AppIndex) (AppLocalStateDelta, bool) {
	if idx, ok := ad.appResourcesCache[AccountApp{addr, aidx}]; ok {
		result := ad.appResources[idx].State
		return result, result.Deleted || result.LocalState != nil
	}
	return AppLocalStateDelta{}, false
}

// GetAssetHolding returns asset holding delta value
func (ad AccountDeltas) GetAssetHolding(addr basics.Address, aidx basics.AssetIndex) (AssetHoldingDelta, bool) {
	if idx, ok := ad.assetResourcesCache[AccountAsset{addr, aidx}]; ok {
		result := ad.assetResources[idx].Holding
		return result, result.Deleted || result.Holding != nil
	}
	return AssetHoldingDelta{}, false
}

// ModifiedAccounts returns list of addresses of modified accounts
func (ad AccountDeltas) ModifiedAccounts() []basics.Address {
	result := make([]basics.Address, len(ad.accts))
	for i := 0; i < len(ad.accts); i++ {
		result[i] = ad.accts[i].Addr
	}

	// consistency check: ensure all addresses for deleted params/holdings/states are also in base accounts
	// it is nice to check created params/holdings/states but we lack of such info here
	for aapp, idx := range ad.appResourcesCache {
		if ad.appResources[idx].Params.Deleted {
			if _, ok := ad.acctsCache[aapp.Address]; !ok {
				panic(fmt.Sprintf("account app param delta: addr %s not in base account", aapp.Address))
			}
		}
		if ad.appResources[idx].State.Deleted {
			if _, ok := ad.acctsCache[aapp.Address]; !ok {
				panic(fmt.Sprintf("account app state delta: addr %s not in base account", aapp.Address))
			}
		}
	}
	for aapp, idx := range ad.assetResourcesCache {
		if ad.assetResources[idx].Params.Deleted {
			if _, ok := ad.acctsCache[aapp.Address]; !ok {
				panic(fmt.Sprintf("account asset param delta: addr %s not in base account", aapp.Address))
			}
		}
		if ad.assetResources[idx].Holding.Deleted {
			if _, ok := ad.acctsCache[aapp.Address]; !ok {
				panic(fmt.Sprintf("account asset holding delta: addr %s not in base account", aapp.Address))
			}
		}
	}

	return result
}

// MergeAccounts applies other accounts into this StateDelta accounts
func (ad *AccountDeltas) MergeAccounts(other AccountDeltas) {
	for new := range other.accts {
		addr := other.accts[new].Addr
		acct := other.accts[new].AccountData
		ad.Upsert(addr, acct)
	}

	for aapp, idx := range other.appResourcesCache {
		params := other.appResources[idx].Params
		state := other.appResources[idx].State
		ad.UpsertAppResource(aapp.Address, aapp.App, params, state)
	}
	for aapp, idx := range other.assetResourcesCache {
		params := other.assetResources[idx].Params
		holding := other.assetResources[idx].Holding
		ad.UpsertAssetResource(aapp.Address, aapp.Asset, params, holding)
	}
}

// GetResource looks up a pair of app or asset resources, given its index and type.
func (ad AccountDeltas) GetResource(addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (ret AccountResource, ok bool) {
	switch ctype {
	case basics.AssetCreatable:
		aa := AccountAsset{addr, basics.AssetIndex(aidx)}
		idx, ok := ad.assetResourcesCache[aa]
		if ok {
			ret.AssetParams = ad.assetResources[idx].Params.Params
			ret.AssetHolding = ad.assetResources[idx].Holding.Holding
		}
		return ret, ok
	case basics.AppCreatable:
		aa := AccountApp{addr, basics.AppIndex(aidx)}
		idx, ok := ad.appResourcesCache[aa]
		if ok {
			ret.AppParams = ad.appResources[idx].Params.Params
			ret.AppLocalState = ad.appResources[idx].State.LocalState
		}
		return ret, ok
	}
	return ret, false
}

// Len returns number of stored accounts
func (ad *AccountDeltas) Len() int {
	return len(ad.accts)
}

// GetByIdx returns address and AccountData
// It does NOT check boundaries.
func (ad *AccountDeltas) GetByIdx(i int) (basics.Address, AccountData) {
	return ad.accts[i].Addr, ad.accts[i].AccountData
}

// Upsert adds ledgercore.AccountData into deltas
func (ad *AccountDeltas) Upsert(addr basics.Address, data AccountData) {
	if idx, exist := ad.acctsCache[addr]; exist { // nil map lookup is OK
		ad.accts[idx] = NewBalanceRecord{Addr: addr, AccountData: data}
		return
	}

	last := len(ad.accts)
	ad.accts = append(ad.accts, NewBalanceRecord{Addr: addr, AccountData: data})

	if ad.acctsCache == nil {
		ad.acctsCache = make(map[basics.Address]int)
	}
	ad.acctsCache[addr] = last
}

// UpsertAppResource adds AppParams and AppLocalState delta
func (ad *AccountDeltas) UpsertAppResource(addr basics.Address, aidx basics.AppIndex, params AppParamsDelta, state AppLocalStateDelta) {
	key := AccountApp{addr, aidx}
	value := AppResourceRecord{aidx, addr, params, state}
	if idx, exist := ad.appResourcesCache[key]; exist {
		ad.appResources[idx] = value
		return
	}

	last := len(ad.appResources)
	ad.appResources = append(ad.appResources, value)

	if ad.appResourcesCache == nil {
		ad.appResourcesCache = make(map[AccountApp]int)
	}
	ad.appResourcesCache[key] = last
}

// UpsertAssetResource adds AssetParams and AssetHolding delta
func (ad *AccountDeltas) UpsertAssetResource(addr basics.Address, aidx basics.AssetIndex, params AssetParamsDelta, holding AssetHoldingDelta) {
	key := AccountAsset{addr, aidx}
	value := AssetResourceRecord{aidx, addr, params, holding}
	if idx, exist := ad.assetResourcesCache[key]; exist {
		ad.assetResources[idx] = value
		return
	}

	last := len(ad.assetResources)
	ad.assetResources = append(ad.assetResources, value)

	if ad.assetResourcesCache == nil {
		ad.assetResourcesCache = make(map[AccountAsset]int)
	}
	ad.assetResourcesCache[key] = last
}

// OptimizeAllocatedMemory by reallocating maps to needed capacity
// For each data structure, reallocate if it would save us at least 50MB aggregate
func (sd *StateDelta) OptimizeAllocatedMemory(proto config.ConsensusParams) {
	// accts takes up 232 bytes per entry, and is saved for 320 rounds
	if uint64(cap(sd.Accts.accts)-len(sd.Accts.accts))*accountArrayEntrySize*proto.MaxBalLookback > stateDeltaTargetOptimizationThreshold {
		accts := make([]NewBalanceRecord, len(sd.Accts.acctsCache))
		copy(accts, sd.Accts.accts)
		sd.Accts.accts = accts
	}

	// acctsCache takes up 64 bytes per entry, and is saved for 320 rounds
	// realloc if original allocation capacity greater than length of data, and space difference is significant
	if 2*sd.initialTransactionsCount > len(sd.Accts.acctsCache) &&
		uint64(2*sd.initialTransactionsCount-len(sd.Accts.acctsCache))*accountMapCacheEntrySize*proto.MaxBalLookback > stateDeltaTargetOptimizationThreshold {
		acctsCache := make(map[basics.Address]int, len(sd.Accts.acctsCache))
		for k, v := range sd.Accts.acctsCache {
			acctsCache[k] = v
		}
		sd.Accts.acctsCache = acctsCache
	}

	// TxLeases takes up 112 bytes per entry, and is saved for 1000 rounds
	if sd.initialTransactionsCount > len(sd.Txleases) &&
		uint64(sd.initialTransactionsCount-len(sd.Txleases))*txleasesEntrySize*proto.MaxTxnLife > stateDeltaTargetOptimizationThreshold {
		txLeases := make(map[Txlease]basics.Round, len(sd.Txleases))
		for k, v := range sd.Txleases {
			txLeases[k] = v
		}
		sd.Txleases = txLeases
	}

	// Creatables takes up 100 bytes per entry, and is saved for 320 rounds
	if uint64(len(sd.Creatables))*creatablesEntrySize*proto.MaxBalLookback > stateDeltaTargetOptimizationThreshold {
		creatableDeltas := make(map[basics.CreatableIndex]ModifiedCreatable, len(sd.Creatables))
		for k, v := range sd.Creatables {
			creatableDeltas[k] = v
		}
		sd.Creatables = creatableDeltas
	}
}

// GetBasicsAccountData returns basics account data for some specific address
// Currently is only used in tests
func (ad AccountDeltas) GetBasicsAccountData(addr basics.Address) (basics.AccountData, bool) {
	idx, ok := ad.acctsCache[addr]
	if !ok {
		return basics.AccountData{}, false
	}

	result := basics.AccountData{}
	acct := ad.accts[idx].AccountData
	AssignAccountData(&result, acct)

	if len(ad.appResourcesCache) > 0 {
		result.AppParams = make(map[basics.AppIndex]basics.AppParams)
		result.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
		for aapp, idx := range ad.appResourcesCache {
			rec := ad.appResources[idx]
			if aapp.Address == addr {
				if !rec.Params.Deleted && rec.Params.Params != nil {
					result.AppParams[aapp.App] = *rec.Params.Params
				}
				if !rec.State.Deleted && rec.State.LocalState != nil {
					result.AppLocalStates[aapp.App] = *rec.State.LocalState
				}
			}
		}
		if len(result.AppParams) == 0 {
			result.AppParams = nil
		}
		if len(result.AppLocalStates) == 0 {
			result.AppLocalStates = nil
		}
	}

	if len(ad.assetResourcesCache) > 0 {
		result.AssetParams = make(map[basics.AssetIndex]basics.AssetParams)
		result.Assets = make(map[basics.AssetIndex]basics.AssetHolding)
		for aapp, idx := range ad.assetResourcesCache {
			rec := ad.assetResources[idx]
			if aapp.Address == addr {
				if !rec.Params.Deleted && rec.Params.Params != nil {
					result.AssetParams[aapp.Asset] = *rec.Params.Params
				}
				if !rec.Holding.Deleted && rec.Holding.Holding != nil {
					result.Assets[aapp.Asset] = *rec.Holding.Holding
				}
			}
		}
		if len(result.AssetParams) == 0 {
			result.AssetParams = nil
		}
		if len(result.Assets) == 0 {
			result.Assets = nil
		}
	}

	return result, true
}

// ToModifiedCreatables is only used in tests, to create a map of ModifiedCreatable.
func (ad AccountDeltas) ToModifiedCreatables(seen map[basics.CreatableIndex]struct{}) map[basics.CreatableIndex]ModifiedCreatable {
	result := make(map[basics.CreatableIndex]ModifiedCreatable, len(ad.appResources)+len(ad.assetResources))
	for aapp, idx := range ad.appResourcesCache {
		rec := ad.appResources[idx]
		if rec.Params.Deleted {
			result[basics.CreatableIndex(rec.Aidx)] = ModifiedCreatable{
				Ctype:   basics.AppCreatable,
				Created: false,
				Creator: aapp.Address,
			}
		} else if rec.Params.Params != nil {
			if _, ok := seen[basics.CreatableIndex(rec.Aidx)]; !ok {
				result[basics.CreatableIndex(rec.Aidx)] = ModifiedCreatable{
					Ctype:   basics.AppCreatable,
					Created: true,
					Creator: aapp.Address,
				}
			}
		}
	}

	for aapp, idx := range ad.assetResourcesCache {
		rec := ad.assetResources[idx]
		if rec.Params.Deleted {
			result[basics.CreatableIndex(rec.Aidx)] = ModifiedCreatable{
				Ctype:   basics.AssetCreatable,
				Created: false,
				Creator: aapp.Address,
			}
		} else if rec.Params.Params != nil {
			if _, ok := seen[basics.CreatableIndex(rec.Aidx)]; !ok {
				result[basics.CreatableIndex(rec.Aidx)] = ModifiedCreatable{
					Ctype:   basics.AssetCreatable,
					Created: true,
					Creator: aapp.Address,
				}
			}
		}
	}

	return result
}

// AccumulateDeltas adds delta into base accounts map in-place
func AccumulateDeltas(base map[basics.Address]basics.AccountData, deltas AccountDeltas) map[basics.Address]basics.AccountData {
	for i := 0; i < deltas.Len(); i++ {
		addr, _ := deltas.GetByIdx(i)
		if acct, ok := deltas.GetData(addr); ok {
			var ad basics.AccountData
			AssignAccountData(&ad, acct)
			base[addr] = ad
		}
	}

	for aapp, idx := range deltas.appResourcesCache {
		ad := base[aapp.Address]
		acct, ok := deltas.GetData(aapp.Address)
		if !ok || (acct.TotalAppParams == 0 && acct.TotalAppLocalStates == 0) {
			continue
		}
		if ad.AppParams == nil {
			ad.AppParams = make(map[basics.AppIndex]basics.AppParams, acct.TotalAppParams)
		}
		if ad.AppLocalStates == nil {
			ad.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState, acct.TotalAppLocalStates)
		}
		rec := deltas.appResources[idx]
		if rec.Params.Deleted {
			delete(ad.AppParams, aapp.App)
		} else if rec.Params.Params != nil {
			ad.AppParams[aapp.App] = *rec.Params.Params
		}
		if rec.State.Deleted {
			delete(ad.AppLocalStates, aapp.App)
		} else if rec.State.LocalState != nil {
			ad.AppLocalStates[aapp.App] = *rec.State.LocalState
		}
		base[aapp.Address] = ad
	}

	for aapp, idx := range deltas.assetResourcesCache {
		ad := base[aapp.Address]
		acct, ok := deltas.GetData(aapp.Address)
		if !ok || (acct.TotalAssetParams == 0 && acct.TotalAssets == 0) {
			continue
		}
		if ad.AssetParams == nil {
			ad.AssetParams = make(map[basics.AssetIndex]basics.AssetParams, acct.TotalAssetParams)
		}
		if ad.Assets == nil {
			ad.Assets = make(map[basics.AssetIndex]basics.AssetHolding, acct.TotalAssets)
		}
		rec := deltas.assetResources[idx]
		if rec.Params.Deleted {
			delete(ad.AssetParams, aapp.Asset)
		} else if rec.Params.Params != nil {
			ad.AssetParams[aapp.Asset] = *rec.Params.Params
		}
		if rec.Holding.Deleted {
			delete(ad.Assets, aapp.Asset)
		} else if rec.Holding.Holding != nil {
			ad.Assets[aapp.Asset] = *rec.Holding.Holding
		}
		base[aapp.Address] = ad
	}

	for addr, ad := range base {
		if len(ad.AppParams) == 0 {
			ad.AppParams = nil
		}
		if len(ad.AppLocalStates) == 0 {
			ad.AppLocalStates = nil
		}
		if len(ad.AssetParams) == 0 {
			ad.AssetParams = nil
		}
		if len(ad.Assets) == 0 {
			ad.Assets = nil
		}

		base[addr] = ad
	}

	return base
}

// ApplyToBasicsAccountData applies partial delta from "ad" to a full account data "prev" and returns a deep copy
func (ad AccountDeltas) ApplyToBasicsAccountData(addr basics.Address, prev basics.AccountData) (result basics.AccountData) {
	// set the base part of account data (balance, status, voting data...)
	acct, ok := ad.GetData(addr)
	if !ok {
		return prev
	}

	AssignAccountData(&result, acct)

	if acct.TotalAppParams > 0 || prev.AppParams != nil {
		result.AppParams = make(map[basics.AppIndex]basics.AppParams)
		for aidx, params := range prev.AppParams {
			result.AppParams[aidx] = params
		}
		for aapp, idx := range ad.appResourcesCache {
			if aapp.Address == addr {
				rec := ad.appResources[idx]
				if rec.Params.Deleted {
					delete(result.AppParams, aapp.App)
				} else if rec.Params.Params != nil {
					result.AppParams[aapp.App] = *rec.Params.Params
				}
			}
		}
		if len(result.AppParams) == 0 {
			result.AppParams = nil
		}
	}

	if acct.TotalAppLocalStates > 0 || prev.AppLocalStates != nil {
		result.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
		for aidx, state := range prev.AppLocalStates {
			result.AppLocalStates[aidx] = state
		}
		for aapp, idx := range ad.appResourcesCache {
			if aapp.Address == addr {
				rec := ad.appResources[idx]
				if rec.State.Deleted {
					delete(result.AppLocalStates, aapp.App)
				} else if rec.State.LocalState != nil {
					result.AppLocalStates[aapp.App] = *rec.State.LocalState
				}
			}
		}
		if len(result.AppLocalStates) == 0 {
			result.AppLocalStates = nil
		}
	}

	if acct.TotalAssetParams > 0 || prev.AssetParams != nil {
		result.AssetParams = make(map[basics.AssetIndex]basics.AssetParams)
		for aidx, params := range prev.AssetParams {
			result.AssetParams[aidx] = params
		}
		for aapp, idx := range ad.assetResourcesCache {
			if aapp.Address == addr {
				rec := ad.assetResources[idx]
				if rec.Params.Deleted {
					delete(result.AssetParams, aapp.Asset)
				} else if rec.Params.Params != nil {
					result.AssetParams[aapp.Asset] = *rec.Params.Params
				}
			}
		}
		if len(result.AssetParams) == 0 {
			result.AssetParams = nil
		}
	}

	if acct.TotalAssets > 0 || prev.Assets != nil {
		result.Assets = make(map[basics.AssetIndex]basics.AssetHolding)
		for aidx, params := range prev.Assets {
			result.Assets[aidx] = params
		}
		for aapp, idx := range ad.assetResourcesCache {
			if aapp.Address == addr {
				rec := ad.assetResources[idx]
				if rec.Holding.Deleted {
					delete(result.Assets, aapp.Asset)
				} else if rec.Holding.Holding != nil {
					result.Assets[aapp.Asset] = *rec.Holding.Holding
				}
			}
		}
		if len(result.Assets) == 0 {
			result.Assets = nil
		}
	}

	return result
}

// GetAllAppResources returns all AppResourceRecords
func (ad *AccountDeltas) GetAllAppResources() []AppResourceRecord {
	return ad.appResources
}

// GetAllAssetResources returns all AssetResourceRecords
func (ad *AccountDeltas) GetAllAssetResources() []AssetResourceRecord {
	return ad.assetResources
}
