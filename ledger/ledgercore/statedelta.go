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
	NewAccts NewAccountDeltas

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

	// Modified local creatable states. The value is true if the creatable local state
	// is created and false if deleted. Used by indexer.
	ModifiedAssetHoldings  map[AccountAsset]bool
	ModifiedAppLocalStates map[AccountApp]bool

	// initial hint for allocating data structures for StateDelta
	initialTransactionsCount int

	// The account totals reflecting the changes in this StateDelta object.
	Totals AccountTotals
}

// AccountDeltas stores ordered accounts and allows fast lookup by address
// type AccountDeltas struct {
// 	// Actual data. If an account is deleted, `accts` contains a balance record
// 	// with empty `AccountData`.
// 	accts []basics.BalanceRecord
// 	// cache for addr to deltas index resolution
// 	acctsCache map[basics.Address]int
// }

// NewBalanceRecord todo
type NewBalanceRecord struct {
	Addr basics.Address

	AccountData
}

// AppParamsRecord todo
type AppParamsRecord struct {
	Aidx   basics.AppIndex
	Addr   basics.Address
	Params *basics.AppParams
}

// AssetParamsRecord todo
type AssetParamsRecord struct {
	Aidx   basics.AssetIndex
	Addr   basics.Address
	Params *basics.AssetParams
}

// AppLocalStateRecord todo
type AppLocalStateRecord struct {
	Aidx  basics.AppIndex
	Addr  basics.Address
	State *basics.AppLocalState
}

// AssetHoldingRecord TODO
type AssetHoldingRecord struct {
	Aidx    basics.AssetIndex
	Addr    basics.Address
	Holding *basics.AssetHolding
}

// NewAccountDeltas stores ordered accounts and allows fast lookup by address
type NewAccountDeltas struct {
	// Actual data. If an account is deleted, `accts` contains a balance record
	// with empty `AccountData`.
	accts []NewBalanceRecord
	// cache for addr to deltas index resolution
	acctsCache map[basics.Address]int

	// AppParams deltas. If app params is deleted, there is a nil value in AppParamsRecord.params
	appParams []AppParamsRecord
	// caches for {addr, app id} to app params delta resolution
	appParamsCache map[AccountApp]int

	// Similar data for asset params, local states and holdings
	appLocalStates      []AppLocalStateRecord
	appLocalStatesCache map[AccountApp]int

	assetParams      []AssetParamsRecord
	assetParamsCache map[AccountAsset]int

	assetHoldings      []AssetHoldingRecord
	assetHoldingsCache map[AccountAsset]int
}

// MakeStateDelta creates a new instance of StateDelta.
// hint is amount of transactions for evaluation, 2 * hint is for sender and receiver balance records.
// This does not play well for AssetConfig and ApplicationCall transactions on scale
func MakeStateDelta(hdr *bookkeeping.BlockHeader, prevTimestamp int64, hint int, compactCertNext basics.Round) StateDelta {
	return StateDelta{
		NewAccts: MakeNewAccountDeltas(hint),
		Txids:    make(map[transactions.Txid]basics.Round, hint),
		Txleases: make(map[Txlease]basics.Round, hint),
		// asset or application creation are considered as rare events so do not pre-allocate space for them
		Creatables:               make(map[basics.CreatableIndex]ModifiedCreatable),
		Hdr:                      hdr,
		CompactCertNext:          compactCertNext,
		PrevTimestamp:            prevTimestamp,
		ModifiedAssetHoldings:    make(map[AccountAsset]bool),
		ModifiedAppLocalStates:   make(map[AccountApp]bool),
		initialTransactionsCount: hint,
	}
}

// MakeNewAccountDeltas creates account delta
func MakeNewAccountDeltas(hint int) NewAccountDeltas {
	return NewAccountDeltas{
		accts:      make([]NewBalanceRecord, 0, hint*2),
		acctsCache: make(map[basics.Address]int, hint*2),

		appParamsCache:      make(map[AccountApp]int),
		appLocalStatesCache: make(map[AccountApp]int),
		assetParamsCache:    make(map[AccountAsset]int),
		assetHoldingsCache:  make(map[AccountAsset]int),
	}
}

// GetData lookups AccountData by address
func (ad NewAccountDeltas) GetData(addr basics.Address) (AccountData, bool) {
	idx, ok := ad.acctsCache[addr]
	if !ok {
		return AccountData{}, false
	}
	return ad.accts[idx].AccountData, true
}

// GetAppParams returns app params delta value
func (ad NewAccountDeltas) GetAppParams(addr basics.Address, aidx basics.AppIndex) (*basics.AppParams, bool) {
	idx, ok := ad.appParamsCache[AccountApp{addr, aidx}]
	var result *basics.AppParams
	if ok {
		result = ad.appParams[idx].Params
	}
	return result, ok
}

// GetAssetParams returns asset params delta value
func (ad NewAccountDeltas) GetAssetParams(addr basics.Address, aidx basics.AssetIndex) (*basics.AssetParams, bool) {
	idx, ok := ad.assetParamsCache[AccountAsset{addr, aidx}]
	var result *basics.AssetParams
	if ok {
		result = ad.assetParams[idx].Params
	}
	return result, ok
}

// GetAppLocalState returns app local state delta value
func (ad NewAccountDeltas) GetAppLocalState(addr basics.Address, aidx basics.AppIndex) (*basics.AppLocalState, bool) {
	idx, ok := ad.appLocalStatesCache[AccountApp{addr, aidx}]
	var result *basics.AppLocalState
	if ok {
		result = ad.appLocalStates[idx].State
	}
	return result, ok
}

// GetAssetHolding returns asset holding delta value
func (ad NewAccountDeltas) GetAssetHolding(addr basics.Address, aidx basics.AssetIndex) (*basics.AssetHolding, bool) {
	idx, ok := ad.assetHoldingsCache[AccountAsset{addr, aidx}]
	var result *basics.AssetHolding
	if ok {
		result = ad.assetHoldings[idx].Holding
	}
	return result, ok
}

// ModifiedAccounts returns list of addresses of modified accounts
func (ad NewAccountDeltas) ModifiedAccounts() []basics.Address {
	result := make([]basics.Address, len(ad.accts))
	for i := 0; i < len(ad.accts); i++ {
		result[i] = ad.accts[i].Addr
	}

	// consistency check: ensure all addresses for deleted params/holdings/states are also in base accounts
	// it is nice to check created params/holdings/states but we lack of such info here
	for aapp, idx := range ad.appParamsCache {
		if ad.appParams[idx].Params == nil {
			if _, ok := ad.acctsCache[aapp.Address]; !ok {
				panic(fmt.Sprintf("account app param delta: addr %s not in base account", aapp.Address))
			}
		}
	}
	for aapp, idx := range ad.appLocalStatesCache {
		if ad.appLocalStates[idx].State == nil {
			if _, ok := ad.acctsCache[aapp.Address]; !ok {
				panic(fmt.Sprintf("account app state delta: addr %s not in base account", aapp.Address))
			}
		}
	}
	for aapp, idx := range ad.assetParamsCache {
		if ad.assetParams[idx].Params == nil {
			if _, ok := ad.acctsCache[aapp.Address]; !ok {
				panic(fmt.Sprintf("account asset param delta: addr %s not in base account", aapp.Address))
			}
		}
	}
	for aapp, idx := range ad.assetHoldingsCache {
		if ad.assetHoldings[idx].Holding == nil {
			if _, ok := ad.acctsCache[aapp.Address]; !ok {
				panic(fmt.Sprintf("account asset holding delta: addr %s not in base account", aapp.Address))
			}
		}
	}

	return result
}

// MergeAccounts applies other accounts into this StateDelta accounts
func (ad *NewAccountDeltas) MergeAccounts(other NewAccountDeltas) {
	for new := range other.accts {
		addr := other.accts[new].Addr
		acct := other.accts[new].AccountData
		ad.Upsert(addr, acct)
	}

	for aapp, idx := range other.appParamsCache {
		params := other.appParams[idx].Params
		ad.UpsertAppParams(aapp.Address, aapp.App, params)
	}
	for aapp, idx := range other.appLocalStatesCache {
		state := other.appLocalStates[idx].State
		ad.UpsertAppLocalState(aapp.Address, aapp.App, state)
	}
	for aapp, idx := range other.assetParamsCache {
		params := other.assetParams[idx].Params
		ad.UpsertAssetParams(aapp.Address, aapp.Asset, params)
	}
	for aapp, idx := range other.assetHoldingsCache {
		holding := other.assetHoldings[idx].Holding
		ad.UpsertAssetHolding(aapp.Address, aapp.Asset, holding)
	}
}

// GetResource looks up a pair of app or asset resources, given its index and type.
func (ad NewAccountDeltas) GetResource(addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (ret AccountResource, ok bool) {
	ret.CreatableIndex = aidx
	ret.CreatableType = ctype
	switch ctype {
	case basics.AssetCreatable:
		aa := AccountAsset{addr, basics.AssetIndex(aidx)}
		paramsIdx, okParams := ad.assetParamsCache[aa]
		if okParams {
			ret.AssetParams = ad.assetParams[paramsIdx].Params
		}
		holdingIdx, okHolding := ad.assetHoldingsCache[aa]
		if okHolding {
			ret.AssetHolding = ad.assetHoldings[holdingIdx].Holding
		}
		return ret, okHolding || okParams
	case basics.AppCreatable:
		aa := AccountApp{addr, basics.AppIndex(aidx)}
		paramsIdx, okParams := ad.appParamsCache[aa]
		if okParams {
			ret.AppParams = ad.appParams[paramsIdx].Params
		}
		localStateIdx, okLocalState := ad.appLocalStatesCache[aa]
		if okLocalState {
			ret.AppLocalState = ad.appLocalStates[localStateIdx].State
		}
		return ret, okLocalState || okParams
	}
	return ret, false
}

// Len returns number of stored accounts
func (ad *NewAccountDeltas) Len() int {
	return len(ad.accts)
}

// GetByIdx returns address and AccountData
// It does NOT check boundaries.
func (ad *NewAccountDeltas) GetByIdx(i int) (basics.Address, AccountData) {
	return ad.accts[i].Addr, ad.accts[i].AccountData
}

// Upsert adds ledgercore.AccountData into deltas
func (ad *NewAccountDeltas) Upsert(addr basics.Address, data AccountData) {
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

// UpsertAppParams adds app params delta
func (ad *NewAccountDeltas) UpsertAppParams(addr basics.Address, aidx basics.AppIndex, params *basics.AppParams) {
	key := AccountApp{addr, aidx}
	value := AppParamsRecord{aidx, addr, params}
	if idx, exist := ad.appParamsCache[key]; exist {
		ad.appParams[idx] = value
		return
	}

	last := len(ad.appParams)
	ad.appParams = append(ad.appParams, value)

	if ad.appParamsCache == nil {
		ad.appParamsCache = make(map[AccountApp]int)
	}
	ad.appParamsCache[key] = last
}

// UpsertAssetParams adds asset params delta
func (ad *NewAccountDeltas) UpsertAssetParams(addr basics.Address, aidx basics.AssetIndex, params *basics.AssetParams) {
	key := AccountAsset{addr, aidx}
	value := AssetParamsRecord{aidx, addr, params}
	if idx, exist := ad.assetParamsCache[key]; exist {
		ad.assetParams[idx] = value
		return
	}

	last := len(ad.assetParams)
	ad.assetParams = append(ad.assetParams, AssetParamsRecord{aidx, addr, params})

	if ad.assetParamsCache == nil {
		ad.assetParamsCache = make(map[AccountAsset]int)
	}
	ad.assetParamsCache[key] = last
}

// UpsertAppLocalState adds app local state delta
func (ad *NewAccountDeltas) UpsertAppLocalState(addr basics.Address, aidx basics.AppIndex, ls *basics.AppLocalState) {
	key := AccountApp{addr, aidx}
	value := AppLocalStateRecord{aidx, addr, ls}
	if idx, exist := ad.appLocalStatesCache[key]; exist {
		ad.appLocalStates[idx] = value
		return
	}

	last := len(ad.appLocalStates)
	ad.appLocalStates = append(ad.appLocalStates, value)

	if ad.appLocalStatesCache == nil {
		ad.appLocalStatesCache = make(map[AccountApp]int)
	}

	ad.appLocalStatesCache[key] = last
}

// UpsertAssetHolding adds asset holding delta
func (ad *NewAccountDeltas) UpsertAssetHolding(addr basics.Address, aidx basics.AssetIndex, holding *basics.AssetHolding) {
	key := AccountAsset{addr, aidx}
	value := AssetHoldingRecord{aidx, addr, holding}
	if idx, exist := ad.assetHoldingsCache[key]; exist {
		ad.assetHoldings[idx] = value
		return
	}

	last := len(ad.assetHoldings)
	ad.assetHoldings = append(ad.assetHoldings, value)

	if ad.assetHoldingsCache == nil {
		ad.assetHoldingsCache = make(map[AccountAsset]int)
	}

	ad.assetHoldingsCache[key] = last
}

// OptimizeAllocatedMemory by reallocating maps to needed capacity
// For each data structure, reallocate if it would save us at least 50MB aggregate
func (sd *StateDelta) OptimizeAllocatedMemory(proto config.ConsensusParams) {
	// accts takes up 232 bytes per entry, and is saved for 320 rounds
	if uint64(cap(sd.NewAccts.accts)-len(sd.NewAccts.accts))*accountArrayEntrySize*proto.MaxBalLookback > stateDeltaTargetOptimizationThreshold {
		accts := make([]NewBalanceRecord, len(sd.NewAccts.acctsCache))
		copy(accts, sd.NewAccts.accts)
		sd.NewAccts.accts = accts
	}

	// acctsCache takes up 64 bytes per entry, and is saved for 320 rounds
	// realloc if original allocation capacity greater than length of data, and space difference is significant
	if 2*sd.initialTransactionsCount > len(sd.NewAccts.acctsCache) &&
		uint64(2*sd.initialTransactionsCount-len(sd.NewAccts.acctsCache))*accountMapCacheEntrySize*proto.MaxBalLookback > stateDeltaTargetOptimizationThreshold {
		acctsCache := make(map[basics.Address]int, len(sd.NewAccts.acctsCache))
		for k, v := range sd.NewAccts.acctsCache {
			acctsCache[k] = v
		}
		sd.NewAccts.acctsCache = acctsCache
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
func (ad NewAccountDeltas) GetBasicsAccountData(addr basics.Address) (basics.AccountData, bool) {
	idx, ok := ad.acctsCache[addr]
	if !ok {
		return basics.AccountData{}, false
	}

	result := basics.AccountData{}
	acct := ad.accts[idx].AccountData
	AssignAccountData(&result, acct)

	if len(ad.appParamsCache) > 0 {
		result.AppParams = make(map[basics.AppIndex]basics.AppParams)
		for aapp, idx := range ad.appParamsCache {
			rec := ad.appParams[idx]
			if aapp.Address == addr {
				if rec.Params != nil {
					result.AppParams[aapp.App] = *rec.Params
				}
			}
		}
		if len(result.AppParams) == 0 {
			result.AppParams = nil
		}
	}

	if len(ad.appLocalStatesCache) > 0 {
		result.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
		for aapp, idx := range ad.appLocalStatesCache {
			rec := ad.appLocalStates[idx]
			if aapp.Address == addr {
				if rec.State != nil {
					result.AppLocalStates[aapp.App] = *rec.State
				}
			}
		}
		if len(result.AppLocalStates) == 0 {
			result.AppLocalStates = nil
		}
	}

	if len(ad.assetParamsCache) > 0 {
		result.AssetParams = make(map[basics.AssetIndex]basics.AssetParams)
		for aapp, idx := range ad.assetParamsCache {
			rec := ad.assetParams[idx]
			if aapp.Address == addr {
				if rec.Params != nil {
					result.AssetParams[aapp.Asset] = *rec.Params
				}
			}
		}
		if len(result.AssetParams) == 0 {
			result.AssetParams = nil
		}
	}

	if len(ad.assetHoldingsCache) > 0 {
		result.Assets = make(map[basics.AssetIndex]basics.AssetHolding)
		for aapp, idx := range ad.assetHoldingsCache {
			rec := ad.assetHoldings[idx]
			if aapp.Address == addr {
				if rec.Holding != nil {
					result.Assets[aapp.Asset] = *rec.Holding
				}
			}
		}
		if len(result.Assets) == 0 {
			result.Assets = nil
		}
	}

	return result, true
}

// ToModifiedCreatables creates map of ModifiedCreatable
func (ad NewAccountDeltas) ToModifiedCreatables(seen map[basics.CreatableIndex]struct{}) map[basics.CreatableIndex]ModifiedCreatable {
	result := make(map[basics.CreatableIndex]ModifiedCreatable, len(ad.appParams)+len(ad.assetParams))
	for aapp, idx := range ad.appParamsCache {
		rec := ad.appParams[idx]
		if rec.Params == nil {
			result[basics.CreatableIndex(rec.Aidx)] = ModifiedCreatable{
				Ctype:   basics.AppCreatable,
				Created: false,
				Creator: aapp.Address,
			}
		} else if _, ok := seen[basics.CreatableIndex(rec.Aidx)]; !ok {
			result[basics.CreatableIndex(rec.Aidx)] = ModifiedCreatable{
				Ctype:   basics.AppCreatable,
				Created: true,
				Creator: aapp.Address,
			}
		}
	}

	for aapp, idx := range ad.assetParamsCache {
		rec := ad.assetParams[idx]
		if rec.Params == nil {
			result[basics.CreatableIndex(rec.Aidx)] = ModifiedCreatable{
				Ctype:   basics.AssetCreatable,
				Created: false,
				Creator: aapp.Address,
			}
		} else if _, ok := seen[basics.CreatableIndex(rec.Aidx)]; !ok {
			result[basics.CreatableIndex(rec.Aidx)] = ModifiedCreatable{
				Ctype:   basics.AssetCreatable,
				Created: true,
				Creator: aapp.Address,
			}
		}
	}

	return result
}

// AccumulateDeltas adds delta into base accounts map in-place
func AccumulateDeltas(base map[basics.Address]basics.AccountData, deltas NewAccountDeltas) map[basics.Address]basics.AccountData {
	for i := 0; i < deltas.Len(); i++ {
		addr, _ := deltas.GetByIdx(i)
		if acct, ok := deltas.GetData(addr); ok {
			var ad basics.AccountData
			AssignAccountData(&ad, acct)
			base[addr] = ad
		}
	}

	for aapp, idx := range deltas.appParamsCache {
		ad := base[aapp.Address]
		acct, ok := deltas.GetData(aapp.Address)
		if !ok || acct.TotalAppParams == 0 {
			continue
		}
		if ad.AppParams == nil {
			ad.AppParams = make(map[basics.AppIndex]basics.AppParams, acct.TotalAppParams)
		}
		rec := deltas.appParams[idx]
		if rec.Params == nil {
			delete(ad.AppParams, aapp.App)
		} else {
			ad.AppParams[aapp.App] = *rec.Params
		}
		base[aapp.Address] = ad
	}

	for aapp, idx := range deltas.appLocalStatesCache {
		ad := base[aapp.Address]
		acct, ok := deltas.GetData(aapp.Address)
		if !ok || acct.TotalAppLocalStates == 0 {
			continue
		}
		if ad.AppLocalStates == nil {
			ad.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState, acct.TotalAppLocalStates)
		}
		rec := deltas.appLocalStates[idx]
		if rec.State == nil {
			delete(ad.AppLocalStates, aapp.App)
		} else {
			ad.AppLocalStates[aapp.App] = *rec.State
		}
		base[aapp.Address] = ad
	}

	for aapp, idx := range deltas.assetParamsCache {
		ad := base[aapp.Address]
		acct, ok := deltas.GetData(aapp.Address)
		if !ok || acct.TotalAssetParams == 0 {
			continue
		}
		if ad.AssetParams == nil {
			ad.AssetParams = make(map[basics.AssetIndex]basics.AssetParams, acct.TotalAssetParams)
		}
		rec := deltas.assetParams[idx]
		if rec.Params == nil {
			delete(ad.AssetParams, aapp.Asset)
		} else {
			ad.AssetParams[aapp.Asset] = *rec.Params
		}
		base[aapp.Address] = ad
	}

	for aapp, idx := range deltas.assetHoldingsCache {
		ad := base[aapp.Address]
		acct, ok := deltas.GetData(aapp.Address)
		if !ok || acct.TotalAssets == 0 {
			continue
		}
		if ad.Assets == nil {
			ad.Assets = make(map[basics.AssetIndex]basics.AssetHolding, acct.TotalAssets)
		}
		rec := deltas.assetHoldings[idx]
		if rec.Holding == nil {
			delete(ad.Assets, aapp.Asset)
		} else {
			ad.Assets[aapp.Asset] = *rec.Holding
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
func (ad NewAccountDeltas) ApplyToBasicsAccountData(addr basics.Address, prev basics.AccountData) (result basics.AccountData) {
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
		// if result.AppParams == nil {
		// 	result.AppParams = make(map[basics.AppIndex]basics.AppParams)
		// }
		for aapp, idx := range ad.appParamsCache {
			if aapp.Address == addr {
				if idx >= len(ad.appParams) {
					fmt.Println("overflow")
				}

				rec := ad.appParams[idx]
				if rec.Params == nil {
					delete(result.AppParams, aapp.App)
				} else {
					result.AppParams[aapp.App] = *rec.Params
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
		// if result.AppLocalStates == nil {
		// 	result.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
		// }

		for aapp, idx := range ad.appLocalStatesCache {
			if aapp.Address == addr {
				if idx >= len(ad.appLocalStates) {
					fmt.Println("overflow")
				}

				rec := ad.appLocalStates[idx]
				if rec.State == nil {
					delete(result.AppLocalStates, aapp.App)
				} else {
					result.AppLocalStates[aapp.App] = *rec.State
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
		// if result.AssetParams == nil {
		// 	result.AssetParams = make(map[basics.AssetIndex]basics.AssetParams)
		// }
		for aapp, idx := range ad.assetParamsCache {
			if aapp.Address == addr {
				if idx >= len(ad.assetParams) {
					fmt.Println("overflow")
				}
				rec := ad.assetParams[idx]
				if rec.Params == nil {
					delete(result.AssetParams, aapp.Asset)
				} else {
					result.AssetParams[aapp.Asset] = *rec.Params
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
		// if result.Assets == nil {
		// 	result.Assets = make(map[basics.AssetIndex]basics.AssetHolding)
		// }
		for aapp, idx := range ad.assetHoldingsCache {
			if aapp.Address == addr {
				if idx >= len(ad.assetHoldings) {
					fmt.Println("overflow")
				}

				rec := ad.assetHoldings[idx]
				if rec.Holding == nil {
					delete(result.Assets, aapp.Asset)
				} else {
					result.Assets[aapp.Asset] = *rec.Holding
				}
			}
		}
		if len(result.Assets) == 0 {
			result.Assets = nil
		}
	}

	return result
}

// GetAllAppParams todo
func (ad *NewAccountDeltas) GetAllAppParams() []AppParamsRecord {
	return ad.appParams
}

// GetAllAppLocalStates todo
func (ad *NewAccountDeltas) GetAllAppLocalStates() []AppLocalStateRecord {
	return ad.appLocalStates
}

// GetAllAssetParams todo
func (ad *NewAccountDeltas) GetAllAssetParams() []AssetParamsRecord {
	return ad.assetParams
}

// GetAllAssetsHoldings todo
func (ad *NewAccountDeltas) GetAllAssetsHoldings() []AssetHoldingRecord {
	return ad.assetHoldings
}

// ExtractDelta extracts only data belonging to a specific address
func (ad NewAccountDeltas) ExtractDelta(addr basics.Address) (result NewAccountDeltas) {
	acct, ok := ad.GetData(addr)
	if ok {
		result = MakeNewAccountDeltas(1)
		result.Upsert(addr, acct)
		result.mergeInOther(addr, ad)
	}
	return result
}

// mergeInOther adds app/asset params, local states and holdings from other to ad for the specified address
func (ad *NewAccountDeltas) mergeInOther(addr basics.Address, other NewAccountDeltas) {
	for _, rec := range other.appParams {
		if rec.Addr == addr {
			var newVal *basics.AppParams
			if rec.Params != nil {
				cp := *rec.Params
				newVal = &cp
			}
			last := len(ad.appParams)
			key := AccountApp{rec.Addr, rec.Aidx}
			ad.appParams = append(ad.appParams, AppParamsRecord{rec.Aidx, addr, newVal})
			ad.appParamsCache[key] = last
		}
	}

	for _, rec := range other.appLocalStates {
		if rec.Addr == addr {
			var newVal *basics.AppLocalState
			if rec.State != nil {
				cp := *rec.State
				newVal = &cp
			}
			last := len(ad.appLocalStates)
			key := AccountApp{rec.Addr, rec.Aidx}
			ad.appLocalStates = append(ad.appLocalStates, AppLocalStateRecord{rec.Aidx, addr, newVal})
			ad.appLocalStatesCache[key] = last
		}
	}

	for _, rec := range other.assetParams {
		if rec.Addr == addr {
			var newVal *basics.AssetParams
			if rec.Params != nil {
				cp := *rec.Params
				newVal = &cp
			}
			last := len(ad.assetParams)
			key := AccountAsset{rec.Addr, rec.Aidx}
			ad.assetParams = append(ad.assetParams, AssetParamsRecord{rec.Aidx, addr, newVal})
			ad.assetParamsCache[key] = last
		}
	}

	for _, rec := range other.assetHoldings {
		if rec.Addr == addr {
			var newVal *basics.AssetHolding
			if rec.Holding != nil {
				cp := *rec.Holding
				newVal = &cp
			}
			last := len(ad.assetHoldings)
			key := AccountAsset{rec.Addr, rec.Aidx}
			ad.assetHoldings = append(ad.assetHoldings, AssetHoldingRecord{rec.Aidx, addr, newVal})
			ad.assetHoldingsCache[key] = last
		}
	}
}
