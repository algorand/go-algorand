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

package ledgercore

import (
	"fmt"
	"maps"

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

// IncludedTransactions defines the transactions included in a block, their index and last valid round.
type IncludedTransactions struct {
	LastValid basics.Round
	Intra     uint64 // the index of the transaction in the block
}

// A KvValueDelta shows how the Data associated with a key in the kvstore has
// changed.  However, OldData is elided during evaluation, and only filled in at
// the conclusion of a block during the called to roundCowState.deltas()
type KvValueDelta struct {
	// Data stores the most recent value (nil == deleted)
	Data []byte

	// OldData stores the previous vlaue (nil == didn't exist)
	OldData []byte
}

// StateDelta describes the delta between a given round to the previous round
// If adding a new field not explicitly allocated by PopulateStateDelta, make sure to reset
// it in .ReuseStateDelta to avoid dirty memory errors.
// If adding fields make sure to add them to the .Reset() method to avoid dirty state
type StateDelta struct {
	// modified new accounts
	Accts AccountDeltas

	// modified kv pairs (nil == delete)
	// not preallocated use .AddKvMod to insert instead of direct assignment
	KvMods map[string]KvValueDelta

	// new Txids for the txtail and TxnCounter, mapped to txn.LastValid
	Txids map[transactions.Txid]IncludedTransactions

	// new txleases for the txtail mapped to expiration
	// not pre-allocated so use .AddTxLease to insert instead of direct assignment
	Txleases map[Txlease]basics.Round

	// new creatables creator lookup table
	// not pre-allocated so use .AddCreatable to insert instead of direct assignment
	Creatables map[basics.CreatableIndex]ModifiedCreatable

	// new block header; read-only
	Hdr *bookkeeping.BlockHeader

	// StateProofNext represents modification on StateProofNextRound field in the block header. If the block contains
	// a valid state proof transaction, this field will contain the next round for state proof.
	// otherwise it will be set to 0.
	StateProofNext basics.Round

	// previous block timestamp
	PrevTimestamp int64

	// initial hint for allocating data structures for StateDelta
	initialHint int

	// The account totals reflecting the changes in this StateDelta object.
	Totals AccountTotals
}

// BalanceRecord is similar to basics.BalanceRecord but with decoupled base and voting data
type BalanceRecord struct {
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
// If adding fields make sure to add them to the .reset() method to avoid dirty state
type AccountDeltas struct {
	// Actual data. If an account is deleted, `Accts` contains the BalanceRecord
	// with an empty `AccountData` and a populated `Addr`.
	Accts []BalanceRecord
	// cache for addr to deltas index resolution
	acctsCache map[basics.Address]int

	// AppResources deltas. If app params or local state is deleted, there is a nil value in AppResources.Params or AppResources.State and Deleted flag set
	AppResources []AppResourceRecord
	// caches for {addr, app id} to app params delta resolution
	// not preallocated - use UpsertAppResource instead of inserting directly
	appResourcesCache map[AccountApp]int

	AssetResources []AssetResourceRecord
	// not preallocated - use UpsertAssertResource instead of inserting directly
	assetResourcesCache map[AccountAsset]int
}

// MakeStateDelta creates a new instance of StateDelta
// hint is amount of transactions for evaluation, 2 * hint is for sender and receiver balance records.
// This does not play well for AssetConfig and ApplicationCall transactions on scale
func MakeStateDelta(hdr *bookkeeping.BlockHeader, prevTimestamp int64, hint int, stateProofNext basics.Round) (sd StateDelta) {
	sd.PopulateStateDelta(hdr, prevTimestamp, hint, stateProofNext)
	return
}

// PopulateStateDelta populates an existing StateDelta struct.
// Used as a helper for MakeStateDelta as well as for re-using already allocated structs from sync.Pool
func (sd *StateDelta) PopulateStateDelta(hdr *bookkeeping.BlockHeader, prevTimestamp int64, hint int, stateProofNext basics.Round) {
	if sd.Txids == nil {
		sd.Txids = make(map[transactions.Txid]IncludedTransactions, hint)
	}
	if sd.Accts.notAllocated() {
		sd.Accts = MakeAccountDeltas(hint)
		sd.initialHint = hint
	}
	sd.Hdr = hdr
	sd.StateProofNext = stateProofNext
	sd.PrevTimestamp = prevTimestamp
}

// Hydrate reverses the effects of Dehydrate, restoring internal data.
func (sd *StateDelta) Hydrate() {
	sd.Accts.Hydrate()
}

// Dehydrate normalized the fields of this StateDelta, and clears any redundant internal caching.
// This is useful for comparing StateDelta objects for equality.
//
// NOTE: initialHint is lost in dehydration. All other fields can be restored by calling Hydrate()
func (sd *StateDelta) Dehydrate() {
	sd.Accts.Dehydrate()
	sd.initialHint = 0
	if sd.KvMods == nil {
		sd.KvMods = make(map[string]KvValueDelta)
	}
	if sd.Txids == nil {
		sd.Txids = make(map[transactions.Txid]IncludedTransactions)
	}
	if sd.Txleases == nil {
		sd.Txleases = make(map[Txlease]basics.Round)
	}
	if sd.Creatables == nil {
		sd.Creatables = make(map[basics.CreatableIndex]ModifiedCreatable)
	}
}

// MakeAccountDeltas creates account delta
// if adding new fields make sure to add them to the .reset() and .isEmpty() methods
func MakeAccountDeltas(hint int) AccountDeltas {
	return AccountDeltas{
		Accts:      make([]BalanceRecord, 0, hint*2),
		acctsCache: make(map[basics.Address]int, hint*2),
	}
}

// Hydrate reverses the effects of Dehydrate, restoring internal data.
func (ad *AccountDeltas) Hydrate() {
	if ad.acctsCache == nil {
		ad.acctsCache = make(map[basics.Address]int, len(ad.Accts))
	}
	for idx, acct := range ad.Accts {
		ad.acctsCache[acct.Addr] = idx
	}

	if ad.appResourcesCache == nil {
		ad.appResourcesCache = make(map[AccountApp]int, len(ad.AppResources))
	}
	for idx, app := range ad.AppResources {
		ad.appResourcesCache[AccountApp{app.Addr, app.Aidx}] = idx
	}

	if ad.assetResourcesCache == nil {
		ad.assetResourcesCache = make(map[AccountAsset]int, len(ad.AssetResources))
	}
	for idx, asset := range ad.AssetResources {
		ad.assetResourcesCache[AccountAsset{asset.Addr, asset.Aidx}] = idx
	}
}

// Dehydrate normalizes the fields of this AccountDeltas, and clears any redundant internal caching.
// This is useful for comparing AccountDeltas objects for equality.
func (ad *AccountDeltas) Dehydrate() {
	if ad.Accts == nil {
		ad.Accts = []BalanceRecord{}
	}
	if ad.AppResources == nil {
		ad.AppResources = []AppResourceRecord{}
	}
	if ad.AssetResources == nil {
		ad.AssetResources = []AssetResourceRecord{}
	}
	if ad.acctsCache == nil {
		ad.acctsCache = make(map[basics.Address]int)
	}
	clear(ad.acctsCache)
	if ad.appResourcesCache == nil {
		ad.appResourcesCache = make(map[AccountApp]int)
	}
	clear(ad.appResourcesCache)
	if ad.assetResourcesCache == nil {
		ad.assetResourcesCache = make(map[AccountAsset]int)
	}
	clear(ad.assetResourcesCache)
}

// Reset resets the StateDelta for re-use with sync.Pool
func (sd *StateDelta) Reset() {
	sd.Accts.reset()
	clear(sd.Txids)
	clear(sd.Txleases)
	clear(sd.Creatables)
	clear(sd.KvMods)
	sd.Totals = AccountTotals{}

	// these fields are going to be populated on next use but resetting them anyway for safety.
	// we are not resetting sd.initialHint since it should only be reset if reallocating AccountDeltas
	sd.Hdr = nil
	sd.StateProofNext = basics.Round(0)
	sd.PrevTimestamp = 0
}

// reset clears out allocated slices from AccountDeltas struct for reuse with sync.Pool
func (ad *AccountDeltas) reset() {
	// reset the slices
	ad.Accts = ad.Accts[:0]
	ad.AppResources = ad.AppResources[:0]
	ad.AssetResources = ad.AssetResources[:0]

	// reset the maps
	clear(ad.acctsCache)
	clear(ad.appResourcesCache)
	clear(ad.assetResourcesCache)
}

// notAllocated returns true if any of the fields allocated by MakeAccountDeltas is nil
func (ad *AccountDeltas) notAllocated() bool {
	return ad.Accts == nil || ad.acctsCache == nil
}

// GetData lookups AccountData by address
func (ad AccountDeltas) GetData(addr basics.Address) (AccountData, bool) {
	idx, ok := ad.acctsCache[addr]
	if !ok {
		return AccountData{}, false
	}
	return ad.Accts[idx].AccountData, true
}

// GetAppParams returns app params delta value
func (ad AccountDeltas) GetAppParams(addr basics.Address, aidx basics.AppIndex) (AppParamsDelta, bool) {
	if idx, ok := ad.appResourcesCache[AccountApp{addr, aidx}]; ok {
		result := ad.AppResources[idx].Params
		return result, result.Deleted || result.Params != nil
	}
	return AppParamsDelta{}, false
}

// GetAssetParams returns asset params delta value
func (ad AccountDeltas) GetAssetParams(addr basics.Address, aidx basics.AssetIndex) (AssetParamsDelta, bool) {
	if idx, ok := ad.assetResourcesCache[AccountAsset{addr, aidx}]; ok {
		result := ad.AssetResources[idx].Params
		return result, result.Deleted || result.Params != nil
	}
	return AssetParamsDelta{}, false
}

// GetAppLocalState returns app local state delta value
func (ad AccountDeltas) GetAppLocalState(addr basics.Address, aidx basics.AppIndex) (AppLocalStateDelta, bool) {
	if idx, ok := ad.appResourcesCache[AccountApp{addr, aidx}]; ok {
		result := ad.AppResources[idx].State
		return result, result.Deleted || result.LocalState != nil
	}
	return AppLocalStateDelta{}, false
}

// GetAssetHolding returns asset holding delta value
func (ad AccountDeltas) GetAssetHolding(addr basics.Address, aidx basics.AssetIndex) (AssetHoldingDelta, bool) {
	if idx, ok := ad.assetResourcesCache[AccountAsset{addr, aidx}]; ok {
		result := ad.AssetResources[idx].Holding
		return result, result.Deleted || result.Holding != nil
	}
	return AssetHoldingDelta{}, false
}

// ModifiedAccounts returns list of addresses of modified accounts
func (ad AccountDeltas) ModifiedAccounts() []basics.Address {
	result := make([]basics.Address, len(ad.Accts))
	for i := 0; i < len(ad.Accts); i++ {
		result[i] = ad.Accts[i].Addr
	}

	// consistency check: ensure all addresses for deleted params/holdings/states are also in base accounts
	// it is nice to check created params/holdings/states but we lack of such info here
	for aapp, idx := range ad.appResourcesCache {
		if ad.AppResources[idx].Params.Deleted {
			if _, ok := ad.acctsCache[aapp.Address]; !ok {
				panic(fmt.Sprintf("account app param delta: addr %s not in base account", aapp.Address))
			}
		}
		if ad.AppResources[idx].State.Deleted {
			if _, ok := ad.acctsCache[aapp.Address]; !ok {
				panic(fmt.Sprintf("account app state delta: addr %s not in base account", aapp.Address))
			}
		}
	}
	for aapp, idx := range ad.assetResourcesCache {
		if ad.AssetResources[idx].Params.Deleted {
			if _, ok := ad.acctsCache[aapp.Address]; !ok {
				panic(fmt.Sprintf("account asset param delta: addr %s not in base account", aapp.Address))
			}
		}
		if ad.AssetResources[idx].Holding.Deleted {
			if _, ok := ad.acctsCache[aapp.Address]; !ok {
				panic(fmt.Sprintf("account asset holding delta: addr %s not in base account", aapp.Address))
			}
		}
	}

	return result
}

// MergeAccounts applies other accounts into this StateDelta accounts
func (ad *AccountDeltas) MergeAccounts(other AccountDeltas) {
	for i := range other.Accts {
		balanceRecord := &other.Accts[i]
		ad.Upsert(balanceRecord.Addr, balanceRecord.AccountData)
	}
	for i := range other.AppResources {
		appResource := &other.AppResources[i]
		ad.UpsertAppResource(appResource.Addr, appResource.Aidx, appResource.Params, appResource.State)
	}
	for i := range other.AssetResources {
		assetResource := &other.AssetResources[i]
		ad.UpsertAssetResource(assetResource.Addr, assetResource.Aidx, assetResource.Params, assetResource.Holding)
	}
}

// GetResource looks up a pair of app or asset resources, given its index and type.
func (ad AccountDeltas) GetResource(addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (ret AccountResource, ok bool) {
	switch ctype {
	case basics.AssetCreatable:
		aa := AccountAsset{addr, basics.AssetIndex(aidx)}
		idx, ok := ad.assetResourcesCache[aa]
		if ok {
			ret.AssetParams = ad.AssetResources[idx].Params.Params
			ret.AssetHolding = ad.AssetResources[idx].Holding.Holding
		}
		return ret, ok
	case basics.AppCreatable:
		aa := AccountApp{addr, basics.AppIndex(aidx)}
		idx, ok := ad.appResourcesCache[aa]
		if ok {
			ret.AppParams = ad.AppResources[idx].Params.Params
			ret.AppLocalState = ad.AppResources[idx].State.LocalState
		}
		return ret, ok
	}
	return ret, false
}

// Len returns number of stored accounts
func (ad *AccountDeltas) Len() int {
	return len(ad.Accts)
}

// GetByIdx returns address and AccountData
// It does NOT check boundaries.
func (ad *AccountDeltas) GetByIdx(i int) (basics.Address, AccountData) {
	return ad.Accts[i].Addr, ad.Accts[i].AccountData
}

// Upsert adds ledgercore.AccountData into deltas
func (ad *AccountDeltas) Upsert(addr basics.Address, data AccountData) {
	if idx, exist := ad.acctsCache[addr]; exist { // nil map lookup is OK
		ad.Accts[idx] = BalanceRecord{Addr: addr, AccountData: data}
		return
	}

	last := len(ad.Accts)
	ad.Accts = append(ad.Accts, BalanceRecord{Addr: addr, AccountData: data})

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
		ad.AppResources[idx] = value
		return
	}

	last := len(ad.AppResources)
	ad.AppResources = append(ad.AppResources, value)

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
		ad.AssetResources[idx] = value
		return
	}

	last := len(ad.AssetResources)
	ad.AssetResources = append(ad.AssetResources, value)

	if ad.assetResourcesCache == nil {
		ad.assetResourcesCache = make(map[AccountAsset]int)
	}
	ad.assetResourcesCache[key] = last
}

// AddTxLease adds a new TxLease to the StateDelta
func (sd *StateDelta) AddTxLease(txLease Txlease, expired basics.Round) {
	if sd.Txleases == nil {
		sd.Txleases = make(map[Txlease]basics.Round)
	}
	sd.Txleases[txLease] = expired
}

// AddCreatable adds a new Creatable to the StateDelta
func (sd *StateDelta) AddCreatable(idx basics.CreatableIndex, creatable ModifiedCreatable) {
	if sd.Creatables == nil {
		sd.Creatables = make(map[basics.CreatableIndex]ModifiedCreatable)
	}
	sd.Creatables[idx] = creatable
}

// AddKvMod adds a new KvMod to the StateDelta
func (sd *StateDelta) AddKvMod(key string, delta KvValueDelta) {
	if sd.KvMods == nil {
		sd.KvMods = make(map[string]KvValueDelta)
	}
	sd.KvMods[key] = delta
}

// OptimizeAllocatedMemory by reallocating maps to needed capacity
// For each data structure, reallocate if it would save us at least 50MB aggregate
// If provided maxBalLookback or maxTxnLife are zero, dependent optimizations will not occur.
func (sd *StateDelta) OptimizeAllocatedMemory(maxBalLookback uint64) {
	// Accts takes up 232 bytes per entry, and is saved for 320 rounds
	if uint64(cap(sd.Accts.Accts)-len(sd.Accts.Accts))*accountArrayEntrySize*maxBalLookback > stateDeltaTargetOptimizationThreshold {
		accts := make([]BalanceRecord, len(sd.Accts.Accts))
		copy(accts, sd.Accts.Accts)
		sd.Accts.Accts = accts
	}

	// acctsCache takes up 64 bytes per entry, and is saved for 320 rounds
	// realloc if original allocation capacity greater than length of data, and space difference is significant
	if 2*sd.initialHint > len(sd.Accts.acctsCache) &&
		uint64(2*sd.initialHint-len(sd.Accts.acctsCache))*accountMapCacheEntrySize*maxBalLookback > stateDeltaTargetOptimizationThreshold {
		sd.Accts.acctsCache = maps.Clone(sd.Accts.acctsCache)
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
	acct := ad.Accts[idx].AccountData
	AssignAccountData(&result, acct)

	if len(ad.appResourcesCache) > 0 {
		result.AppParams = make(map[basics.AppIndex]basics.AppParams)
		result.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
		for aapp, idx := range ad.appResourcesCache {
			rec := ad.AppResources[idx]
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
			rec := ad.AssetResources[idx]
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
	result := make(map[basics.CreatableIndex]ModifiedCreatable, len(ad.AppResources)+len(ad.AssetResources))
	for aapp, idx := range ad.appResourcesCache {
		rec := ad.AppResources[idx]
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
		rec := ad.AssetResources[idx]
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
		rec := deltas.AppResources[idx]
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
		rec := deltas.AssetResources[idx]
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
		maps.Copy(result.AppParams, prev.AppParams)
		for aapp, idx := range ad.appResourcesCache {
			if aapp.Address == addr {
				rec := ad.AppResources[idx]
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
		maps.Copy(result.AppLocalStates, prev.AppLocalStates)
		for aapp, idx := range ad.appResourcesCache {
			if aapp.Address == addr {
				rec := ad.AppResources[idx]
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
		maps.Copy(result.AssetParams, prev.AssetParams)
		for aapp, idx := range ad.assetResourcesCache {
			if aapp.Address == addr {
				rec := ad.AssetResources[idx]
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
		maps.Copy(result.Assets, prev.Assets)
		for aapp, idx := range ad.assetResourcesCache {
			if aapp.Address == addr {
				rec := ad.AssetResources[idx]
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
	return ad.AppResources
}

// GetAllAssetResources returns all AssetResourceRecords
func (ad *AccountDeltas) GetAllAssetResources() []AssetResourceRecord {
	return ad.AssetResources
}
