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

// A Txlease is a transaction (sender, lease) pair which uniquely specifies a
// transaction lease.
type Txlease struct {
	Sender basics.Address
	Lease  [32]byte
}

// StateDelta describes the delta between a given round to the previous round
type StateDelta struct {
	// modified accounts
	Accts AccountDeltas

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
}

// EntityAction is an enum of actions on holdings
//msgp:ignore EntityAction
type EntityAction uint64

const (
	// ActionHoldingCreate is for asset holding creation
	ActionHoldingCreate EntityAction = 1 + iota
	// ActionHoldingDelete is for asset holding creation
	ActionHoldingDelete
	// ActionParamsCreate is for asset holding creation
	ActionParamsCreate
	// ActionParamsDelete is for asset holding creation
	ActionParamsDelete
)

// EntityDelta holds asset/app actions
//msgp:ignore EntityDelta
type EntityDelta map[basics.CreatableIndex]EntityAction

// AccountEntityDelta holds asset/app actions per account
//msgp:ignore AccountEntityDelta
type AccountEntityDelta map[basics.Address]EntityDelta

// AccountDeltas stores ordered accounts and allows fast lookup by address
//msgp:ignore AccountDeltas
type AccountDeltas struct {
	// actual data
	accts []PersistedBalanceRecord
	// cache for addr to deltas index resolution
	acctsCache map[basics.Address]int
	// entityHoldings keeps track of created and deleted assets holdings and app local states per address
	entityHoldings AccountEntityDelta
	// entityParams keeps track of created and deleted asset and app params per address
	entityParams AccountEntityDelta
}

// PersistedBalanceRecord is similar to BalanceRecord but contains PersistedAccountData
//msgp:ignore PersistedBalanceRecord
type PersistedBalanceRecord struct {
	Addr basics.Address
	PersistedAccountData
}

// MakeStateDelta creates a new instance of StateDelta.
// hint is amount of transactions for evaluation, 2 * hint is for sender and receiver balance records.
// This does not play well for AssetConfig and ApplicationCall transactions on scale
func MakeStateDelta(hdr *bookkeeping.BlockHeader, prevTimestamp int64, hint int, compactCertNext basics.Round) StateDelta {
	return StateDelta{
		Accts: AccountDeltas{
			accts:          make([]PersistedBalanceRecord, 0, hint*2),
			acctsCache:     make(map[basics.Address]int, hint*2),
			entityHoldings: make(AccountEntityDelta),
			entityParams:   make(AccountEntityDelta),
		},
		Txids:    make(map[transactions.Txid]basics.Round, hint),
		Txleases: make(map[Txlease]basics.Round, hint),
		// asset or application creation are considered as rare events so do not pre-allocate space for them
		Creatables:               make(map[basics.CreatableIndex]ModifiedCreatable),
		Hdr:                      hdr,
		PrevTimestamp:            prevTimestamp,
		initialTransactionsCount: hint,
		CompactCertNext:          compactCertNext,
	}
}

// Get lookups AccountData by address
func (ad *AccountDeltas) Get(addr basics.Address) (PersistedAccountData, bool) {
	idx, ok := ad.acctsCache[addr]
	if !ok {
		return PersistedAccountData{}, false
	}
	return ad.accts[idx].PersistedAccountData, true
}

// ModifiedAccounts returns list of addresses of modified accounts
func (ad *AccountDeltas) ModifiedAccounts() []basics.Address {
	result := make([]basics.Address, len(ad.accts))
	for i := 0; i < len(ad.accts); i++ {
		result[i] = ad.accts[i].Addr
	}
	return result
}

// MergeAccounts applies other accounts into this StateDelta accounts
func (ad *AccountDeltas) MergeAccounts(other AccountDeltas) {
	for new := range other.accts {
		ad.upsert(other.accts[new])
	}
}

// Len returns number of stored accounts
func (ad *AccountDeltas) Len() int {
	return len(ad.accts)
}

// GetByIdx returns address and AccountData
// It does NOT check boundaries.
func (ad *AccountDeltas) GetByIdx(i int) (basics.Address, PersistedAccountData) {
	return ad.accts[i].Addr, ad.accts[i].PersistedAccountData
}

// Upsert adds new or updates existing account account
func (ad *AccountDeltas) Upsert(addr basics.Address, pad PersistedAccountData) {
	ad.upsert(PersistedBalanceRecord{Addr: addr, PersistedAccountData: pad})
}

func (ad *AccountDeltas) upsert(pbr PersistedBalanceRecord) {
	addr := pbr.Addr
	if idx, exist := ad.acctsCache[addr]; exist { // nil map lookup is OK
		ad.accts[idx] = pbr
		return
	}

	last := len(ad.accts)
	ad.accts = append(ad.accts, pbr)

	if ad.acctsCache == nil {
		ad.acctsCache = make(map[basics.Address]int)
	}
	ad.acctsCache[addr] = last
}

// SetEntityDelta saves creation/deletion info about asset/app params/holding
// Creation is not really important since the holding is already in ad.accts,
// but saving deleteion info is only the way to know if the asset gone
func (ad *AccountDeltas) SetEntityDelta(addr basics.Address, cidx basics.CreatableIndex, action EntityAction) {
	var entityDelta EntityDelta
	ok := false

	if action == ActionHoldingCreate || action == ActionHoldingDelete {
		entityDelta, ok = ad.entityHoldings[addr]
	} else if action == ActionParamsCreate || action == ActionParamsDelete {
		entityDelta, ok = ad.entityParams[addr]
	} else {
		panic(fmt.Sprintf("SetEntityDelta: unknown action %d", action))
	}

	if !ok {
		// in most cases there will be only one asset modification per account
		entityDelta = EntityDelta{cidx: action}
	} else {
		entityDelta[cidx] = action
	}

	if action == ActionHoldingCreate || action == ActionHoldingDelete {
		if ad.entityHoldings == nil {
			ad.entityHoldings = make(AccountEntityDelta)
		}
		ad.entityHoldings[addr] = entityDelta
	} else if action == ActionParamsCreate || action == ActionParamsDelete {
		if ad.entityParams == nil {
			ad.entityParams = make(AccountEntityDelta)
		}
		ad.entityParams[addr] = entityDelta
	}
}

// GetEntityParamsDeltas return map of created/deleted asset/app params
func (ad AccountDeltas) GetEntityParamsDeltas(addr basics.Address) EntityDelta {
	return ad.entityParams[addr]
}

// GetEntityHoldingDeltas return map of created/deleted assets/apps holding
func (ad AccountDeltas) GetEntityHoldingDeltas(addr basics.Address) EntityDelta {
	return ad.entityHoldings[addr]
}

// Update adds new data from other to old data in e and returns a new object
func (e EntityDelta) Update(other EntityDelta) (result EntityDelta) {
	result = make(EntityDelta, len(e)+len(other))
	for cidx, action := range e {
		result[cidx] = action
	}
	for cidx, action := range other {
		result[cidx] = action
	}
	return
}

// OptimizeAllocatedMemory by reallocating maps to needed capacity
// For each data structure, reallocate if it would save us at least 50MB aggregate
func (sd *StateDelta) OptimizeAllocatedMemory(proto config.ConsensusParams) {
	// accts takes up 232 bytes per entry, and is saved for 320 rounds
	if uint64(cap(sd.Accts.accts)-len(sd.Accts.accts))*accountArrayEntrySize*proto.MaxBalLookback > stateDeltaTargetOptimizationThreshold {
		accts := make([]PersistedBalanceRecord, len(sd.Accts.acctsCache))
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
