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

package testing

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/config/bounds"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"

	"github.com/algorand/go-algorand/ledger/ledgercore"
)

var testPoolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var testSinkAddr = basics.Address{0x2c, 0x2a, 0x6c, 0xe9, 0xa9, 0xa7, 0xc2, 0x8c, 0x22, 0x95, 0xfd, 0x32, 0x4f, 0x77, 0xa5, 0x4, 0x8b, 0x42, 0xc2, 0xb7, 0xa8, 0x54, 0x84, 0xb6, 0x80, 0xb1, 0xe1, 0x3d, 0x59, 0x9b, 0xeb, 0x36}

// PoolAddr returns a copy of the test pool address
func PoolAddr() basics.Address {
	return testPoolAddr
}

// SinkAddr returns a copy of the test sink address
func SinkAddr() basics.Address {
	return testSinkAddr
}

// RandomAddress generates a random address
func RandomAddress() basics.Address {
	var addr basics.Address
	crypto.RandBytes(addr[:])
	return addr
}

// RandomNote generates a random notes data
func RandomNote() []byte {
	var note [16]byte
	crypto.RandBytes(note[:])
	return note[:]
}

// RandomAccountData generates a random AccountData with no associated resources.
func RandomAccountData(rewardsBase uint64) basics.AccountData {
	var data basics.AccountData

	// Avoid overflowing totals
	data.MicroAlgos.Raw = crypto.RandUint64() % (1 << 32)
	// 0 is an invalid round, but would be right if never proposed
	data.LastProposed = basics.Round(crypto.RandUint64() % 10)
	// 0 is an invalid round, but would be right if never needed a heartbeat
	data.LastHeartbeat = basics.Round(crypto.RandUint64() % 10)

	switch crypto.RandUint64() % 3 {
	case 0:
		data.Status = basics.Online
		data.IncentiveEligible = crypto.RandUint64()%5 == 0
	case 1:
		data.Status = basics.Offline
	case 2:
		data.Status = basics.NotParticipating
	}

	// Give online accounts voting data, and some of the offline too. They are "suspended".
	if data.Status == basics.Online || (data.Status == basics.Offline && crypto.RandUint64()%5 == 1) {
		crypto.RandBytes(data.VoteID[:])
		crypto.RandBytes(data.SelectionID[:])
		crypto.RandBytes(data.StateProofID[:])
		data.VoteFirstValid = basics.Round(crypto.RandUint64())
		data.VoteLastValid = basics.Round(crypto.RandUint63()) // int64 is the max sqlite can store
		data.VoteKeyDilution = crypto.RandUint64()
	}

	data.RewardsBase = rewardsBase
	return data
}

// RandomOnlineAccountData is similar to RandomAccountData but always creates online account
func RandomOnlineAccountData(rewardsBase uint64) basics.AccountData {
	for {
		data := RandomAccountData(rewardsBase)
		if data.Status == basics.Online {
			return data
		}
	}
}

// RandomAssetParams creates a random basics.AssetParams
func RandomAssetParams() basics.AssetParams {
	ap := basics.AssetParams{
		Total:         crypto.RandUint64(),
		Decimals:      uint32(crypto.RandUint64() % 20),
		DefaultFrozen: crypto.RandUint64()%2 == 0,
	}
	// Since 0 and 1 Total assets seem extra interesting, make them more often.
	if crypto.RandUint64()%5 != 0 {
		ap.Total = crypto.RandUint64() % 2
	}
	if crypto.RandUint64()%5 != 0 {
		ap.UnitName = fmt.Sprintf("un%x", uint32(crypto.RandUint64()%0x7fffff))
	}
	if crypto.RandUint64()%5 != 0 {
		ap.AssetName = fmt.Sprintf("an%x", uint32(crypto.RandUint64()%0x7fffffff))
	}
	if crypto.RandUint64()%5 != 0 {
		ap.URL = fmt.Sprintf("url%x", uint32(crypto.RandUint64()%0x7fffffff))
	}
	if crypto.RandUint64()%5 != 0 {
		crypto.RandBytes(ap.MetadataHash[:])
	}
	if crypto.RandUint64()%5 != 0 {
		crypto.RandBytes(ap.Manager[:])
	}
	if crypto.RandUint64()%5 != 0 {
		crypto.RandBytes(ap.Reserve[:])
	}
	if crypto.RandUint64()%5 != 0 {
		crypto.RandBytes(ap.Freeze[:])
	}
	if crypto.RandUint64()%5 != 0 {
		crypto.RandBytes(ap.Clawback[:])
	}
	return ap
}

// RandomAssetHolding creates a random basics.AssetHolding.
// If forceFrozen is set the Frozen field is set to True to prevent possible empty AssetHolding struct
func RandomAssetHolding(forceFrozen bool) basics.AssetHolding {
	frozen := crypto.RandUint64()%2 == 0
	if forceFrozen {
		frozen = true
	}

	var amount uint64
	if crypto.RandUint64()%5 != 0 {
		amount = crypto.RandUint64()
	}

	ah := basics.AssetHolding{
		Amount: amount,
		Frozen: frozen,
	}
	return ah
}

// RandomAppParams creates a random basics.AppParams
func RandomAppParams() basics.AppParams {
	var schemas basics.StateSchemas
	if crypto.RandUint64()%10 != 0 {
		schemas = basics.StateSchemas{
			LocalStateSchema: basics.StateSchema{
				NumUint:      crypto.RandUint64() % 5,
				NumByteSlice: crypto.RandUint64() % 5,
			},
			GlobalStateSchema: basics.StateSchema{
				NumUint:      crypto.RandUint64() % 5,
				NumByteSlice: crypto.RandUint64() % 5,
			},
		}
	}

	ap := basics.AppParams{
		ApprovalProgram:   make([]byte, int(crypto.RandUint63())%bounds.MaxAppProgramLen),
		ClearStateProgram: make([]byte, int(crypto.RandUint63())%bounds.MaxAppProgramLen),
		GlobalState:       make(basics.TealKeyValue),
		StateSchemas:      schemas,
		ExtraProgramPages: uint32(crypto.RandUint64() % 4),
		Version:           crypto.RandUint64() % 10,
	}
	if len(ap.ApprovalProgram) > 0 {
		crypto.RandBytes(ap.ApprovalProgram[:])
	} else {
		ap.ApprovalProgram = nil
	}
	if len(ap.ClearStateProgram) > 0 {
		crypto.RandBytes(ap.ClearStateProgram[:])
	} else {
		ap.ClearStateProgram = nil
	}

	// The can only be a sponsor if there's extra storage
	if ap.ExtraProgramPages > 0 && !ap.StateSchemas.GlobalStateSchema.Empty() {
		if crypto.RandUint63()%2 == 0 {
			crypto.RandBytes(ap.SizeSponsor[:])
		}
	}

	for i := uint64(0); i < ap.StateSchemas.GlobalStateSchema.NumUint; i++ {
		var keyName string
		if crypto.RandUint64()%5 != 0 {
			keyName = fmt.Sprintf("tapp%x-%x", crypto.RandUint64(), i)
		}
		var value uint64
		if crypto.RandUint64()%5 != 0 {
			value = crypto.RandUint64()
		}
		ap.GlobalState[keyName] = basics.TealValue{
			Type: basics.TealUintType,
			Uint: value,
		}
	}
	for i := uint64(0); i < ap.StateSchemas.GlobalStateSchema.NumByteSlice; i++ {
		var keyName string
		if crypto.RandUint64()%5 != 0 {
			keyName = fmt.Sprintf("tapp%x-%x", crypto.RandUint64(), i)
		}

		var bytes []byte
		if crypto.RandUint64()%5 != 0 {
			bytes = make([]byte, crypto.RandUint64()%uint64(bounds.MaxBytesKeyValueLen-len(keyName)))
			crypto.RandBytes(bytes[:])
		}

		ap.GlobalState[keyName] = basics.TealValue{
			Type:  basics.TealBytesType,
			Bytes: string(bytes),
		}
	}
	if len(ap.GlobalState) == 0 {
		ap.GlobalState = nil
	}
	return ap
}

// RandomAppLocalState creates a random basics.AppLocalState
func RandomAppLocalState() basics.AppLocalState {
	ls := basics.AppLocalState{
		Schema: basics.StateSchema{
			NumUint:      crypto.RandUint64() % 5,
			NumByteSlice: crypto.RandUint64() % 5,
		},
		KeyValue: make(map[string]basics.TealValue),
	}

	for i := uint64(0); i < ls.Schema.NumUint; i++ {
		var keyName string
		if crypto.RandUint64()%5 != 0 {
			keyName = fmt.Sprintf("tapp%x-%x", crypto.RandUint64(), i)
		}
		var value uint64
		if crypto.RandUint64()%5 != 0 {
			value = crypto.RandUint64()
		}
		ls.KeyValue[keyName] = basics.TealValue{
			Type: basics.TealUintType,
			Uint: value,
		}
	}
	for i := uint64(0); i < ls.Schema.NumByteSlice; i++ {
		var keyName string
		if crypto.RandUint64()%5 != 0 {
			keyName = fmt.Sprintf("tapp%x-%x", crypto.RandUint64(), i)
		}
		var bytes []byte
		if crypto.RandUint64()%5 != 0 {
			bytes = make([]byte, crypto.RandUint64()%uint64(bounds.MaxBytesKeyValueLen-len(keyName)))
			crypto.RandBytes(bytes[:])
		}

		ls.KeyValue[keyName] = basics.TealValue{
			Type:  basics.TealBytesType,
			Bytes: string(bytes),
		}
	}
	if len(ls.KeyValue) == 0 {
		ls.KeyValue = nil
	}

	return ls
}

// RandomFullAccountData generates a random AccountData
func RandomFullAccountData(rewardsLevel uint64, lastCreatableID *basics.CreatableIndex, assets map[basics.AssetIndex]struct{}, apps map[basics.AppIndex]struct{}) basics.AccountData {
	data := RandomAccountData(rewardsLevel)

	if (crypto.RandUint64() % 2) == 1 {
		// if account has created assets, have these defined.
		createdAssetsCount := crypto.RandUint64()%20 + 1
		data.AssetParams = make(map[basics.AssetIndex]basics.AssetParams, createdAssetsCount)
		for i := uint64(0); i < createdAssetsCount; i++ {
			ap := RandomAssetParams()
			*lastCreatableID++
			data.AssetParams[basics.AssetIndex(*lastCreatableID)] = ap
			assets[basics.AssetIndex(*lastCreatableID)] = struct{}{}
		}
	}
	if (crypto.RandUint64()%2 == 1) && (len(assets) > 0) {
		// if account owns assets
		ownedAssetsCount := crypto.RandUint64()%20 + 1
		data.Assets = make(map[basics.AssetIndex]basics.AssetHolding, ownedAssetsCount)
		for i := uint64(0); i < ownedAssetsCount; i++ {
			ah := RandomAssetHolding(false)
			var aidx basics.AssetIndex
			for {
				aidx = basics.AssetIndex(crypto.RandUint64()%uint64(*lastCreatableID) + 1)
				if _, ok := assets[aidx]; ok {
					break
				}
			}

			data.Assets[aidx] = ah
		}
	}
	if (crypto.RandUint64() % 5) == 1 {
		crypto.RandBytes(data.AuthAddr[:])
	}

	if (crypto.RandUint64() % 3) == 1 {
		appParamsCount := crypto.RandUint64()%5 + 1
		data.AppParams = make(map[basics.AppIndex]basics.AppParams, appParamsCount)
		for i := uint64(0); i < appParamsCount; i++ {
			ap := RandomAppParams()
			*lastCreatableID++
			data.AppParams[basics.AppIndex(*lastCreatableID)] = ap
			apps[basics.AppIndex(*lastCreatableID)] = struct{}{}
		}
	}
	if (crypto.RandUint64()%3 == 1) && (len(apps) > 0) {
		appStatesCount := crypto.RandUint64()%20 + 1
		data.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState, appStatesCount)
		for i := uint64(0); i < appStatesCount; i++ {
			ap := RandomAppLocalState()
			var aidx basics.AppIndex
			for {
				aidx = basics.AppIndex(crypto.RandUint64()%uint64(*lastCreatableID) + 1)
				if _, ok := apps[aidx]; ok {
					break
				}
			}
			data.AppLocalStates[aidx] = ap
		}
	}

	if (crypto.RandUint64() % 3) == 1 {
		data.TotalAppSchema = basics.StateSchema{
			NumUint:      crypto.RandUint64() % 50,
			NumByteSlice: crypto.RandUint64() % 50,
		}
		data.TotalExtraAppPages = uint32(crypto.RandUint64() % 50)
	}

	if (crypto.RandUint64() % 3) == 1 {
		data.TotalBoxes = crypto.RandUint64() % 100
		data.TotalBoxBytes = crypto.RandUint64() % 10000
	}

	return data
}

// RandomAccounts generates a random set of accounts map
func RandomAccounts(niter int, simpleAccounts bool) map[basics.Address]basics.AccountData {
	res := make(map[basics.Address]basics.AccountData)
	if simpleAccounts {
		for i := 0; i < niter; i++ {
			res[RandomAddress()] = RandomAccountData(0)
		}
	} else {
		lastCreatableID := basics.CreatableIndex(crypto.RandUint64() % 512)
		assets := make(map[basics.AssetIndex]struct{})
		apps := make(map[basics.AppIndex]struct{})
		for i := 0; i < niter; i++ {
			res[RandomAddress()] = RandomFullAccountData(0, &lastCreatableID, assets, apps)
		}
	}
	return res
}

// RandomDeltas generates a random set of accounts delta
func RandomDeltas(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]ledgercore.AccountData, imbalance int64) {
	var lastCreatableID basics.CreatableIndex
	updates, totals, imbalance =
		RandomDeltasImpl(niter, base, rewardsLevel, true, &lastCreatableID)
	return
}

// RandomDeltasFull generates a random set of accounts delta
func RandomDeltasFull(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, lastCreatableID *basics.CreatableIndex) (updates ledgercore.AccountDeltas, totals map[basics.Address]ledgercore.AccountData, imbalance int64) {
	updates, totals, imbalance = RandomDeltasImpl(niter, base, rewardsLevel, false, lastCreatableID)
	return
}

// RandomDeltasImpl generates a random set of accounts delta
func RandomDeltasImpl(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, simple bool, lastCreatableID *basics.CreatableIndex) (updates ledgercore.AccountDeltas, totals map[basics.Address]ledgercore.AccountData, imbalance int64) {
	rewardUnit := config.Consensus[protocol.ConsensusCurrentVersion].RewardUnit
	totals = make(map[basics.Address]ledgercore.AccountData)

	updates = ledgercore.MakeAccountDeltas(len(base))

	// copy base -> totals
	for addr, data := range base {
		totals[addr] = ledgercore.ToAccountData(data)
	}

	// if making a full delta then need to determine max asset/app id to get rid of conflicts
	assets := make(map[basics.AssetIndex]struct{})
	apps := make(map[basics.AppIndex]struct{})
	if !simple {
		for _, ad := range base {
			for aid := range ad.AssetParams {
				assets[aid] = struct{}{}
			}
			for aid := range ad.Assets {
				assets[aid] = struct{}{}
			}
			for aid := range ad.AppParams {
				apps[aid] = struct{}{}
			}
			for aid := range ad.AppLocalStates {
				apps[aid] = struct{}{}
			}
		}
	}

	// Change some existing accounts
	{
		i := 0
		for addr, old := range base {
			if i >= len(base)/2 || i >= niter {
				break
			}

			if addr == testPoolAddr {
				continue
			}
			i++

			var data basics.AccountData
			var new ledgercore.AccountData
			if simple {
				data = RandomAccountData(rewardsLevel)
				new = ledgercore.ToAccountData(data)
				updates.Upsert(addr, new)
			} else {
				data = RandomFullAccountData(rewardsLevel, lastCreatableID, assets, apps)
				new = ledgercore.ToAccountData(data)
				updates.Upsert(addr, new)
				appResources := make(map[basics.AppIndex]ledgercore.AppResourceRecord)
				assetResources := make(map[basics.AssetIndex]ledgercore.AssetResourceRecord)

				for aidx, params := range data.AppParams {
					val := params
					res := appResources[aidx]
					res.Params.Params = &val
					appResources[aidx] = res
				}
				for aidx, states := range data.AppLocalStates {
					val := states
					res := appResources[aidx]
					res.State.LocalState = &val
					appResources[aidx] = res
				}

				for aidx, params := range data.AssetParams {
					val := params
					res := assetResources[aidx]
					res.Params.Params = &val
					assetResources[aidx] = res
				}
				for aidx, holding := range data.Assets {
					val := holding
					res := assetResources[aidx]
					res.Holding.Holding = &val
					assetResources[aidx] = res
				}

				// remove deleted
				for aidx := range old.AppParams {
					if _, ok := data.AppParams[aidx]; !ok {
						res := appResources[aidx]
						res.Params.Deleted = true
						appResources[aidx] = res
					}
				}
				for aidx := range old.AppLocalStates {
					if _, ok := data.AppLocalStates[aidx]; !ok {
						res := appResources[aidx]
						res.State.Deleted = true
						appResources[aidx] = res
					}
				}
				for aidx := range old.AssetParams {
					if _, ok := data.AssetParams[aidx]; !ok {
						res := assetResources[aidx]
						res.Params.Deleted = true
						assetResources[aidx] = res
					}
				}
				for aidx := range old.Assets {
					if _, ok := data.Assets[aidx]; !ok {
						res := assetResources[aidx]
						res.Holding.Deleted = true
						assetResources[aidx] = res
					}
				}

				for aidx, res := range appResources {
					updates.UpsertAppResource(addr, aidx, res.Params, res.State)
				}
				for aidx, res := range assetResources {
					updates.UpsertAssetResource(addr, aidx, res.Params, res.Holding)
				}
			}
			imbalance += int64(old.WithUpdatedRewards(rewardUnit, rewardsLevel).MicroAlgos.Raw - new.MicroAlgos.Raw)
			totals[addr] = new
		}
	}

	// Change some new accounts
	for i := 0; i < niter; i++ {
		addr := RandomAddress()
		old := totals[addr]
		var new ledgercore.AccountData
		var data basics.AccountData
		if simple {
			data = RandomAccountData(rewardsLevel)
			new = ledgercore.ToAccountData(data)
			updates.Upsert(addr, new)
		} else {
			data = RandomFullAccountData(rewardsLevel, lastCreatableID, assets, apps)
			new = ledgercore.ToAccountData(data)
			updates.Upsert(addr, new)
			appResources := make(map[basics.AppIndex]ledgercore.AppResourceRecord)
			assetResources := make(map[basics.AssetIndex]ledgercore.AssetResourceRecord)

			for aidx, params := range data.AppParams {
				val := params
				res := appResources[aidx]
				res.Params.Params = &val
				appResources[aidx] = res
			}
			for aidx, states := range data.AppLocalStates {
				val := states
				res := appResources[aidx]
				res.State.LocalState = &val
				appResources[aidx] = res
			}
			for aidx, params := range data.AssetParams {
				val := params
				res := assetResources[aidx]
				res.Params.Params = &val
				assetResources[aidx] = res
			}
			for aidx, holding := range data.Assets {
				val := holding
				res := assetResources[aidx]
				res.Holding.Holding = &val
				assetResources[aidx] = res
			}

			for aidx, res := range appResources {
				updates.UpsertAppResource(addr, aidx, res.Params, res.State)
			}
			for aidx, res := range assetResources {
				updates.UpsertAssetResource(addr, aidx, res.Params, res.Holding)
			}
		}
		imbalance += int64(old.WithUpdatedRewards(rewardUnit, rewardsLevel).MicroAlgos.Raw - new.MicroAlgos.Raw)
		totals[addr] = new
	}

	return
}

// RandomDeltasBalanced generates a random set of accounts delta
func RandomDeltasBalanced(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]ledgercore.AccountData) {
	var lastCreatableID basics.CreatableIndex
	updates, totals = RandomDeltasBalancedImpl(
		niter, base, rewardsLevel, true, &lastCreatableID)
	return
}

// RandomDeltasBalancedFull generates a random set of accounts delta
func RandomDeltasBalancedFull(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, lastCreatableID *basics.CreatableIndex) (updates ledgercore.AccountDeltas, totals map[basics.Address]ledgercore.AccountData) {
	updates, totals = RandomDeltasBalancedImpl(niter, base, rewardsLevel, false, lastCreatableID)
	return
}

// RandomDeltasBalancedImpl generates a random set of accounts delta
func RandomDeltasBalancedImpl(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, simple bool, lastCreatableID *basics.CreatableIndex) (updates ledgercore.AccountDeltas, totals map[basics.Address]ledgercore.AccountData) {
	var imbalance int64
	if simple {
		updates, totals, imbalance = RandomDeltas(niter, base, rewardsLevel)
	} else {
		updates, totals, imbalance =
			RandomDeltasFull(niter, base, rewardsLevel, lastCreatableID)
	}

	oldPool := base[testPoolAddr]
	newPoolData := oldPool
	newPoolData.MicroAlgos.Raw += uint64(imbalance)

	newPool := ledgercore.ToAccountData(newPoolData)
	updates.Upsert(testPoolAddr, newPool)
	totals[testPoolAddr] = newPool

	return updates, totals
}
