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

package testing

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"

	//"github.com/algorand/go-algorand/data/bookkeeping"

	"github.com/algorand/go-algorand/ledger/ledgercore"
)

var testPoolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var testSinkAddr = basics.Address{0x2c, 0x2a, 0x6c, 0xe9, 0xa9, 0xa7, 0xc2, 0x8c, 0x22, 0x95, 0xfd, 0x32, 0x4f, 0x77, 0xa5, 0x4, 0x8b, 0x42, 0xc2, 0xb7, 0xa8, 0x54, 0x84, 0xb6, 0x80, 0xb1, 0xe1, 0x3d, 0x59, 0x9b, 0xeb, 0x36}

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

// RandomAccountData generates a random AccountData
func RandomAccountData(rewardsBase uint64) basics.AccountData {
	var data basics.AccountData

	// Avoid overflowing totals
	data.MicroAlgos.Raw = crypto.RandUint64() % (1 << 32)

	switch crypto.RandUint64() % 3 {
	case 0:
		data.Status = basics.Online
		data.VoteLastValid = 1000
	case 1:
		data.Status = basics.Offline
		data.VoteLastValid = 0
	default:
		data.Status = basics.NotParticipating
	}

	data.VoteFirstValid = 0
	data.RewardsBase = rewardsBase
	return data
}

// RandomOnlineAccountData is similar to RandomAccountData but always creates online account
func RandomOnlineAccountData(rewardsBase uint64) basics.AccountData {
	var data basics.AccountData
	data.MicroAlgos.Raw = crypto.RandUint64() % (1 << 32)
	data.Status = basics.Online
	data.VoteLastValid = 1000
	data.VoteFirstValid = 0
	data.RewardsBase = rewardsBase
	return data
}

// RandomAssetParams creates a randim basics.AssetParams
func RandomAssetParams() basics.AssetParams {
	ap := basics.AssetParams{
		Total:         crypto.RandUint64(),
		Decimals:      uint32(crypto.RandUint64() % 20),
		DefaultFrozen: crypto.RandUint64()%2 == 0,
		UnitName:      fmt.Sprintf("un%x", uint32(crypto.RandUint64()%0x7fffffff)),
		AssetName:     fmt.Sprintf("an%x", uint32(crypto.RandUint64()%0x7fffffff)),
		URL:           fmt.Sprintf("url%x", uint32(crypto.RandUint64()%0x7fffffff)),
	}
	crypto.RandBytes(ap.MetadataHash[:])
	crypto.RandBytes(ap.Manager[:])
	crypto.RandBytes(ap.Reserve[:])
	crypto.RandBytes(ap.Freeze[:])
	crypto.RandBytes(ap.Clawback[:])
	return ap
}

// RandomAssetHolding creates a random basics.AssetHolding.
// If forceFrozen is set the Frozen field is set to True to prevent possible empty AssetHolding struct
func RandomAssetHolding(forceFrozen bool) basics.AssetHolding {
	frozen := crypto.RandUint64()%2 == 0
	if forceFrozen {
		frozen = true
	}

	ah := basics.AssetHolding{
		Amount: crypto.RandUint64(),
		Frozen: frozen,
	}
	return ah
}

// RandomAppParams creates a random basics.AppParams
func RandomAppParams() basics.AppParams {
	ap := basics.AppParams{
		ApprovalProgram:   make([]byte, int(crypto.RandUint63())%config.MaxAppProgramLen),
		ClearStateProgram: make([]byte, int(crypto.RandUint63())%config.MaxAppProgramLen),
		GlobalState:       make(basics.TealKeyValue),
		StateSchemas: basics.StateSchemas{
			LocalStateSchema: basics.StateSchema{
				NumUint:      crypto.RandUint64()%5 + 1,
				NumByteSlice: crypto.RandUint64() % 5,
			},
			GlobalStateSchema: basics.StateSchema{
				NumUint:      crypto.RandUint64()%5 + 1,
				NumByteSlice: crypto.RandUint64() % 5,
			},
		},
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

	for i := uint64(0); i < ap.StateSchemas.LocalStateSchema.NumUint+ap.StateSchemas.GlobalStateSchema.NumUint; i++ {
		appName := fmt.Sprintf("tapp%x-%x", crypto.RandUint64(), i)
		ap.GlobalState[appName] = basics.TealValue{
			Type: basics.TealUintType,
			Uint: crypto.RandUint64(),
		}
	}
	for i := uint64(0); i < ap.StateSchemas.LocalStateSchema.NumByteSlice+ap.StateSchemas.GlobalStateSchema.NumByteSlice; i++ {
		appName := fmt.Sprintf("tapp%x-%x", crypto.RandUint64(), i)
		tv := basics.TealValue{
			Type: basics.TealBytesType,
		}
		bytes := make([]byte, crypto.RandUint64()%uint64(config.MaxBytesKeyValueLen))
		crypto.RandBytes(bytes[:])
		tv.Bytes = string(bytes)
		ap.GlobalState[appName] = tv
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
			NumUint:      crypto.RandUint64()%5 + 1,
			NumByteSlice: crypto.RandUint64() % 5,
		},
		KeyValue: make(map[string]basics.TealValue),
	}

	for i := uint64(0); i < ls.Schema.NumUint; i++ {
		appName := fmt.Sprintf("lapp%x-%x", crypto.RandUint64(), i)
		ls.KeyValue[appName] = basics.TealValue{
			Type: basics.TealUintType,
			Uint: crypto.RandUint64(),
		}
	}
	for i := uint64(0); i < ls.Schema.NumByteSlice; i++ {
		appName := fmt.Sprintf("lapp%x-%x", crypto.RandUint64(), i)
		tv := basics.TealValue{
			Type: basics.TealBytesType,
		}
		bytes := make([]byte, crypto.RandUint64()%uint64(config.MaxBytesKeyValueLen-len(appName)))
		crypto.RandBytes(bytes[:])
		tv.Bytes = string(bytes)
		ls.KeyValue[appName] = tv
	}
	if len(ls.KeyValue) == 0 {
		ls.KeyValue = nil
	}

	return ls
}

const maxInt64 = int64((^uint64(0)) >> 1)

// RandomFullAccountData generates a random AccountData
func RandomFullAccountData(rewardsLevel uint64, knownCreatables map[basics.CreatableIndex]basics.CreatableType, lastCreatableID uint64) (basics.AccountData, map[basics.CreatableIndex]basics.CreatableType, uint64) {
	data := RandomAccountData(rewardsLevel)

	if data.Status == basics.Online {
		crypto.RandBytes(data.VoteID[:])
		crypto.RandBytes(data.SelectionID[:])
		crypto.RandBytes(data.StateProofID[:])
		data.VoteFirstValid = basics.Round(crypto.RandUint64())
		data.VoteLastValid = basics.Round(crypto.RandUint64() % uint64(maxInt64)) // int64 is the max sqlite can store
		data.VoteKeyDilution = crypto.RandUint64()
	} else {
		data.VoteID = crypto.OneTimeSignatureVerifier{}
		data.SelectionID = crypto.VRFVerifier{}
		data.StateProofID = merklesignature.Verifier{}
		data.VoteFirstValid = 0
		data.VoteLastValid = 0
		data.VoteKeyDilution = 0
	}
	if (crypto.RandUint64() % 2) == 1 {
		// if account has created assets, have these defined.
		createdAssetsCount := crypto.RandUint64()%20 + 1
		data.AssetParams = make(map[basics.AssetIndex]basics.AssetParams, createdAssetsCount)
		for i := uint64(0); i < createdAssetsCount; i++ {
			ap := RandomAssetParams()
			lastCreatableID++
			data.AssetParams[basics.AssetIndex(lastCreatableID)] = ap
			knownCreatables[basics.CreatableIndex(lastCreatableID)] = basics.AssetCreatable
		}
	}
	if (crypto.RandUint64()%2) == 1 && lastCreatableID > 0 {
		// if account owns assets
		ownedAssetsCount := crypto.RandUint64()%20 + 1
		data.Assets = make(map[basics.AssetIndex]basics.AssetHolding, ownedAssetsCount)
		for i := uint64(0); i < ownedAssetsCount; i++ {
			ah := RandomAssetHolding(false)
			aidx := crypto.RandUint64() % lastCreatableID
			for {
				ctype, ok := knownCreatables[basics.CreatableIndex(aidx)]
				if !ok || ctype == basics.AssetCreatable {
					break
				}
				aidx = crypto.RandUint64() % lastCreatableID
			}

			data.Assets[basics.AssetIndex(aidx)] = ah
			knownCreatables[basics.CreatableIndex(aidx)] = basics.AssetCreatable
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
			lastCreatableID++
			data.AppParams[basics.AppIndex(lastCreatableID)] = ap
			knownCreatables[basics.CreatableIndex(lastCreatableID)] = basics.AppCreatable
		}
	}
	if (crypto.RandUint64()%3) == 1 && lastCreatableID > 0 {
		appStatesCount := crypto.RandUint64()%20 + 1
		data.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState, appStatesCount)
		for i := uint64(0); i < appStatesCount; i++ {
			ap := RandomAppLocalState()
			aidx := crypto.RandUint64() % lastCreatableID
			for {
				ctype, ok := knownCreatables[basics.CreatableIndex(aidx)]
				if !ok || ctype == basics.AppCreatable {
					break
				}
				aidx = crypto.RandUint64() % lastCreatableID
			}
			data.AppLocalStates[basics.AppIndex(aidx)] = ap
			knownCreatables[basics.CreatableIndex(aidx)] = basics.AppCreatable
		}
	}

	if (crypto.RandUint64() % 3) == 1 {
		data.TotalAppSchema = basics.StateSchema{
			NumUint:      crypto.RandUint64() % 50,
			NumByteSlice: crypto.RandUint64() % 50,
		}
	}
	return data, knownCreatables, lastCreatableID
}

// RandomAccounts generates a random set of accounts map
func RandomAccounts(niter int, simpleAccounts bool) map[basics.Address]basics.AccountData {
	res := make(map[basics.Address]basics.AccountData)
	if simpleAccounts {
		for i := 0; i < niter; i++ {
			res[RandomAddress()] = RandomAccountData(0)
		}
	} else {
		lastCreatableID := crypto.RandUint64() % 512
		knownCreatables := make(map[basics.CreatableIndex]basics.CreatableType)
		for i := 0; i < niter; i++ {
			res[RandomAddress()], knownCreatables, lastCreatableID = RandomFullAccountData(0, knownCreatables, lastCreatableID)
		}
	}
	return res
}

// RandomDeltas generates a random set of accounts delta
func RandomDeltas(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]ledgercore.AccountData, imbalance int64) {
	updates, totals, imbalance, _ = RandomDeltasImpl(niter, base, rewardsLevel, true, 0)
	return
}

// RandomDeltasFull generates a random set of accounts delta
func RandomDeltasFull(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, lastCreatableIDIn uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]ledgercore.AccountData, imbalance int64, lastCreatableID uint64) {
	updates, totals, imbalance, lastCreatableID = RandomDeltasImpl(niter, base, rewardsLevel, false, lastCreatableIDIn)
	return
}

// RandomDeltasImpl generates a random set of accounts delta
func RandomDeltasImpl(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, simple bool, lastCreatableIDIn uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]ledgercore.AccountData, imbalance int64, lastCreatableID uint64) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	totals = make(map[basics.Address]ledgercore.AccountData)

	updates = ledgercore.MakeAccountDeltas(len(base))

	// copy base -> totals
	for addr, data := range base {
		totals[addr] = ledgercore.ToAccountData(data)
	}

	// if making a full delta then need to determine max asset/app id to get rid of conflicts
	lastCreatableID = lastCreatableIDIn
	knownCreatables := make(map[basics.CreatableIndex]basics.CreatableType)
	if !simple {
		for _, ad := range base {
			for aid := range ad.AssetParams {
				if uint64(aid) > lastCreatableID {
					lastCreatableID = uint64(aid)
				}
				knownCreatables[basics.CreatableIndex(aid)] = basics.AssetCreatable
			}
			for aid := range ad.Assets {
				// do not check lastCreatableID since lastCreatableID is only incremented for new params
				knownCreatables[basics.CreatableIndex(aid)] = basics.AssetCreatable
			}

			for aid := range ad.AppParams {
				if uint64(aid) > lastCreatableID {
					lastCreatableID = uint64(aid)
				}
				knownCreatables[basics.CreatableIndex(aid)] = basics.AppCreatable
			}
			for aid := range ad.AppLocalStates {
				// do not check lastCreatableID since lastCreatableID is only incremented for new params
				knownCreatables[basics.CreatableIndex(aid)] = basics.AppCreatable
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
				data, knownCreatables, lastCreatableID = RandomFullAccountData(rewardsLevel, knownCreatables, lastCreatableID)
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
			imbalance += int64(old.WithUpdatedRewards(proto, rewardsLevel).MicroAlgos.Raw - new.MicroAlgos.Raw)
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
			data, knownCreatables, lastCreatableID = RandomFullAccountData(rewardsLevel, knownCreatables, lastCreatableID)
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
		imbalance += int64(old.WithUpdatedRewards(proto, rewardsLevel).MicroAlgos.Raw - new.MicroAlgos.Raw)
		totals[addr] = new
	}

	return
}

// RandomDeltasBalanced generates a random set of accounts delta
func RandomDeltasBalanced(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]ledgercore.AccountData) {
	updates, totals, _ = RandomDeltasBalancedImpl(niter, base, rewardsLevel, true, 0)
	return
}

// RandomDeltasBalancedFull generates a random set of accounts delta
func RandomDeltasBalancedFull(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, lastCreatableIDIn uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]ledgercore.AccountData, lastCreatableID uint64) {
	updates, totals, lastCreatableID = RandomDeltasBalancedImpl(niter, base, rewardsLevel, false, lastCreatableIDIn)
	return
}

// RandomDeltasBalancedImpl generates a random set of accounts delta
func RandomDeltasBalancedImpl(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, simple bool, lastCreatableIDIn uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]ledgercore.AccountData, lastCreatableID uint64) {
	var imbalance int64
	if simple {
		updates, totals, imbalance = RandomDeltas(niter, base, rewardsLevel)
	} else {
		updates, totals, imbalance, lastCreatableID = RandomDeltasFull(niter, base, rewardsLevel, lastCreatableIDIn)
	}

	oldPool := base[testPoolAddr]
	newPoolData := oldPool
	newPoolData.MicroAlgos.Raw += uint64(imbalance)

	newPool := ledgercore.ToAccountData(newPoolData)
	updates.Upsert(testPoolAddr, newPool)
	totals[testPoolAddr] = newPool

	return updates, totals, lastCreatableID
}
