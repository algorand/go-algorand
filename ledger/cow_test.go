// Copyright (C) 2019-2020 Algorand, Inc.
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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/protocol"
)

func randomDeltas(niter int, base map[basics.Address]apply.MiniAccountData, rewardsLevel uint64) (updates map[basics.Address]miniAccountDelta, totals map[basics.Address]apply.MiniAccountData, imbalance int64) {
	updates, totals, imbalance, _ = randomDeltasImpl(niter, base, rewardsLevel, true, 0)
	return
}

func randomDeltasImpl(niter int, base map[basics.Address]apply.MiniAccountData, rewardsLevel uint64, simple bool, lastCreatableIDIn uint64) (updates map[basics.Address]miniAccountDelta, totals map[basics.Address]apply.MiniAccountData, imbalance int64, lastCreatableID uint64) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	updates = make(map[basics.Address]miniAccountDelta)
	totals = make(map[basics.Address]apply.MiniAccountData)

	// copy base -> totals
	for addr, data := range base {
		totals[addr] = data
	}

	// if making a full delta then need to determine max asset/app id to get rid of conflicts
	lastCreatableID = lastCreatableIDIn
	if !simple {
		for _, ad := range base {
			for aid := range ad.AssetParams {
				if uint64(aid) > lastCreatableID {
					lastCreatableID = uint64(aid)
				}
			}
			for aid := range ad.AppParams {
				if uint64(aid) > lastCreatableID {
					lastCreatableID = uint64(aid)
				}
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

			var new basics.AccountData
			if simple {
				new = randomAccountData(rewardsLevel)
			} else {
				new, lastCreatableID = randomFullAccountData(rewardsLevel, lastCreatableID)
			}
			updates[addr] = miniAccountDelta{old: old, new: apply.AccountData(new).WithoutAppKV()}
			imbalance += int64(old.WithUpdatedRewards(proto, rewardsLevel).MicroAlgos.Raw - new.MicroAlgos.Raw)
			totals[addr] = apply.AccountData(new).WithoutAppKV()
			break
		}
	}

	// Change some new accounts
	for i := 0; i < niter; i++ {
		addr := randomAddress()
		old := totals[addr]
		var new basics.AccountData
		if simple {
			new = randomAccountData(rewardsLevel)
		} else {
			new, lastCreatableID = randomFullAccountData(rewardsLevel, lastCreatableID)
		}
		updates[addr] = miniAccountDelta{old: old, new: apply.AccountData(new).WithoutAppKV()}
		imbalance += int64(old.WithUpdatedRewards(proto, rewardsLevel).MicroAlgos.Raw - new.MicroAlgos.Raw)
		totals[addr] = apply.AccountData(new).WithoutAppKV()
	}

	return
}

type mockLedger struct {
	balanceMap map[basics.Address]apply.MiniAccountData
}

func (ml *mockLedger) lookup(addr basics.Address) (apply.MiniAccountData, error) {
	return ml.balanceMap[addr], nil
}

func (ml *mockLedger) isDup(firstValid, lastValid basics.Round, txn transactions.Txid, txl txlease) (bool, error) {
	return false, nil
}

func (ml *mockLedger) getAssetCreator(assetIdx basics.AssetIndex) (basics.Address, bool, error) {
	return basics.Address{}, false, nil
}

func (ml *mockLedger) getAppCreator(appIdx basics.AppIndex) (basics.Address, bool, error) {
	return basics.Address{}, false, nil
}

func (ml *mockLedger) getCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return basics.Address{}, false, nil
}

func (ml *mockLedger) getStorageCounts(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	return basics.StateSchema{}, nil
}

func (ml *mockLedger) Allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error) {
	return true, nil
}

func (ml *mockLedger) GetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) (basics.TealValue, bool, error) {
	return basics.TealValue{}, false, nil
}

func (ml *mockLedger) txnCounter() uint64 {
	return 0
}

func checkCow(t *testing.T, cow *roundCowState, accts map[basics.Address]apply.MiniAccountData) {
	for addr, data := range accts {
		d, err := cow.lookup(addr)
		require.NoError(t, err)
		require.Equal(t, d, data)
	}

	d, err := cow.lookup(randomAddress())
	require.NoError(t, err)
	require.Equal(t, d, basics.AccountData{})
}

func applyUpdates(cow *roundCowState, updates map[basics.Address]miniAccountDelta) {
	for addr, delta := range updates {
		cow.put(addr, delta.old, delta.new, nil, nil)
	}
}

func TestCowBalance(t *testing.T) {
	accts0 := randomMiniAccounts(20, true)
	ml := mockLedger{balanceMap: accts0}

	c0 := makeRoundCowState(&ml, bookkeeping.BlockHeader{}, 0)
	checkCow(t, c0, accts0)

	c1 := c0.child()
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts0)

	updates1, accts1, _ := randomDeltas(10, accts0, 0)
	applyUpdates(c1, updates1)
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts1)

	c2 := c1.child()
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts1)
	checkCow(t, c2, accts1)

	updates2, accts2, _ := randomDeltas(10, accts1, 0)
	applyUpdates(c2, updates2)
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts1)
	checkCow(t, c2, accts2)

	c2.commitToParent()
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts2)

	c1.commitToParent()
	checkCow(t, c0, accts2)
}

// TODO

func randomAddress() basics.Address {
	var addr basics.Address
	crypto.RandBytes(addr[:])
	return addr
}

func randomAccountData(rewardsLevel uint64) basics.AccountData {
	var data basics.AccountData

	// Avoid overflowing totals
	data.MicroAlgos.Raw = crypto.RandUint64() % (1 << 32)

	switch crypto.RandUint64() % 3 {
	case 0:
		data.Status = basics.Online
	case 1:
		data.Status = basics.Offline
	default:
		data.Status = basics.NotParticipating
	}

	data.RewardsBase = rewardsLevel

	return data
}

func randomFullAccountData(rewardsLevel, lastCreatableID uint64) (basics.AccountData, uint64) {
	data := randomAccountData(rewardsLevel)

	crypto.RandBytes(data.VoteID[:])
	crypto.RandBytes(data.SelectionID[:])
	data.VoteFirstValid = basics.Round(crypto.RandUint64())
	data.VoteLastValid = basics.Round(crypto.RandUint64())
	data.VoteKeyDilution = crypto.RandUint64()
	if 1 == (crypto.RandUint64() % 2) {
		// if account has created assets, have these defined.
		data.AssetParams = make(map[basics.AssetIndex]basics.AssetParams)
		createdAssetsCount := crypto.RandUint64()%20 + 1
		for i := uint64(0); i < createdAssetsCount; i++ {
			ap := basics.AssetParams{
				Total:         crypto.RandUint64(),
				Decimals:      uint32(crypto.RandUint64() % 20),
				DefaultFrozen: (crypto.RandUint64()%2 == 0),
				UnitName:      fmt.Sprintf("un%x", uint32(crypto.RandUint64()%0x7fffffff)),
				AssetName:     fmt.Sprintf("an%x", uint32(crypto.RandUint64()%0x7fffffff)),
				URL:           fmt.Sprintf("url%x", uint32(crypto.RandUint64()%0x7fffffff)),
			}
			crypto.RandBytes(ap.MetadataHash[:])
			crypto.RandBytes(ap.Manager[:])
			crypto.RandBytes(ap.Reserve[:])
			crypto.RandBytes(ap.Freeze[:])
			crypto.RandBytes(ap.Clawback[:])
			lastCreatableID++
			data.AssetParams[basics.AssetIndex(lastCreatableID)] = ap
		}
	}
	if 1 == (crypto.RandUint64() % 2) {
		// if account owns assets
		data.Assets = make(map[basics.AssetIndex]basics.AssetHolding)
		ownedAssetsCount := crypto.RandUint64()%20 + 1
		for i := uint64(0); i < ownedAssetsCount; i++ {
			ah := basics.AssetHolding{
				Amount: crypto.RandUint64(),
				Frozen: (crypto.RandUint64()%2 == 0),
			}
			data.Assets[basics.AssetIndex(crypto.RandUint64()%lastCreatableID)] = ah
		}
	}
	if 1 == (crypto.RandUint64() % 5) {
		crypto.RandBytes(data.AuthAddr[:])
	}

	if 1 == (crypto.RandUint64() % 3) {
		data.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
		appStatesCount := crypto.RandUint64()%20 + 1
		for i := uint64(0); i < appStatesCount; i++ {
			ap := basics.AppLocalState{
				Schema: basics.StateSchema{
					NumUint:      crypto.RandUint64() % 5,
					NumByteSlice: crypto.RandUint64() % 5,
				},
				KeyValue: make(map[string]basics.TealValue),
			}

			for i := uint64(0); i < ap.Schema.NumUint; i++ {
				appName := fmt.Sprintf("lapp%x-%x", crypto.RandUint64(), i)
				ap.KeyValue[appName] = basics.TealValue{
					Type: basics.TealUintType,
					Uint: crypto.RandUint64(),
				}
			}
			for i := uint64(0); i < ap.Schema.NumByteSlice; i++ {
				appName := fmt.Sprintf("lapp%x-%x", crypto.RandUint64(), i)
				tv := basics.TealValue{
					Type: basics.TealBytesType,
				}
				bytes := make([]byte, crypto.RandUint64()%512)
				crypto.RandBytes(bytes[:])
				tv.Bytes = string(bytes)
				ap.KeyValue[appName] = tv
			}
			if len(ap.KeyValue) == 0 {
				ap.KeyValue = nil
			}
			data.AppLocalStates[basics.AppIndex(crypto.RandUint64()%lastCreatableID)] = ap
		}
	}

	if 1 == (crypto.RandUint64() % 3) {
		data.TotalAppSchema = basics.StateSchema{
			NumUint:      crypto.RandUint64() % 50,
			NumByteSlice: crypto.RandUint64() % 50,
		}
	}
	if 1 == (crypto.RandUint64() % 3) {
		data.AppParams = make(map[basics.AppIndex]basics.AppParams)
		appParamsCount := crypto.RandUint64()%5 + 1
		for i := uint64(0); i < appParamsCount; i++ {
			ap := basics.AppParams{
				ApprovalProgram:   make([]byte, int(crypto.RandUint63())%config.MaxAppProgramLen),
				ClearStateProgram: make([]byte, int(crypto.RandUint63())%config.MaxAppProgramLen),
				GlobalState:       make(basics.TealKeyValue),
				StateSchemas: basics.StateSchemas{
					LocalStateSchema: basics.StateSchema{
						NumUint:      crypto.RandUint64() % 5,
						NumByteSlice: crypto.RandUint64() % 5,
					},
					GlobalStateSchema: basics.StateSchema{
						NumUint:      crypto.RandUint64() % 5,
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
				bytes := make([]byte, crypto.RandUint64()%512)
				crypto.RandBytes(bytes[:])
				tv.Bytes = string(bytes)
				ap.GlobalState[appName] = tv
			}
			if len(ap.GlobalState) == 0 {
				ap.GlobalState = nil
			}
			lastCreatableID++
			data.AppParams[basics.AppIndex(lastCreatableID)] = ap
		}

	}
	return data, lastCreatableID
}

func randomMiniAccounts(niter int, simpleAccounts bool) map[basics.Address]apply.MiniAccountData {
	res := make(map[basics.Address]apply.MiniAccountData)
	if simpleAccounts {
		for i := 0; i < niter; i++ {
			res[randomAddress()] = apply.AccountData(randomAccountData(0)).WithoutAppKV()
		}
	} else {
		lastCreatableID := crypto.RandUint64() % 512
		for i := 0; i < niter; i++ {
			x, id := randomFullAccountData(0, lastCreatableID)
			lastCreatableID = id
			res[randomAddress()] = apply.AccountData(x).WithoutAppKV()
		}
	}
	return res
}
