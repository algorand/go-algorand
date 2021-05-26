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
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// randAccountType defines how many data goes into a random AccountData struct
type randAccountType int

const (
	simpleAccount             randAccountType = iota // only basic AccountData fields
	fullAccount                                      // some applications and assets
	largeAssetHoldingsAccount                        // like full but 1k+ asset holdings
)

var assetsThreshold = config.Consensus[protocol.ConsensusV18].MaxAssetsPerAccount

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
	data.VoteFirstValid = 0
	data.VoteLastValid = 1000
	return data
}

func randomFullAccountData(rewardsLevel, lastCreatableID uint64, acctType randAccountType) (basics.AccountData, uint64) {
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
		if acctType == largeAssetHoldingsAccount {
			ownedAssetsCount = 1000 + uint64(crypto.RandUint64()%512)
		}
		data.Assets = make(map[basics.AssetIndex]basics.AssetHolding, ownedAssetsCount)
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
					NumUint:      crypto.RandUint64()%5 + 1,
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
				bytes := make([]byte, crypto.RandUint64()%uint64(config.MaxBytesKeyValueLen))
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
			lastCreatableID++
			data.AppParams[basics.AppIndex(lastCreatableID)] = ap
		}

	}
	return data, lastCreatableID
}

func randomAccounts(niter int, simpleAccounts bool) map[basics.Address]basics.AccountData {
	res := make(map[basics.Address]basics.AccountData)
	if simpleAccounts {
		for i := 0; i < niter; i++ {
			res[randomAddress()] = randomAccountData(0)
		}
	} else {
		lastCreatableID := crypto.RandUint64() % 512
		for i := 0; i < niter; i++ {
			res[randomAddress()], lastCreatableID = randomFullAccountData(0, lastCreatableID, fullAccount)
		}
	}
	return res
}

func randomDeltas(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]basics.AccountData, imbalance int64) {
	updates, totals, imbalance, _ = randomDeltasImpl(niter, base, rewardsLevel, simpleAccount, 0)
	return
}

func randomDeltasFull(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, lastCreatableIDIn uint64, acctType randAccountType) (updates ledgercore.AccountDeltas, totals map[basics.Address]basics.AccountData, imbalance int64, lastCreatableID uint64) {
	updates, totals, imbalance, lastCreatableID = randomDeltasImpl(niter, base, rewardsLevel, acctType, lastCreatableIDIn)
	return
}

func randomDeltasImpl(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, acctType randAccountType, lastCreatableIDIn uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]basics.AccountData, imbalance int64, lastCreatableID uint64) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	totals = make(map[basics.Address]basics.AccountData)

	// copy base -> totals
	for addr, data := range base {
		totals[addr] = data
	}

	// if making a full delta then need to determine max asset/app id to get rid of conflicts
	lastCreatableID = lastCreatableIDIn
	if acctType != simpleAccount {
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
			if acctType == simpleAccount {
				new = randomAccountData(rewardsLevel)
			} else {
				new, lastCreatableID = randomFullAccountData(rewardsLevel, lastCreatableID, acctType)
				for aidx := range new.Assets {
					if _, ok := old.Assets[aidx]; !ok {
						// if not in old => created
						updates.SetHoldingDelta(addr, aidx, ledgercore.ActionCreate)
					}
				}
				for aidx := range old.Assets {
					if _, ok := new.Assets[aidx]; !ok {
						// if not in new => deleted
						updates.SetHoldingDelta(addr, aidx, ledgercore.ActionDelete)
					}
				}
			}
			updates.Upsert(addr, ledgercore.PersistedAccountData{AccountData: new})
			imbalance += int64(old.WithUpdatedRewards(proto, rewardsLevel).MicroAlgos.Raw - new.MicroAlgos.Raw)
			totals[addr] = new
			break
		}
	}

	// Change some new accounts
	for i := 0; i < niter; i++ {
		addr := randomAddress()
		old := totals[addr]
		var new basics.AccountData
		if acctType == simpleAccount {
			new = randomAccountData(rewardsLevel)
		} else {
			new, lastCreatableID = randomFullAccountData(rewardsLevel, lastCreatableID, acctType)
		}
		updates.Upsert(addr, ledgercore.PersistedAccountData{AccountData: new})
		imbalance += int64(old.WithUpdatedRewards(proto, rewardsLevel).MicroAlgos.Raw - new.MicroAlgos.Raw)
		totals[addr] = new
	}

	return
}

func randomDeltasBalanced(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]basics.AccountData) {
	updates, totals, _ = randomDeltasBalancedImpl(niter, base, rewardsLevel, simpleAccount, 0)
	return
}

func randomDeltasBalancedFull(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, lastCreatableIDIn uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]basics.AccountData, lastCreatableID uint64) {
	updates, totals, lastCreatableID = randomDeltasBalancedImpl(niter, base, rewardsLevel, fullAccount, lastCreatableIDIn)
	return
}

func randomDeltasBalancedImpl(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, acctType randAccountType, lastCreatableIDIn uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]basics.AccountData, lastCreatableID uint64) {
	var imbalance int64
	if acctType == simpleAccount {
		updates, totals, imbalance = randomDeltas(niter, base, rewardsLevel)
	} else {
		updates, totals, imbalance, lastCreatableID = randomDeltasFull(niter, base, rewardsLevel, lastCreatableIDIn, acctType)
	}

	oldPool := base[testPoolAddr]
	newPool := oldPool
	newPool.MicroAlgos.Raw += uint64(imbalance)

	updates.Upsert(testPoolAddr, ledgercore.PersistedAccountData{AccountData: newPool})
	totals[testPoolAddr] = newPool

	return updates, totals, lastCreatableID
}

func checkAccounts(t *testing.T, tx *sql.Tx, rnd basics.Round, accts map[basics.Address]basics.AccountData) {
	r, _, err := accountsRound(tx)
	require.NoError(t, err)
	require.Equal(t, r, rnd)

	aq, err := accountsDbInit(tx, tx)
	require.NoError(t, err)
	defer aq.close()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	err = accountsAddNormalizedBalance(tx, proto)
	require.NoError(t, err)

	var totalOnline, totalOffline, totalNotPart uint64

	all, err := accountsAll(tx)
	for addr, data := range accts {
		pad, ok := all[addr]
		require.True(t, ok)
		d := pad.AccountData
		require.NoError(t, err)
		require.Equal(t, d, data)

		switch d.Status {
		case basics.Online:
			totalOnline += d.MicroAlgos.Raw
		case basics.Offline:
			totalOffline += d.MicroAlgos.Raw
		case basics.NotParticipating:
			totalNotPart += d.MicroAlgos.Raw
		default:
			t.Errorf("unknown status %v", d.Status)
		}
	}

	require.NoError(t, err)
	for a, pad := range all {
		ad := accts[a]
		if pad.ExtendedAssetHolding.Count > 0 {
			require.Equal(t, int(pad.ExtendedAssetHolding.Count), len(ad.Assets))
		} else {
			require.Equal(t, pad.AccountData.Assets, ad.Assets)
		}
	}

	totals, err := accountsTotals(tx, false)
	require.NoError(t, err)
	require.Equal(t, totals.Online.Money.Raw, totalOnline)
	require.Equal(t, totals.Offline.Money.Raw, totalOffline)
	require.Equal(t, totals.NotParticipating.Money.Raw, totalNotPart)
	require.Equal(t, totals.Participating().Raw, totalOnline+totalOffline)
	require.Equal(t, totals.All().Raw, totalOnline+totalOffline+totalNotPart)

	dbad, err := aq.lookup(randomAddress())
	require.NoError(t, err)
	require.Equal(t, rnd, dbad.round)
	require.Equal(t, dbad.pad.AccountData, basics.AccountData{})

	onlineAccounts := make(map[basics.Address]*onlineAccount)
	for addr, data := range accts {
		if data.Status == basics.Online {
			onlineAccounts[addr] = accountDataToOnline(addr, &data, proto)
		}
	}

	for i := 0; i < len(onlineAccounts); i++ {
		dbtop, err := accountsOnlineTop(tx, 0, uint64(i), proto)
		require.NoError(t, err)
		require.Equal(t, i, len(dbtop))

		// Compute the top-N accounts ourselves
		var testtop []onlineAccount
		for _, data := range onlineAccounts {
			testtop = append(testtop, *data)
		}

		sort.Slice(testtop, func(i, j int) bool {
			ibal := testtop[i].NormalizedOnlineBalance
			jbal := testtop[j].NormalizedOnlineBalance
			if ibal > jbal {
				return true
			}
			if ibal < jbal {
				return false
			}
			return bytes.Compare(testtop[i].Address[:], testtop[j].Address[:]) > 0
		})

		for j := 0; j < i; j++ {
			_, ok := dbtop[testtop[j].Address]
			require.True(t, ok)
		}
	}

	top, err := accountsOnlineTop(tx, 0, uint64(len(onlineAccounts)+1), proto)
	require.NoError(t, err)
	require.Equal(t, len(top), len(onlineAccounts))
}

func initTestAccountDB(tx *sql.Tx, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (err error) {
	err = accountsInit(tx, initAccounts, proto)
	if err != nil {
		return
	}
	err = accountsAddNormalizedBalance(tx, proto)
	if err != nil {
		return
	}
	err = createAccountExtTable(tx)
	return
}

func TestAccountDBInit(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	accts := randomAccounts(20, true)
	err = initTestAccountDB(tx, accts, proto)
	require.NoError(t, err)
	checkAccounts(t, tx, 0, accts)

	err = accountsInit(tx, accts, proto)
	require.NoError(t, err)
	checkAccounts(t, tx, 0, accts)
}

// creatablesFromUpdates calculates creatables from updates
func creatablesFromUpdates(base map[basics.Address]basics.AccountData, updates ledgercore.AccountDeltas, seen map[basics.CreatableIndex]bool) map[basics.CreatableIndex]ledgercore.ModifiedCreatable {
	creatables := make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
	for i := 0; i < updates.Len(); i++ {
		addr, update := updates.GetByIdx(i)
		// no sets in Go, so iterate over
		if ad, ok := base[addr]; ok {
			for idx := range ad.Assets {
				if _, ok := update.Assets[idx]; !ok {
					creatables[basics.CreatableIndex(idx)] = ledgercore.ModifiedCreatable{
						Ctype:   basics.AssetCreatable,
						Created: false, // exists in base, not in new => deleted
						Creator: addr,
					}
				}
			}
			for idx := range ad.AppParams {
				if _, ok := update.AppParams[idx]; !ok {
					creatables[basics.CreatableIndex(idx)] = ledgercore.ModifiedCreatable{
						Ctype:   basics.AppCreatable,
						Created: false, // exists in base, not in new => deleted
						Creator: addr,
					}
				}
			}
		}
		for idx := range update.Assets {
			if seen[basics.CreatableIndex(idx)] {
				continue
			}
			ad, found := base[addr]
			if found {
				if _, ok := ad.Assets[idx]; !ok {
					found = false
				}
			}
			if !found {
				creatables[basics.CreatableIndex(idx)] = ledgercore.ModifiedCreatable{
					Ctype:   basics.AssetCreatable,
					Created: true, // exists in new, not in base => created
					Creator: addr,
				}
			}
			seen[basics.CreatableIndex(idx)] = true
		}
		for idx := range update.AppParams {
			if seen[basics.CreatableIndex(idx)] {
				continue
			}
			ad, found := base[addr]
			if found {
				if _, ok := ad.AppParams[idx]; !ok {
					found = false
				}
			}
			if !found {
				creatables[basics.CreatableIndex(idx)] = ledgercore.ModifiedCreatable{
					Ctype:   basics.AppCreatable,
					Created: true, // exists in new, not in base => created
					Creator: addr,
				}
			}
			seen[basics.CreatableIndex(idx)] = true
		}
	}
	return creatables
}

func TestAccountDBRound(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)

	accts := randomAccounts(20, true)
	err = initTestAccountDB(tx, accts, proto)
	require.NoError(t, err)
	checkAccounts(t, tx, 0, accts)

	// used to determine how many creatables element will be in the test per iteration
	numElementsPerSegment := 10

	// lastCreatableID stores asset or app max used index to get rid of conflicts
	lastCreatableID := crypto.RandUint64() % 512
	ctbsList, randomCtbs := randomCreatables(numElementsPerSegment)
	expectedDbImage := make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
	var baseAccounts lruAccounts
	baseAccounts.init(nil, 100, 80)
	round := basics.Round(1)
	for i := 1; i < 10; i++ {
		var updates ledgercore.AccountDeltas
		var newaccts map[basics.Address]basics.AccountData
		updates, newaccts, _, lastCreatableID = randomDeltasFull(20, accts, 0, lastCreatableID, fullAccount)
		accts = newaccts
		ctbsWithDeletes := randomCreatableSampling(i, ctbsList, randomCtbs,
			expectedDbImage, numElementsPerSegment)

		updatesCnt := makeCompactAccountDeltas([]ledgercore.AccountDeltas{updates}, baseAccounts)
		err = updatesCnt.accountsLoadOld(tx)
		require.NoError(t, err)
		err = totalsNewRounds(tx, []ledgercore.AccountDeltas{updates}, updatesCnt, []ledgercore.AccountTotals{{}}, proto)
		require.NoError(t, err)
		_, err = accountsNewRound(tx, updatesCnt, ctbsWithDeletes, proto, round)
		require.NoError(t, err)
		err = updateAccountsRound(tx, round, 0)
		require.NoError(t, err)
		checkAccounts(t, tx, round, accts)
		checkCreatables(t, tx, i, expectedDbImage)
		round++
	}

	// add deltas with 1000+ holdings
	ctbsList, randomCtbs = randomCreatables(numElementsPerSegment)
	lastCreatableID = lastCreatableID + 4096
	largeHoldingsNum := 0
	fixupOldPad := func(cd compactAccountDeltas) compactAccountDeltas {
		for j := range cd.deltas {
			cd.deltas[j].new.ExtendedAssetHolding = cd.deltas[j].old.pad.ExtendedAssetHolding
		}
		return cd
	}

	err = tx.Commit()
	require.NoError(t, err)
retry:
	for i := 1; i < 10; i++ {
		var updates ledgercore.AccountDeltas
		var newaccts map[basics.Address]basics.AccountData
		updates, newaccts, _, lastCreatableID = randomDeltasFull(20, accts, 0, lastCreatableID, largeAssetHoldingsAccount)

		tx, err = dbs.Wdb.Handle.Begin()
		require.NoError(t, err)

		// ensure all data are consistent
		aq, err := accountsDbInit(tx, tx)
		require.NoError(t, err)
		for _, addr := range updates.ModifiedAccounts() {
			hd := updates.GetHoldingDeltas(addr)
			ad := accts[addr]
			dbad, err := lookupFull(dbs.Rdb, addr)
			prevEnd := uint64(0)
			for _, g := range dbad.pad.ExtendedAssetHolding.Groups {
				start := uint64(g.MinAssetIndex)
				if start != 0 { // group 0 might start with 0, ignore
					require.Less(t, prevEnd, start)
				}
				prevEnd = start + g.DeltaMaxAssetIndex
			}
			require.Equal(t, ad, dbad.pad.AccountData)
			if len(ad.Assets) > assetsThreshold {
				for aidx := range ad.Assets {
					gi, ai := dbad.pad.ExtendedAssetHolding.FindAsset(aidx, 0)
					require.NotEqual(t, -1, gi)
					require.NotEqual(t, -1, ai)
				}
			}
			require.NoError(t, err)
			for aidx, action := range hd {
				if action == ledgercore.ActionDelete {
					_, ok := ad.Assets[aidx]
					require.True(t, ok)
					if len(ad.Assets) > assetsThreshold {
						gi, ai := dbad.pad.ExtendedAssetHolding.FindAsset(aidx, 0)
						require.NotEqual(t, -1, gi)
						require.NotEqual(t, -1, ai)
					}
				}
			}
		}
		aq.close()

		accts = newaccts
		ctbsWithDeletes := randomCreatableSampling(i, ctbsList, randomCtbs,
			expectedDbImage, numElementsPerSegment)

		// ensure large holdings were generated
		for _, acct := range accts {
			if len(acct.Assets) > assetsThreshold {
				largeHoldingsNum++
			}
		}
		updatesCnt := makeCompactAccountDeltas([]ledgercore.AccountDeltas{updates}, baseAccounts)
		err = updatesCnt.accountsLoadOld(tx)
		require.NoError(t, err)

		// because our rand functions work with AccountData, accountDelta.new does not have ExtendedAssetHolding info.
		// copy it from old
		updatesCnt = fixupOldPad(updatesCnt)

		err = totalsNewRounds(tx, []ledgercore.AccountDeltas{updates}, updatesCnt, []ledgercore.AccountTotals{{}}, proto)
		require.NoError(t, err)
		_, err = accountsNewRound(tx, updatesCnt, ctbsWithDeletes, proto, round)
		require.NoError(t, err)
		err = updateAccountsRound(tx, round, 0)
		require.NoError(t, err)
		checkAccounts(t, tx, round, accts)
		checkCreatables(t, tx, i, expectedDbImage)
		round++

		err = tx.Commit()
		require.NoError(t, err)
	}
	// 10 iterations 20 accts each => 200 accounts, want at least 25% to have large holdings
	if largeHoldingsNum < 50 {
		goto retry
	}
}

func TestAccountDBRoundAssetHoldings(t *testing.T) {
	// deterministic test for 1000+ holdings:
	// select an account, add 256 * 6 holdings, then delete one bucket, and modify others
	// ensure all holdings match expectations

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	accts := randomAccounts(20, true)
	err = initTestAccountDB(tx, accts, proto)
	require.NoError(t, err)
	checkAccounts(t, tx, 0, accts)

	// lastCreatableID stores asset or app max used index to get rid of conflicts
	var baseAccounts lruAccounts
	baseAccounts.init(nil, 100, 80)
	round := basics.Round(1)

	// select some random account
	var addr basics.Address
	var ad basics.AccountData
	for a, data := range accts {
		addr = a
		ad = data
		break
	}
	require.NotEmpty(t, addr)

	applyUpdate := func(tx *sql.Tx, updates ledgercore.AccountDeltas) {
		updatesCnt := makeCompactAccountDeltas([]ledgercore.AccountDeltas{updates}, baseAccounts)
		err = updatesCnt.accountsLoadOld(tx)
		require.NoError(t, err)

		for j := range updatesCnt.deltas {
			updatesCnt.deltas[j].new.ExtendedAssetHolding = updatesCnt.deltas[j].old.pad.ExtendedAssetHolding
		}

		_, err = accountsNewRound(tx, updatesCnt, nil, proto, round)
		require.NoError(t, err)
		err = updateAccountsRound(tx, round, 0)
		require.NoError(t, err)
		round++
	}
	// remove all the assets first to make predictable assets distribution
	var updates ledgercore.AccountDeltas
	for aidx := range ad.Assets {
		updates.SetHoldingDelta(addr, aidx, ledgercore.ActionDelete)
	}
	ad.Assets = nil
	updates.Upsert(addr, ledgercore.PersistedAccountData{AccountData: ad})
	applyUpdate(tx, updates)
	err = tx.Commit()
	require.NoError(t, err)

	// verify removal
	require.NoError(t, err)
	dbad, err := lookupFull(dbs.Rdb, addr)
	require.NoError(t, err)
	require.Empty(t, dbad.pad.AccountData.Assets)
	require.Empty(t, dbad.pad.ExtendedAssetHolding)

	// create 6 holding groups
	tx, err = dbs.Wdb.Handle.Begin()
	require.NoError(t, err)

	holdingsNum := ledgercore.MaxHoldingGroupSize * 6
	updates = ledgercore.AccountDeltas{}
	ad = dbad.pad.AccountData
	ad.Assets = make(map[basics.AssetIndex]basics.AssetHolding, holdingsNum)
	for aidx := 1; aidx <= holdingsNum; aidx++ {
		ad.Assets[basics.AssetIndex(aidx)] = basics.AssetHolding{Amount: uint64(aidx)}
		updates.SetHoldingDelta(addr, basics.AssetIndex(aidx), ledgercore.ActionCreate)
	}
	updates.Upsert(addr, ledgercore.PersistedAccountData{AccountData: ad})
	applyUpdate(tx, updates)
	err = tx.Commit()
	require.NoError(t, err)

	// verify creation
	dbad, err = lookupFull(dbs.Rdb, addr)
	require.NoError(t, err)
	require.Equal(t, holdingsNum, len(dbad.pad.AccountData.Assets))
	require.Equal(t, holdingsNum, int(dbad.pad.ExtendedAssetHolding.Count))
	require.Equal(t, 6, len(dbad.pad.ExtendedAssetHolding.Groups))

	// completely remove group 1, remove 32 assets from all other groups, update 32 other assets
	tx, err = dbs.Wdb.Handle.Begin()
	require.NoError(t, err)

	updates = ledgercore.AccountDeltas{}
	ad = dbad.pad.AccountData
	for aidx := ledgercore.MaxHoldingGroupSize + 1; aidx <= 2*ledgercore.MaxHoldingGroupSize; aidx++ {
		delete(ad.Assets, basics.AssetIndex(aidx))
		updates.SetHoldingDelta(addr, basics.AssetIndex(aidx), ledgercore.ActionDelete)
	}
	updates.Upsert(addr, ledgercore.PersistedAccountData{AccountData: ad})
	for _, gi := range []int{0, 2, 3, 4, 5} {
		start := gi*ledgercore.MaxHoldingGroupSize + 1
		end := (gi + 1) * ledgercore.MaxHoldingGroupSize
		seq := make([]int, 0, ledgercore.MaxHoldingGroupSize)
		for i := start; i <= end; i++ {
			seq = append(seq, i)
		}
		rand.Shuffle(ledgercore.MaxHoldingGroupSize, func(i, j int) { seq[i], seq[j] = seq[j], seq[i] })
		for _, aidx := range seq[:32] {
			delete(ad.Assets, basics.AssetIndex(aidx))
			updates.SetHoldingDelta(addr, basics.AssetIndex(aidx), ledgercore.ActionDelete)
		}
		for _, aidx := range seq[32:64] {
			ad.Assets[basics.AssetIndex(aidx)] = basics.AssetHolding{Amount: uint64(aidx * 10)}
		}
		// remove reset from ad.Assets since they are not in the update
		for _, aidx := range seq[64:] {
			delete(ad.Assets, basics.AssetIndex(aidx))
		}
	}
	updates.Upsert(addr, ledgercore.PersistedAccountData{AccountData: ad})
	applyUpdate(tx, updates)
	err = tx.Commit()
	require.NoError(t, err)

	// verify update
	dbad, err = lookupFull(dbs.Rdb, addr)
	require.NoError(t, err)
	require.Equal(t, holdingsNum-ledgercore.MaxHoldingGroupSize-5*32, len(dbad.pad.AccountData.Assets))
	require.Equal(t, len(dbad.pad.AccountData.Assets), int(dbad.pad.ExtendedAssetHolding.Count))
	require.Equal(t, 5, len(dbad.pad.ExtendedAssetHolding.Groups))
	gi := 0
	for _, ogi := range []int{0, 2, 3, 4, 5} {
		g := dbad.pad.ExtendedAssetHolding.Groups[gi]
		start := ogi*ledgercore.MaxHoldingGroupSize + 1
		end := (ogi + 1) * ledgercore.MaxHoldingGroupSize
		require.LessOrEqual(t, uint64(start), uint64(g.MinAssetIndex))
		require.LessOrEqual(t, uint64(g.MinAssetIndex)+g.DeltaMaxAssetIndex, uint64(end))
		aidx := g.MinAssetIndex
		for ai, offset := range g.TestGetGroupData().AssetOffsets {
			h := g.GetHolding(ai)
			aidx += offset
			require.True(t, h.Amount == uint64(aidx) || h.Amount == uint64(aidx*10))
			require.GreaterOrEqual(t, uint64(aidx), uint64(g.MinAssetIndex))
			require.LessOrEqual(t, uint64(aidx), uint64(g.MinAssetIndex)+g.DeltaMaxAssetIndex)
		}
		gi++
	}

	// create a new group
	tx, err = dbs.Wdb.Handle.Begin()
	require.NoError(t, err)

	updates = ledgercore.AccountDeltas{}
	ad = dbad.pad.AccountData
	ad.Assets = make(map[basics.AssetIndex]basics.AssetHolding, ledgercore.MaxHoldingGroupSize)
	for aidx := 6*ledgercore.MaxHoldingGroupSize + 1; aidx <= 7*ledgercore.MaxHoldingGroupSize; aidx++ {
		updates.SetHoldingDelta(addr, basics.AssetIndex(aidx), ledgercore.ActionCreate)
		ad.Assets[basics.AssetIndex(aidx)] = basics.AssetHolding{Amount: uint64(aidx)}
	}
	updates.Upsert(addr, ledgercore.PersistedAccountData{AccountData: ad})
	applyUpdate(tx, updates)
	err = tx.Commit()
	require.NoError(t, err)

	// verify creation
	dbad, err = lookupFull(dbs.Rdb, addr)
	require.NoError(t, err)
	require.Equal(t, holdingsNum-5*32, len(dbad.pad.AccountData.Assets))
	require.Equal(t, len(dbad.pad.AccountData.Assets), int(dbad.pad.ExtendedAssetHolding.Count))
	require.Equal(t, 6, len(dbad.pad.ExtendedAssetHolding.Groups))
	gi = 0
	for _, ogi := range []int{0, 2, 3, 4, 5, 6} {
		g := dbad.pad.ExtendedAssetHolding.Groups[gi]
		start := ogi*ledgercore.MaxHoldingGroupSize + 1
		end := (ogi + 1) * ledgercore.MaxHoldingGroupSize
		if ogi == 5 {
			// group 5 accepted 32 assets
			end += 32
		}
		require.LessOrEqual(t, uint64(start), uint64(g.MinAssetIndex))
		require.LessOrEqual(t, uint64(g.MinAssetIndex)+g.DeltaMaxAssetIndex, uint64(end))
		aidx := g.MinAssetIndex
		for ai, offset := range g.TestGetGroupData().AssetOffsets {
			h := g.GetHolding(ai)
			aidx += offset
			require.True(t, h.Amount == uint64(aidx) || h.Amount == uint64(aidx*10))
			require.GreaterOrEqual(t, uint64(aidx), uint64(g.MinAssetIndex))
			require.LessOrEqual(t, uint64(aidx), uint64(g.MinAssetIndex)+g.DeltaMaxAssetIndex)
		}
		gi++
	}

	// delete groups 0, 2, 4 and ensure holdins collapse back to ad.Assets
	tx, err = dbs.Wdb.Handle.Begin()
	require.NoError(t, err)

	updates = ledgercore.AccountDeltas{}
	ad = dbad.pad.AccountData
	for _, gi := range []int{0, 2, 4} {
		start := gi*ledgercore.MaxHoldingGroupSize + 1
		end := (gi + 1) * ledgercore.MaxHoldingGroupSize
		for aidx := start; aidx <= end; aidx++ {
			delete(ad.Assets, basics.AssetIndex(aidx))
			updates.SetHoldingDelta(addr, basics.AssetIndex(aidx), ledgercore.ActionDelete)
		}
	}

	updates.Upsert(addr, ledgercore.PersistedAccountData{AccountData: ad})
	applyUpdate(tx, updates)
	err = tx.Commit()
	require.NoError(t, err)

	// check removal
	dbad1, err := lookupFull(dbs.Rdb, addr)
	require.NoError(t, err)
	require.Equal(t, holdingsNum-2*32-3*ledgercore.MaxHoldingGroupSize, len(dbad1.pad.AccountData.Assets))
	require.Empty(t, dbad1.pad.ExtendedAssetHolding)

	// delete the account
	tx, err = dbs.Wdb.Handle.Begin()
	require.NoError(t, err)

	updates = ledgercore.AccountDeltas{}
	updates.Upsert(addr, ledgercore.PersistedAccountData{})
	applyUpdate(tx, updates)
	err = tx.Commit()
	require.NoError(t, err)
	dbad, err = lookupFull(dbs.Rdb, addr)
	require.NoError(t, err)
	require.Empty(t, dbad.pad)
}

// checkCreatables compares the expected database image to the actual database content
func checkCreatables(t *testing.T,
	tx *sql.Tx, iteration int,
	expectedDbImage map[basics.CreatableIndex]ledgercore.ModifiedCreatable) {

	stmt, err := tx.Prepare("SELECT asset, creator, ctype FROM assetcreators")
	require.NoError(t, err)

	defer stmt.Close()
	rows, err := stmt.Query()
	if err != sql.ErrNoRows {
		require.NoError(t, err)
	}
	defer rows.Close()
	counter := 0
	for rows.Next() {
		counter++
		mc := ledgercore.ModifiedCreatable{}
		var buf []byte
		var asset basics.CreatableIndex
		err := rows.Scan(&asset, &buf, &mc.Ctype)
		require.NoError(t, err)
		copy(mc.Creator[:], buf)

		require.NotNil(t, expectedDbImage[asset])
		require.Equal(t, expectedDbImage[asset].Creator, mc.Creator)
		require.Equal(t, expectedDbImage[asset].Ctype, mc.Ctype)
		require.True(t, expectedDbImage[asset].Created)
	}
	require.Equal(t, len(expectedDbImage), counter)
}

// randomCreatableSampling sets elements to delete from previous iteration
// It consideres 10 elements in an iteration.
// loop 0: returns the first 10 elements
// loop 1: returns: * the second 10 elements
//                  * random sample of elements from the first 10: created changed from true -> false
// loop 2: returns: * the elements 20->30
//                  * random sample of elements from 10->20: created changed from true -> false
func randomCreatableSampling(iteration int, crtbsList []basics.CreatableIndex,
	creatables map[basics.CreatableIndex]ledgercore.ModifiedCreatable,
	expectedDbImage map[basics.CreatableIndex]ledgercore.ModifiedCreatable,
	numElementsPerSegement int) map[basics.CreatableIndex]ledgercore.ModifiedCreatable {

	iteration-- // 0-based here

	delSegmentEnd := iteration * numElementsPerSegement
	delSegmentStart := delSegmentEnd - numElementsPerSegement
	if delSegmentStart < 0 {
		delSegmentStart = 0
	}

	newSample := make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
	stop := delSegmentEnd + numElementsPerSegement

	for i := delSegmentStart; i < delSegmentEnd; i++ {
		ctb := creatables[crtbsList[i]]
		if ctb.Created &&
			// Always delete the first element, to make sure at least one
			// element is always deleted.
			(i == delSegmentStart || 1 == (crypto.RandUint64()%2)) {
			ctb.Created = false
			newSample[crtbsList[i]] = ctb
			delete(expectedDbImage, crtbsList[i])
		}
	}

	for i := delSegmentEnd; i < stop; i++ {
		newSample[crtbsList[i]] = creatables[crtbsList[i]]
		if creatables[crtbsList[i]].Created {
			expectedDbImage[crtbsList[i]] = creatables[crtbsList[i]]
		}
	}

	return newSample
}

func randomCreatables(numElementsPerSegement int) ([]basics.CreatableIndex,
	map[basics.CreatableIndex]ledgercore.ModifiedCreatable) {
	creatables := make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
	creatablesList := make([]basics.CreatableIndex, numElementsPerSegement*10)
	uniqueAssetIds := make(map[basics.CreatableIndex]bool)

	for i := 0; i < numElementsPerSegement*10; i++ {
		assetIndex, mc := randomCreatable(uniqueAssetIds)
		creatables[assetIndex] = mc
		creatablesList[i] = assetIndex
	}
	return creatablesList, creatables // creatablesList is needed for maintaining the order
}

// randomCreatable generates a random creatable.
func randomCreatable(uniqueAssetIds map[basics.CreatableIndex]bool) (
	assetIndex basics.CreatableIndex, mc ledgercore.ModifiedCreatable) {

	var ctype basics.CreatableType

	switch crypto.RandUint64() % 2 {
	case 0:
		ctype = basics.AssetCreatable
	case 1:
		ctype = basics.AppCreatable
	}

	creatable := ledgercore.ModifiedCreatable{
		Ctype:   ctype,
		Created: (crypto.RandUint64() % 2) == 1,
		Creator: randomAddress(),
		Ndeltas: 1,
	}

	var assetIdx basics.CreatableIndex
	for {
		assetIdx = basics.CreatableIndex(crypto.RandUint64() % (uint64(2) << 50))
		_, found := uniqueAssetIds[assetIdx]
		if !found {
			uniqueAssetIds[assetIdx] = true
			break
		}
	}
	return assetIdx, creatable
}

func generateRandomTestingAccountBalances(numAccounts int) (updates map[basics.Address]basics.AccountData) {
	secrets := crypto.GenerateOneTimeSignatureSecrets(15, 500)
	pubVrfKey, _ := crypto.VrfKeygenFromSeed([32]byte{0, 1, 2, 3})
	updates = make(map[basics.Address]basics.AccountData, numAccounts)

	for i := 0; i < numAccounts; i++ {
		addr := randomAddress()
		updates[addr] = basics.AccountData{
			MicroAlgos:         basics.MicroAlgos{Raw: 0x000ffffffffffffff / uint64(numAccounts)},
			Status:             basics.NotParticipating,
			RewardsBase:        uint64(i),
			RewardedMicroAlgos: basics.MicroAlgos{Raw: 0x000ffffffffffffff / uint64(numAccounts)},
			VoteID:             secrets.OneTimeSignatureVerifier,
			SelectionID:        pubVrfKey,
			VoteFirstValid:     basics.Round(0x000ffffffffffffff),
			VoteLastValid:      basics.Round(0x000ffffffffffffff),
			VoteKeyDilution:    0x000ffffffffffffff,
			AssetParams: map[basics.AssetIndex]basics.AssetParams{
				0x000ffffffffffffff: {
					Total:         0x000ffffffffffffff,
					Decimals:      0x2ffffff,
					DefaultFrozen: true,
					UnitName:      "12345678",
					AssetName:     "12345678901234567890123456789012",
					URL:           "12345678901234567890123456789012",
					MetadataHash:  pubVrfKey,
					Manager:       addr,
					Reserve:       addr,
					Freeze:        addr,
					Clawback:      addr,
				},
			},
			Assets: map[basics.AssetIndex]basics.AssetHolding{
				0x000ffffffffffffff: {
					Amount: 0x000ffffffffffffff,
					Frozen: true,
				},
			},
		}
	}
	return
}

// benchmarkInitBalances is a common accounts initialization function for benchmarks.
// numAccounts specifies how many accounts to create
// maxHoldingsPerAccount sets a maximum asset holdings per account (normally distributed across all accounts)
// largeAccountsRatio is a percentage of numAccounts to have maxHoldingsPerAccount holdings
func benchmarkInitBalances(b testing.TB, numAccounts int, dbs db.Pair, proto config.ConsensusParams, maxHoldingsPerAccount int, largeAccountsRatio int) (accts map[basics.Address]basics.AccountData) {
	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(b, err)

	accts = generateRandomTestingAccountBalances(numAccounts)

	err = accountsInit(tx, accts, proto)
	require.NoError(b, err)
	err = accountsAddNormalizedBalance(tx, proto)
	require.NoError(b, err)
	err = createAccountExtTable(tx)
	require.NoError(b, err)

	// create large holdings as an update because accountsInit does not know about accountext table
	// the distribution is normal from (maxAssets / numAccounts) to maxHoldingsPerAccount
	// want have 95% of accounts to be between [1/4 maxHoldingsPerAccount/8, maxHoldingsPerAccount] then
	// mean = 5/8 maxHoldingsPerAccount and stddev = 3/16 maxHoldingsPerAccount

	largeHoldings := maxHoldingsPerAccount > numAccounts
	if largeHoldings {
		maxAssetIndex := maxHoldingsPerAccount + 1
		aidxs := make([]basics.AssetIndex, maxAssetIndex, maxAssetIndex)
		for i := 0; i < maxAssetIndex; i++ {
			aidxs[i] = basics.AssetIndex(i + 1)
		}
		maxAccts := numAccounts * largeAccountsRatio / 100
		var updates ledgercore.AccountDeltas
		acctCounter := 0
		for addr, ad := range accts {
			rand.Shuffle(len(aidxs), func(i, j int) { aidxs[i], aidxs[j] = aidxs[j], aidxs[i] })
			numHoldings := int(rand.NormFloat64()*3*float64(maxHoldingsPerAccount)/16 + float64(5*maxHoldingsPerAccount)/8)
			if numHoldings > maxAssetIndex {
				numHoldings = maxAssetIndex
			}
			if numHoldings < 0 {
				numHoldings = 0
			}
			for _, aidx := range aidxs[:numHoldings] {
				if _, ok := ad.Assets[aidx]; !ok {
					ad.Assets[aidx] = basics.AssetHolding{Amount: uint64(aidx), Frozen: true}
					updates.SetHoldingDelta(addr, aidx, ledgercore.ActionCreate)
				}
			}
			updates.Upsert(addr, ledgercore.PersistedAccountData{AccountData: ad})
			accts[addr] = ad

			acctCounter++
			if acctCounter >= maxAccts {
				break
			}
		}

		baseAccounts := lruAccounts{}
		updatesCnt := makeCompactAccountDeltas([]ledgercore.AccountDeltas{updates}, baseAccounts)
		err = updatesCnt.accountsLoadOld(tx)
		require.NoError(b, err)

		round := basics.Round(1)
		for j := range updatesCnt.deltas {
			updatesCnt.deltas[j].new.ExtendedAssetHolding = updatesCnt.deltas[j].old.pad.ExtendedAssetHolding
		}
		_, err = accountsNewRound(tx, updatesCnt, nil, proto, round)
		require.NoError(b, err)
		err = updateAccountsRound(tx, round, 0)
		require.NoError(b, err)
	}

	err = tx.Commit()
	require.NoError(b, err)

	return
}

func cleanupTestDb(dbs db.Pair, dbName string, inMemory bool) {
	dbs.Close()
	if !inMemory {
		os.Remove(dbName)
	}
}

func benchmarkReadingAllBalances(b *testing.B, inMemory bool, maxHoldingsPerAccount int, largeAccountsRatio int) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	dbs, fn := dbOpenTest(b, inMemory)
	setDbLogging(b, dbs)
	defer cleanupTestDb(dbs, fn, inMemory)

	benchmarkInitBalances(b, b.N, dbs, proto, maxHoldingsPerAccount, largeAccountsRatio)
	tx, err := dbs.Rdb.Handle.Begin()
	require.NoError(b, err)

	var bal map[basics.Address]ledgercore.PersistedAccountData
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// read all the balances in the database.
		bal, err = accountsAll(tx)
		require.NoError(b, err)
	}
	b.StopTimer()

	var numDbReads int
	err = tx.QueryRow("SELECT COUNT(1) FROM accountbase").Scan(&numDbReads)
	require.NoError(b, err)
	var numGroupData int
	err = tx.QueryRow("SELECT COUNT(1) FROM accountext").Scan(&numGroupData)
	numDbReads += numGroupData
	require.NoError(b, err)
	b.ReportMetric(float64(numDbReads), "num_db_reads")

	tx.Commit()

	prevHash := crypto.Digest{}
	for _, accountBalance := range bal {
		encodedAccountBalance := protocol.Encode(&accountBalance)
		prevHash = crypto.Hash(append(encodedAccountBalance, ([]byte(prevHash[:]))...))
	}
	require.Equal(b, b.N, len(bal))
}

func BenchmarkReadingAllBalancesRAM(b *testing.B) {
	benchmarkReadingAllBalances(b, true, 1, 100)
}

func BenchmarkReadingAllBalancesDisk(b *testing.B) {
	benchmarkReadingAllBalances(b, false, 1, 100)
}

func benchmarkReadingAllBalancesLarge(b *testing.B, inMemory bool) {
	var pct = []int{100, 10}
	var tests = []int{1, 512, 2000, 3000, 5000, 10000, 100000}
	for _, p := range pct {
		for _, n := range tests {
			b.Run(fmt.Sprintf("holdings=%d/pct=%d", n, p), func(b *testing.B) {
				benchmarkReadingAllBalances(b, inMemory, n, p)
			})
		}
	}
}

func BenchmarkReadingAllBalancesRAMLarge(b *testing.B) {
	benchmarkReadingAllBalancesLarge(b, true)
}

func BenchmarkReadingAllBalancesDiskLarge(b *testing.B) {
	benchmarkReadingAllBalancesLarge(b, false)
}

func benchLoadHolding(b *testing.B, qs *accountsDbQueries, dbad dbAccountData, aidx basics.AssetIndex) basics.AssetHolding {
	gi, ai := dbad.pad.ExtendedAssetHolding.FindAsset(aidx, 0)
	require.NotEqual(b, -1, gi)
	require.Equal(b, -1, ai)
	var err error
	_, dbad.pad.ExtendedAssetHolding.Groups[gi], _, err = loadHoldingGroup(qs.loadAccountGroupDataStmt, dbad.pad.ExtendedAssetHolding.Groups[gi], nil)
	require.NoError(b, err)
	_, ai = dbad.pad.ExtendedAssetHolding.FindAsset(aidx, gi)
	require.NotEqual(b, -1, ai)
	return dbad.pad.ExtendedAssetHolding.Groups[gi].GetHolding(ai)
}

func benchmarkReadingRandomBalances(b *testing.B, inMemory bool, maxHoldingsPerAccount int, largeAccountsRatio int, simple bool) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	dbs, fn := dbOpenTest(b, inMemory)
	setDbLogging(b, dbs)
	defer cleanupTestDb(dbs, fn, inMemory)

	accounts := benchmarkInitBalances(b, b.N, dbs, proto, maxHoldingsPerAccount, largeAccountsRatio)

	qs, err := accountsDbInit(dbs.Rdb.Handle, dbs.Wdb.Handle)
	require.NoError(b, err)

	// read all the balances in the database, shuffled
	addrs := make([]basics.Address, len(accounts))
	pos := 0
	for addr := range accounts {
		addrs[pos] = addr
		pos++
	}
	rand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })

	// only measure the actual fetch time
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, addr := range addrs {
			dbad, err := qs.lookup(addr)
			require.NoError(b, err)
			if !simple && len(accounts[addr].Assets) > assetsThreshold {
				for aidx := range accounts[addr].Assets {
					h := benchLoadHolding(b, qs, dbad, aidx)
					require.NotEmpty(b, h)
					break // take first from randomly interated map
				}
			}
		}
	}
}

func BenchmarkReadingRandomBalancesRAM(b *testing.B) {
	benchmarkReadingRandomBalances(b, true, 1, 100, true)
}

func BenchmarkReadingRandomBalancesDisk(b *testing.B) {
	benchmarkReadingRandomBalances(b, false, 1, 100, true)
}

func BenchmarkReadingRandomBalancesDiskLarge(b *testing.B) {
	var tests = []struct {
		numHoldings int
		simple      bool
	}{
		{1, true},
		{512, true},
		{2000, false},
		{5000, false},
		{10000, false},
		{100000, false},
	}
	for _, t := range tests {
		b.Run(fmt.Sprintf("holdings=%d simple=%v", t.numHoldings, t.simple), func(b *testing.B) {
			benchmarkReadingRandomBalances(b, false, t.numHoldings, 10, t.simple)
		})
	}
}

func BenchmarkWritingRandomBalancesDisk(b *testing.B) {
	totalStartupAccountsNumber := 5000000
	batchCount := 1000
	startupAcct := 5
	initDatabase := func() (*sql.Tx, func(), error) {
		proto := config.Consensus[protocol.ConsensusCurrentVersion]
		dbs, fn := dbOpenTest(b, false)
		setDbLogging(b, dbs)
		cleanup := func() {
			cleanupTestDb(dbs, fn, false)
		}

		benchmarkInitBalances(b, startupAcct, dbs, proto, 1, 100)
		dbs.Wdb.SetSynchronousMode(context.Background(), db.SynchronousModeOff, false)

		// insert 1M accounts data, in batches of 1000
		for batch := 0; batch <= batchCount; batch++ {
			fmt.Printf("\033[M\r %d / %d accounts written", totalStartupAccountsNumber*batch/batchCount, totalStartupAccountsNumber)

			tx, err := dbs.Wdb.Handle.Begin()

			require.NoError(b, err)

			acctsData := generateRandomTestingAccountBalances(totalStartupAccountsNumber / batchCount)
			replaceStmt, err := tx.Prepare("INSERT INTO accountbase (address, normalizedonlinebalance, data) VALUES (?, ?, ?)")
			require.NoError(b, err)
			defer replaceStmt.Close()
			for addr, acctData := range acctsData {
				_, err = replaceStmt.Exec(addr[:], uint64(0), protocol.Encode(&acctData))
				require.NoError(b, err)
			}

			err = tx.Commit()
			require.NoError(b, err)
		}
		dbs.Wdb.SetSynchronousMode(context.Background(), db.SynchronousModeFull, true)
		tx, err := dbs.Wdb.Handle.Begin()
		require.NoError(b, err)
		fmt.Printf("\033[M\r")
		return tx, cleanup, err
	}

	selectAccounts := func(tx *sql.Tx) (accountsAddress [][]byte, accountsRowID []int) {
		accountsAddress = make([][]byte, 0, totalStartupAccountsNumber+startupAcct)
		accountsRowID = make([]int, 0, totalStartupAccountsNumber+startupAcct)

		// read all the accounts to obtain the addrs.
		rows, err := tx.Query("SELECT rowid, address FROM accountbase")
		defer rows.Close()
		for rows.Next() {
			var addrbuf []byte
			var rowid int
			err = rows.Scan(&rowid, &addrbuf)
			require.NoError(b, err)
			accountsAddress = append(accountsAddress, addrbuf)
			accountsRowID = append(accountsRowID, rowid)
		}
		return
	}

	tx, cleanup, err := initDatabase()
	require.NoError(b, err)
	defer cleanup()

	accountsAddress, accountsRowID := selectAccounts(tx)

	b.Run("ByAddr", func(b *testing.B) {
		preparedUpdate, err := tx.Prepare("UPDATE accountbase SET data = ? WHERE address = ?")
		require.NoError(b, err)
		defer preparedUpdate.Close()
		// updates accounts by address
		randomAccountData := make([]byte, 200)
		crypto.RandBytes(randomAccountData)
		updateOrder := rand.Perm(len(accountsRowID))
		b.ResetTimer()
		startTime := time.Now()
		for n := 0; n < b.N; n++ {
			for _, acctIdx := range updateOrder {
				res, err := preparedUpdate.Exec(randomAccountData[:], accountsAddress[acctIdx])
				require.NoError(b, err)
				rowsAffected, err := res.RowsAffected()
				require.NoError(b, err)
				require.Equal(b, int64(1), rowsAffected)
				n++
				if n == b.N {
					break
				}
			}

		}
		b.ReportMetric(float64(int(time.Now().Sub(startTime))/b.N), "ns/acct_update")
	})

	b.Run("ByRowID", func(b *testing.B) {
		preparedUpdate, err := tx.Prepare("UPDATE accountbase SET data = ? WHERE rowid = ?")
		require.NoError(b, err)
		defer preparedUpdate.Close()
		// updates accounts by address
		randomAccountData := make([]byte, 200)
		crypto.RandBytes(randomAccountData)
		updateOrder := rand.Perm(len(accountsRowID))
		b.ResetTimer()
		startTime := time.Now()
		for n := 0; n < b.N; n++ {
			for _, acctIdx := range updateOrder {
				res, err := preparedUpdate.Exec(randomAccountData[:], accountsRowID[acctIdx])
				require.NoError(b, err)
				rowsAffected, err := res.RowsAffected()
				require.NoError(b, err)
				require.Equal(b, int64(1), rowsAffected)
				n++
				if n == b.N {
					break
				}
			}
		}
		b.ReportMetric(float64(int(time.Now().Sub(startTime))/b.N), "ns/acct_update")

	})

	err = tx.Commit()
	require.NoError(b, err)
}

func benchmarkAcctUpdateLarge(b *testing.B, maxHoldingsPerAccount int, largeHoldingsRation int, assetUpdateRatio int) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	dbs, fn := dbOpenTest(b, false)
	setDbLogging(b, dbs)
	defer cleanupTestDb(dbs, fn, false)

	numAccounts := 100
	accts := benchmarkInitBalances(b, numAccounts, dbs, proto, maxHoldingsPerAccount, largeHoldingsRation)

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(b, err)

	_, err = accountsDbInit(dbs.Rdb.Handle, dbs.Wdb.Handle)
	require.NoError(b, err)

	loaded := make(map[basics.Address]dbAccountData, len(accts))
	for addr := range accts {
		loaded[addr], err = lookupFull(dbs.Rdb, addr)
		require.NoError(b, err)
	}

	acctUpdateStmt, err := tx.Prepare("UPDATE accountbase SET normalizedonlinebalance = ?, data = ? WHERE rowid = ?")
	require.NoError(b, err)
	gdUpdateStmt, err := tx.Prepare("UPDATE accountext SET data = ? WHERE id = ?")
	require.NoError(b, err)

	type groupDataUpdate struct {
		gi   int
		data []byte
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for addr := range accts {
			b.StopTimer()
			// one AD update per account and few group data updates
			dbad := loaded[addr]
			encodedPad := protocol.Encode(&dbad.pad)
			var numToUpdate int
			var gdu []groupDataUpdate
			if len(dbad.pad.Assets) > assetsThreshold {
				numToUpdate = assetUpdateRatio * len(dbad.pad.Assets) / 100
				gdu = make([]groupDataUpdate, numToUpdate, numToUpdate)
				k := 0
				for aidx := range dbad.pad.Assets {
					gi := dbad.pad.ExtendedAssetHolding.FindGroup(aidx, 0)
					require.NotEqual(b, -1, gi)
					data := dbad.pad.ExtendedAssetHolding.Groups[gi].TestGetGroupData()
					gdu[k] = groupDataUpdate{gi, protocol.Encode(&data)}
					k++
					if k >= numToUpdate {
						break
					}
				}
			}

			b.StartTimer()
			_, err = acctUpdateStmt.Exec(dbad.pad.MicroAlgos.Raw, encodedPad, dbad.rowid)
			require.NoError(b, err)

			if len(dbad.pad.Assets) > assetsThreshold {
				for _, entry := range gdu {
					_, err = gdUpdateStmt.Exec(entry.data, entry.gi)
				}
			}
		}
	}

	tx.Commit()
}

var benchCreatedAccts map[basics.Address]basics.AccountData

// Benchmark large asset holding creation.
// This included splitting data into groups and writing into legder
func BenchmarkLargeAccountsCreation(b *testing.B) {
	holdings := []int{1, 512, 2000, 3000, 5000, 10000, 100000}
	numAccounts := 100
	for _, n := range holdings {
		b.Run(fmt.Sprintf("holdings=%d", n), func(b *testing.B) {
			proto := config.Consensus[protocol.ConsensusCurrentVersion]
			dbs, fn := dbOpenTest(b, true)
			setDbLogging(b, dbs)
			b.ResetTimer()
			benchCreatedAccts = benchmarkInitBalances(b, numAccounts, dbs, proto, n, 100)
			b.StopTimer()
			cleanupTestDb(dbs, fn, true)
		})
	}
}

// Benchmark large asset holding writing
func BenchmarkAcctUpdatesDiskLarge(b *testing.B) {
	holdings := []int{1, 512, 2000, 3000, 5000, 10000, 100000}
	largeRatio := []int{100, 10}
	for _, p := range largeRatio {
		for _, n := range holdings {
			b.Run(fmt.Sprintf("holdings=%d/pct=%d", n, p), func(b *testing.B) {
				benchmarkAcctUpdateLarge(b, n, p, 50)
			})
		}
	}
}

func TestAccountsReencoding(t *testing.T) {
	oldEncodedAccountsData := [][]byte{
		{132, 164, 97, 108, 103, 111, 206, 5, 234, 236, 80, 164, 97, 112, 97, 114, 129, 206, 0, 3, 60, 164, 137, 162, 97, 109, 196, 32, 49, 54, 101, 102, 97, 97, 51, 57, 50, 52, 97, 54, 102, 100, 57, 100, 51, 97, 52, 56, 50, 52, 55, 57, 57, 97, 52, 97, 99, 54, 53, 100, 162, 97, 110, 167, 65, 80, 84, 75, 73, 78, 71, 162, 97, 117, 174, 104, 116, 116, 112, 58, 47, 47, 115, 111, 109, 101, 117, 114, 108, 161, 99, 196, 32, 183, 97, 139, 76, 1, 45, 180, 52, 183, 186, 220, 252, 85, 135, 185, 87, 156, 87, 158, 83, 49, 200, 133, 169, 43, 205, 26, 148, 50, 121, 28, 105, 161, 102, 196, 32, 183, 97, 139, 76, 1, 45, 180, 52, 183, 186, 220, 252, 85, 135, 185, 87, 156, 87, 158, 83, 49, 200, 133, 169, 43, 205, 26, 148, 50, 121, 28, 105, 161, 109, 196, 32, 60, 69, 244, 159, 234, 26, 168, 145, 153, 184, 85, 182, 46, 124, 227, 144, 84, 113, 176, 206, 109, 204, 245, 165, 100, 23, 71, 49, 32, 242, 146, 68, 161, 114, 196, 32, 183, 97, 139, 76, 1, 45, 180, 52, 183, 186, 220, 252, 85, 135, 185, 87, 156, 87, 158, 83, 49, 200, 133, 169, 43, 205, 26, 148, 50, 121, 28, 105, 161, 116, 205, 3, 32, 162, 117, 110, 163, 65, 80, 75, 165, 97, 115, 115, 101, 116, 129, 206, 0, 3, 60, 164, 130, 161, 97, 0, 161, 102, 194, 165, 101, 98, 97, 115, 101, 205, 98, 54},
		{132, 164, 97, 108, 103, 111, 206, 5, 230, 217, 88, 164, 97, 112, 97, 114, 129, 206, 0, 3, 60, 175, 137, 162, 97, 109, 196, 32, 49, 54, 101, 102, 97, 97, 51, 57, 50, 52, 97, 54, 102, 100, 57, 100, 51, 97, 52, 56, 50, 52, 55, 57, 57, 97, 52, 97, 99, 54, 53, 100, 162, 97, 110, 167, 65, 80, 84, 75, 105, 110, 103, 162, 97, 117, 174, 104, 116, 116, 112, 58, 47, 47, 115, 111, 109, 101, 117, 114, 108, 161, 99, 196, 32, 111, 157, 243, 205, 146, 155, 167, 149, 44, 226, 153, 150, 6, 105, 206, 72, 182, 218, 38, 146, 98, 94, 57, 205, 145, 152, 12, 60, 175, 149, 94, 13, 161, 102, 196, 32, 111, 157, 243, 205, 146, 155, 167, 149, 44, 226, 153, 150, 6, 105, 206, 72, 182, 218, 38, 146, 98, 94, 57, 205, 145, 152, 12, 60, 175, 149, 94, 13, 161, 109, 196, 32, 60, 69, 244, 159, 234, 26, 168, 145, 153, 184, 85, 182, 46, 124, 227, 144, 84, 113, 176, 206, 109, 204, 245, 165, 100, 23, 71, 49, 32, 242, 146, 68, 161, 114, 196, 32, 111, 157, 243, 205, 146, 155, 167, 149, 44, 226, 153, 150, 6, 105, 206, 72, 182, 218, 38, 146, 98, 94, 57, 205, 145, 152, 12, 60, 175, 149, 94, 13, 161, 116, 205, 1, 44, 162, 117, 110, 164, 65, 80, 84, 75, 165, 97, 115, 115, 101, 116, 130, 206, 0, 3, 56, 153, 130, 161, 97, 10, 161, 102, 194, 206, 0, 3, 60, 175, 130, 161, 97, 0, 161, 102, 194, 165, 101, 98, 97, 115, 101, 205, 98, 54},
		{131, 164, 97, 108, 103, 111, 206, 5, 233, 179, 208, 165, 97, 115, 115, 101, 116, 130, 206, 0, 3, 60, 164, 130, 161, 97, 2, 161, 102, 194, 206, 0, 3, 60, 175, 130, 161, 97, 30, 161, 102, 194, 165, 101, 98, 97, 115, 101, 205, 98, 54},
		{131, 164, 97, 108, 103, 111, 206, 0, 3, 48, 104, 165, 97, 115, 115, 101, 116, 129, 206, 0, 1, 242, 159, 130, 161, 97, 0, 161, 102, 194, 165, 101, 98, 97, 115, 101, 205, 98, 54},
	}
	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	secrets := crypto.GenerateOneTimeSignatureSecrets(15, 500)
	pubVrfKey, _ := crypto.VrfKeygenFromSeed([32]byte{0, 1, 2, 3})

	err := dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		err = accountsInit(tx, make(map[basics.Address]basics.AccountData), config.Consensus[protocol.ConsensusCurrentVersion])
		if err != nil {
			return err
		}

		for _, oldAccData := range oldEncodedAccountsData {
			addr := randomAddress()
			_, err = tx.ExecContext(ctx, "INSERT INTO accountbase (address, data) VALUES (?, ?)", addr[:], oldAccData)
			if err != nil {
				return err
			}
		}
		for i := 0; i < 100; i++ {
			addr := randomAddress()
			accData := basics.AccountData{
				MicroAlgos:         basics.MicroAlgos{Raw: 0x000ffffffffffffff},
				Status:             basics.NotParticipating,
				RewardsBase:        uint64(i),
				RewardedMicroAlgos: basics.MicroAlgos{Raw: 0x000ffffffffffffff},
				VoteID:             secrets.OneTimeSignatureVerifier,
				SelectionID:        pubVrfKey,
				VoteFirstValid:     basics.Round(0x000ffffffffffffff),
				VoteLastValid:      basics.Round(0x000ffffffffffffff),
				VoteKeyDilution:    0x000ffffffffffffff,
				AssetParams: map[basics.AssetIndex]basics.AssetParams{
					0x000ffffffffffffff: {
						Total:         0x000ffffffffffffff,
						Decimals:      0x2ffffff,
						DefaultFrozen: true,
						UnitName:      "12345678",
						AssetName:     "12345678901234567890123456789012",
						URL:           "12345678901234567890123456789012",
						MetadataHash:  pubVrfKey,
						Manager:       addr,
						Reserve:       addr,
						Freeze:        addr,
						Clawback:      addr,
					},
				},
				Assets: map[basics.AssetIndex]basics.AssetHolding{
					0x000ffffffffffffff: {
						Amount: 0x000ffffffffffffff,
						Frozen: true,
					},
				},
			}

			_, err = tx.ExecContext(ctx, "INSERT INTO accountbase (address, data) VALUES (?, ?)", addr[:], protocol.Encode(&accData))
			if err != nil {
				return err
			}
		}
		return nil
	})
	require.NoError(t, err)

	err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		modifiedAccounts, err := reencodeAccounts(ctx, tx)
		if err != nil {
			return err
		}
		if len(oldEncodedAccountsData) != int(modifiedAccounts) {
			return fmt.Errorf("len(oldEncodedAccountsData) != int(modifiedAccounts) %d != %d", len(oldEncodedAccountsData), int(modifiedAccounts))
		}
		require.Equal(t, len(oldEncodedAccountsData), int(modifiedAccounts))
		return nil
	})
	require.NoError(t, err)
}

// TestAccountsDbQueriesCreateClose tests to see that we can create the accountsDbQueries and close it.
// it also verify that double-closing it doesn't create an issue.
func TestAccountsDbQueriesCreateClose(t *testing.T) {
	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	err := dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		err = initTestAccountDB(tx, nil, config.Consensus[protocol.ConsensusCurrentVersion])
		if err != nil {
			return err
		}
		return nil
	})
	require.NoError(t, err)
	qs, err := accountsDbInit(dbs.Rdb.Handle, dbs.Wdb.Handle)
	require.NoError(t, err)
	require.NotNil(t, qs.listCreatablesStmt)
	qs.close()
	require.Nil(t, qs.listCreatablesStmt)
	qs.close()
	require.Nil(t, qs.listCreatablesStmt)
}

func benchmarkWriteCatchpointStagingBalancesSub(b *testing.B, ascendingOrder bool) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	genesisInitState, _ := testGenerateInitState(b, protocol.ConsensusCurrentVersion, 100)
	const inMem = false
	log := logging.TestingLog(b)
	cfg := config.GetDefaultLocal()
	cfg.Archival = false
	log.SetLevel(logging.Warn)
	dbBaseFileName := strings.Replace(b.Name(), "/", "_", -1)
	l, err := OpenLedger(log, dbBaseFileName, inMem, genesisInitState, cfg)
	require.NoError(b, err, "could not open ledger")
	defer func() {
		l.Close()
		os.Remove(dbBaseFileName + ".block.sqlite")
		os.Remove(dbBaseFileName + ".tracker.sqlite")
	}()
	catchpointAccessor := MakeCatchpointCatchupAccessor(l, log)
	catchpointAccessor.ResetStagingBalances(context.Background(), true)
	targetAccountsCount := uint64(b.N)
	accountsLoaded := uint64(0)
	var last64KStart time.Time
	last64KSize := uint64(0)
	last64KAccountCreationTime := time.Duration(0)
	accountsWritingStarted := time.Now()
	accountsGenerationDuration := time.Duration(0)
	b.ResetTimer()
	for accountsLoaded < targetAccountsCount {
		b.StopTimer()
		balancesLoopStart := time.Now()
		// generate a chunk;
		chunkSize := targetAccountsCount - accountsLoaded
		if chunkSize > BalancesPerCatchpointFileChunk {
			chunkSize = BalancesPerCatchpointFileChunk
		}
		last64KSize += chunkSize
		if accountsLoaded >= targetAccountsCount-64*1024 && last64KStart.IsZero() {
			last64KStart = time.Now()
			last64KSize = chunkSize
			last64KAccountCreationTime = time.Duration(0)
		}
		var balances catchpointFileBalancesChunk
		balances.Balances = make([]encodedBalanceRecord, chunkSize)
		for i := uint64(0); i < chunkSize; i++ {
			var randomAccount encodedBalanceRecord
			accountData := basics.AccountData{RewardsBase: accountsLoaded + i}
			accountData.MicroAlgos.Raw = crypto.RandUint63()
			randomAccount.AccountData = protocol.Encode(&accountData)
			crypto.RandBytes(randomAccount.Address[:])
			if ascendingOrder {
				binary.LittleEndian.PutUint64(randomAccount.Address[:], accountsLoaded+i)
			}
			balances.Balances[i] = randomAccount
		}
		balanceLoopDuration := time.Now().Sub(balancesLoopStart)
		last64KAccountCreationTime += balanceLoopDuration
		accountsGenerationDuration += balanceLoopDuration

		normalizedAccountBalances, err := prepareNormalizedBalances(balances.Balances, proto)
		b.StartTimer()
		err = l.trackerDBs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
			err = writeCatchpointStagingBalances(ctx, tx, normalizedAccountBalances)
			return
		})

		require.NoError(b, err)
		accountsLoaded += chunkSize
	}
	if !last64KStart.IsZero() {
		last64KDuration := time.Now().Sub(last64KStart) - last64KAccountCreationTime
		fmt.Printf("%-82s%-7d (last 64k) %-6d ns/account       %d accounts/sec\n", b.Name(), last64KSize, (last64KDuration / time.Duration(last64KSize)).Nanoseconds(), int(float64(last64KSize)/float64(last64KDuration.Seconds())))
	}
	stats, err := l.trackerDBs.Wdb.Vacuum(context.Background())
	require.NoError(b, err)
	fmt.Printf("%-82sdb fragmentation   %.1f%%\n", b.Name(), float32(stats.PagesBefore-stats.PagesAfter)*100/float32(stats.PagesBefore))
	b.ReportMetric(float64(b.N)/float64((time.Now().Sub(accountsWritingStarted)-accountsGenerationDuration).Seconds()), "accounts/sec")
}

func BenchmarkWriteCatchpointStagingBalances(b *testing.B) {
	benchSizes := []int{1024 * 100, 1024 * 200, 1024 * 400}
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("RandomInsertOrder-%d", size), func(b *testing.B) {
			b.N = size
			benchmarkWriteCatchpointStagingBalancesSub(b, false)
		})
	}
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("AscendingInsertOrder-%d", size), func(b *testing.B) {
			b.N = size
			benchmarkWriteCatchpointStagingBalancesSub(b, true)
		})
	}
}

func TestCompactAccountDeltas(t *testing.T) {
	a := require.New(t)

	ad := compactAccountDeltas{}
	data, idx := ad.get(basics.Address{})
	a.Equal(-1, idx)
	a.Equal(accountDelta{}, data)

	addr := randomAddress()
	data, idx = ad.get(addr)
	a.Equal(-1, idx)
	a.Equal(accountDelta{}, data)

	a.Equal(0, ad.len())
	a.Panics(func() { ad.getByIdx(0) })

	sample1 := accountDelta{new: ledgercore.PersistedAccountData{AccountData: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 123}}}}
	ad.upsert(addr, sample1)
	data, idx = ad.get(addr)
	a.NotEqual(-1, idx)
	a.Equal(sample1, data)

	a.Equal(1, ad.len())
	address, data := ad.getByIdx(0)
	a.Equal(addr, address)
	a.Equal(sample1, data)

	sample2 := accountDelta{new: ledgercore.PersistedAccountData{AccountData: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 456}}}}
	ad.upsert(addr, sample2)
	data, idx = ad.get(addr)
	a.NotEqual(-1, idx)
	a.Equal(sample2, data)

	a.Equal(1, ad.len())
	address, data = ad.getByIdx(0)
	a.Equal(addr, address)
	a.Equal(sample2, data)

	ad.update(idx, sample2)
	data, idx2 := ad.get(addr)
	a.Equal(idx, idx2)
	a.Equal(sample2, data)

	a.Equal(1, ad.len())
	address, data = ad.getByIdx(0)
	a.Equal(addr, address)
	a.Equal(sample2, data)

	old1 := dbAccountData{addr: addr, pad: ledgercore.PersistedAccountData{AccountData: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 789}}}}
	ad.upsertOld(old1)
	a.Equal(1, ad.len())
	address, data = ad.getByIdx(0)
	a.Equal(addr, address)
	a.Equal(accountDelta{new: sample2.new, old: old1}, data)

	addr1 := randomAddress()
	old2 := dbAccountData{addr: addr1, pad: ledgercore.PersistedAccountData{AccountData: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 789}}}}
	ad.upsertOld(old2)
	a.Equal(2, ad.len())
	address, data = ad.getByIdx(0)
	a.Equal(addr, address)
	a.Equal(accountDelta{new: sample2.new, old: old1}, data)

	address, data = ad.getByIdx(1)
	a.Equal(addr1, address)
	a.Equal(accountDelta{old: old2}, data)

	ad.updateOld(0, old2)
	a.Equal(2, ad.len())
	address, data = ad.getByIdx(0)
	a.Equal(addr, address)
	a.Equal(accountDelta{new: sample2.new, old: old2}, data)

	addr2 := randomAddress()
	idx = ad.insert(addr2, sample2)
	a.Equal(3, ad.len())
	a.Equal(2, idx)
	address, data = ad.getByIdx(idx)
	a.Equal(addr2, address)
	a.Equal(sample2, data)
}

// cleanPad copies and clears non-serializable loaded nad groupData fields to match account data
func cleanPad(pad ledgercore.PersistedAccountData) ledgercore.PersistedAccountData {
	clean := pad
	if len(clean.ExtendedAssetHolding.Groups) > 0 {
		clean.ExtendedAssetHolding.Groups = make([]ledgercore.AssetsHoldingGroup, len(pad.ExtendedAssetHolding.Groups))
		copy(clean.ExtendedAssetHolding.Groups, pad.ExtendedAssetHolding.Groups)
		clean.ExtendedAssetHolding.TestClearGroupData() // group data ignored on serialization, reset
	}
	return clean
}

func TestAccountsNewCRUD(t *testing.T) {
	a := require.New(t)

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	a.NoError(err)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	err = initTestAccountDB(tx, nil, proto)
	a.NoError(err)
	tx.Commit()

	qs, err := accountsDbInit(dbs.Rdb.Handle, dbs.Wdb.Handle)
	a.NoError(err)

	q, err := makeAccountsNewQueries(dbs.Wdb.Handle)

	allAccounts, err := dbs.Wdb.Handle.Prepare("SELECT address from accountbase")
	a.NoError(err)
	allExtData, err := dbs.Wdb.Handle.Prepare("SELECT data from accountext")
	a.NoError(err)

	addr := randomAddress()

	//----------------------------------------------------------------------------------------------
	// test create and delete function
	var createDeleteTests = []struct {
		count int
	}{
		{0}, {1}, {assetsThreshold + 1},
	}
	temp := randomAccountData(100)

	for _, test := range createDeleteTests {
		t.Run(fmt.Sprintf("create-asset-%d", test.count), func(t *testing.T) {
			ad := basics.AccountData{}
			if test.count > 0 {
				ad.Assets = make(map[basics.AssetIndex]basics.AssetHolding, test.count)
			}
			for i := 1; i <= test.count; i++ {
				ad.Assets[basics.AssetIndex(i)] = basics.AssetHolding{Amount: uint64(i), Frozen: true}
			}

			updatedAccounts := []dbAccountData{{pad: ledgercore.PersistedAccountData{AccountData: temp}}}
			updatedAccountIdx := 0

			updatedAccounts, err = accountsNewCreate(
				q.insertStmt, q.insertGroupDataStmt,
				addr, ledgercore.PersistedAccountData{AccountData: ad}, proto,
				updatedAccounts, updatedAccountIdx,
			)
			a.NoError(err)
			a.NotEmpty(updatedAccounts[updatedAccountIdx])
			a.NotEqual(updatedAccounts[updatedAccountIdx].pad.AccountData, temp)

			var buf []byte
			var rowid sql.NullInt64
			var rnd uint64
			var pad ledgercore.PersistedAccountData

			err = qs.lookupStmt.QueryRow(addr[:]).Scan(&rowid, &rnd, &buf)
			a.NoError(err)
			a.True(rowid.Valid)
			a.NoError(protocol.Decode(buf, &pad))

			mempad := cleanPad(updatedAccounts[updatedAccountIdx].pad)
			a.Equal(mempad, pad)

			rows, err := allExtData.Query()
			i := 0
			for rows.Next() {
				err = rows.Scan(&buf)
				a.NoError(err)
				var gd ledgercore.AssetsHoldingGroupData
				a.NoError(protocol.Decode(buf, &gd))
				a.Equal(updatedAccounts[updatedAccountIdx].pad.ExtendedAssetHolding.Groups[i].TestGetGroupData(), gd)
				i++
			}
			rows.Close()

			numRowsExpected := test.count / ledgercore.MaxHoldingGroupSize
			a.GreaterOrEqual(i, numRowsExpected)

			// check deletion
			dbad, err := qs.lookup(addr)
			a.NoError(err)
			updatedAccounts, err = accountsNewDelete(
				q.deleteByRowIDStmt, q.deleteGroupDataStmt,
				addr, dbad,
				updatedAccounts, updatedAccountIdx,
			)
			a.NoError(err)
			dbad = updatedAccounts[updatedAccountIdx]
			a.Empty(dbad.pad)

			rows, err = allExtData.Query()
			a.NoError(err)
			a.False(rows.Next())
			rows.Close()

			rows, err = allAccounts.Query()
			a.NoError(err)
			a.False(rows.Next())
			rows.Close()

		})
	}

	//----------------------------------------------------------------------------------------------
	// check accouts update func
	// cover three cases: 1) old and new below the assetsThreshold
	// 2) old is below and new is above
	// 3) old and above the assetsThreshold
	updatedAccounts := []dbAccountData{{pad: ledgercore.PersistedAccountData{AccountData: temp}}}
	updatedAccountIdx := 0

	// case 1)
	// first create a basic record with 10 assets
	ad := basics.AccountData{}
	numBaseAssets := 10
	ad.Assets = make(map[basics.AssetIndex]basics.AssetHolding, numBaseAssets)
	for i := 1; i <= numBaseAssets; i++ {
		ad.Assets[basics.AssetIndex(i)] = basics.AssetHolding{Amount: uint64(i), Frozen: true}
	}

	updatedAccounts, err = accountsNewCreate(
		q.insertStmt, q.insertGroupDataStmt,
		addr, ledgercore.PersistedAccountData{AccountData: ad}, proto,
		updatedAccounts, updatedAccountIdx,
	)

	// use it as OLD
	old, err := qs.lookup(addr)

	// add some assets to NEW
	updated := basics.AccountData{}
	numNewAssets1 := 20
	updated.Assets = make(map[basics.AssetIndex]basics.AssetHolding, numBaseAssets+numNewAssets1)
	for k, v := range old.pad.Assets {
		updated.Assets[k] = v
	}
	for i := 1001; i <= 1000+numNewAssets1; i++ {
		updated.Assets[basics.AssetIndex(i)] = basics.AssetHolding{Amount: uint64(i), Frozen: true}
	}

	delta := accountDelta{old: old, new: ledgercore.PersistedAccountData{AccountData: updated}}
	updatedAccounts, err = accountsNewUpdate(
		q.updateStmt, q.queryGroupDataStmt,
		q.updateGroupDataStmt, q.insertGroupDataStmt, q.deleteGroupDataStmt,
		addr, delta, proto,
		updatedAccounts, updatedAccountIdx)

	a.NoError(err)
	// ensure correctness of the data written
	a.NotEmpty(updatedAccounts[updatedAccountIdx])
	a.NotEqual(updatedAccounts[updatedAccountIdx].pad.AccountData, temp)

	var buf []byte
	var rowid sql.NullInt64
	var rnd uint64
	var pad ledgercore.PersistedAccountData

	// check raw accountbase data
	err = qs.lookupStmt.QueryRow(addr[:]).Scan(&rowid, &rnd, &buf)
	a.NoError(err)
	a.True(rowid.Valid)
	a.NoError(protocol.Decode(buf, &pad))
	a.Equal(updatedAccounts[updatedAccountIdx].pad, pad)

	// check no records in accountext table
	rows, err := allExtData.Query()
	a.NoError(err)
	a.False(rows.Next())
	rows.Close()

	old, err = qs.lookup(addr)
	a.Equal(numBaseAssets+numNewAssets1, len(old.pad.AccountData.Assets))
	a.Equal(numBaseAssets+numNewAssets1, old.pad.NumAssetHoldings())
	a.NotEmpty(old.rowid)

	// case 2)
	// now create additional 1000 assets to exceed assetsThreshold
	numNewAssets2 := assetsThreshold
	updated = basics.AccountData{}
	updated.Assets = make(map[basics.AssetIndex]basics.AssetHolding, numBaseAssets+numNewAssets1+numNewAssets2)
	savedAssets := make(map[basics.AssetIndex]bool, numBaseAssets+numNewAssets1+numNewAssets2)
	for k, v := range old.pad.Assets {
		updated.Assets[k] = v
		savedAssets[k] = true
	}
	for i := 2001; i <= 2000+numNewAssets2; i++ {
		updated.Assets[basics.AssetIndex(i)] = basics.AssetHolding{Amount: uint64(i), Frozen: true}
		savedAssets[basics.AssetIndex(i)] = true
	}

	delta = accountDelta{old: old, new: ledgercore.PersistedAccountData{AccountData: updated}}
	updatedAccounts, err = accountsNewUpdate(
		q.updateStmt, q.queryGroupDataStmt,
		q.updateGroupDataStmt, q.insertGroupDataStmt, q.deleteGroupDataStmt,
		addr, delta, proto,
		updatedAccounts, updatedAccountIdx)

	a.NoError(err)
	// ensure correctness of the data written
	a.NotEmpty(updatedAccounts[updatedAccountIdx])

	// ensure a single row
	rows, err = allAccounts.Query()
	a.True(rows.Next())
	a.False(rows.Next())
	rows.Close()

	// check raw accountbase data
	pad = ledgercore.PersistedAccountData{}
	err = qs.lookupStmt.QueryRow(addr[:]).Scan(&rowid, &rnd, &buf)
	a.NoError(err)
	a.True(rowid.Valid)
	a.NoError(protocol.Decode(buf, &pad))
	mempad := cleanPad(updatedAccounts[updatedAccountIdx].pad)
	a.Equal(mempad, pad)

	// check records in accountext table
	rows, err = allExtData.Query()
	a.NoError(err)
	i := 0
	for rows.Next() {
		err = rows.Scan(&buf)
		a.NoError(err)
		var gd ledgercore.AssetsHoldingGroupData
		a.NoError(protocol.Decode(buf, &gd))
		a.Equal(updatedAccounts[updatedAccountIdx].pad.ExtendedAssetHolding.Groups[i].TestGetGroupData(), gd)
		i++
	}
	rows.Close()

	numRowsExpected := (numBaseAssets + numNewAssets1 + numNewAssets2) / ledgercore.MaxHoldingGroupSize
	a.GreaterOrEqual(i, numRowsExpected)

	old, err = qs.lookup(addr)
	a.NoError(err)
	a.Equal(0, len(old.pad.AccountData.Assets))
	a.Equal(numBaseAssets+numNewAssets1+numNewAssets2, old.pad.NumAssetHoldings())
	for i := 0; i < len(old.pad.ExtendedAssetHolding.Groups); i++ {
		a.False(old.pad.ExtendedAssetHolding.Groups[i].Loaded())
		a.NotZero(old.pad.ExtendedAssetHolding.Groups[i].AssetGroupKey)
	}

	// case 3.1)
	// len(old.Assets) > assetsThreshold
	// new count > assetsThreshold => delete, update, create few
	a.GreaterOrEqual(assetsThreshold, 1000)
	del := []basics.AssetIndex{1, 2, 3, 10, 2900}
	upd := []basics.AssetIndex{4, 5, 2999}
	crt := []basics.AssetIndex{9001, 9501}
	loaded := make(map[int]bool, numRowsExpected)
	old.pad.Assets = make(map[basics.AssetIndex]basics.AssetHolding, len(del)+len(upd))
	for _, aidx := range append(del, upd...) {
		gi, ai := old.pad.ExtendedAssetHolding.FindAsset(aidx, 0)
		a.NotEqual(-1, gi, aidx)
		g := &old.pad.ExtendedAssetHolding.Groups[gi]
		if !g.Loaded() {
			groupData, _, err := loadHoldingGroupData(qs.loadAccountGroupDataStmt, g.AssetGroupKey)
			a.NoError(err)
			g.Load(groupData)
			loaded[gi] = true
		}
		gi, ai = old.pad.ExtendedAssetHolding.FindAsset(aidx, gi)
		a.NotEqual(-1, gi)
		a.NotEqual(-1, ai)
		old.pad.Assets[aidx] = g.GetHolding(ai)
	}

	deltaHoldings := make(map[basics.AssetIndex]ledgercore.HoldingAction, len(del)+len(crt))
	for _, aidx := range del {
		delete(savedAssets, aidx)
		deltaHoldings[aidx] = ledgercore.ActionDelete
	}
	for _, aidx := range crt {
		savedAssets[aidx] = true
		deltaHoldings[aidx] = ledgercore.ActionCreate
	}

	updated = basics.AccountData{}
	updated.Assets = make(map[basics.AssetIndex]basics.AssetHolding, len(upd)+len(crt))
	for _, aidx := range upd {
		updated.Assets[aidx] = old.pad.Assets[aidx]
	}
	for _, aidx := range crt {
		updated.Assets[aidx] = basics.AssetHolding{Amount: uint64(aidx), Frozen: true}
	}

	delta = accountDelta{
		old:      old,
		new:      ledgercore.PersistedAccountData{AccountData: updated, ExtendedAssetHolding: old.pad.ExtendedAssetHolding},
		holdings: deltaHoldings,
	}

	updatedAccounts, err = accountsNewUpdate(
		q.updateStmt, q.queryGroupDataStmt,
		q.updateGroupDataStmt, q.insertGroupDataStmt, q.deleteGroupDataStmt,
		addr, delta, proto,
		updatedAccounts, updatedAccountIdx)

	a.NoError(err)
	// ensure correctness of the data written
	a.NotEmpty(updatedAccounts[updatedAccountIdx])
	expectedCount := numBaseAssets + numNewAssets1 + numNewAssets2 - len(del) + len(crt)
	a.Equal(expectedCount, updatedAccounts[updatedAccountIdx].pad.NumAssetHoldings())

	// ensure a single row
	rows, err = allAccounts.Query()
	a.True(rows.Next())
	a.False(rows.Next())
	rows.Close()

	// check raw accountbase data
	pad = ledgercore.PersistedAccountData{}
	err = qs.lookupStmt.QueryRow(addr[:]).Scan(&rowid, &rnd, &buf)
	a.NoError(err)
	a.True(rowid.Valid)
	a.NoError(protocol.Decode(buf, &pad))
	mempad = cleanPad(updatedAccounts[updatedAccountIdx].pad)
	a.Equal(mempad, pad)

	// check records in accountext table
	rows, err = allExtData.Query()
	a.NoError(err)
	i = 0
	j := 0
	for rows.Next() {
		err = rows.Scan(&buf)
		a.NoError(err)
		var gd ledgercore.AssetsHoldingGroupData
		a.NoError(protocol.Decode(buf, &gd))
		if loaded[i] {
			a.Equal(updatedAccounts[updatedAccountIdx].pad.ExtendedAssetHolding.Groups[i].TestGetGroupData(), gd, i)
			j++
		}
		i++
	}
	rows.Close()

	numRowsExpected = expectedCount / ledgercore.MaxHoldingGroupSize
	a.GreaterOrEqual(i, numRowsExpected)
	a.Equal(len(loaded), j)

	old, err = qs.lookup(addr)
	a.NoError(err)
	a.Equal(0, len(old.pad.AccountData.Assets))
	for _, aidx := range append(crt, upd...) {
		gi, ai := old.pad.ExtendedAssetHolding.FindAsset(aidx, 0)
		a.NotEqual(-1, gi, aidx)
		a.Equal(-1, ai) // not loaded
	}

	for gi := range old.pad.ExtendedAssetHolding.Groups {
		g := &old.pad.ExtendedAssetHolding.Groups[gi]
		if !g.Loaded() {
			groupData, _, err := loadHoldingGroupData(qs.loadAccountGroupDataStmt, g.AssetGroupKey)
			a.NoError(err)
			g.Load(groupData)
		}
	}
	for _, aidx := range append(crt, upd...) {
		gi, ai := old.pad.ExtendedAssetHolding.FindAsset(aidx, 0)
		a.NotEqual(-1, gi, aidx)
		a.NotEqual(-1, ai)
	}

	for _, aidx := range del {
		gi, ai := old.pad.ExtendedAssetHolding.FindAsset(aidx, 0)
		a.Equal(-1, gi, aidx)
		a.Equal(-1, ai)
	}

	// case 3.2)
	// len(old.Assets) > assetsThreshold
	// new count > assetsThreshold => delete most and update, create some

	holdingMap, _, err := loadHoldings(qs.loadAccountGroupDataStmt, old.pad.ExtendedAssetHolding, 0)
	a.Equal(len(savedAssets), len(holdingMap))
	for k := range savedAssets {
		a.Contains(holdingMap, k)
	}

	old.pad.Assets = holdingMap // cache all the modifed
	holdings := make([]basics.AssetIndex, 0, len(holdingMap))
	for k := range holdingMap {
		holdings = append(holdings, k)
	}
	del = holdings[:len(holdings)-3]
	upd = holdings[len(holdings)-3:]
	crt = []basics.AssetIndex{10001, 10002}

	updated = basics.AccountData{}
	updated.Assets = make(map[basics.AssetIndex]basics.AssetHolding, len(upd)+len(crt))
	deltaHoldings = make(map[basics.AssetIndex]ledgercore.HoldingAction, len(del)+len(crt))
	for _, aidx := range del {
		deltaHoldings[aidx] = ledgercore.ActionDelete
	}
	for _, aidx := range upd {
		updated.Assets[aidx] = old.pad.Assets[aidx]
	}
	for _, aidx := range crt {
		updated.Assets[aidx] = basics.AssetHolding{Amount: uint64(aidx), Frozen: true}
		deltaHoldings[aidx] = ledgercore.ActionCreate
	}

	delta = accountDelta{
		old:      old,
		new:      ledgercore.PersistedAccountData{AccountData: updated, ExtendedAssetHolding: old.pad.ExtendedAssetHolding},
		holdings: deltaHoldings,
	}

	updatedAccounts, err = accountsNewUpdate(
		q.updateStmt, q.queryGroupDataStmt,
		q.updateGroupDataStmt, q.insertGroupDataStmt, q.deleteGroupDataStmt,
		addr, delta, proto,
		updatedAccounts, updatedAccountIdx)

	a.NoError(err)
	a.NotEmpty(updatedAccounts[updatedAccountIdx])
	expectedCount = len(crt) + len(upd)
	a.Equal(expectedCount, updatedAccounts[updatedAccountIdx].pad.NumAssetHoldings())

	// ensure a single row
	rows, err = allAccounts.Query()
	a.True(rows.Next())
	a.False(rows.Next())
	rows.Close()

	pad = ledgercore.PersistedAccountData{}
	err = qs.lookupStmt.QueryRow(addr[:]).Scan(&rowid, &rnd, &buf)
	a.NoError(err)
	a.True(rowid.Valid)
	a.NoError(protocol.Decode(buf, &pad))
	mempad = cleanPad(updatedAccounts[updatedAccountIdx].pad)
	a.Equal(mempad, pad)

	// check no records in accountext table
	rows, err = allExtData.Query()
	a.NoError(err)
	a.False(rows.Next())
	rows.Close()

	old, err = qs.lookup(addr)
	a.Equal(expectedCount, len(old.pad.AccountData.Assets))
	a.Equal(expectedCount, old.pad.NumAssetHoldings())
	for _, aidx := range append(upd, crt...) {
		a.Contains(old.pad.AccountData.Assets, aidx)
	}
}

// TestLoadHolding verifies ExtendedAssetHolding.Group copying, and baseRound error handling
func TestLoadHolding(t *testing.T) {
	a := require.New(t)

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	a.NoError(err)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	err = initTestAccountDB(tx, nil, proto)
	a.NoError(err)
	tx.Commit()

	qs, err := accountsDbInit(dbs.Rdb.Handle, dbs.Wdb.Handle)
	a.NoError(err)

	q, err := makeAccountsNewQueries(dbs.Wdb.Handle)
	a.NoError(err)

	addr := randomAddress()
	assetsThreshold := config.Consensus[protocol.ConsensusV18].MaxAssetsPerAccount

	updatedAccounts := []dbAccountData{{pad: ledgercore.PersistedAccountData{AccountData: randomAccountData(100)}}}
	updatedAccountIdx := 0

	// first create a basic record with 10 assets
	ad := basics.AccountData{}
	numBaseAssets := 10
	ad.Assets = make(map[basics.AssetIndex]basics.AssetHolding, numBaseAssets)
	for i := 1; i <= numBaseAssets; i++ {
		ad.Assets[basics.AssetIndex(i)] = basics.AssetHolding{Amount: uint64(i), Frozen: true}
	}

	updatedAccounts, err = accountsNewCreate(
		q.insertStmt, q.insertGroupDataStmt,
		addr, ledgercore.PersistedAccountData{AccountData: ad}, proto,
		updatedAccounts, updatedAccountIdx,
	)

	// use it as OLD
	old, err := qs.lookup(addr)

	// now create additional 1000 assets to exceed assetsThreshold
	numNewAssets := assetsThreshold
	updated := basics.AccountData{}
	updated.Assets = make(map[basics.AssetIndex]basics.AssetHolding, numBaseAssets)
	for k, v := range old.pad.Assets {
		updated.Assets[k] = v
	}
	for i := 2001; i <= 2000+numNewAssets; i++ {
		updated.Assets[basics.AssetIndex(i)] = basics.AssetHolding{Amount: uint64(i), Frozen: true}
	}

	delta := accountDelta{old: old, new: ledgercore.PersistedAccountData{AccountData: updated}}
	updatedAccounts, err = accountsNewUpdate(
		q.updateStmt, q.queryGroupDataStmt,
		q.updateGroupDataStmt, q.insertGroupDataStmt, q.deleteGroupDataStmt,
		addr, delta, proto,
		updatedAccounts, updatedAccountIdx)

	a.NoError(err)
	// ensure correctness of the data written
	a.NotEmpty(updatedAccounts[updatedAccountIdx])

	var buf []byte
	var rowid sql.NullInt64
	var rnd uint64
	var pad ledgercore.PersistedAccountData

	// check raw accountbase data
	err = qs.lookupStmt.QueryRow(addr[:]).Scan(&rowid, &rnd, &buf)
	a.NoError(err)
	a.True(rowid.Valid)
	a.NoError(protocol.Decode(buf, &pad))
	mempad := cleanPad(updatedAccounts[updatedAccountIdx].pad)
	a.Equal(mempad, pad)

	old, err = qs.lookup(addr)
	a.Equal(0, len(old.pad.AccountData.Assets))
	a.Equal(numBaseAssets+numNewAssets, old.pad.NumAssetHoldings())
	a.NotEmpty(old.rowid)

	clone := func(s ledgercore.ExtendedAssetHolding) (t ledgercore.ExtendedAssetHolding) {
		t = s
		t.Groups = make([]ledgercore.AssetsHoldingGroup, len(s.Groups))
		for i, g := range s.Groups {
			t.Groups[i] = g
		}
		return
	}

	saved := clone(old.pad.ExtendedAssetHolding)
	_, eah, err := loadHoldings(qs.loadAccountGroupDataStmt, old.pad.ExtendedAssetHolding, 0)
	a.NoError(err)
	a.Equal(saved, old.pad.ExtendedAssetHolding)
	a.NotEqual(eah, old.pad.ExtendedAssetHolding)

	_, eah, err = loadHoldings(qs.loadAccountGroupDataStmt, old.pad.ExtendedAssetHolding, old.round)
	a.NoError(err)

	_, eah, err = loadHoldings(qs.loadAccountGroupDataStmt, old.pad.ExtendedAssetHolding, old.round+1)
	a.Error(err)
	a.IsType(&MismatchingDatabaseRoundError{}, err)
}
