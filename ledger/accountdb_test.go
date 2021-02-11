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
			res[randomAddress()], lastCreatableID = randomFullAccountData(0, lastCreatableID)
		}
	}
	return res
}

func randomDeltas(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]basics.AccountData, imbalance int64) {
	updates, totals, imbalance, _ = randomDeltasImpl(niter, base, rewardsLevel, true, 0)
	return
}

func randomDeltasFull(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, lastCreatableIDIn uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]basics.AccountData, imbalance int64, lastCreatableID uint64) {
	updates, totals, imbalance, lastCreatableID = randomDeltasImpl(niter, base, rewardsLevel, false, lastCreatableIDIn)
	return
}

func randomDeltasImpl(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, simple bool, lastCreatableIDIn uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]basics.AccountData, imbalance int64, lastCreatableID uint64) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	totals = make(map[basics.Address]basics.AccountData)

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
			updates.Upsert(addr, new)
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
		if simple {
			new = randomAccountData(rewardsLevel)
		} else {
			new, lastCreatableID = randomFullAccountData(rewardsLevel, lastCreatableID)
		}
		updates.Upsert(addr, new)
		imbalance += int64(old.WithUpdatedRewards(proto, rewardsLevel).MicroAlgos.Raw - new.MicroAlgos.Raw)
		totals[addr] = new
	}

	return
}

func randomDeltasBalanced(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]basics.AccountData) {
	updates, totals, _ = randomDeltasBalancedImpl(niter, base, rewardsLevel, true, 0)
	return
}

func randomDeltasBalancedFull(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, lastCreatableIDIn uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]basics.AccountData, lastCreatableID uint64) {
	updates, totals, lastCreatableID = randomDeltasBalancedImpl(niter, base, rewardsLevel, false, lastCreatableIDIn)
	return
}

func randomDeltasBalancedImpl(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, simple bool, lastCreatableIDIn uint64) (updates ledgercore.AccountDeltas, totals map[basics.Address]basics.AccountData, lastCreatableID uint64) {
	var imbalance int64
	if simple {
		updates, totals, imbalance = randomDeltas(niter, base, rewardsLevel)
	} else {
		updates, totals, imbalance, lastCreatableID = randomDeltasFull(niter, base, rewardsLevel, lastCreatableIDIn)
	}

	oldPool := base[testPoolAddr]
	newPool := oldPool
	newPool.MicroAlgos.Raw += uint64(imbalance)

	updates.Upsert(testPoolAddr, newPool)
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

	for addr, data := range accts {
		pad, err := aq.lookup(addr)
		d := pad.pad.AccountData
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

	all, err := accountsAll(tx)
	require.NoError(t, err)
	require.Equal(t, all, accts)

	totals, err := accountsTotals(tx, false)
	require.NoError(t, err)
	require.Equal(t, totals.Online.Money.Raw, totalOnline)
	require.Equal(t, totals.Offline.Money.Raw, totalOffline)
	require.Equal(t, totals.NotParticipating.Money.Raw, totalNotPart)
	require.Equal(t, totals.Participating().Raw, totalOnline+totalOffline)
	require.Equal(t, totals.All().Raw, totalOnline+totalOffline+totalNotPart)

	d, err := aq.lookup(randomAddress())
	require.NoError(t, err)
	require.Equal(t, rnd, d.round)
	require.Equal(t, d.pad.AccountData, basics.AccountData{})

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

func TestAccountDBInit(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	accts := randomAccounts(20, true)
	err = accountsInit(tx, accts, proto)
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
	defer tx.Rollback()

	accts := randomAccounts(20, true)
	err = accountsInit(tx, accts, proto)
	require.NoError(t, err)
	checkAccounts(t, tx, 0, accts)

	// used to determine how many creatables element will be in the test per iteration
	numElementsPerSegement := 10

	// lastCreatableID stores asset or app max used index to get rid of conflicts
	lastCreatableID := crypto.RandUint64() % 512
	ctbsList, randomCtbs := randomCreatables(numElementsPerSegement)
	expectedDbImage := make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
	var baseAccounts lruAccounts
	baseAccounts.init(nil, 100, 80)
	for i := 1; i < 10; i++ {
		var updates ledgercore.AccountDeltas
		var newaccts map[basics.Address]basics.AccountData
		updates, newaccts, _, lastCreatableID = randomDeltasFull(20, accts, 0, lastCreatableID)
		accts = newaccts
		ctbsWithDeletes := randomCreatableSampling(i, ctbsList, randomCtbs,
			expectedDbImage, numElementsPerSegement)

		updatesCnt := makeCompactAccountDeltas([]ledgercore.AccountDeltas{updates}, baseAccounts)
		err = updatesCnt.accountsLoadOld(tx)
		require.NoError(t, err)
		err = totalsNewRounds(tx, []ledgercore.AccountDeltas{updates}, updatesCnt, []ledgercore.AccountTotals{{}}, []config.ConsensusParams{proto})
		require.NoError(t, err)
		_, err = accountsNewRound(tx, updatesCnt, ctbsWithDeletes, proto, basics.Round(i))
		require.NoError(t, err)
		err = updateAccountsRound(tx, basics.Round(i), 0)
		require.NoError(t, err)
		checkAccounts(t, tx, basics.Round(i), accts)
		checkCreatables(t, tx, i, expectedDbImage)
	}
}

// checkCreatables compares the expected database image to the actual databse content
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

func benchmarkInitBalances(b testing.TB, numAccounts int, dbs db.Pair, proto config.ConsensusParams) (updates map[basics.Address]basics.AccountData) {
	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(b, err)

	updates = generateRandomTestingAccountBalances(numAccounts)

	err = accountsInit(tx, updates, proto)
	require.NoError(b, err)
	err = accountsAddNormalizedBalance(tx, proto)
	require.NoError(b, err)
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

func benchmarkReadingAllBalances(b *testing.B, inMemory bool) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	dbs, fn := dbOpenTest(b, inMemory)
	setDbLogging(b, dbs)
	defer cleanupTestDb(dbs, fn, inMemory)

	benchmarkInitBalances(b, b.N, dbs, proto)
	tx, err := dbs.Rdb.Handle.Begin()
	require.NoError(b, err)

	b.ResetTimer()
	// read all the balances in the database.
	bal, err2 := accountsAll(tx)
	require.NoError(b, err2)
	tx.Commit()

	prevHash := crypto.Digest{}
	for _, accountBalance := range bal {
		encodedAccountBalance := protocol.Encode(&accountBalance)
		prevHash = crypto.Hash(append(encodedAccountBalance, ([]byte(prevHash[:]))...))
	}
	require.Equal(b, b.N, len(bal))
}

func BenchmarkReadingAllBalancesRAM(b *testing.B) {
	benchmarkReadingAllBalances(b, true)
}

func BenchmarkReadingAllBalancesDisk(b *testing.B) {
	benchmarkReadingAllBalances(b, false)
}

func benchmarkReadingRandomBalances(b *testing.B, inMemory bool) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	dbs, fn := dbOpenTest(b, inMemory)
	setDbLogging(b, dbs)
	defer cleanupTestDb(dbs, fn, inMemory)

	accounts := benchmarkInitBalances(b, b.N, dbs, proto)

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
	for _, addr := range addrs {
		_, err = qs.lookup(addr)
		require.NoError(b, err)
	}
}

func BenchmarkReadingRandomBalancesRAM(b *testing.B) {
	benchmarkReadingRandomBalances(b, true)
}

func BenchmarkReadingRandomBalancesDisk(b *testing.B) {
	benchmarkReadingRandomBalances(b, false)
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

		benchmarkInitBalances(b, startupAcct, dbs, proto)
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
		err = accountsInit(tx, make(map[basics.Address]basics.AccountData), config.Consensus[protocol.ConsensusCurrentVersion])
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
	genesisInitState, _ := testGenerateInitState(b, protocol.ConsensusCurrentVersion)
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

	sample1 := accountDelta{new: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 123}}}
	ad.upsert(addr, sample1)
	data, idx = ad.get(addr)
	a.NotEqual(-1, idx)
	a.Equal(sample1, data)

	a.Equal(1, ad.len())
	address, data := ad.getByIdx(0)
	a.Equal(addr, address)
	a.Equal(sample1, data)

	sample2 := accountDelta{new: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 456}}}
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

	old1 := dbAccountData{addr: addr, pad: PersistedAccountData{AccountData: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 789}}}}
	ad.upsertOld(old1)
	a.Equal(1, ad.len())
	address, data = ad.getByIdx(0)
	a.Equal(addr, address)
	a.Equal(accountDelta{new: sample2.new, old: old1}, data)

	addr1 := randomAddress()
	old2 := dbAccountData{addr: addr1, pad: PersistedAccountData{AccountData: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 789}}}}
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

func TestAssetHoldingConvertToGroups(t *testing.T) {
	a := require.New(t)

	var e ExtendedAssetHolding

	e.convertToGroups(nil)
	a.Equal(uint32(0), e.Count)
	a.Equal(0, len(e.Groups))
	a.False(e.loaded)

	e.convertToGroups(map[basics.AssetIndex]basics.AssetHolding{})
	a.Equal(uint32(0), e.Count)
	a.Equal(0, len(e.Groups))
	a.False(e.loaded)

	var tests = []struct {
		size        int
		numGroups   int
		minAssets   []basics.AssetIndex
		deltaAssets []uint64
	}{
		{10, 1, []basics.AssetIndex{1}, []uint64{9}},
		{255, 1, []basics.AssetIndex{1}, []uint64{254}},
		{256, 1, []basics.AssetIndex{1}, []uint64{255}},
		{257, 2, []basics.AssetIndex{1, 257}, []uint64{255, 0}},
		{1024, 4, []basics.AssetIndex{1, 257, 513, 769}, []uint64{255, 255, 255, 255}},
		{1028, 5, []basics.AssetIndex{1, 257, 513, 769, 1025}, []uint64{255, 255, 255, 255, 3}},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%d-assets-convert", test.size), func(t *testing.T) {
			a := require.New(t)
			assets := make(map[basics.AssetIndex]basics.AssetHolding, test.size)
			for i := 0; i < test.size; i++ {
				assets[basics.AssetIndex(i+1)] = basics.AssetHolding{Amount: uint64(i), Frozen: i%2 != 0}
			}

			var e ExtendedAssetHolding
			e.convertToGroups(assets)
			a.Equal(uint32(test.size), e.Count)
			a.True(e.loaded)
			a.Equal(test.numGroups, len(e.Groups))
			total := 0
			for i := 0; i < len(e.Groups); i++ {
				total += int(e.Groups[i].Count)
				a.Equal(test.minAssets[i], e.Groups[i].MinAssetIndex)
				a.Equal(test.deltaAssets[i], e.Groups[i].DeltaMaxAssetIndex)
				a.Equal(uint64(0), e.Groups[i].AssetGroupKey)
				a.True(e.Groups[i].loaded)

				a.Equal(int(e.Groups[i].Count), len(e.Groups[i].groupData.Amounts))
				a.Equal(len(e.Groups[i].groupData.Amounts), len(e.Groups[i].groupData.Frozens))
				a.Equal(len(e.Groups[i].groupData.Amounts), len(e.Groups[i].groupData.AssetOffsets))
				aidx := e.Groups[i].MinAssetIndex
				a.Equal(0, int(e.Groups[i].groupData.AssetOffsets[0]))
				for j := 0; j < len(e.Groups[i].groupData.AssetOffsets); j++ {
					aidx += e.Groups[i].groupData.AssetOffsets[j]
					a.Contains(assets, aidx)
					a.Equal(uint64(aidx)-1, e.Groups[i].groupData.Amounts[j])
				}
				a.Equal(e.Groups[i].MinAssetIndex+basics.AssetIndex(e.Groups[i].DeltaMaxAssetIndex), aidx)
			}
			a.Equal(int(e.Count), total)
		})
	}
}

func TestAssetHoldingFindAsset(t *testing.T) {
	a := require.New(t)

	var e ExtendedAssetHolding
	for aidx := 0; aidx < 2; aidx++ {
		for startIdx := 0; startIdx < 2; startIdx++ {
			gi, ai := e.findAsset(basics.AssetIndex(aidx), startIdx)
			a.Equal(-1, gi)
			a.Equal(-1, ai)
		}
	}

	var tests = []struct {
		size      int
		numGroups int
		samples   []basics.AssetIndex
		groups    []int
		assets    []int
	}{
		{10, 1, []basics.AssetIndex{1, 5, 10, 12}, []int{0, 0, 0, -1}, []int{0, 4, 9, -1}},
		{255, 1, []basics.AssetIndex{1, 255, 256, 257, 258}, []int{0, 0, -1, -1, -1}, []int{0, 254, -1, -1, -1}},
		{256, 1, []basics.AssetIndex{1, 255, 256, 257, 258}, []int{0, 0, 0, -1, -1}, []int{0, 254, 255, -1, -1}},
		{257, 2, []basics.AssetIndex{1, 255, 256, 257, 258}, []int{0, 0, 0, 1, -1}, []int{0, 254, 255, 0, -1}},
		{1024, 4, []basics.AssetIndex{1, 255, 1024, 1025}, []int{0, 0, 3, -1}, []int{0, 254, 255, -1}},
		{1028, 5, []basics.AssetIndex{1, 255, 1024, 1025}, []int{0, 0, 3, 4}, []int{0, 254, 255, 0}},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%d-find-asset", test.size), func(t *testing.T) {
			a := require.New(t)
			assets := make(map[basics.AssetIndex]basics.AssetHolding, test.size)
			for i := 0; i < test.size; i++ {
				assets[basics.AssetIndex(i+1)] = basics.AssetHolding{Amount: uint64(i), Frozen: i%2 != 0}
			}

			var e ExtendedAssetHolding
			e.convertToGroups(assets)

			for i := 0; i < len(test.samples); i++ {
				gi, ai := e.findAsset(test.samples[i], 0)
				a.Equal(test.groups[i], gi)
				a.Equal(test.assets[i], ai)
			}

			goodIdx := 0
			for i := 0; i < len(test.samples); i++ {
				gi, ai := e.findAsset(test.samples[i], goodIdx)
				expgi := test.groups[i]
				expai := test.assets[i]
				a.Equal(expgi, gi)
				a.Equal(expai, ai)
				if gi > 0 {
					goodIdx = gi
				}
			}
			if test.numGroups > 1 {
				a.Greater(goodIdx, 0)
			}
		})
	}
}

type groupSpec struct {
	start basics.AssetIndex
	end   basics.AssetIndex
	count int
}

func genExtendedHolding(t *testing.T, spec []groupSpec) (e ExtendedAssetHolding) {
	e.Groups = make([]AssetsHoldingGroup, len(spec))
	for i, s := range spec {
		e.Groups[i].Count = uint32(s.count)
		e.Groups[i].MinAssetIndex = s.start
		e.Groups[i].DeltaMaxAssetIndex = uint64(s.end - s.start)
		ao := make([]basics.AssetIndex, s.count)
		ao[0] = 0
		gap := (s.end + 1 - s.start) / basics.AssetIndex(s.count)
		aidx := s.start
		for j := 1; j < s.count; j++ {
			ao[j] = gap
			aidx += gap
		}
		if aidx != s.end {
			ao[s.count-1] = s.end - aidx + gap
		}
		e.Groups[i].groupData = AssetsHoldingGroupData{AssetOffsets: ao, Amounts: make([]uint64, len(ao)), Frozens: make([]bool, len(ao))}
		e.Count += uint32(s.count)
	}

	a := require.New(t)
	for _, s := range spec {
		gi, ai := e.findAsset(s.start, 0)
		a.NotEqual(-1, gi)
		a.NotEqual(-1, ai)
		gi, ai = e.findAsset(s.end, 0)
		a.NotEqual(-1, gi)
		a.NotEqual(-1, ai)
	}

	return e
}

// test for AssetsHoldingGroup.insert
func TestAssetHoldingGroupInsert(t *testing.T) {
	a := require.New(t)

	spec := []groupSpec{
		{1001, 1060, 20},
	}

	e := genExtendedHolding(t, spec)
	oldCount := e.Count
	oldDeltaMaxAssetIndex := e.Groups[0].DeltaMaxAssetIndex
	oldAssetOffsets := make([]basics.AssetIndex, spec[0].count)
	oldAssets := make(map[basics.AssetIndex]basics.AssetHolding, spec[0].count)
	aidx := e.Groups[0].MinAssetIndex
	for i := 0; i < spec[0].count; i++ {
		oldAssetOffsets[i] = e.Groups[0].groupData.AssetOffsets[i]
		aidx += e.Groups[0].groupData.AssetOffsets[i]
		oldAssets[aidx] = basics.AssetHolding{}
	}
	a.Equal(int(oldCount), len(oldAssets))
	a.Contains(oldAssets, spec[0].start)
	a.Contains(oldAssets, spec[0].end)

	checkAssetMap := func(newAsset basics.AssetIndex, g AssetsHoldingGroup) {
		newAssets := make(map[basics.AssetIndex]basics.AssetHolding, g.Count)
		aidx = g.MinAssetIndex
		for i := 0; i < int(g.Count); i++ {
			aidx += g.groupData.AssetOffsets[i]
			newAssets[aidx] = basics.AssetHolding{}
		}
		a.Equal(int(g.Count), len(newAssets))
		a.Contains(newAssets, newAsset)
		delete(newAssets, newAsset)
		a.Equal(oldAssets, newAssets)
	}

	// prepend
	aidx = spec[0].start - 10
	e.Groups[0].insert(aidx, basics.AssetHolding{})
	a.Equal(oldCount+1, e.Groups[0].Count)
	a.Equal(aidx, e.Groups[0].MinAssetIndex)
	a.Equal(oldDeltaMaxAssetIndex, e.Groups[0].DeltaMaxAssetIndex)
	a.Equal(basics.AssetIndex(0), e.Groups[0].groupData.AssetOffsets[0])
	a.Equal(spec[0].start-aidx, e.Groups[0].groupData.AssetOffsets[1])
	a.Equal(oldAssetOffsets[1:], e.Groups[0].groupData.AssetOffsets[2:])
	checkAssetMap(aidx, e.Groups[0])

	// append
	e = genExtendedHolding(t, spec)
	aidx = spec[0].end + 10
	e.Groups[0].insert(aidx, basics.AssetHolding{})
	a.Equal(oldCount+1, e.Groups[0].Count)
	a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
	a.Equal(uint64(aidx-spec[0].start), e.Groups[0].DeltaMaxAssetIndex)
	a.Equal(basics.AssetIndex(0), e.Groups[0].groupData.AssetOffsets[0])
	a.Equal(oldAssetOffsets, e.Groups[0].groupData.AssetOffsets[:e.Groups[0].Count-1])
	a.Equal(aidx-spec[0].end, e.Groups[0].groupData.AssetOffsets[e.Groups[0].Count-1])
	checkAssetMap(aidx, e.Groups[0])

	// insert in the middle
	e = genExtendedHolding(t, spec)
	aidx = spec[0].end - 1
	delta := spec[0].end - aidx
	e.Groups[0].insert(aidx, basics.AssetHolding{})
	a.Equal(oldCount+1, e.Groups[0].Count)
	a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
	a.Equal(uint64(spec[0].end-spec[0].start), e.Groups[0].DeltaMaxAssetIndex)
	a.Equal(basics.AssetIndex(0), e.Groups[0].groupData.AssetOffsets[0])
	a.Equal(oldAssetOffsets[:len(oldAssetOffsets)-1], e.Groups[0].groupData.AssetOffsets[:e.Groups[0].Count-2])
	a.Equal(oldAssetOffsets[len(oldAssetOffsets)-1]-delta, e.Groups[0].groupData.AssetOffsets[e.Groups[0].Count-2])
	a.Equal(delta, e.Groups[0].groupData.AssetOffsets[e.Groups[0].Count-1])
	checkAssetMap(aidx, e.Groups[0])
}

// test for AssetsHoldingGroup.splitInsert
func TestAssetHoldingSplitInsertGroup(t *testing.T) {
	a := require.New(t)

	spec := []groupSpec{
		{10, 700, maxHoldingGroupSize},
	}

	e := genExtendedHolding(t, spec)
	// save original data for later comparison
	oldCount := e.Count
	a.Equal(uint32(spec[0].count), oldCount)
	oldAssetOffsets1 := make([]basics.AssetIndex, spec[0].count/2)
	oldAssetOffsets2 := make([]basics.AssetIndex, spec[0].count/2)
	for i := 0; i < spec[0].count/2; i++ {
		oldAssetOffsets1[i] = e.Groups[0].groupData.AssetOffsets[i]
		oldAssetOffsets2[i] = e.Groups[0].groupData.AssetOffsets[i+spec[0].count/2]
	}
	num := spec[0].count / 2
	// genExtendedHoldingfunction increments assets as (700-20)/256 = 2
	gap := int(spec[0].end-spec[0].start) / spec[0].count

	// split the group and insert left
	e.splitInsert(0, spec[0].start+1, basics.AssetHolding{})
	a.Equal(oldCount+1, e.Count)
	a.Equal(2, len(e.Groups))
	a.Equal(e.Count, e.Groups[0].Count+e.Groups[1].Count)

	a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
	a.Equal(uint32(maxHoldingGroupSize/2+1), e.Groups[0].Count)
	a.Equal(uint64((num-1)*gap), e.Groups[0].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.AssetOffsets))
	a.Equal(oldAssetOffsets1[0], e.Groups[0].groupData.AssetOffsets[0])
	a.Equal(basics.AssetIndex(1), e.Groups[0].groupData.AssetOffsets[1])
	a.Equal(basics.AssetIndex(1), e.Groups[0].groupData.AssetOffsets[2])
	a.Equal(oldAssetOffsets1[2:], e.Groups[0].groupData.AssetOffsets[3:])

	a.Equal(spec[0].start+basics.AssetIndex(e.Groups[0].DeltaMaxAssetIndex+uint64(gap)), e.Groups[1].MinAssetIndex)
	a.Equal(uint32(maxHoldingGroupSize/2), e.Groups[1].Count)
	a.Equal(uint64(spec[0].end-e.Groups[1].MinAssetIndex), e.Groups[1].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[1].Count), len(e.Groups[1].groupData.AssetOffsets))
	a.Equal(basics.AssetIndex(0), e.Groups[1].groupData.AssetOffsets[0])
	a.Equal(oldAssetOffsets2[1:], e.Groups[1].groupData.AssetOffsets[1:])

	e = genExtendedHolding(t, spec)

	// split the group and insert right
	e.splitInsert(0, spec[0].end-1, basics.AssetHolding{})
	a.Equal(oldCount+1, e.Count)
	a.Equal(2, len(e.Groups))
	a.Equal(e.Count, e.Groups[0].Count+e.Groups[1].Count)

	a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
	a.Equal(uint32(maxHoldingGroupSize/2), e.Groups[0].Count)
	a.Equal(uint64((num-1)*gap), e.Groups[0].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.AssetOffsets))
	a.Equal(oldAssetOffsets1, e.Groups[0].groupData.AssetOffsets)

	a.Equal(spec[0].start+basics.AssetIndex(e.Groups[0].DeltaMaxAssetIndex+uint64(gap)), e.Groups[1].MinAssetIndex)
	a.Equal(uint32(maxHoldingGroupSize/2+1), e.Groups[1].Count)
	a.Equal(uint64(spec[0].end-e.Groups[1].MinAssetIndex), e.Groups[1].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[1].Count), len(e.Groups[1].groupData.AssetOffsets))
	a.Equal(basics.AssetIndex(0), e.Groups[1].groupData.AssetOffsets[0])
	a.Equal(oldAssetOffsets2[1:len(oldAssetOffsets2)-1], e.Groups[1].groupData.AssetOffsets[1:e.Groups[1].Count-2])
	a.Equal(oldAssetOffsets2[len(oldAssetOffsets2)-1]-1, e.Groups[1].groupData.AssetOffsets[e.Groups[1].Count-2])
	a.Equal(basics.AssetIndex(1), e.Groups[1].groupData.AssetOffsets[e.Groups[1].Count-1])
}

// test for ExtendedAssetHolding.insert and findGroup
func TestAssetHoldingInsertGroup(t *testing.T) {
	a := require.New(t)

	spec1 := []groupSpec{
		{10, 700, maxHoldingGroupSize},
		{1001, 1060, 20},
		{2001, 3000, maxHoldingGroupSize},
		{4001, 5000, maxHoldingGroupSize},
	}

	e := genExtendedHolding(t, spec1)

	// new group at the beginning
	aidx := basics.AssetIndex(1)
	res := e.findGroup(aidx, 0)
	a.False(res.found)
	a.False(res.split)
	a.Equal(-1, res.gi)

	// split group 0
	aidx = basics.AssetIndex(spec1[0].start + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.True(res.split)
	a.Equal(0, res.gi)

	// insert into group 1 if skipping 0
	res = e.findGroup(aidx, 1)
	a.True(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	// prepend into group 1
	aidx = basics.AssetIndex(spec1[0].end + 10)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	// append into group 1
	aidx = basics.AssetIndex(spec1[1].end + 10)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	// insert into group 1
	aidx = basics.AssetIndex(spec1[1].start + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	// split group 2
	aidx = basics.AssetIndex(spec1[2].start + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.True(res.split)
	a.Equal(2, res.gi)

	// new group after group 2
	aidx = basics.AssetIndex(spec1[2].end + 100)
	res = e.findGroup(aidx, 0)
	a.False(res.found)
	a.False(res.split)
	a.Equal(2, res.gi)

	// new group after group 3
	aidx = basics.AssetIndex(spec1[3].end + 100)
	res = e.findGroup(aidx, 0)
	a.False(res.found)
	a.False(res.split)
	a.Equal(3, res.gi)

	// check insertion
	assets := []basics.AssetIndex{
		1,                  // create a new group at the beginning (new 0)
		spec1[0].start + 1, // split old group 0 and insert left
		spec1[0].end + 10,  // insert into new group 1
		spec1[1].start + 1, // insert into old group 1 (new 3)
		spec1[2].end + 100, // create a new after old group 2 (new 4)
		spec1[3].end + 100, // create a new group after old group 3 (new 7)
	}
	holdings := make(map[basics.AssetIndex]basics.AssetHolding, len(assets))
	for _, aidx := range assets {
		holdings[aidx] = basics.AssetHolding{}
	}
	oldCount := e.Count
	e.insert(assets, holdings)

	a.Equal(oldCount+uint32(len(assets)), e.Count)
	a.Equal(4+len(spec1), len(e.Groups))

	a.Equal(uint32(1), e.Groups[0].Count)
	a.Equal(assets[0], e.Groups[0].MinAssetIndex)
	a.Equal(uint64(0), e.Groups[0].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.AssetOffsets))
	a.Equal(basics.AssetIndex(0), e.Groups[0].groupData.AssetOffsets[0])

	// two cases below checked in splitInsert test
	a.Equal(uint32(spec1[0].count/2+1), e.Groups[1].Count)
	a.Equal(int(e.Groups[1].Count), len(e.Groups[1].groupData.AssetOffsets))

	a.Equal(uint32(spec1[0].count/2+1), e.Groups[2].Count)
	a.Equal(int(e.Groups[2].Count), len(e.Groups[2].groupData.AssetOffsets))

	a.Equal(uint32(spec1[1].count+1), e.Groups[3].Count)
	a.Equal(spec1[1].start, e.Groups[3].MinAssetIndex)
	a.Equal(uint64(spec1[1].end-spec1[1].start), e.Groups[3].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[3].Count), len(e.Groups[3].groupData.AssetOffsets))

	// checked in group insert test
	a.Equal(uint32(spec1[2].count), e.Groups[4].Count)
	a.Equal(int(e.Groups[4].Count), len(e.Groups[4].groupData.AssetOffsets))

	a.Equal(uint32(1), e.Groups[5].Count)
	a.Equal(assets[4], e.Groups[5].MinAssetIndex)
	a.Equal(uint64(0), e.Groups[5].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[5].Count), len(e.Groups[5].groupData.AssetOffsets))
	a.Equal(basics.AssetIndex(0), e.Groups[5].groupData.AssetOffsets[0])

	a.Equal(uint32(1), e.Groups[7].Count)
	a.Equal(assets[5], e.Groups[7].MinAssetIndex)
	a.Equal(uint64(0), e.Groups[7].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[7].Count), len(e.Groups[7].groupData.AssetOffsets))
	a.Equal(basics.AssetIndex(0), e.Groups[7].groupData.AssetOffsets[0])

	spec2 := []groupSpec{
		{1001, 1060, 20},
		{2001, 3000, maxHoldingGroupSize},
	}

	e = genExtendedHolding(t, spec2)

	// insert into group 0
	aidx = basics.AssetIndex(1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(0, res.gi)

	// insert into group 0
	aidx = basics.AssetIndex(spec2[0].start + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(0, res.gi)

	// insert into group 0
	aidx = basics.AssetIndex(spec2[0].end + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(0, res.gi)

	// split group 1
	aidx = basics.AssetIndex(spec2[1].start + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.True(res.split)
	a.Equal(1, res.gi)

	// new group after group 1
	aidx = basics.AssetIndex(spec2[1].end + 1)
	res = e.findGroup(aidx, 0)
	a.False(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	spec3 := []groupSpec{
		{2001, 3000, maxHoldingGroupSize},
		{3002, 3062, 20},
	}

	e = genExtendedHolding(t, spec3)

	// split group 0
	aidx = basics.AssetIndex(spec3[0].start + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.True(res.split)
	a.Equal(0, res.gi)

	// insert into group 1
	aidx = basics.AssetIndex(spec3[1].start - 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	// insert into group 1
	aidx = basics.AssetIndex(spec3[1].end + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	spec4 := []groupSpec{
		{2001, 3000, maxHoldingGroupSize},
		{3002, 4000, maxHoldingGroupSize},
	}

	e = genExtendedHolding(t, spec4)

	// new group after 0
	aidx = basics.AssetIndex(spec4[0].end + 1)
	res = e.findGroup(aidx, 0)
	a.False(res.found)
	a.False(res.split)
	a.Equal(0, res.gi)
}
