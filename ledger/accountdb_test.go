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
	"github.com/algorand/go-algorand/ledger/common"
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

func randomDeltas(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64) (updates map[basics.Address]common.AccountDelta, totals map[basics.Address]basics.AccountData, imbalance int64) {
	updates, totals, imbalance, _ = randomDeltasImpl(niter, base, rewardsLevel, true, 0)
	return
}

func randomDeltasFull(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, lastCreatableIDIn uint64) (updates map[basics.Address]common.AccountDelta, totals map[basics.Address]basics.AccountData, imbalance int64, lastCreatableID uint64) {
	updates, totals, imbalance, lastCreatableID = randomDeltasImpl(niter, base, rewardsLevel, false, lastCreatableIDIn)
	return
}

func randomDeltasImpl(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, simple bool, lastCreatableIDIn uint64) (updates map[basics.Address]common.AccountDelta, totals map[basics.Address]basics.AccountData, imbalance int64, lastCreatableID uint64) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	updates = make(map[basics.Address]common.AccountDelta)
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
			updates[addr] = common.AccountDelta{Old: old, New: new}
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
		updates[addr] = common.AccountDelta{Old: old, New: new}
		imbalance += int64(old.WithUpdatedRewards(proto, rewardsLevel).MicroAlgos.Raw - new.MicroAlgos.Raw)
		totals[addr] = new
	}

	return
}

func randomDeltasBalanced(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64) (updates map[basics.Address]common.AccountDelta, totals map[basics.Address]basics.AccountData) {
	updates, totals, _ = randomDeltasBalancedImpl(niter, base, rewardsLevel, true, 0)
	return
}

func randomDeltasBalancedFull(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, lastCreatableIDIn uint64) (updates map[basics.Address]common.AccountDelta, totals map[basics.Address]basics.AccountData, lastCreatableID uint64) {
	updates, totals, lastCreatableID = randomDeltasBalancedImpl(niter, base, rewardsLevel, false, lastCreatableIDIn)
	return
}

func randomDeltasBalancedImpl(niter int, base map[basics.Address]basics.AccountData, rewardsLevel uint64, simple bool, lastCreatableIDIn uint64) (updates map[basics.Address]common.AccountDelta, totals map[basics.Address]basics.AccountData, lastCreatableID uint64) {
	var imbalance int64
	if simple {
		updates, totals, imbalance = randomDeltas(niter, base, rewardsLevel)
	} else {
		updates, totals, imbalance, lastCreatableID = randomDeltasFull(niter, base, rewardsLevel, lastCreatableIDIn)
	}

	oldPool := base[testPoolAddr]
	newPool := oldPool
	newPool.MicroAlgos.Raw += uint64(imbalance)

	updates[testPoolAddr] = common.AccountDelta{Old: oldPool, New: newPool}

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
		d := pad.accountData
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
	require.Equal(t, d.accountData, basics.AccountData{})

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
func creatablesFromUpdates(updates map[basics.Address]common.AccountDelta, seen map[basics.CreatableIndex]bool) map[basics.CreatableIndex]common.ModifiedCreatable {
	creatables := make(map[basics.CreatableIndex]common.ModifiedCreatable)
	for addr, update := range updates {
		// no sets in Go, so iterate over
		for idx := range update.Old.Assets {
			if _, ok := update.New.Assets[idx]; !ok {
				creatables[basics.CreatableIndex(idx)] = common.ModifiedCreatable{
					Ctype:   basics.AssetCreatable,
					Created: false, // exists in old, not in new => deleted
					Creator: addr,
				}
			}
		}
		for idx := range update.New.Assets {
			if seen[basics.CreatableIndex(idx)] {
				continue
			}
			if _, ok := update.Old.Assets[idx]; !ok {
				creatables[basics.CreatableIndex(idx)] = common.ModifiedCreatable{
					Ctype:   basics.AssetCreatable,
					Created: true, // exists in new, not in old => created
					Creator: addr,
				}
			}
			seen[basics.CreatableIndex(idx)] = true
		}
		for idx := range update.Old.AppParams {
			if _, ok := update.New.AppParams[idx]; !ok {
				creatables[basics.CreatableIndex(idx)] = common.ModifiedCreatable{
					Ctype:   basics.AppCreatable,
					Created: false, // exists in old, not in new => deleted
					Creator: addr,
				}
			}
		}
		for idx := range update.New.AppParams {
			if seen[basics.CreatableIndex(idx)] {
				continue
			}
			if _, ok := update.Old.AppParams[idx]; !ok {
				creatables[basics.CreatableIndex(idx)] = common.ModifiedCreatable{
					Ctype:   basics.AppCreatable,
					Created: true, // exists in new, not in old => created
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
	expectedDbImage := make(map[basics.CreatableIndex]common.ModifiedCreatable)
	var baseAccounts lruAccounts
	baseAccounts.init(nil, 100, 80)
	for i := 1; i < 10; i++ {
		var updates map[basics.Address]common.AccountDelta
		var newaccts map[basics.Address]basics.AccountData
		updates, newaccts, _, lastCreatableID = randomDeltasFull(20, accts, 0, lastCreatableID)
		accts = newaccts
		ctbsWithDeletes := randomCreatableSampling(i, ctbsList, randomCtbs,
			expectedDbImage, numElementsPerSegement)

		updatesCnt, needLoadAddresses, _ := compactDeltas([]map[basics.Address]common.AccountDelta{updates}, nil, baseAccounts)

		err = accountsLoadOld(tx, needLoadAddresses, updatesCnt)
		require.NoError(t, err)
		err = totalsNewRounds(tx, []map[basics.Address]common.AccountDelta{updates}, updatesCnt, []AccountTotals{{}}, []config.ConsensusParams{proto})
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
	expectedDbImage map[basics.CreatableIndex]common.ModifiedCreatable) {

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
		mc := common.ModifiedCreatable{}
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
	creatables map[basics.CreatableIndex]common.ModifiedCreatable,
	expectedDbImage map[basics.CreatableIndex]common.ModifiedCreatable,
	numElementsPerSegement int) map[basics.CreatableIndex]common.ModifiedCreatable {

	iteration-- // 0-based here

	delSegmentEnd := iteration * numElementsPerSegement
	delSegmentStart := delSegmentEnd - numElementsPerSegement
	if delSegmentStart < 0 {
		delSegmentStart = 0
	}

	newSample := make(map[basics.CreatableIndex]common.ModifiedCreatable)
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
	map[basics.CreatableIndex]common.ModifiedCreatable) {
	creatables := make(map[basics.CreatableIndex]common.ModifiedCreatable)
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
	assetIndex basics.CreatableIndex, mc common.ModifiedCreatable) {

	var ctype basics.CreatableType

	switch crypto.RandUint64() % 2 {
	case 0:
		ctype = basics.AssetCreatable
	case 1:
		ctype = basics.AppCreatable
	}

	creatable := common.ModifiedCreatable{
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
