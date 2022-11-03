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

package ledger

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand/data/transactions/logic"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

func accountsInitTest(tb testing.TB, tx *sql.Tx, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	newDB, err := accountsInit(tx, initAccounts, config.Consensus[proto])
	require.NoError(tb, err)

	err = accountsAddNormalizedBalance(tx, config.Consensus[proto])
	require.NoError(tb, err)

	err = accountsCreateResourceTable(context.Background(), tx)
	require.NoError(tb, err)

	err = performResourceTableMigration(context.Background(), tx, nil)
	require.NoError(tb, err)

	err = accountsCreateOnlineAccountsTable(context.Background(), tx)
	require.NoError(tb, err)

	err = accountsCreateTxTailTable(context.Background(), tx)
	require.NoError(tb, err)

	err = performOnlineAccountsTableMigration(context.Background(), tx, nil, nil)
	require.NoError(tb, err)

	// since this is a test that starts from genesis, there is no tail that needs to be migrated.
	// we'll pass a nil here in order to ensure we still call this method, although it would
	// be a noop.
	err = performTxTailTableMigration(context.Background(), nil, db.Accessor{})
	require.NoError(tb, err)

	err = accountsCreateOnlineRoundParamsTable(context.Background(), tx)
	require.NoError(tb, err)

	err = performOnlineRoundParamsTailMigration(context.Background(), tx, db.Accessor{}, true, proto)
	require.NoError(tb, err)

	err = accountsCreateBoxTable(context.Background(), tx)
	require.NoError(tb, err)

	return newDB
}

func checkAccounts(t *testing.T, tx *sql.Tx, rnd basics.Round, accts map[basics.Address]basics.AccountData) {
	r, err := accountsRound(tx)
	require.NoError(t, err)
	require.Equal(t, r, rnd)

	aq, err := accountsInitDbQueries(tx)
	require.NoError(t, err)
	defer aq.close()

	var totalOnline, totalOffline, totalNotPart uint64

	for addr, data := range accts {
		expected := ledgercore.ToAccountData(data)
		pad, err := aq.lookup(addr)
		require.NoError(t, err)
		d := pad.accountData.GetLedgerCoreAccountData()
		require.Equal(t, expected, d)

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

	totals, err := accountsTotals(context.Background(), tx, false)
	require.NoError(t, err)
	require.Equal(t, totalOnline, totals.Online.Money.Raw, "mismatching total online money")
	require.Equal(t, totalOffline, totals.Offline.Money.Raw)
	require.Equal(t, totalNotPart, totals.NotParticipating.Money.Raw)
	require.Equal(t, totalOnline+totalOffline, totals.Participating().Raw)
	require.Equal(t, totalOnline+totalOffline+totalNotPart, totals.All().Raw)

	d, err := aq.lookup(ledgertesting.RandomAddress())
	require.NoError(t, err)
	require.Equal(t, rnd, d.round)
	require.Equal(t, d.accountData, baseAccountData{})

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	onlineAccounts := make(map[basics.Address]*ledgercore.OnlineAccount)
	for addr, data := range accts {
		if data.Status == basics.Online {
			ad := ledgercore.ToAccountData(data)
			onlineAccounts[addr] = accountDataToOnline(addr, &ad, proto)
		}
	}

	// Compute the top-N accounts ourselves
	var testtop []ledgercore.OnlineAccount
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

	for i := 0; i < len(onlineAccounts); i++ {
		dbtop, err := accountsOnlineTop(tx, rnd, 0, uint64(i), proto)
		require.NoError(t, err)
		require.Equal(t, i, len(dbtop))

		for j := 0; j < i; j++ {
			_, ok := dbtop[testtop[j].Address]
			require.True(t, ok)
		}
	}

	top, err := accountsOnlineTop(tx, rnd, 0, uint64(len(onlineAccounts)+1), proto)
	require.NoError(t, err)
	require.Equal(t, len(top), len(onlineAccounts))
}

func TestAccountDBInit(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	accts := ledgertesting.RandomAccounts(20, true)
	newDB := accountsInitTest(t, tx, accts, protocol.ConsensusCurrentVersion)
	require.True(t, newDB)

	checkAccounts(t, tx, 0, accts)

	newDB, err = accountsInit(tx, accts, proto)
	require.NoError(t, err)
	require.False(t, newDB)
	checkAccounts(t, tx, 0, accts)
}

// creatablesFromUpdates calculates creatables from updates
func creatablesFromUpdates(base map[basics.Address]basics.AccountData, updates ledgercore.AccountDeltas, seen map[basics.CreatableIndex]bool) map[basics.CreatableIndex]ledgercore.ModifiedCreatable {
	known := make(map[basics.CreatableIndex]struct{}, len(seen))
	for aidx := range seen {
		known[aidx] = struct{}{}
	}
	for _, ad := range base {
		for aidx := range ad.AppParams {
			known[basics.CreatableIndex(aidx)] = struct{}{}
		}
		for aidx := range ad.AssetParams {
			known[basics.CreatableIndex(aidx)] = struct{}{}
		}
	}
	return updates.ToModifiedCreatables(known)
}

func applyPartialDeltas(base map[basics.Address]basics.AccountData, deltas ledgercore.AccountDeltas) map[basics.Address]basics.AccountData {
	result := make(map[basics.Address]basics.AccountData, len(base)+deltas.Len())
	for addr, ad := range base {
		result[addr] = ad
	}

	for i := 0; i < deltas.Len(); i++ {
		addr, _ := deltas.GetByIdx(i)
		ad, ok := result[addr]
		if !ok {
			ad, _ = deltas.GetBasicsAccountData(addr)
		} else {
			ad = deltas.ApplyToBasicsAccountData(addr, ad)
		}
		result[addr] = ad
	}
	return result
}

func TestAccountDBRound(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	accts := ledgertesting.RandomAccounts(20, true)
	accountsInitTest(t, tx, accts, protocol.ConsensusCurrentVersion)
	checkAccounts(t, tx, 0, accts)
	totals, err := accountsTotals(context.Background(), tx, false)
	require.NoError(t, err)
	expectedOnlineRoundParams, endRound, err := accountsOnlineRoundParams(tx)
	require.NoError(t, err)
	require.Equal(t, 1, len(expectedOnlineRoundParams))
	require.Equal(t, 0, int(endRound))

	// used to determine how many creatables element will be in the test per iteration
	numElementsPerSegment := 10

	// lastCreatableID stores asset or app max used index to get rid of conflicts
	lastCreatableID := basics.CreatableIndex(crypto.RandUint64() % 512)
	ctbsList, randomCtbs := randomCreatables(numElementsPerSegment)
	expectedDbImage := make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
	var baseAccounts lruAccounts
	var baseResources lruResources
	var baseOnlineAccounts lruOnlineAccounts
	var newacctsTotals map[basics.Address]ledgercore.AccountData
	baseAccounts.init(nil, 100, 80)
	baseResources.init(nil, 100, 80)
	baseOnlineAccounts.init(nil, 100, 80)
	for i := 1; i < 10; i++ {
		var updates ledgercore.AccountDeltas
		updates, newacctsTotals, _ = ledgertesting.RandomDeltasFull(20, accts, 0, &lastCreatableID)
		totals = ledgertesting.CalculateNewRoundAccountTotals(t, updates, 0, proto, accts, totals)
		accts = applyPartialDeltas(accts, updates)
		ctbsWithDeletes := randomCreatableSampling(i, ctbsList, randomCtbs,
			expectedDbImage, numElementsPerSegment)

		oldBase := i - 1
		updatesCnt := makeCompactAccountDeltas([]ledgercore.AccountDeltas{updates}, basics.Round(oldBase), true, baseAccounts)
		resourceUpdatesCnt := makeCompactResourceDeltas([]ledgercore.AccountDeltas{updates}, basics.Round(oldBase), true, baseAccounts, baseResources)
		updatesOnlineCnt := makeCompactOnlineAccountDeltas([]ledgercore.AccountDeltas{updates}, basics.Round(oldBase), baseOnlineAccounts)

		err = updatesCnt.accountsLoadOld(tx)
		require.NoError(t, err)

		err = updatesOnlineCnt.accountsLoadOld(tx)
		require.NoError(t, err)

		knownAddresses := make(map[basics.Address]int64)
		for _, delta := range updatesCnt.deltas {
			knownAddresses[delta.oldAcct.addr] = delta.oldAcct.rowid
		}

		err = resourceUpdatesCnt.resourcesLoadOld(tx, knownAddresses)
		require.NoError(t, err)

		err = accountsPutTotals(tx, totals, false)
		require.NoError(t, err)
		onlineRoundParams := ledgercore.OnlineRoundParamsData{RewardsLevel: totals.RewardsLevel, OnlineSupply: totals.Online.Money.Raw, CurrentProtocol: protocol.ConsensusCurrentVersion}
		err = accountsPutOnlineRoundParams(tx, []ledgercore.OnlineRoundParamsData{onlineRoundParams}, basics.Round(i))
		require.NoError(t, err)
		expectedOnlineRoundParams = append(expectedOnlineRoundParams, onlineRoundParams)

		updatedAccts, updatesResources, updatedKVs, err := accountsNewRound(tx, updatesCnt, resourceUpdatesCnt, nil, ctbsWithDeletes, proto, basics.Round(i))
		require.NoError(t, err)
		require.Equal(t, updatesCnt.len(), len(updatedAccts))
		numResUpdates := 0
		for _, rs := range updatesResources {
			numResUpdates += len(rs)
		}
		require.Equal(t, resourceUpdatesCnt.len(), numResUpdates)
		require.Empty(t, updatedKVs)

		updatedOnlineAccts, err := onlineAccountsNewRound(tx, updatesOnlineCnt, proto, basics.Round(i))
		require.NoError(t, err)

		err = updateAccountsRound(tx, basics.Round(i))
		require.NoError(t, err)

		// TODO: calculate exact number of updates?
		// newly created online accounts + accounts went offline + voting data/stake modifed accounts
		require.NotEmpty(t, updatedOnlineAccts)

		checkAccounts(t, tx, basics.Round(i), accts)
		checkCreatables(t, tx, i, expectedDbImage)
	}

	// test the accounts totals
	var updates ledgercore.AccountDeltas
	for addr, acctData := range newacctsTotals {
		updates.Upsert(addr, acctData)
	}

	expectedTotals := ledgertesting.CalculateNewRoundAccountTotals(t, updates, 0, proto, nil, ledgercore.AccountTotals{})
	actualTotals, err := accountsTotals(context.Background(), tx, false)
	require.NoError(t, err)
	require.Equal(t, expectedTotals, actualTotals)

	actualOnlineRoundParams, endRound, err := accountsOnlineRoundParams(tx)
	require.NoError(t, err)
	require.Equal(t, expectedOnlineRoundParams, actualOnlineRoundParams)
	require.Equal(t, 9, int(endRound))

	// check LoadAllFullAccounts
	loaded := make(map[basics.Address]basics.AccountData, len(accts))
	acctCb := func(addr basics.Address, data basics.AccountData) {
		loaded[addr] = data
	}
	count, err := LoadAllFullAccounts(context.Background(), tx, "accountbase", "resources", acctCb)
	require.NoError(t, err)
	require.Equal(t, count, len(accts))
	require.Equal(t, count, len(loaded))
	require.Equal(t, accts, loaded)
}

// TestAccountDBInMemoryAcct checks in-memory only account modifications are handled correctly by
// makeCompactAccountDeltas, makeCompactResourceDeltas and accountsNewRound
func TestAccountDBInMemoryAcct(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	type testfunc func(basics.Address) ([]ledgercore.AccountDeltas, int, int)
	var tests = []testfunc{
		func(addr basics.Address) ([]ledgercore.AccountDeltas, int, int) {
			const numRounds = 4
			accountDeltas := make([]ledgercore.AccountDeltas, numRounds)
			accountDeltas[0].Upsert(addr, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}}})
			accountDeltas[0].UpsertAssetResource(addr, 100, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 0}})
			// transfer some asset
			accountDeltas[1].UpsertAssetResource(addr, 100, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 100}})
			// close out the asset
			accountDeltas[2].UpsertAssetResource(addr, 100, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Deleted: true})
			// close the account
			accountDeltas[3].Upsert(addr, ledgercore.AccountData{})
			return accountDeltas, 2, 3
		},
		func(addr basics.Address) ([]ledgercore.AccountDeltas, int, int) {
			const numRounds = 4
			accountDeltas := make([]ledgercore.AccountDeltas, numRounds)
			accountDeltas[0].Upsert(addr, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}}})
			accountDeltas[1].UpsertAssetResource(addr, 100, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 0}})
			// close out the asset
			accountDeltas[2].UpsertAssetResource(addr, 100, ledgercore.AssetParamsDelta{}, ledgercore.AssetHoldingDelta{Deleted: true})
			// close the account
			accountDeltas[3].Upsert(addr, ledgercore.AccountData{})
			return accountDeltas, 2, 2
		},
	}

	for i, test := range tests {

		dbs, _ := dbOpenTest(t, true)
		setDbLogging(t, dbs)
		defer dbs.Close()

		tx, err := dbs.Wdb.Handle.Begin()
		require.NoError(t, err)
		defer tx.Rollback()

		accts := ledgertesting.RandomAccounts(1, true)
		accountsInitTest(t, tx, accts, protocol.ConsensusCurrentVersion)
		addr := ledgertesting.RandomAddress()

		// lastCreatableID stores asset or app max used index to get rid of conflicts
		var baseAccounts lruAccounts
		var baseResources lruResources
		baseAccounts.init(nil, 100, 80)
		baseResources.init(nil, 100, 80)

		t.Run(fmt.Sprintf("test%d", i), func(t *testing.T) {

			accountDeltas, numAcctDeltas, numResDeltas := test(addr)
			lastRound := uint64(len(accountDeltas) + 1)

			outAccountDeltas := makeCompactAccountDeltas(accountDeltas, basics.Round(1), true, baseAccounts)
			require.Equal(t, 1, len(outAccountDeltas.deltas))
			require.Equal(t, accountDelta{newAcct: baseAccountData{UpdateRound: lastRound}, nAcctDeltas: numAcctDeltas, address: addr}, outAccountDeltas.deltas[0])
			require.Equal(t, 1, len(outAccountDeltas.misses))

			outResourcesDeltas := makeCompactResourceDeltas(accountDeltas, basics.Round(1), true, baseAccounts, baseResources)
			require.Equal(t, 1, len(outResourcesDeltas.deltas))
			require.Equal(t,
				resourceDelta{
					oldResource: persistedResourcesData{aidx: 100}, newResource: makeResourcesData(lastRound - 1),
					nAcctDeltas: numResDeltas, address: addr,
				},
				outResourcesDeltas.deltas[0],
			)
			require.Equal(t, 1, len(outAccountDeltas.misses))

			err = outAccountDeltas.accountsLoadOld(tx)
			require.NoError(t, err)

			knownAddresses := make(map[basics.Address]int64)
			for _, delta := range outAccountDeltas.deltas {
				knownAddresses[delta.oldAcct.addr] = delta.oldAcct.rowid
			}

			err = outResourcesDeltas.resourcesLoadOld(tx, knownAddresses)
			require.NoError(t, err)

			updatedAccts, updatesResources, updatedKVs, err := accountsNewRound(tx, outAccountDeltas, outResourcesDeltas, nil, nil, proto, basics.Round(lastRound))
			require.NoError(t, err)
			require.Equal(t, 1, len(updatedAccts)) // we store empty even for deleted accounts
			require.Equal(t,
				persistedAccountData{addr: addr, round: basics.Round(lastRound)},
				updatedAccts[0],
			)

			require.Equal(t, 1, len(updatesResources[addr])) // we store empty even for deleted resources
			require.Equal(t,
				persistedResourcesData{addrid: 0, aidx: 100, data: makeResourcesData(0), round: basics.Round(lastRound)},
				updatesResources[addr][0],
			)

			require.Empty(t, updatedKVs)
		})
	}
}

func TestAccountStorageWithStateProofID(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	accts := ledgertesting.RandomAccounts(20, false)
	_ = accountsInitTest(t, tx, accts, protocol.ConsensusCurrentVersion)
	checkAccounts(t, tx, 0, accts)
	require.True(t, allAccountsHaveStateProofPKs(accts))
}

func allAccountsHaveStateProofPKs(accts map[basics.Address]basics.AccountData) bool {
	for _, data := range accts {
		if data.Status == basics.Online && data.StateProofID.IsEmpty() {
			return false
		}
	}
	return true
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
// loop 1: returns:
// - the second 10 elements
// - random sample of elements from the first 10: created changed from true -> false
// loop 2: returns:
// - the elements 20->30
// - random sample of elements from 10->20: created changed from true -> false
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
			(i == delSegmentStart || (crypto.RandUint64()%2) == 1) {
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
		Creator: ledgertesting.RandomAddress(),
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
	var stateProofID merklesignature.Verifier
	crypto.RandBytes(stateProofID.Commitment[:])
	updates = make(map[basics.Address]basics.AccountData, numAccounts)

	for i := 0; i < numAccounts; i++ {
		addr := ledgertesting.RandomAddress()
		updates[addr] = basics.AccountData{
			MicroAlgos:         basics.MicroAlgos{Raw: 0x000ffffffffffffff / uint64(numAccounts)},
			Status:             basics.NotParticipating,
			RewardsBase:        uint64(i),
			RewardedMicroAlgos: basics.MicroAlgos{Raw: 0x000ffffffffffffff / uint64(numAccounts)},
			VoteID:             secrets.OneTimeSignatureVerifier,
			SelectionID:        pubVrfKey,
			StateProofID:       stateProofID.Commitment,
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

func benchmarkInitBalances(b testing.TB, numAccounts int, dbs db.Pair, proto protocol.ConsensusVersion) (updates map[basics.Address]basics.AccountData) {
	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(b, err)

	updates = generateRandomTestingAccountBalances(numAccounts)

	accountsInitTest(b, tx, updates, proto)
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
	dbs, fn := dbOpenTest(b, inMemory)
	setDbLogging(b, dbs)
	defer cleanupTestDb(dbs, fn, inMemory)

	benchmarkInitBalances(b, b.N, dbs, protocol.ConsensusCurrentVersion)
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
		prevHash = crypto.Hash(append(encodedAccountBalance, []byte(prevHash[:])...))
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
	dbs, fn := dbOpenTest(b, inMemory)
	setDbLogging(b, dbs)
	defer cleanupTestDb(dbs, fn, inMemory)

	accounts := benchmarkInitBalances(b, b.N, dbs, protocol.ConsensusCurrentVersion)

	qs, err := accountsInitDbQueries(dbs.Rdb.Handle)
	require.NoError(b, err)
	defer qs.close()

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
		dbs, fn := dbOpenTest(b, false)
		setDbLogging(b, dbs)
		cleanup := func() {
			cleanupTestDb(dbs, fn, false)
		}

		benchmarkInitBalances(b, startupAcct, dbs, protocol.ConsensusCurrentVersion)
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
		require.NoError(b, err)
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
		b.ReportMetric(float64(int(time.Since(startTime))/b.N), "ns/acct_update")
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
		b.ReportMetric(float64(int(time.Since(startTime))/b.N), "ns/acct_update")

	})

	err = tx.Commit()
	require.NoError(b, err)
}
func TestAccountsReencoding(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	var stateProofID merklesignature.Verifier
	crypto.RandBytes(stateProofID.Commitment[:])

	err := dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		accountsInitTest(t, tx, make(map[basics.Address]basics.AccountData), protocol.ConsensusCurrentVersion)

		for _, oldAccData := range oldEncodedAccountsData {
			addr := ledgertesting.RandomAddress()
			_, err = tx.ExecContext(ctx, "INSERT INTO accountbase (address, data) VALUES (?, ?)", addr[:], oldAccData)
			if err != nil {
				return err
			}
		}
		for i := 0; i < 100; i++ {
			addr := ledgertesting.RandomAddress()
			accData := basics.AccountData{
				MicroAlgos:         basics.MicroAlgos{Raw: 0x000ffffffffffffff},
				Status:             basics.NotParticipating,
				RewardsBase:        uint64(i),
				RewardedMicroAlgos: basics.MicroAlgos{Raw: 0x000ffffffffffffff},
				VoteID:             secrets.OneTimeSignatureVerifier,
				SelectionID:        pubVrfKey,
				StateProofID:       stateProofID.Commitment,
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
	partitiontest.PartitionTest(t)

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	err := dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		accountsInitTest(t, tx, make(map[basics.Address]basics.AccountData), protocol.ConsensusCurrentVersion)
		return nil
	})
	require.NoError(t, err)
	qs, err := accountsInitDbQueries(dbs.Rdb.Handle)
	require.NoError(t, err)
	require.NotNil(t, qs.listCreatablesStmt)
	qs.close()
	require.Nil(t, qs.listCreatablesStmt)
	qs.close()
	require.Nil(t, qs.listCreatablesStmt)
}

func benchmarkWriteCatchpointStagingBalancesSub(b *testing.B, ascendingOrder bool) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	genesisInitState, _ := ledgertesting.GenerateInitState(b, protocol.ConsensusCurrentVersion, 100)
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
		var chunk catchpointFileChunkV6
		chunk.Balances = make([]encodedBalanceRecordV6, chunkSize)
		for i := uint64(0); i < chunkSize; i++ {
			var randomAccount encodedBalanceRecordV6
			accountData := baseAccountData{RewardsBase: accountsLoaded + i}
			accountData.MicroAlgos.Raw = crypto.RandUint63()
			randomAccount.AccountData = protocol.Encode(&accountData)
			crypto.RandBytes(randomAccount.Address[:])
			if ascendingOrder {
				binary.LittleEndian.PutUint64(randomAccount.Address[:], accountsLoaded+i)
			}
			chunk.Balances[i] = randomAccount
		}
		balanceLoopDuration := time.Since(balancesLoopStart)
		last64KAccountCreationTime += balanceLoopDuration
		accountsGenerationDuration += balanceLoopDuration

		normalizedAccountBalances, err := prepareNormalizedBalancesV6(chunk.Balances, proto)
		require.NoError(b, err)
		b.StartTimer()
		err = l.trackerDBs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
			err = writeCatchpointStagingBalances(ctx, tx, normalizedAccountBalances)
			return
		})

		require.NoError(b, err)
		accountsLoaded += chunkSize
	}
	if !last64KStart.IsZero() {
		last64KDuration := time.Since(last64KStart) - last64KAccountCreationTime
		fmt.Printf("%-82s%-7d (last 64k) %-6d ns/account       %d accounts/sec\n", b.Name(), last64KSize, (last64KDuration / time.Duration(last64KSize)).Nanoseconds(), int(float64(last64KSize)/float64(last64KDuration.Seconds())))
	}
	stats, err := l.trackerDBs.Wdb.Vacuum(context.Background())
	require.NoError(b, err)
	fmt.Printf("%-82sdb fragmentation   %.1f%%\n", b.Name(), float32(stats.PagesBefore-stats.PagesAfter)*100/float32(stats.PagesBefore))
	b.ReportMetric(float64(b.N)/float64((time.Since(accountsWritingStarted)-accountsGenerationDuration).Seconds()), "accounts/sec")
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

func TestKeyPrefixIntervalPreprocessing(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testCases := []struct {
		input            []byte
		outputPrefix     []byte
		outputPrefixIncr []byte
	}{
		{input: []byte{0xAB, 0xCD}, outputPrefix: []byte{0xAB, 0xCD}, outputPrefixIncr: []byte{0xAB, 0xCE}},
		{input: []byte{0xFF}, outputPrefix: []byte{0xFF}, outputPrefixIncr: nil},
		{input: []byte{0xFE, 0xFF}, outputPrefix: []byte{0xFE, 0xFF}, outputPrefixIncr: []byte{0xFF}},
		{input: []byte{0xFF, 0xFF}, outputPrefix: []byte{0xFF, 0xFF}, outputPrefixIncr: nil},
		{input: []byte{0xAB, 0xCD}, outputPrefix: []byte{0xAB, 0xCD}, outputPrefixIncr: []byte{0xAB, 0xCE}},
		{input: []byte{0x1E, 0xFF, 0xFF}, outputPrefix: []byte{0x1E, 0xFF, 0xFF}, outputPrefixIncr: []byte{0x1F}},
		{input: []byte{0xFF, 0xFE, 0xFF, 0xFF}, outputPrefix: []byte{0xFF, 0xFE, 0xFF, 0xFF}, outputPrefixIncr: []byte{0xFF, 0xFF}},
		{input: []byte{0x00, 0xFF}, outputPrefix: []byte{0x00, 0xFF}, outputPrefixIncr: []byte{0x01}},
		{input: []byte(string("bx:123")), outputPrefix: []byte(string("bx:123")), outputPrefixIncr: []byte(string("bx:124"))},
		{input: []byte{}, outputPrefix: []byte{}, outputPrefixIncr: nil},
		{input: nil, outputPrefix: []byte{}, outputPrefixIncr: nil},
		{input: []byte{0x1E, 0xFF, 0xFF}, outputPrefix: []byte{0x1E, 0xFF, 0xFF}, outputPrefixIncr: []byte{0x1F}},
		{input: []byte{0xFF, 0xFE, 0xFF, 0xFF}, outputPrefix: []byte{0xFF, 0xFE, 0xFF, 0xFF}, outputPrefixIncr: []byte{0xFF, 0xFF}},
		{input: []byte{0x00, 0xFF}, outputPrefix: []byte{0x00, 0xFF}, outputPrefixIncr: []byte{0x01}},
	}
	for _, tc := range testCases {
		actualOutputPrefix, actualOutputPrefixIncr := keyPrefixIntervalPreprocessing(tc.input)
		require.Equal(t, tc.outputPrefix, actualOutputPrefix)
		require.Equal(t, tc.outputPrefixIncr, actualOutputPrefixIncr)
	}
}

func TestLookupKeysByPrefix(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	dbs, fn := dbOpenTest(t, false)
	setDbLogging(t, dbs)
	defer cleanupTestDb(dbs, fn, false)

	// return account data, initialize DB tables from accountsInitTest
	_ = benchmarkInitBalances(t, 1, dbs, protocol.ConsensusCurrentVersion)

	qs, err := accountsInitDbQueries(dbs.Rdb.Handle)
	require.NoError(t, err)
	defer qs.close()

	kvPairDBPrepareSet := []struct {
		key   []byte
		value []byte
	}{
		{key: []byte{0xFF, 0x12, 0x34, 0x56, 0x78}, value: []byte("val0")},
		{key: []byte{0xFF, 0xFF, 0x34, 0x56, 0x78}, value: []byte("val1")},
		{key: []byte{0xFF, 0xFF, 0xFF, 0x56, 0x78}, value: []byte("val2")},
		{key: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x78}, value: []byte("val3")},
		{key: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, value: []byte("val4")},
		{key: []byte{0xFF, 0xFE, 0xFF}, value: []byte("val5")},
		{key: []byte{0xFF, 0xFF, 0x00, 0xFF, 0xFF}, value: []byte("val6")},
		{key: []byte{0xFF, 0xFF}, value: []byte("should not confuse with 0xFF-0xFE")},
		{key: []byte{0xBA, 0xDD, 0xAD, 0xFF, 0xFF}, value: []byte("baddadffff")},
		{key: []byte{0xBA, 0xDD, 0xAE, 0x00}, value: []byte("baddae00")},
		{key: []byte{0xBA, 0xDD, 0xAE}, value: []byte("baddae")},
		{key: []byte("TACOCAT"), value: []byte("val6")},
		{key: []byte("TACOBELL"), value: []byte("2bucks50cents?")},
		{key: []byte("DingHo-SmallPack"), value: []byte("3bucks75cents")},
		{key: []byte("DingHo-StandardPack"), value: []byte("5bucks25cents")},
		{key: []byte("BostonKitchen-CheeseSlice"), value: []byte("3bucks50cents")},
		{key: []byte(`™£´´∂ƒ∂ƒßƒ©∑®ƒß∂†¬∆`), value: []byte("random Bluh")},
	}

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)

	// writer is only for kvstore
	writer, err := makeAccountsSQLWriter(tx, true, true, true, true)
	if err != nil {
		return
	}

	for i := 0; i < len(kvPairDBPrepareSet); i++ {
		err := writer.upsertKvPair(string(kvPairDBPrepareSet[i].key), kvPairDBPrepareSet[i].value)
		require.NoError(t, err)
	}

	err = tx.Commit()
	require.NoError(t, err)
	writer.close()

	testCases := []struct {
		prefix        []byte
		expectedNames [][]byte
		err           string
	}{
		{
			prefix: []byte{0xFF},
			err:    "strange prefix",
		},
		{
			prefix: []byte{0xFF, 0xFE},
			expectedNames: [][]byte{
				{0xFF, 0xFE, 0xFF},
			},
		},
		{
			prefix: []byte{0xFF, 0xFE, 0xFF},
			expectedNames: [][]byte{
				{0xFF, 0xFE, 0xFF},
			},
		},
		{
			prefix: []byte{0xFF, 0xFF},
			err:    "strange prefix",
		},
		{
			prefix: []byte{0xFF, 0xFF, 0xFF},
			err:    "strange prefix",
		},
		{
			prefix: []byte{0xFF, 0xFF, 0xFF, 0xFF},
			err:    "strange prefix",
		},
		{
			prefix: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			err:    "strange prefix",
		},
		{
			prefix: []byte{0xBA, 0xDD, 0xAD, 0xFF},
			expectedNames: [][]byte{
				{0xBA, 0xDD, 0xAD, 0xFF, 0xFF},
			},
		},
		{
			prefix: []byte{0xBA, 0xDD, 0xAD, 0xFF, 0xFF},
			expectedNames: [][]byte{
				{0xBA, 0xDD, 0xAD, 0xFF, 0xFF},
			},
		},
		{
			prefix: []byte{0xBA, 0xDD},
			expectedNames: [][]byte{
				{0xBA, 0xDD, 0xAE},
				{0xBA, 0xDD, 0xAE, 0x00},
				{0xBA, 0xDD, 0xAD, 0xFF, 0xFF},
			},
		},
		{
			prefix: []byte{0xBA, 0xDD, 0xAE},
			expectedNames: [][]byte{
				{0xBA, 0xDD, 0xAE},
				{0xBA, 0xDD, 0xAE, 0x00},
			},
		},
		{
			prefix: []byte("TACO"),
			expectedNames: [][]byte{
				[]byte("TACOCAT"),
				[]byte("TACOBELL"),
			},
		},
		{
			prefix:        []byte("TACOC"),
			expectedNames: [][]byte{[]byte("TACOCAT")},
		},
		{
			prefix: []byte("DingHo"),
			expectedNames: [][]byte{
				[]byte("DingHo-SmallPack"),
				[]byte("DingHo-StandardPack"),
			},
		},
		{
			prefix: []byte("DingHo-S"),
			expectedNames: [][]byte{
				[]byte("DingHo-SmallPack"),
				[]byte("DingHo-StandardPack"),
			},
		},
		{
			prefix:        []byte("DingHo-Small"),
			expectedNames: [][]byte{[]byte("DingHo-SmallPack")},
		},
		{
			prefix:        []byte("BostonKitchen"),
			expectedNames: [][]byte{[]byte("BostonKitchen-CheeseSlice")},
		},
		{
			prefix:        []byte(`™£´´∂ƒ∂ƒßƒ©`),
			expectedNames: [][]byte{[]byte(`™£´´∂ƒ∂ƒßƒ©∑®ƒß∂†¬∆`)},
		},
		{
			prefix: []byte{},
			err:    "strange prefix",
		},
	}

	for index, testCase := range testCases {
		t.Run("lookupKVByPrefix-testcase-"+strconv.Itoa(index), func(t *testing.T) {
			actual := make(map[string]bool)
			_, err := qs.lookupKeysByPrefix(string(testCase.prefix), uint64(len(kvPairDBPrepareSet)), actual, 0)
			if err != nil {
				require.NotEmpty(t, testCase.err, testCase.prefix)
				require.Contains(t, err.Error(), testCase.err)
			} else {
				require.Empty(t, testCase.err)
				expected := make(map[string]bool)
				for _, name := range testCase.expectedNames {
					expected[string(name)] = true
				}
				require.Equal(t, actual, expected)
			}
		})
	}
}

func BenchmarkLookupKeyByPrefix(b *testing.B) {
	// learn something from BenchmarkWritingRandomBalancesDisk

	dbs, fn := dbOpenTest(b, false)
	setDbLogging(b, dbs)
	defer cleanupTestDb(dbs, fn, false)

	// return account data, initialize DB tables from accountsInitTest
	_ = benchmarkInitBalances(b, 1, dbs, protocol.ConsensusCurrentVersion)

	qs, err := accountsInitDbQueries(dbs.Rdb.Handle)
	require.NoError(b, err)
	defer qs.close()

	currentDBSize := 0
	nextDBSize := 2
	increment := 2

	nameBuffer := make([]byte, 5)
	valueBuffer := make([]byte, 5)

	// from 2^1 -> 2^2 -> ... -> 2^22 sized DB
	for bIndex := 0; bIndex < 22; bIndex++ {
		// make writer to DB
		tx, err := dbs.Wdb.Handle.Begin()
		require.NoError(b, err)

		// writer is only for kvstore
		writer, err := makeAccountsSQLWriter(tx, true, true, true, true)
		if err != nil {
			return
		}

		var prefix string
		// how to write to dbs a bunch of stuffs?
		for i := 0; i < nextDBSize-currentDBSize; i++ {
			crypto.RandBytes(nameBuffer)
			crypto.RandBytes(valueBuffer)
			appID := basics.AppIndex(crypto.RandUint64())
			boxKey := logic.MakeBoxKey(appID, string(nameBuffer))
			err = writer.upsertKvPair(boxKey, valueBuffer)
			require.NoError(b, err)

			if i == 0 {
				prefix = logic.MakeBoxKey(appID, "")
			}
		}
		err = tx.Commit()
		require.NoError(b, err)
		writer.close()

		// benchmark the query against large DB, see if we have O(log N) speed
		currentDBSize = nextDBSize
		nextDBSize *= increment

		b.Run("lookupKVByPrefix-DBsize"+strconv.Itoa(currentDBSize), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				results := make(map[string]bool)
				_, err := qs.lookupKeysByPrefix(prefix, uint64(currentDBSize), results, 0)
				require.NoError(b, err)
				require.True(b, len(results) >= 1)
			}
		})
	}
}

// upsert updates existing or inserts a new entry
func (a *compactResourcesDeltas) upsert(delta resourceDelta) {
	if idx, exist := a.cache[accountCreatable{address: delta.address, index: delta.oldResource.aidx}]; exist {
		a.deltas[idx] = delta
		return
	}
	a.insert(delta)
}

// upsertOld updates existing or inserts a new partial entry with only old field filled
func (a *compactAccountDeltas) upsertOld(old persistedAccountData) {
	addr := old.addr
	if idx, exist := a.cache[addr]; exist {
		a.deltas[idx].oldAcct = old
		return
	}
	a.insert(accountDelta{oldAcct: old, address: old.addr})
}

// upsert updates existing or inserts a new entry
func (a *compactAccountDeltas) upsert(addr basics.Address, delta accountDelta) {
	if idx, exist := a.cache[addr]; exist { // nil map lookup is OK
		a.deltas[idx] = delta
		return
	}
	a.insert(delta)
}
func TestCompactAccountDeltas(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	ad := compactAccountDeltas{}
	data, idx := ad.get(basics.Address{})
	a.Equal(-1, idx)
	a.Equal(accountDelta{}, data)

	addr := ledgertesting.RandomAddress()
	data, idx = ad.get(addr)
	a.Equal(-1, idx)
	a.Equal(accountDelta{}, data)

	a.Zero(ad.len())
	a.Panics(func() { ad.getByIdx(0) })

	sample1 := accountDelta{newAcct: baseAccountData{MicroAlgos: basics.MicroAlgos{Raw: 123}}, address: addr}
	ad.upsert(addr, sample1)
	data, idx = ad.get(addr)
	a.NotEqual(-1, idx)
	a.Equal(sample1, data)

	a.Equal(1, ad.len())
	data = ad.getByIdx(0)
	a.Equal(addr, data.address)
	a.Equal(sample1, data)

	sample2 := accountDelta{newAcct: baseAccountData{MicroAlgos: basics.MicroAlgos{Raw: 456}}, address: addr}
	ad.upsert(addr, sample2)
	data, idx = ad.get(addr)
	a.NotEqual(-1, idx)
	a.Equal(sample2, data)

	a.Equal(1, ad.len())
	data = ad.getByIdx(0)
	a.Equal(addr, data.address)
	a.Equal(sample2, data)

	ad.update(idx, sample2)
	data, idx2 := ad.get(addr)
	a.Equal(idx, idx2)
	a.Equal(sample2, data)

	a.Equal(1, ad.len())
	data = ad.getByIdx(0)
	a.Equal(addr, data.address)
	a.Equal(sample2, data)

	old1 := persistedAccountData{addr: addr, accountData: baseAccountData{MicroAlgos: basics.MicroAlgos{Raw: 789}}}
	ad.upsertOld(old1)
	a.Equal(1, ad.len())
	data = ad.getByIdx(0)
	a.Equal(addr, data.address)
	a.Equal(accountDelta{newAcct: sample2.newAcct, oldAcct: old1, address: addr}, data)

	addr1 := ledgertesting.RandomAddress()
	old2 := persistedAccountData{addr: addr1, accountData: baseAccountData{MicroAlgos: basics.MicroAlgos{Raw: 789}}}
	ad.upsertOld(old2)
	a.Equal(2, ad.len())
	data = ad.getByIdx(0)
	a.Equal(addr, data.address)
	a.Equal(accountDelta{newAcct: sample2.newAcct, oldAcct: old1, address: addr}, data)

	data = ad.getByIdx(1)
	a.Equal(addr1, data.oldAcct.addr)
	a.Equal(accountDelta{oldAcct: old2, address: addr1}, data)

	// apply old on empty delta object, expect no changes
	ad.updateOld(0, old2)
	a.Equal(2, ad.len())
	data = ad.getByIdx(0)
	a.Equal(addr, data.address)
	a.Equal(accountDelta{newAcct: sample2.newAcct, oldAcct: old2, address: addr}, data)

	addr2 := ledgertesting.RandomAddress()
	sample2.address = addr2
	idx = ad.insert(sample2)
	a.Equal(3, ad.len())
	a.Equal(2, idx)
	data = ad.getByIdx(idx)
	a.Equal(addr2, data.address)
	a.Equal(sample2, data)
}

// upsertOld updates existing or inserts a new partial entry with only old field filled
func (a *compactResourcesDeltas) upsertOld(addr basics.Address, old persistedResourcesData) {
	if idx, exist := a.cache[accountCreatable{address: addr, index: old.aidx}]; exist {
		a.deltas[idx].oldResource = old
		return
	}
	idx := a.insert(resourceDelta{oldResource: old, address: addr})
	a.deltas[idx].address = addr
}
func TestCompactResourceDeltas(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	ad := compactResourcesDeltas{}
	data, idx := ad.get(basics.Address{}, 0)
	a.Equal(-1, idx)
	a.Equal(resourceDelta{}, data)

	addr := ledgertesting.RandomAddress()
	data, idx = ad.get(addr, 0)
	a.Equal(-1, idx)
	a.Equal(resourceDelta{}, data)

	a.Zero(ad.len())
	a.Panics(func() { ad.getByIdx(0) })

	sample1 := resourceDelta{newResource: resourcesData{Total: 123}, address: addr, oldResource: persistedResourcesData{aidx: 1}}
	ad.upsert(sample1)
	data, idx = ad.get(addr, 1)
	a.NotEqual(-1, idx)
	a.Equal(sample1, data)

	a.Equal(1, ad.len())
	data = ad.getByIdx(0)
	a.Equal(addr, data.address)
	a.Equal(sample1, data)

	sample2 := resourceDelta{newResource: resourcesData{Total: 456}, address: addr, oldResource: persistedResourcesData{aidx: 1}}
	ad.upsert(sample2)
	data, idx = ad.get(addr, 1)
	a.NotEqual(-1, idx)
	a.Equal(sample2, data)

	a.Equal(1, ad.len())
	data = ad.getByIdx(0)
	a.Equal(addr, data.address)
	a.Equal(sample2, data)

	ad.update(idx, sample2)
	data, idx2 := ad.get(addr, 1)
	a.Equal(idx, idx2)
	a.Equal(sample2, data)

	a.Equal(1, ad.len())
	data = ad.getByIdx(0)
	a.Equal(addr, data.address)
	a.Equal(sample2, data)

	old1 := persistedResourcesData{addrid: 111, aidx: 1, data: resourcesData{Total: 789}}
	ad.upsertOld(addr, old1)
	a.Equal(1, ad.len())
	data = ad.getByIdx(0)
	a.Equal(addr, data.address)
	a.Equal(resourceDelta{newResource: sample2.newResource, oldResource: old1, address: addr}, data)

	addr1 := ledgertesting.RandomAddress()
	old2 := persistedResourcesData{addrid: 222, aidx: 2, data: resourcesData{Total: 789}}
	ad.upsertOld(addr1, old2)
	a.Equal(2, ad.len())
	data = ad.getByIdx(0)
	a.Equal(addr, data.address)
	a.Equal(resourceDelta{newResource: sample2.newResource, oldResource: old1, address: addr}, data)

	data = ad.getByIdx(1)
	a.Equal(addr1, data.address)
	a.Equal(resourceDelta{oldResource: old2, address: addr1}, data)

	ad.updateOld(0, old2)
	a.Equal(2, ad.len())
	data = ad.getByIdx(0)
	a.Equal(addr, data.address)
	a.Equal(resourceDelta{newResource: sample2.newResource, oldResource: old2, address: addr}, data)

	addr2 := ledgertesting.RandomAddress()
	sample2.oldResource.aidx = 2
	sample2.address = addr2
	idx = ad.insert(sample2)
	a.Equal(3, ad.len())
	a.Equal(2, idx)
	data = ad.getByIdx(idx)
	a.Equal(addr2, data.address)
	cachedData, pos := ad.get(addr2, 2)
	a.Equal(2, pos)
	a.Equal(data, cachedData)
	a.Equal(sample2, data)
}

func TestResourcesDataApp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(t)

	rd := resourcesData{}
	a.False(rd.IsApp())
	a.True(rd.IsEmpty())

	rd = makeResourcesData(1)
	a.False(rd.IsApp())
	a.False(rd.IsHolding())
	a.False(rd.IsOwning())
	a.True(rd.IsEmpty())

	// check empty
	appParamsEmpty := basics.AppParams{}
	rd = resourcesData{}
	rd.SetAppParams(appParamsEmpty, false)
	a.True(rd.IsApp())
	a.True(rd.IsOwning())
	a.True(rd.IsEmptyAppFields())
	a.False(rd.IsEmpty())
	a.Equal(appParamsEmpty, rd.GetAppParams())

	appLocalEmpty := basics.AppLocalState{}
	rd = resourcesData{}
	rd.SetAppLocalState(appLocalEmpty)
	a.True(rd.IsApp())
	a.True(rd.IsHolding())
	a.True(rd.IsEmptyAppFields())
	a.False(rd.IsEmpty())
	a.Equal(appLocalEmpty, rd.GetAppLocalState())

	// check both empty
	rd = resourcesData{}
	rd.SetAppLocalState(appLocalEmpty)
	rd.SetAppParams(appParamsEmpty, true)
	a.True(rd.IsApp())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.True(rd.IsEmptyAppFields())
	a.False(rd.IsEmpty())
	a.Equal(appParamsEmpty, rd.GetAppParams())
	a.Equal(appLocalEmpty, rd.GetAppLocalState())

	// Since some steps use randomly generated input, the test is run N times
	// to cover a larger search space of inputs.
	for i := 0; i < 1000; i++ {
		// check empty states + non-empty params
		appParams := ledgertesting.RandomAppParams()
		rd = resourcesData{}
		rd.SetAppLocalState(appLocalEmpty)
		rd.SetAppParams(appParams, true)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.True(rd.IsHolding())
		a.False(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())
		a.Equal(appParams, rd.GetAppParams())
		a.Equal(appLocalEmpty, rd.GetAppLocalState())

		appState := ledgertesting.RandomAppLocalState()
		rd.SetAppLocalState(appState)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.True(rd.IsHolding())
		a.False(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())
		a.Equal(appParams, rd.GetAppParams())
		a.Equal(appState, rd.GetAppLocalState())

		// check ClearAppLocalState
		rd.ClearAppLocalState()
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.False(rd.IsHolding())
		a.False(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())
		a.Equal(appParams, rd.GetAppParams())
		a.Equal(appLocalEmpty, rd.GetAppLocalState())

		// check ClearAppParams
		rd.SetAppLocalState(appState)
		rd.ClearAppParams()
		a.True(rd.IsApp())
		a.False(rd.IsOwning())
		a.True(rd.IsHolding())
		if appState.Schema.NumEntries() == 0 {
			a.True(rd.IsEmptyAppFields())
		} else {
			a.False(rd.IsEmptyAppFields())
		}
		a.False(rd.IsEmpty())
		a.Equal(appParamsEmpty, rd.GetAppParams())
		a.Equal(appState, rd.GetAppLocalState())

		// check both clear
		rd.ClearAppLocalState()
		a.False(rd.IsApp())
		a.False(rd.IsOwning())
		a.False(rd.IsHolding())
		a.True(rd.IsEmptyAppFields())
		a.True(rd.IsEmpty())
		a.Equal(appParamsEmpty, rd.GetAppParams())
		a.Equal(appLocalEmpty, rd.GetAppLocalState())

		// check params clear when non-empty params and empty holding
		rd = resourcesData{}
		rd.SetAppLocalState(appLocalEmpty)
		rd.SetAppParams(appParams, true)
		rd.ClearAppParams()
		a.True(rd.IsApp())
		a.False(rd.IsOwning())
		a.True(rd.IsHolding())
		a.True(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())
		a.Equal(appParamsEmpty, rd.GetAppParams())
		a.Equal(appLocalEmpty, rd.GetAppLocalState())

		rd = resourcesData{}
		rd.SetAppLocalState(appLocalEmpty)
		a.True(rd.IsEmptyAppFields())
		a.True(rd.IsApp())
		a.False(rd.IsEmpty())
		a.Equal(rd.ResourceFlags, resourceFlagsEmptyApp)
		rd.ClearAppLocalState()
		a.False(rd.IsApp())
		a.True(rd.IsEmptyAppFields())
		a.True(rd.IsEmpty())
		a.Equal(rd.ResourceFlags, resourceFlagsNotHolding)

		// check migration flow (accountDataResources)
		// 1. both exist and empty
		rd = makeResourcesData(0)
		rd.SetAppLocalState(appLocalEmpty)
		rd.SetAppParams(appParamsEmpty, true)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.True(rd.IsHolding())
		a.True(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())

		// 2. both exist and not empty
		rd = makeResourcesData(0)
		rd.SetAppLocalState(appState)
		rd.SetAppParams(appParams, true)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.True(rd.IsHolding())
		a.False(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())

		// 3. both exist: holding not empty, param is empty
		rd = makeResourcesData(0)
		rd.SetAppLocalState(appState)
		rd.SetAppParams(appParamsEmpty, true)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.True(rd.IsHolding())
		if appState.Schema.NumEntries() == 0 {
			a.True(rd.IsEmptyAppFields())
		} else {
			a.False(rd.IsEmptyAppFields())
		}
		a.False(rd.IsEmpty())

		// 4. both exist: holding empty, param is not empty
		rd = makeResourcesData(0)
		rd.SetAppLocalState(appLocalEmpty)
		rd.SetAppParams(appParams, true)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.True(rd.IsHolding())
		a.False(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())

		// 5. holding does not exist and params is empty
		rd = makeResourcesData(0)
		rd.SetAppParams(appParamsEmpty, false)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.False(rd.IsHolding())
		a.True(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())

		// 6. holding does not exist and params is not empty
		rd = makeResourcesData(0)
		rd.SetAppParams(appParams, false)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.False(rd.IsHolding())
		a.False(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())

		// 7. holding exist and not empty and params does not exist
		rd = makeResourcesData(0)
		rd.SetAppLocalState(appState)
		a.True(rd.IsApp())
		a.False(rd.IsOwning())
		a.True(rd.IsHolding())
		if appState.Schema.NumEntries() == 0 {
			a.True(rd.IsEmptyAppFields())
		} else {
			a.False(rd.IsEmptyAppFields())
		}
		a.False(rd.IsEmpty())

		// 8. both do not exist
		rd = makeResourcesData(0)
		a.False(rd.IsApp())
		a.False(rd.IsOwning())
		a.False(rd.IsHolding())
		a.True(rd.IsEmptyAppFields())
		a.True(rd.IsEmpty())
	}
}

func TestResourcesDataAsset(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	rd := resourcesData{}
	a.False(rd.IsAsset())
	a.True(rd.IsEmpty())

	rd = makeResourcesData(1)
	a.False(rd.IsAsset())
	a.False(rd.IsHolding())
	a.False(rd.IsOwning())
	a.True(rd.IsEmpty())

	// check empty
	assetParamsEmpty := basics.AssetParams{}
	rd = resourcesData{}
	rd.SetAssetParams(assetParamsEmpty, false)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParamsEmpty, rd.GetAssetParams())

	assetHoldingEmpty := basics.AssetHolding{}
	rd = resourcesData{}
	rd.SetAssetHolding(assetHoldingEmpty)
	a.True(rd.IsAsset())
	a.True(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetHoldingEmpty, rd.GetAssetHolding())

	// check both empty
	rd = resourcesData{}
	rd.SetAssetHolding(assetHoldingEmpty)
	rd.SetAssetParams(assetParamsEmpty, true)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParamsEmpty, rd.GetAssetParams())
	a.Equal(assetHoldingEmpty, rd.GetAssetHolding())

	// check empty states + non-empty params
	assetParams := ledgertesting.RandomAssetParams()
	rd = resourcesData{}
	rd.SetAssetHolding(assetHoldingEmpty)
	rd.SetAssetParams(assetParams, true)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParams, rd.GetAssetParams())
	a.Equal(assetHoldingEmpty, rd.GetAssetHolding())

	assetHolding := ledgertesting.RandomAssetHolding(true)
	rd.SetAssetHolding(assetHolding)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParams, rd.GetAssetParams())
	a.Equal(assetHolding, rd.GetAssetHolding())

	// check ClearAssetHolding
	rd.ClearAssetHolding()
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.False(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParams, rd.GetAssetParams())
	a.Equal(assetHoldingEmpty, rd.GetAssetHolding())

	// check ClearAssetParams
	rd.SetAssetHolding(assetHolding)
	rd.ClearAssetParams()
	a.True(rd.IsAsset())
	a.False(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParamsEmpty, rd.GetAssetParams())
	a.Equal(assetHolding, rd.GetAssetHolding())

	// check both clear
	rd.ClearAssetHolding()
	a.False(rd.IsAsset())
	a.False(rd.IsOwning())
	a.False(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.True(rd.IsEmpty())
	a.Equal(assetParamsEmpty, rd.GetAssetParams())
	a.Equal(assetHoldingEmpty, rd.GetAssetHolding())

	// check params clear when non-empty params and empty holding
	rd = resourcesData{}
	rd.SetAssetHolding(assetHoldingEmpty)
	rd.SetAssetParams(assetParams, true)
	rd.ClearAssetParams()
	a.True(rd.IsAsset())
	a.False(rd.IsOwning())
	a.True(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParamsEmpty, rd.GetAssetParams())
	a.Equal(assetHoldingEmpty, rd.GetAssetHolding())

	rd = resourcesData{}
	rd.SetAssetHolding(assetHoldingEmpty)
	a.True(rd.IsEmptyAssetFields())
	a.True(rd.IsAsset())
	a.False(rd.IsEmpty())
	a.Equal(rd.ResourceFlags, resourceFlagsEmptyAsset)
	rd.ClearAssetHolding()
	a.False(rd.IsAsset())
	a.True(rd.IsEmptyAssetFields())
	a.True(rd.IsEmpty())
	a.Equal(rd.ResourceFlags, resourceFlagsNotHolding)

	// check migration operations (accountDataResources)
	// 1. both exist and empty
	rd = makeResourcesData(0)
	rd.SetAssetHolding(assetHoldingEmpty)
	rd.SetAssetParams(assetParamsEmpty, true)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 2. both exist and not empty
	rd = makeResourcesData(0)
	rd.SetAssetHolding(assetHolding)
	rd.SetAssetParams(assetParams, true)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 3. both exist: holding not empty, param is empty
	rd = makeResourcesData(0)
	rd.SetAssetHolding(assetHolding)
	rd.SetAssetParams(assetParamsEmpty, true)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 4. both exist: holding empty, param is not empty
	rd = makeResourcesData(0)
	rd.SetAssetHolding(assetHoldingEmpty)
	rd.SetAssetParams(assetParams, true)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 5. holding does not exist and params is empty
	rd = makeResourcesData(0)
	rd.SetAssetParams(assetParamsEmpty, false)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.False(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 6. holding does not exist and params is not empty
	rd = makeResourcesData(0)
	rd.SetAssetParams(assetParams, false)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.False(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 7. holding exist and not empty and params does not exist
	rd = makeResourcesData(0)
	rd.SetAssetHolding(assetHolding)
	a.True(rd.IsAsset())
	a.False(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 8. both do not exist
	rd = makeResourcesData(0)
	a.False(rd.IsAsset())
	a.False(rd.IsOwning())
	a.False(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.True(rd.IsEmpty())
}

// TestResourcesDataSetData checks combinations of old/new values when
// updating resourceData from resourceDelta
func TestResourcesDataSetData(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	type deltaCode int
	const (
		tri deltaCode = iota + 1
		del
		emp
		act
	)

	// apply deltas encoded as deltaCode to a base resourcesData for both apps and assets
	apply := func(t *testing.T, base resourcesData, testType basics.CreatableType, pcode, hcode deltaCode) resourcesData {
		if testType == basics.AssetCreatable {
			var p ledgercore.AssetParamsDelta
			var h ledgercore.AssetHoldingDelta
			switch pcode {
			case tri:
				break
			case del:
				p = ledgercore.AssetParamsDelta{Deleted: true}
			case emp:
				p = ledgercore.AssetParamsDelta{Params: &basics.AssetParams{}}
			case act:
				p = ledgercore.AssetParamsDelta{Params: &basics.AssetParams{Total: 1000}}
			default:
				t.Logf("invalid pcode: %d", pcode)
				t.Fail()
			}
			switch hcode {
			case tri:
				break
			case del:
				h = ledgercore.AssetHoldingDelta{Deleted: true}
			case emp:
				h = ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{}}
			case act:
				h = ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 555}}
			default:
				t.Logf("invalid hcode: %d", hcode)
				t.Fail()
			}
			base.SetAssetData(p, h)
		} else {
			var p ledgercore.AppParamsDelta
			var h ledgercore.AppLocalStateDelta
			switch pcode {
			case tri:
				break
			case del:
				p = ledgercore.AppParamsDelta{Deleted: true}
			case emp:
				p = ledgercore.AppParamsDelta{Params: &basics.AppParams{}}
			case act:
				p = ledgercore.AppParamsDelta{Params: &basics.AppParams{ClearStateProgram: []byte{4, 5, 6}}}
			default:
				t.Logf("invalid pcode: %d", pcode)
				t.Fail()
			}
			switch hcode {
			case tri:
				break
			case del:
				h = ledgercore.AppLocalStateDelta{Deleted: true}
			case emp:
				h = ledgercore.AppLocalStateDelta{LocalState: &basics.AppLocalState{}}
			case act:
				h = ledgercore.AppLocalStateDelta{LocalState: &basics.AppLocalState{Schema: basics.StateSchema{NumByteSlice: 5}}}
			default:
				t.Logf("invalid hcode: %d", hcode)
				t.Fail()
			}
			base.SetAppData(p, h)
		}

		return base
	}

	itb := func(i int) (b bool) {
		return i != 0
	}

	type testcase struct {
		p             deltaCode
		h             deltaCode
		isAsset       int
		isOwning      int
		isHolding     int
		isEmptyFields int
		isEmpty       int
	}

	empty := func(testType basics.CreatableType) resourcesData {
		return makeResourcesData(0)
	}
	emptyParamsNoHolding := func(testType basics.CreatableType) resourcesData {
		rd := makeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetParams(basics.AssetParams{}, false)
		} else {
			rd.SetAppParams(basics.AppParams{}, false)
		}
		return rd
	}
	emptyParamsEmptyHolding := func(testType basics.CreatableType) resourcesData {
		rd := makeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetHolding(basics.AssetHolding{})
			rd.SetAssetParams(basics.AssetParams{}, true)
		} else {
			rd.SetAppLocalState(basics.AppLocalState{})
			rd.SetAppParams(basics.AppParams{}, true)
		}
		return rd
	}
	emptyParamsNotEmptyHolding := func(testType basics.CreatableType) resourcesData {
		rd := makeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetHolding(basics.AssetHolding{Amount: 111})
			rd.SetAssetParams(basics.AssetParams{}, true)
		} else {
			rd.SetAppLocalState(basics.AppLocalState{Schema: basics.StateSchema{NumUint: 10}})
			rd.SetAppParams(basics.AppParams{}, true)
		}
		return rd
	}
	paramsNoHolding := func(testType basics.CreatableType) resourcesData {
		rd := makeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetParams(basics.AssetParams{Total: 222}, false)
		} else {
			rd.SetAppParams(basics.AppParams{ApprovalProgram: []byte{1, 2, 3}}, false)
		}
		return rd
	}
	paramsEmptyHolding := func(testType basics.CreatableType) resourcesData {
		rd := makeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetHolding(basics.AssetHolding{})
			rd.SetAssetParams(basics.AssetParams{Total: 222}, true)
		} else {
			rd.SetAppLocalState(basics.AppLocalState{})
			rd.SetAppParams(basics.AppParams{ApprovalProgram: []byte{1, 2, 3}}, true)
		}
		return rd
	}
	paramsAndHolding := func(testType basics.CreatableType) resourcesData {
		rd := makeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetHolding(basics.AssetHolding{Amount: 111})
			rd.SetAssetParams(basics.AssetParams{Total: 222}, true)
		} else {
			rd.SetAppLocalState(basics.AppLocalState{Schema: basics.StateSchema{NumUint: 10}})
			rd.SetAppParams(basics.AppParams{ApprovalProgram: []byte{1, 2, 3}}, true)
		}
		return rd
	}
	noParamsEmptyHolding := func(testType basics.CreatableType) resourcesData {
		rd := makeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetHolding(basics.AssetHolding{})
		} else {
			rd.SetAppLocalState(basics.AppLocalState{})
		}
		return rd
	}
	noParamsNotEmptyHolding := func(testType basics.CreatableType) resourcesData {
		rd := makeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetHolding(basics.AssetHolding{Amount: 111})
		} else {
			rd.SetAppLocalState(basics.AppLocalState{Schema: basics.StateSchema{NumUint: 10}})
		}
		return rd
	}

	var tests = []struct {
		name      string
		baseRD    func(testType basics.CreatableType) resourcesData
		testcases []testcase
	}{
		{
			"empty_base", empty,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 0, 0, 0, 1, 1},
				{del, tri, 0, 0, 0, 1, 1},
				{emp, tri, 1, 1, 0, 1, 0},
				{act, tri, 1, 1, 0, 0, 0},

				{tri, del, 0, 0, 0, 1, 1},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 0, 1, 1, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 0, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},

		{
			"empty_params_no_holding", emptyParamsNoHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 1, 0, 1, 0},
				{del, tri, 0, 0, 0, 1, 1},
				{emp, tri, 1, 1, 0, 1, 0},
				{act, tri, 1, 1, 0, 0, 0},

				{tri, del, 1, 1, 0, 1, 0},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 1, 1, 1, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 1, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"empty_params_empty_holding", emptyParamsEmptyHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 1, 1, 1, 0},
				{del, tri, 1, 0, 1, 1, 0},
				{emp, tri, 1, 1, 1, 1, 0},
				{act, tri, 1, 1, 1, 0, 0},

				{tri, del, 1, 1, 0, 1, 0},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 1, 1, 1, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 1, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"empty_params_not_empty_holding", emptyParamsNotEmptyHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 1, 1, 0, 0},
				{del, tri, 1, 0, 1, 0, 0},
				{emp, tri, 1, 1, 1, 0, 0},
				{act, tri, 1, 1, 1, 0, 0},

				{tri, del, 1, 1, 0, 1, 0},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 1, 1, 1, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 1, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"params_no_holding", paramsNoHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 1, 0, 0, 0},
				{del, tri, 0, 0, 0, 1, 1},
				{emp, tri, 1, 1, 0, 1, 0},
				{act, tri, 1, 1, 0, 0, 0},

				{tri, del, 1, 1, 0, 0, 0},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 1, 1, 0, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 1, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"params_empty_holding", paramsEmptyHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 1, 1, 0, 0},
				{del, tri, 1, 0, 1, 1, 0},
				{emp, tri, 1, 1, 1, 1, 0},
				{act, tri, 1, 1, 1, 0, 0},

				{tri, del, 1, 1, 0, 0, 0},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 1, 1, 0, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 1, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"params_and_holding", paramsAndHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 1, 1, 0, 0},
				{del, tri, 1, 0, 1, 0, 0},
				{emp, tri, 1, 1, 1, 0, 0},
				{act, tri, 1, 1, 1, 0, 0},

				{tri, del, 1, 1, 0, 0, 0},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 1, 1, 0, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 1, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"no_params_empty_holding", noParamsEmptyHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 0, 1, 1, 0},
				{del, tri, 1, 0, 1, 1, 0},
				{emp, tri, 1, 1, 1, 1, 0},
				{act, tri, 1, 1, 1, 0, 0},

				{tri, del, 0, 0, 0, 1, 1},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 0, 1, 1, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 0, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"no_params_not_empty_holding", noParamsNotEmptyHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 0, 1, 0, 0},
				{del, tri, 1, 0, 1, 0, 0},
				{emp, tri, 1, 1, 1, 0, 0},
				{act, tri, 1, 1, 1, 0, 0},

				{tri, del, 0, 0, 0, 1, 1},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 0, 1, 1, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 0, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
	}
	for _, testType := range []basics.CreatableType{basics.AssetCreatable, basics.AppCreatable} {
		for _, test := range tests {
			var testTypeStr string
			if testType == basics.AssetCreatable {
				testTypeStr = "asset"
			} else {
				testTypeStr = "app"
			}
			t.Run(fmt.Sprintf("test_%s_%s", testTypeStr, test.name), func(t *testing.T) {
				for i, ts := range test.testcases {
					t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
						rd := test.baseRD(testType)
						rd = apply(t, rd, testType, ts.p, ts.h)
						if testType == basics.AssetCreatable {
							a.Equal(itb(ts.isAsset), rd.IsAsset())
							a.Equal(itb(ts.isEmptyFields), rd.IsEmptyAssetFields())
							a.False(rd.IsApp())
							a.True(rd.IsEmptyAppFields())
						} else {
							a.Equal(itb(ts.isAsset), rd.IsApp())
							a.Equal(itb(ts.isEmptyFields), rd.IsEmptyAppFields())
							a.False(rd.IsAsset())
							a.True(rd.IsEmptyAssetFields())
						}
						a.Equal(itb(ts.isOwning), rd.IsOwning())
						a.Equal(itb(ts.isHolding), rd.IsHolding())
						a.Equal(itb(ts.isEmpty), rd.IsEmpty())
					})
				}
			})
		}
	}
}

// TestResourceDataRoundtripConversion ensures that basics.AppLocalState, basics.AppParams,
// basics.AssetHolding, and basics.AssetParams can be converted to resourcesData and back without
// losing any data. It uses reflection to be sure that no new fields are omitted.
//
// In other words, this test makes sure any new fields in basics.AppLocalState, basics.AppParams,
// basics.AssetHolding, or basics.AssetParam also get added to resourcesData.
func TestResourceDataRoundtripConversion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("basics.AppLocalState", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 1000; i++ {
			randObj, _ := protocol.RandomizeObject(&basics.AppLocalState{})
			basicsAppLocalState := *randObj.(*basics.AppLocalState)

			var data resourcesData
			data.SetAppLocalState(basicsAppLocalState)
			roundTripAppLocalState := data.GetAppLocalState()

			require.Equal(t, basicsAppLocalState, roundTripAppLocalState)
		}
	})

	t.Run("basics.AppParams", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 1000; i++ {
			randObj, _ := protocol.RandomizeObject(&basics.AppParams{})
			basicsAppParams := *randObj.(*basics.AppParams)

			for _, haveHoldings := range []bool{true, false} {
				var data resourcesData
				data.SetAppParams(basicsAppParams, haveHoldings)
				roundTripAppParams := data.GetAppParams()

				require.Equal(t, basicsAppParams, roundTripAppParams)
			}
		}
	})

	t.Run("basics.AssetHolding", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 1000; i++ {
			randObj, _ := protocol.RandomizeObject(&basics.AssetHolding{})
			basicsAssetHolding := *randObj.(*basics.AssetHolding)

			var data resourcesData
			data.SetAssetHolding(basicsAssetHolding)
			roundTripAssetHolding := data.GetAssetHolding()

			require.Equal(t, basicsAssetHolding, roundTripAssetHolding)
		}
	})

	t.Run("basics.AssetParams", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 1000; i++ {
			randObj, _ := protocol.RandomizeObject(&basics.AssetParams{})
			basicsAssetParams := *randObj.(*basics.AssetParams)

			for _, haveHoldings := range []bool{true, false} {
				var data resourcesData
				data.SetAssetParams(basicsAssetParams, haveHoldings)
				roundTripAssetParams := data.GetAssetParams()

				require.Equal(t, basicsAssetParams, roundTripAssetParams)
			}
		}
	})
}

// TestBaseAccountDataRoundtripConversion ensures that baseAccountData can be converted to
// ledgercore.AccountData and basics.AccountData and back without losing any data. It uses
// reflection to be sure that no new fields are omitted.
//
// In other words, this test makes sure any new fields in baseAccountData also get added to
// ledgercore.AccountData and basics.AccountData. You should add a manual override in this test if
// the field really only belongs in baseAccountData.
func TestBaseAccountDataRoundtripConversion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("ledgercore.AccountData", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 1000; i++ {
			randObj, _ := protocol.RandomizeObject(&baseAccountData{})
			baseAccount := *randObj.(*baseAccountData)

			ledgercoreAccount := baseAccount.GetLedgerCoreAccountData()
			var roundTripAccount baseAccountData
			roundTripAccount.SetCoreAccountData(&ledgercoreAccount)

			// Manually set UpdateRound, since it is lost in GetLedgerCoreAccountData
			roundTripAccount.UpdateRound = baseAccount.UpdateRound

			require.Equal(t, baseAccount, roundTripAccount)
		}
	})

	t.Run("basics.AccountData", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 1000; i++ {
			randObj, _ := protocol.RandomizeObject(&baseAccountData{})
			baseAccount := *randObj.(*baseAccountData)

			basicsAccount := baseAccount.GetAccountData()
			var roundTripAccount baseAccountData
			roundTripAccount.SetAccountData(&basicsAccount)

			// Manually set UpdateRound, since it is lost in GetAccountData
			roundTripAccount.UpdateRound = baseAccount.UpdateRound

			// Manually set resources, since resource information is lost in GetAccountData
			roundTripAccount.TotalAssetParams = baseAccount.TotalAssetParams
			roundTripAccount.TotalAssets = baseAccount.TotalAssets
			roundTripAccount.TotalAppLocalStates = baseAccount.TotalAppLocalStates
			roundTripAccount.TotalAppParams = baseAccount.TotalAppParams

			require.Equal(t, baseAccount, roundTripAccount)
		}
	})
}

// TestBasicsAccountDataRoundtripConversion ensures that basics.AccountData can be converted to
// baseAccountData and back without losing any data. It uses reflection to be sure that this test is
// always up-to-date with new fields.
//
// In other words, this test makes sure any new fields in basics.AccountData also get added to
// baseAccountData.
func TestBasicsAccountDataRoundtripConversion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for i := 0; i < 1000; i++ {
		randObj, _ := protocol.RandomizeObject(&basics.AccountData{})
		basicsAccount := *randObj.(*basics.AccountData)

		var baseAccount baseAccountData
		baseAccount.SetAccountData(&basicsAccount)
		roundTripAccount := baseAccount.GetAccountData()

		// Manually set resources, since GetAccountData doesn't attempt to restore them
		roundTripAccount.AssetParams = basicsAccount.AssetParams
		roundTripAccount.Assets = basicsAccount.Assets
		roundTripAccount.AppLocalStates = basicsAccount.AppLocalStates
		roundTripAccount.AppParams = basicsAccount.AppParams

		require.Equal(t, basicsAccount, roundTripAccount)
		require.Equal(t, uint64(len(roundTripAccount.AssetParams)), baseAccount.TotalAssetParams)
		require.Equal(t, uint64(len(roundTripAccount.Assets)), baseAccount.TotalAssets)
		require.Equal(t, uint64(len(roundTripAccount.AppLocalStates)), baseAccount.TotalAppLocalStates)
		require.Equal(t, uint64(len(roundTripAccount.AppParams)), baseAccount.TotalAppParams)
	}
}

// TestLedgercoreAccountDataRoundtripConversion ensures that ledgercore.AccountData can be converted
// to baseAccountData and back without losing any data. It uses reflection to be sure that no new
// fields are omitted.
//
// In other words, this test makes sure any new fields in ledgercore.AccountData also get added to
// baseAccountData.
func TestLedgercoreAccountDataRoundtripConversion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for i := 0; i < 1000; i++ {
		randObj, _ := protocol.RandomizeObject(&ledgercore.AccountData{})
		ledgercoreAccount := *randObj.(*ledgercore.AccountData)

		var baseAccount baseAccountData
		baseAccount.SetCoreAccountData(&ledgercoreAccount)
		roundTripAccount := baseAccount.GetLedgerCoreAccountData()

		require.Equal(t, ledgercoreAccount, roundTripAccount)
	}
}

func TestBaseAccountDataIsEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)
	positiveTesting := func(t *testing.T) {
		var ba baseAccountData
		require.True(t, ba.IsEmpty())
		for i := 0; i < 20; i++ {
			h := crypto.Hash([]byte{byte(i)})
			rnd := binary.BigEndian.Uint64(h[:])
			ba.UpdateRound = rnd
			require.True(t, ba.IsEmpty())
		}
	}
	var empty baseAccountData
	negativeTesting := func(t *testing.T) {
		for i := 0; i < 10000; i++ {
			randObj, _ := protocol.RandomizeObjectField(&baseAccountData{})
			ba := randObj.(*baseAccountData)
			if *ba == empty || ba.UpdateRound != 0 {
				continue
			}
			require.False(t, ba.IsEmpty(), "base account : %v", ba)
		}
	}
	structureTesting := func(t *testing.T) {
		encoding, err := json.Marshal(&empty)
		zeros32 := "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
		expectedEncoding := `{"Status":0,"MicroAlgos":{"Raw":0},"RewardsBase":0,"RewardedMicroAlgos":{"Raw":0},"AuthAddr":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ","TotalAppSchemaNumUint":0,"TotalAppSchemaNumByteSlice":0,"TotalExtraAppPages":0,"TotalAssetParams":0,"TotalAssets":0,"TotalAppParams":0,"TotalAppLocalStates":0,"TotalBoxes":0,"TotalBoxBytes":0,"VoteID":[` + zeros32 + `],"SelectionID":[` + zeros32 + `],"VoteFirstValid":0,"VoteLastValid":0,"VoteKeyDilution":0,"StateProofID":[` + zeros32 + `,` + zeros32 + `],"UpdateRound":0}`
		require.NoError(t, err)
		require.Equal(t, expectedEncoding, string(encoding))
	}
	t.Run("Positive", positiveTesting)
	t.Run("Negative", negativeTesting)
	t.Run("Structure", structureTesting)

}

func TestBaseOnlineAccountDataIsEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)

	positiveTesting := func(t *testing.T) {
		var ba baseOnlineAccountData
		require.True(t, ba.IsEmpty())
		require.True(t, ba.IsVotingEmpty())
		ba.MicroAlgos.Raw = 100
		require.True(t, ba.IsVotingEmpty())
		ba.RewardsBase = 200
		require.True(t, ba.IsVotingEmpty())
	}
	var empty baseOnlineAccountData
	negativeTesting := func(t *testing.T) {
		for i := 0; i < 10; i++ {
			randObj, _ := protocol.RandomizeObjectField(&baseOnlineAccountData{})
			ba := randObj.(*baseOnlineAccountData)
			if *ba == empty {
				continue
			}
			require.False(t, ba.IsEmpty(), "base account : %v", ba)
			break
		}
		{
			var ba baseOnlineAccountData
			ba.MicroAlgos.Raw = 100
			require.False(t, ba.IsEmpty())
		}
		{
			var ba baseOnlineAccountData
			ba.RewardsBase = 200
			require.False(t, ba.IsEmpty())
		}
	}
	structureTesting := func(t *testing.T) {
		encoding, err := json.Marshal(&empty)
		zeros32 := "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
		expectedEncoding := `{"VoteID":[` + zeros32 + `],"SelectionID":[` + zeros32 + `],"VoteFirstValid":0,"VoteLastValid":0,"VoteKeyDilution":0,"StateProofID":[` + zeros32 + `,` + zeros32 + `],"MicroAlgos":{"Raw":0},"RewardsBase":0}`
		require.NoError(t, err)
		require.Equal(t, expectedEncoding, string(encoding))
	}
	t.Run("Positive", positiveTesting)
	t.Run("Negative", negativeTesting)
	t.Run("Structure", structureTesting)

}

func TestBaseOnlineAccountDataGettersSetters(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	addr := ledgertesting.RandomAddress()
	data := ledgertesting.RandomAccountData(1)
	data.Status = basics.Online
	crypto.RandBytes(data.VoteID[:])
	crypto.RandBytes(data.SelectionID[:])
	crypto.RandBytes(data.StateProofID[:])
	data.VoteFirstValid = basics.Round(crypto.RandUint64())
	data.VoteLastValid = basics.Round(crypto.RandUint64()) // int64 is the max sqlite can store
	data.VoteKeyDilution = crypto.RandUint64()

	var ba baseOnlineAccountData
	ad := ledgercore.ToAccountData(data)
	ba.SetCoreAccountData(&ad)

	require.Equal(t, data.MicroAlgos, ba.MicroAlgos)
	require.Equal(t, data.RewardsBase, ba.RewardsBase)
	require.Equal(t, data.VoteID, ba.VoteID)
	require.Equal(t, data.SelectionID, ba.SelectionID)
	require.Equal(t, data.VoteFirstValid, ba.VoteFirstValid)
	require.Equal(t, data.VoteLastValid, ba.VoteLastValid)
	require.Equal(t, data.VoteKeyDilution, ba.VoteKeyDilution)
	require.Equal(t, data.StateProofID, ba.StateProofID)

	normBalance := basics.NormalizedOnlineAccountBalance(basics.Online, data.RewardsBase, data.MicroAlgos, proto)
	require.Equal(t, normBalance, ba.NormalizedOnlineBalance(proto))
	oa := ba.GetOnlineAccount(addr, normBalance)

	require.Equal(t, addr, oa.Address)
	require.Equal(t, ba.MicroAlgos, oa.MicroAlgos)
	require.Equal(t, ba.RewardsBase, oa.RewardsBase)
	require.Equal(t, normBalance, oa.NormalizedOnlineBalance)
	require.Equal(t, ba.VoteFirstValid, oa.VoteFirstValid)
	require.Equal(t, ba.VoteLastValid, oa.VoteLastValid)
	require.Equal(t, ba.StateProofID, oa.StateProofID)

	rewardsLevel := uint64(1)
	microAlgos, _, _ := basics.WithUpdatedRewards(
		proto, basics.Online, oa.MicroAlgos, basics.MicroAlgos{}, ba.RewardsBase, rewardsLevel,
	)
	oad := ba.GetOnlineAccountData(proto, rewardsLevel)

	require.Equal(t, microAlgos, oad.MicroAlgosWithRewards)
	require.Equal(t, ba.VoteID, oad.VoteID)
	require.Equal(t, ba.SelectionID, oad.SelectionID)
	require.Equal(t, ba.StateProofID, oad.StateProofID)
	require.Equal(t, ba.VoteFirstValid, oad.VoteFirstValid)
	require.Equal(t, ba.VoteLastValid, oad.VoteLastValid)
	require.Equal(t, ba.VoteKeyDilution, oad.VoteKeyDilution)
}

func TestBaseVotingDataGettersSetters(t *testing.T) {
	partitiontest.PartitionTest(t)

	data := ledgertesting.RandomAccountData(1)
	data.Status = basics.Online
	crypto.RandBytes(data.VoteID[:])
	crypto.RandBytes(data.SelectionID[:])
	crypto.RandBytes(data.StateProofID[:])
	data.VoteFirstValid = basics.Round(crypto.RandUint64())
	data.VoteLastValid = basics.Round(crypto.RandUint64()) // int64 is the max sqlite can store
	data.VoteKeyDilution = crypto.RandUint64()

	var bv baseVotingData
	require.True(t, bv.IsEmpty())

	ad := ledgercore.ToAccountData(data)
	bv.SetCoreAccountData(&ad)

	require.False(t, bv.IsEmpty())
	require.Equal(t, data.VoteID, bv.VoteID)
	require.Equal(t, data.SelectionID, bv.SelectionID)
	require.Equal(t, data.VoteFirstValid, bv.VoteFirstValid)
	require.Equal(t, data.VoteLastValid, bv.VoteLastValid)
	require.Equal(t, data.VoteKeyDilution, bv.VoteKeyDilution)
	require.Equal(t, data.StateProofID, bv.StateProofID)
}

func TestBaseOnlineAccountDataReflect(t *testing.T) {
	partitiontest.PartitionTest(t)

	require.Equal(t, 4, reflect.TypeOf(baseOnlineAccountData{}).NumField(), "update all getters and setters for baseOnlineAccountData and change the field count")
}

func TestBaseVotingDataReflect(t *testing.T) {
	partitiontest.PartitionTest(t)

	require.Equal(t, 7, reflect.TypeOf(baseVotingData{}).NumField(), "update all getters and setters for baseVotingData and change the field count")
}

func TestLookupAccountAddressFromAddressID(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	addrs := make([]basics.Address, 100)
	for i := range addrs {
		addrs[i] = ledgertesting.RandomAddress()
	}
	addrsids := make(map[basics.Address]int64)
	err := dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		accountsInitTest(t, tx, make(map[basics.Address]basics.AccountData), protocol.ConsensusCurrentVersion)

		for i := range addrs {
			res, err := tx.ExecContext(ctx, "INSERT INTO accountbase (address, data) VALUES (?, ?)", addrs[i][:], []byte{12, 3, 4})
			if err != nil {
				return err
			}
			rowid, err := res.LastInsertId()
			if err != nil {
				return err
			}
			addrsids[addrs[i]] = rowid
		}
		return nil
	})
	require.NoError(t, err)

	err = dbs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		for addr, addrid := range addrsids {
			retAddr, err := lookupAccountAddressFromAddressID(ctx, tx, addrid)
			if err != nil {
				return err
			}
			if retAddr != addr {
				return fmt.Errorf("mismatching addresses")
			}
		}
		// test fail case:
		retAddr, err := lookupAccountAddressFromAddressID(ctx, tx, -1)

		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("unexpected error : %w", err)
		}
		if !retAddr.IsZero() {
			return fmt.Errorf("unexpected address; should have been empty")
		}
		return nil
	})
	require.NoError(t, err)
}

type mockResourcesKey struct {
	addrid int64
	aidx   basics.CreatableIndex
}
type mockAccountWriter struct {
	// rowid to data
	accounts map[int64]ledgercore.AccountData
	// addr to rowid
	addresses map[basics.Address]int64
	// rowid to addr
	rowids    map[int64]basics.Address
	resources map[mockResourcesKey]ledgercore.AccountResource

	kvStore map[string][]byte

	lastRowid   int64
	availRowIds []int64
}

func makeMockAccountWriter() (m mockAccountWriter) {
	m.accounts = make(map[int64]ledgercore.AccountData)
	m.resources = make(map[mockResourcesKey]ledgercore.AccountResource)
	m.addresses = make(map[basics.Address]int64)
	m.rowids = make(map[int64]basics.Address)
	return
}

func (m mockAccountWriter) clone() (m2 mockAccountWriter) {
	m2.accounts = make(map[int64]ledgercore.AccountData, len(m.accounts))
	m2.resources = make(map[mockResourcesKey]ledgercore.AccountResource, len(m.resources))
	m2.addresses = make(map[basics.Address]int64, len(m.resources))
	m2.rowids = make(map[int64]basics.Address, len(m.rowids))
	for k, v := range m.accounts {
		m2.accounts[k] = v
	}
	for k, v := range m.resources {
		m2.resources[k] = v
	}
	for k, v := range m.addresses {
		m2.addresses[k] = v
	}
	for k, v := range m.rowids {
		m2.rowids[k] = v
	}
	m2.lastRowid = m.lastRowid
	m2.availRowIds = m.availRowIds
	return m2
}

func (m *mockAccountWriter) nextRowid() (rowid int64) {
	if len(m.availRowIds) > 0 {
		rowid = m.availRowIds[len(m.availRowIds)-1]
		m.availRowIds = m.availRowIds[:len(m.availRowIds)-1]
	} else {
		m.lastRowid++
		rowid = m.lastRowid
	}
	return
}

func (m *mockAccountWriter) setAccount(addr basics.Address, data ledgercore.AccountData) {
	var rowid int64
	var ok bool
	if rowid, ok = m.addresses[addr]; !ok {
		rowid = m.nextRowid()
		m.rowids[rowid] = addr
		m.addresses[addr] = rowid
	}
	m.accounts[rowid] = data
}

func (m *mockAccountWriter) setResource(addr basics.Address, cidx basics.CreatableIndex, data ledgercore.AccountResource) error {
	var rowid int64
	var ok bool
	if rowid, ok = m.addresses[addr]; !ok {
		return fmt.Errorf("account %s does not exist", addr.String())
	}
	key := mockResourcesKey{rowid, cidx}
	m.resources[key] = data

	return nil
}

func (m *mockAccountWriter) lookup(addr basics.Address) (pad persistedAccountData, ok bool, err error) {
	rowid, ok := m.addresses[addr]
	if !ok {
		return
	}
	data, ok := m.accounts[rowid]
	if !ok {
		err = fmt.Errorf("not found %s", addr.String())
		return
	}
	pad.accountData.SetCoreAccountData(&data)
	pad.addr = addr
	pad.rowid = rowid
	return
}

func (m *mockAccountWriter) lookupResource(addr basics.Address, cidx basics.CreatableIndex) (prd persistedResourcesData, ok bool, err error) {
	rowid, ok := m.addresses[addr]
	if !ok {
		return
	}
	res, ok := m.resources[mockResourcesKey{rowid, cidx}]
	if !ok {
		err = fmt.Errorf("not found (%s, %d)", addr.String(), cidx)
		return
	}
	if res.AppLocalState != nil {
		prd.data.SetAppLocalState(*res.AppLocalState)
	}
	if res.AppParams != nil {
		prd.data.SetAppParams(*res.AppParams, prd.data.IsHolding())
	}
	if res.AssetHolding != nil {
		prd.data.SetAssetHolding(*res.AssetHolding)
	}
	if res.AssetParams != nil {
		prd.data.SetAssetParams(*res.AssetParams, prd.data.IsHolding())
	}
	prd.addrid = rowid
	prd.aidx = cidx
	return
}

func (m *mockAccountWriter) insertAccount(addr basics.Address, normBalance uint64, data baseAccountData) (rowid int64, err error) {
	rowid, ok := m.addresses[addr]
	if ok {
		err = fmt.Errorf("insertAccount: addr %s, rowid %d: UNIQUE constraint failed", addr.String(), rowid)
		return
	}
	rowid = m.nextRowid()
	m.addresses[addr] = rowid
	m.rowids[rowid] = addr
	m.accounts[rowid] = data.GetLedgerCoreAccountData()
	return
}

func (m *mockAccountWriter) deleteAccount(rowid int64) (rowsAffected int64, err error) {
	var addr basics.Address
	var ok bool
	if addr, ok = m.rowids[rowid]; !ok {
		return 0, nil
	}

	delete(m.addresses, addr)
	delete(m.rowids, rowid)
	delete(m.accounts, rowid)
	m.availRowIds = append(m.availRowIds, rowid)
	return 1, nil
}

func (m *mockAccountWriter) updateAccount(rowid int64, normBalance uint64, data baseAccountData) (rowsAffected int64, err error) {
	if _, ok := m.rowids[rowid]; !ok {
		return 0, fmt.Errorf("updateAccount: not found rowid %d", rowid)
	}
	old, ok := m.accounts[rowid]
	if !ok {
		return 0, fmt.Errorf("updateAccount: not found data for %d", rowid)
	}
	if old == data.GetLedgerCoreAccountData() {
		return 0, nil
	}
	m.accounts[rowid] = data.GetLedgerCoreAccountData()
	return 1, nil
}

func (m *mockAccountWriter) insertResource(addrid int64, aidx basics.CreatableIndex, data resourcesData) (rowid int64, err error) {
	key := mockResourcesKey{addrid, aidx}
	if _, ok := m.resources[key]; ok {
		return 0, fmt.Errorf("insertResource: (%d, %d): UNIQUE constraint failed", addrid, aidx)
	}
	// use persistedResourcesData.AccountResource for conversion
	prd := persistedResourcesData{data: data}
	new := prd.AccountResource()
	m.resources[key] = new
	return 1, nil
}

func (m *mockAccountWriter) deleteResource(addrid int64, aidx basics.CreatableIndex) (rowsAffected int64, err error) {
	key := mockResourcesKey{addrid, aidx}
	if _, ok := m.resources[key]; !ok {
		return 0, nil
	}
	delete(m.resources, key)
	return 1, nil
}

func (m *mockAccountWriter) updateResource(addrid int64, aidx basics.CreatableIndex, data resourcesData) (rowsAffected int64, err error) {
	key := mockResourcesKey{addrid, aidx}
	old, ok := m.resources[key]
	if !ok {
		return 0, fmt.Errorf("updateResource: not found (%d, %d)", addrid, aidx)
	}
	// use persistedResourcesData.AccountResource for conversion
	prd := persistedResourcesData{data: data}
	new := prd.AccountResource()
	if new == old {
		return 0, nil
	}
	m.resources[key] = new
	return 1, nil
}

func (m *mockAccountWriter) upsertKvPair(key string, value []byte) error {
	m.kvStore[key] = value
	return nil
}

func (m *mockAccountWriter) deleteKvPair(key string) error {
	delete(m.kvStore, key)
	return nil
}

func (m *mockAccountWriter) insertCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType, creator []byte) (rowid int64, err error) {
	return 0, fmt.Errorf("insertCreatable: not implemented")
}

func (m *mockAccountWriter) deleteCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType) (rowsAffected int64, err error) {
	return 0, fmt.Errorf("deleteCreatable: not implemented")
}

func (m *mockAccountWriter) close() {
}

func factorial(n int) int {
	res := 1
	for i := 1; i <= n; i++ {
		res = res * i
	}
	return res
}

// permHeap generates all permutations for an integer array from 0 to n-1 inclusive
// uses Heap's non-recursive algorithm
func permHeap(n int) (result [][]int) {
	numResults := factorial(n)
	result = make([][]int, 0, numResults)
	input := make([]int, n)
	for i := 0; i < n; i++ {
		input[i] = i
	}
	temp := make([]int, n)
	copy(temp, input)
	result = append(result, temp)

	c := make([]int, n)

	i := 0
	for i < n {
		if c[i] < i {
			if i%2 == 0 {
				input[0], input[i] = input[i], input[0]
			} else {
				input[c[i]], input[i] = input[i], input[c[i]]
			}
			temp := make([]int, n)
			copy(temp, input)
			result = append(result, temp)
			c[i]++
			i = 0
		} else {
			c[i] = 0
			i++
		}
	}
	return
}

func TestFactorialPerm(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	a.Equal(1, factorial(0))
	a.Equal(1, factorial(1))
	a.Equal(2, factorial(2))
	a.Equal(6, factorial(3))
	a.Equal(120, factorial(5))

	perms := permHeap(5)
	dict := make(map[string]struct{}, len(perms))
	for _, perm := range perms {
		var key string
		for _, i := range perm {
			key += strconv.Itoa(i)
		}
		dict[key] = struct{}{}
	}
	a.Equal(len(perms), len(dict))
}

func compactAccountDeltasPermutations(a *require.Assertions, cad compactAccountDeltas) []compactAccountDeltas {
	a.Empty(cad.misses)

	size := cad.len()
	result := make([]compactAccountDeltas, 0, factorial(size))

	perms := permHeap(size)
	// remap existing deltas to permutated one
	for _, perm := range perms {
		new := compactAccountDeltas{}
		new.cache = make(map[basics.Address]int, size)
		new.deltas = make([]accountDelta, size)
		for i, k := range perm {
			new.deltas[k] = cad.deltas[i]
		}
		for key, i := range cad.cache {
			new.cache[key] = perm[i]
		}
		result = append(result, new)
	}

	// ensure remapping
	for _, new := range result {
		for key, idx := range new.cache {
			d1 := cad.getByIdx(cad.cache[key])
			d2 := new.getByIdx(idx)
			a.Equal(d1, d2)
		}
	}

	return result
}

func compactResourcesDeltasPermutations(a *require.Assertions, crd compactResourcesDeltas) []compactResourcesDeltas {

	size := crd.len()
	result := make([]compactResourcesDeltas, 0, factorial(size))

	perms := permHeap(size)
	// remap existing deltas to permutated one
	for _, perm := range perms {
		new := compactResourcesDeltas{}
		new.cache = make(map[accountCreatable]int, size)
		new.deltas = make([]resourceDelta, size)
		new.misses = make([]int, len(crd.misses))
		for i, k := range perm {
			new.deltas[k] = crd.deltas[i]
		}
		for key, i := range crd.cache {
			new.cache[key] = perm[i]
		}
		copy(new.misses, crd.misses)
		result = append(result, new)
	}

	// ensure remapping
	for _, new := range result {
		for key, idx := range new.cache {
			d1 := crd.getByIdx(crd.cache[key])
			d2 := new.getByIdx(idx)
			a.Equal(d1, d2)
		}
	}

	return result
}

// TestAccountUnorderedUpdates ensures rowid reuse in accountbase does not lead to
// resources insertion problems.
// This test simulates a problem found while testing resources deltas on testnet:
//
// unable to advance tracker db snapshot (16541781-16541801): db op failed:
// addr RGJVDTZIFR7VIHI4QMSA6Y7H3FCHUXIBS5H26UKDGMWHALTMW3ZRGMNX3M addrid 515356, aidx 22045503, err: UNIQUE constraint failed
//
// Investigation shown there was another account YF5GJTPPMOUPU2GRGGVP2PGJTQZWGSWZISFHNIKDJSZ2CDPPWN4KKKYVQE
// opted in into the same app 22045503. During the commit range the following happened:
// at 16541783 YF5 made a payment txn (one acct delta)
// at 16541785 RGJ has been funded and and opted in into app 22045503 (one acct delta, one res delta)
// at 16541788 YF5 address had clear state txn for 22045503, and close out txn for the entire account (one acct delta, one res delta)
// Because YF5 had modifications before RGJ, all its acct deltas were compacted into a single entry before RGJ (delete, create)
// In the same time, the order in resources delta remained the same (opt-in, delete).
// While processing acct deltas (delete, create) SQLite reused on old rowid for new account.
// Then this rowid was discovered as addrid for opt-in operation and the "UNIQUE constraint failed" error happened.
func TestAccountUnorderedUpdates(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	mock := makeMockAccountWriter()
	addr1 := ledgertesting.RandomAddress()
	addr2 := ledgertesting.RandomAddress()
	observer := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(22045503)

	// set a base state: fund couple accounts, create an app and opt-in
	mock.setAccount(observer, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 10000000}, TotalAppParams: 1}})
	err := mock.setResource(observer, basics.CreatableIndex(aidx), ledgercore.AccountResource{AppParams: &basics.AppParams{ApprovalProgram: []byte{1, 2, 3}}})
	a.NoError(err)
	mock.setAccount(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 10000000}, TotalAppLocalStates: 1}})
	err = mock.setResource(addr1, basics.CreatableIndex(aidx), ledgercore.AccountResource{AppLocalState: &basics.AppLocalState{Schema: basics.StateSchema{NumUint: 10}}})
	a.NoError(err)

	updates := make([]ledgercore.AccountDeltas, 4)
	// payment addr1 -> observer
	updates[0].Upsert(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 9000000}, TotalAppLocalStates: 1}})
	updates[0].Upsert(observer, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 11000000}, TotalAppParams: 1}})

	// fund addr2, opt-in
	updates[1].Upsert(observer, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 10000000}, TotalAppParams: 1}})
	updates[1].Upsert(addr2, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAppLocalStates: 1}})
	updates[1].UpsertAppResource(addr2, aidx, ledgercore.AppParamsDelta{}, ledgercore.AppLocalStateDelta{LocalState: &basics.AppLocalState{Schema: basics.StateSchema{NumUint: 10}}})

	// close addr1: delete app, move funds
	updates[2].UpsertAppResource(addr1, aidx, ledgercore.AppParamsDelta{}, ledgercore.AppLocalStateDelta{Deleted: true})
	updates[2].Upsert(observer, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 19000000}, TotalAppParams: 1}})
	updates[2].Upsert(addr1, ledgercore.AccountData{})

	// this is not required but adds one more resource entry and helps in combinations testing
	// update the app
	updates[3].UpsertAppResource(observer, aidx, ledgercore.AppParamsDelta{Params: &basics.AppParams{ApprovalProgram: []byte{4, 5, 6}}}, ledgercore.AppLocalStateDelta{})

	dbRound := basics.Round(16541781)
	latestRound := basics.Round(16541801)

	// we want to have all accounts to be found: addr1, observer existed, and addr2 non-existed
	// this would have compact deltas current and without missing entries
	var baseAccounts lruAccounts
	baseAccounts.init(nil, 100, 80)

	pad, ok, err := mock.lookup(addr1)
	a.NoError(err)
	a.True(ok)
	baseAccounts.write(pad)
	pad, ok, err = mock.lookup(observer)
	a.NoError(err)
	a.True(ok)
	baseAccounts.write(pad)
	baseAccounts.write(persistedAccountData{addr: addr2})

	acctDeltas := makeCompactAccountDeltas(updates, dbRound, false, baseAccounts)
	a.Empty(acctDeltas.misses)
	a.Equal(3, acctDeltas.len())

	// we want to have (addr1, aidx) and (observer, aidx)
	var baseResources lruResources
	baseResources.init(nil, 100, 80)

	prd, ok, err := mock.lookupResource(addr1, basics.CreatableIndex(aidx))
	a.NoError(err)
	a.True(ok)
	baseResources.write(prd, addr1)
	prd, ok, err = mock.lookupResource(observer, basics.CreatableIndex(aidx))
	a.NoError(err)
	a.True(ok)
	baseResources.write(prd, observer)

	resDeltas := makeCompactResourceDeltas(updates, dbRound, false, baseAccounts, baseResources)
	a.Equal(1, len(resDeltas.misses)) // (addr2, aidx) does not exist
	a.Equal(3, resDeltas.len())       // (addr1, aidx), (observer, aidx) found

	acctVariants := compactAccountDeltasPermutations(a, acctDeltas)
	resVariants := compactResourcesDeltasPermutations(a, resDeltas)
	for i, acctVariant := range acctVariants {
		for j, resVariant := range resVariants {
			t.Run(fmt.Sprintf("acct-perm-%d|res-perm-%d", i, j), func(t *testing.T) {
				a := require.New(t)
				mock2 := mock.clone()
				updatedAccounts, updatedResources, updatedKVs, err := accountsNewRoundImpl(
					&mock2, acctVariant, resVariant, nil, nil, config.ConsensusParams{}, latestRound,
				)
				a.NoError(err)
				a.Len(updatedAccounts, 3)
				a.Len(updatedResources, 3)
				a.Empty(updatedKVs)
			})
		}
	}
}

// TestAccountsNewRoundDeletedResourceEntries checks that accountsNewRound
// returns updated entries with empty addrid as an indication of deleted entry
func TestAccountsNewRoundDeletedResourceEntries(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	mock := makeMockAccountWriter()
	addr1 := ledgertesting.RandomAddress()
	addr2 := ledgertesting.RandomAddress()
	observer := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(22045503)

	// set a base state: fund couple accounts, create an app and opt-in
	mock.setAccount(observer, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 10000000}, TotalAppParams: 1}})
	err := mock.setResource(observer, basics.CreatableIndex(aidx), ledgercore.AccountResource{AppParams: &basics.AppParams{ApprovalProgram: []byte{1, 2, 3}}})
	a.NoError(err)
	mock.setAccount(addr1, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 10000000}, TotalAppLocalStates: 1}})
	err = mock.setResource(addr1, basics.CreatableIndex(aidx), ledgercore.AccountResource{AppLocalState: &basics.AppLocalState{Schema: basics.StateSchema{NumUint: 10}}})
	a.NoError(err)

	updates := make([]ledgercore.AccountDeltas, 3)
	// fund addr2, opt-in, delete app, move funds
	updates[0].Upsert(addr2, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, TotalAppLocalStates: 1}})
	updates[0].UpsertAppResource(addr2, aidx, ledgercore.AppParamsDelta{}, ledgercore.AppLocalStateDelta{LocalState: &basics.AppLocalState{Schema: basics.StateSchema{NumUint: 10}}})

	// close addr1: delete app, move funds
	updates[1].UpsertAppResource(addr1, aidx, ledgercore.AppParamsDelta{}, ledgercore.AppLocalStateDelta{Deleted: true})
	updates[1].Upsert(observer, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 20000000}, TotalAppParams: 1}})
	updates[1].Upsert(addr1, ledgercore.AccountData{})

	// close addr2: delete app, move funds
	updates[2].UpsertAppResource(addr2, aidx, ledgercore.AppParamsDelta{}, ledgercore.AppLocalStateDelta{Deleted: true})
	updates[2].Upsert(observer, ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 11000000}, TotalAppParams: 1}})
	updates[2].Upsert(addr2, ledgercore.AccountData{})

	dbRound := basics.Round(1)
	latestRound := basics.Round(10)

	var baseAccounts lruAccounts
	baseAccounts.init(nil, 100, 80)
	var baseResources lruResources
	baseResources.init(nil, 100, 80)

	pad, ok, err := mock.lookup(addr1)
	a.NoError(err)
	a.True(ok)
	baseAccounts.write(pad)
	pad, ok, err = mock.lookup(observer)
	a.NoError(err)
	a.True(ok)
	baseAccounts.write(pad)
	baseAccounts.write(persistedAccountData{addr: addr2}) // put an empty record for addr2 to get rid of lookups

	acctDeltas := makeCompactAccountDeltas(updates, dbRound, false, baseAccounts)
	a.Empty(acctDeltas.misses)
	a.Equal(3, acctDeltas.len())

	// we want to have (addr1, aidx) and (observer, aidx)
	prd, ok, err := mock.lookupResource(addr1, basics.CreatableIndex(aidx))
	a.NoError(err)
	a.True(ok)
	baseResources.write(prd, addr1)
	prd, ok, err = mock.lookupResource(observer, basics.CreatableIndex(aidx))
	a.NoError(err)
	a.True(ok)
	baseResources.write(prd, observer)

	resDeltas := makeCompactResourceDeltas(updates, dbRound, false, baseAccounts, baseResources)
	a.Equal(1, len(resDeltas.misses)) // (addr2, aidx) does not exist
	a.Equal(2, resDeltas.len())       // (addr1, aidx) found

	updatedAccounts, updatedResources, updatedKVs, err := accountsNewRoundImpl(
		&mock, acctDeltas, resDeltas, nil, nil, config.ConsensusParams{}, latestRound,
	)
	a.NoError(err)
	a.Equal(3, len(updatedAccounts))
	a.Equal(2, len(updatedResources))
	a.Equal(0, len(updatedKVs))

	// one deletion entry for pre-existing account addr1, and one entry for in-memory account addr2
	// in base accounts updates and in resources updates
	addressesToCheck := map[basics.Address]bool{addr1: true, addr2: true}
	matches := 0
	for _, upd := range updatedAccounts {
		if addressesToCheck[upd.addr] {
			a.Equal(int64(0), upd.rowid)
			a.Empty(upd.accountData)
			matches++
		}
	}
	a.Equal(len(addressesToCheck), matches)

	for addr := range addressesToCheck {
		upd := updatedResources[addr]
		a.Equal(1, len(upd))
		a.Equal(int64(0), upd[0].addrid)
		a.Equal(basics.CreatableIndex(aidx), upd[0].aidx)
		a.Equal(makeResourcesData(uint64(0)), upd[0].data)
	}
}

func BenchmarkLRUResources(b *testing.B) {
	var baseResources lruResources
	baseResources.init(nil, 1000, 850)

	var data persistedResourcesData
	var has bool
	addrs := make([]basics.Address, 850)
	for i := 0; i < 850; i++ {
		data.data.ApprovalProgram = make([]byte, 8096*4)
		data.aidx = basics.CreatableIndex(1)
		addrBytes := ([]byte(fmt.Sprintf("%d", i)))[:32]
		var addr basics.Address
		for i, b := range addrBytes {
			addr[i] = b
		}
		addrs[i] = addr
		baseResources.write(data, addr)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pos := i % 850
		data, has = baseResources.read(addrs[pos], basics.CreatableIndex(1))
		require.True(b, has)
	}
}

func initBoxDatabase(b *testing.B, totalBoxes, boxSize int) (db.Pair, func(), error) {
	batchCount := 100
	if batchCount > totalBoxes {
		batchCount = 1
	}

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	dbs, fn := dbOpenTest(b, false)
	setDbLogging(b, dbs)
	cleanup := func() {
		cleanupTestDb(dbs, fn, false)
	}

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(b, err)
	_, err = accountsInit(tx, make(map[basics.Address]basics.AccountData), proto)
	require.NoError(b, err)
	err = tx.Commit()
	require.NoError(b, err)
	err = dbs.Wdb.SetSynchronousMode(context.Background(), db.SynchronousModeOff, false)
	require.NoError(b, err)

	cnt := 0
	for batch := 0; batch <= batchCount; batch++ {
		tx, err = dbs.Wdb.Handle.Begin()
		require.NoError(b, err)
		writer, err := makeAccountsSQLWriter(tx, false, false, true, false)
		require.NoError(b, err)
		for boxIdx := 0; boxIdx < totalBoxes/batchCount; boxIdx++ {
			err = writer.upsertKvPair(fmt.Sprintf("%d", cnt), make([]byte, boxSize))
			require.NoError(b, err)
			cnt++
		}

		err = tx.Commit()
		require.NoError(b, err)
		writer.close()
	}
	err = dbs.Wdb.SetSynchronousMode(context.Background(), db.SynchronousModeFull, true)
	return dbs, cleanup, err
}

func BenchmarkBoxDatabaseRead(b *testing.B) {
	getBoxNamePermutation := func(totalBoxes int) []int {
		rand.Seed(time.Now().UnixNano())
		boxNames := make([]int, totalBoxes)
		for i := 0; i < totalBoxes; i++ {
			boxNames[i] = i
		}
		rand.Shuffle(len(boxNames), func(x, y int) { boxNames[x], boxNames[y] = boxNames[y], boxNames[x] })
		return boxNames
	}

	boxCnt := []int{10, 1000, 100000}
	boxSizes := []int{2, 2048, 4 * 8096}
	for _, totalBoxes := range boxCnt {
		for _, boxSize := range boxSizes {
			b.Run(fmt.Sprintf("totalBoxes=%d/boxSize=%d", totalBoxes, boxSize), func(b *testing.B) {
				b.StopTimer()

				dbs, cleanup, err := initBoxDatabase(b, totalBoxes, boxSize)
				require.NoError(b, err)

				boxNames := getBoxNamePermutation(totalBoxes)
				lookupStmt, err := dbs.Wdb.Handle.Prepare("SELECT rnd, value FROM acctrounds LEFT JOIN kvstore ON key = ? WHERE id='acctbase';")
				require.NoError(b, err)
				var v sql.NullString
				for i := 0; i < b.N; i++ {
					var pv persistedKVData
					boxName := boxNames[i%totalBoxes]
					b.StartTimer()
					err = lookupStmt.QueryRow([]byte(fmt.Sprintf("%d", boxName))).Scan(&pv.round, &v)
					b.StopTimer()
					require.NoError(b, err)
					require.True(b, v.Valid)
				}

				cleanup()
			})
		}
	}

	// test caching performance
	lookbacks := []int{1, 32, 256, 2048}
	for _, lookback := range lookbacks {
		for _, boxSize := range boxSizes {
			totalBoxes := 100000

			b.Run(fmt.Sprintf("lookback=%d/boxSize=%d", lookback, boxSize), func(b *testing.B) {
				b.StopTimer()

				dbs, cleanup, err := initBoxDatabase(b, totalBoxes, boxSize)
				require.NoError(b, err)

				boxNames := getBoxNamePermutation(totalBoxes)
				lookupStmt, err := dbs.Wdb.Handle.Prepare("SELECT rnd, value FROM acctrounds LEFT JOIN kvstore ON key = ? WHERE id='acctbase';")
				require.NoError(b, err)
				var v sql.NullString
				for i := 0; i < b.N+lookback; i++ {
					var pv persistedKVData
					boxName := boxNames[i%totalBoxes]
					err = lookupStmt.QueryRow([]byte(fmt.Sprintf("%d", boxName))).Scan(&pv.round, &v)
					require.NoError(b, err)
					require.True(b, v.Valid)

					// benchmark reading the potentially cached value that was read lookback boxes ago
					if i >= lookback {
						boxName = boxNames[(i-lookback)%totalBoxes]
						b.StartTimer()
						err = lookupStmt.QueryRow([]byte(fmt.Sprintf("%d", boxName))).Scan(&pv.round, &v)
						b.StopTimer()
						require.NoError(b, err)
						require.True(b, v.Valid)
					}
				}

				cleanup()
			})
		}
	}
}

// TestAccountTopOnline ensures accountsOnlineTop return a right subset of accounts
// from the history table.
// Start with two online accounts A, B at round 1
// At round 2 make A offline.
// At round 3 make B offline and add a new online account C.
//
// addr | rnd | status
// -----|-----|--------
// A    |  1  |    1
// B    |  1  |    1
// A    |  2  |    0
// B    |  3  |    0
// C    |  3  |    1
//
// Ensure
// - for round 1 A and B returned
// - for round 2 only B returned
// - for round 3 only C returned
// The test also checks accountsDbQueries.lookupOnline
func TestAccountOnlineQueries(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	var accts map[basics.Address]basics.AccountData
	accountsInitTest(t, tx, accts, protocol.ConsensusCurrentVersion)
	totals, err := accountsTotals(context.Background(), tx, false)
	require.NoError(t, err)

	var baseAccounts lruAccounts
	var baseResources lruResources
	var baseOnlineAccounts lruOnlineAccounts
	baseAccounts.init(nil, 100, 80)
	baseResources.init(nil, 100, 80)
	baseOnlineAccounts.init(nil, 100, 80)

	addrA := basics.Address(crypto.Hash([]byte("A")))
	addrB := basics.Address(crypto.Hash([]byte("B")))
	addrC := basics.Address(crypto.Hash([]byte("C")))

	var voteIDA crypto.OneTimeSignatureVerifier
	crypto.RandBytes(voteIDA[:])
	var voteIDB crypto.OneTimeSignatureVerifier
	crypto.RandBytes(voteIDB[:])
	var voteIDC crypto.OneTimeSignatureVerifier
	crypto.RandBytes(voteIDC[:])

	dataA1 := ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{
			MicroAlgos: basics.MicroAlgos{Raw: 100_000_000},
			Status:     basics.Online,
		},
		VotingData: ledgercore.VotingData{
			VoteID: voteIDA,
		},
	}

	dataB1 := ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{
			MicroAlgos: basics.MicroAlgos{Raw: 200_000_000},
			Status:     basics.Online,
		},
		VotingData: ledgercore.VotingData{
			VoteID: voteIDB,
		},
	}

	dataC3 := ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{
			MicroAlgos: basics.MicroAlgos{Raw: 300_000_000},
			Status:     basics.Online,
		},
		VotingData: ledgercore.VotingData{
			VoteID: voteIDC,
		},
	}

	dataA2 := dataA1
	dataA2.Status = basics.Offline
	dataA2.VoteID = crypto.OneTimeSignatureVerifier{}

	dataB2 := dataB1
	dataB2.Status = basics.Offline
	dataB2.VoteID = crypto.OneTimeSignatureVerifier{}

	delta1 := ledgercore.AccountDeltas{}
	delta1.Upsert(addrA, dataA1)
	delta1.Upsert(addrB, dataB1)

	delta2 := ledgercore.AccountDeltas{}
	delta2.Upsert(addrA, dataA2)

	delta3 := ledgercore.AccountDeltas{}
	delta3.Upsert(addrB, dataB2)
	delta3.Upsert(addrC, dataC3)

	addRound := func(rnd basics.Round, updates ledgercore.AccountDeltas) {
		totals = ledgertesting.CalculateNewRoundAccountTotals(t, updates, 0, proto, accts, totals)
		accts = applyPartialDeltas(accts, updates)

		oldBase := rnd - 1
		updatesCnt := makeCompactAccountDeltas([]ledgercore.AccountDeltas{updates}, oldBase, true, baseAccounts)
		updatesOnlineCnt := makeCompactOnlineAccountDeltas([]ledgercore.AccountDeltas{updates}, oldBase, baseOnlineAccounts)

		err = updatesCnt.accountsLoadOld(tx)
		require.NoError(t, err)

		err = updatesOnlineCnt.accountsLoadOld(tx)
		require.NoError(t, err)

		err = accountsPutTotals(tx, totals, false)
		require.NoError(t, err)
		updatedAccts, _, _, err := accountsNewRound(tx, updatesCnt, compactResourcesDeltas{}, nil, nil, proto, rnd)
		require.NoError(t, err)
		require.Equal(t, updatesCnt.len(), len(updatedAccts))

		updatedOnlineAccts, err := onlineAccountsNewRound(tx, updatesOnlineCnt, proto, rnd)
		require.NoError(t, err)
		require.NotEmpty(t, updatedOnlineAccts)

		err = updateAccountsRound(tx, rnd)
		require.NoError(t, err)
	}

	addRound(1, delta1)
	addRound(2, delta2)
	addRound(3, delta3)

	queries, err := onlineAccountsInitDbQueries(tx)
	require.NoError(t, err)

	// check round 1
	rnd := basics.Round(1)
	online, err := accountsOnlineTop(tx, rnd, 0, 10, proto)
	require.NoError(t, err)
	require.Equal(t, 2, len(online))
	require.NotContains(t, online, addrC)

	onlineAcctA, ok := online[addrA]
	require.True(t, ok)
	require.NotNil(t, onlineAcctA)
	require.Equal(t, addrA, onlineAcctA.Address)
	require.Equal(t, dataA1.AccountBaseData.MicroAlgos, onlineAcctA.MicroAlgos)

	onlineAcctB, ok := online[addrB]
	require.True(t, ok)
	require.NotNil(t, onlineAcctB)
	require.Equal(t, addrB, onlineAcctB.Address)
	require.Equal(t, dataB1.AccountBaseData.MicroAlgos, onlineAcctB.MicroAlgos)

	paod, err := queries.lookupOnline(addrA, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrA, paod.addr)
	require.Equal(t, dataA1.AccountBaseData.MicroAlgos, paod.accountData.MicroAlgos)
	require.Equal(t, voteIDA, paod.accountData.VoteID)

	paod, err = queries.lookupOnline(addrB, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrB, paod.addr)
	require.Equal(t, dataB1.AccountBaseData.MicroAlgos, paod.accountData.MicroAlgos)
	require.Equal(t, voteIDB, paod.accountData.VoteID)

	paod, err = queries.lookupOnline(addrC, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrC, paod.addr)
	require.Empty(t, paod.accountData)

	// check round 2
	rnd = basics.Round(2)
	online, err = accountsOnlineTop(tx, rnd, 0, 10, proto)
	require.NoError(t, err)
	require.Equal(t, 1, len(online))
	require.NotContains(t, online, addrA)
	require.NotContains(t, online, addrC)

	onlineAcctB, ok = online[addrB]
	require.True(t, ok)
	require.NotNil(t, onlineAcctB)
	require.Equal(t, addrB, onlineAcctB.Address)
	require.Equal(t, dataB1.AccountBaseData.MicroAlgos, onlineAcctB.MicroAlgos)

	paod, err = queries.lookupOnline(addrA, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrA, paod.addr)
	require.Empty(t, paod.accountData)

	paod, err = queries.lookupOnline(addrB, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrB, paod.addr)
	require.Equal(t, dataB1.AccountBaseData.MicroAlgos, paod.accountData.MicroAlgos)
	require.Equal(t, voteIDB, paod.accountData.VoteID)

	paod, err = queries.lookupOnline(addrC, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrC, paod.addr)
	require.Empty(t, paod.accountData)

	// check round 3
	rnd = basics.Round(3)
	online, err = accountsOnlineTop(tx, rnd, 0, 10, proto)
	require.NoError(t, err)
	require.Equal(t, 1, len(online))
	require.NotContains(t, online, addrA)
	require.NotContains(t, online, addrB)

	onlineAcctC, ok := online[addrC]
	require.True(t, ok)
	require.NotNil(t, onlineAcctC)
	require.Equal(t, addrC, onlineAcctC.Address)
	require.Equal(t, dataC3.AccountBaseData.MicroAlgos, onlineAcctC.MicroAlgos)

	paod, err = queries.lookupOnline(addrA, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrA, paod.addr)
	require.Empty(t, paod.accountData)

	paod, err = queries.lookupOnline(addrB, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrB, paod.addr)
	require.Empty(t, paod.accountData)

	paod, err = queries.lookupOnline(addrC, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrC, paod.addr)
	require.Equal(t, dataC3.AccountBaseData.MicroAlgos, paod.accountData.MicroAlgos)
	require.Equal(t, voteIDC, paod.accountData.VoteID)

	paods, err := onlineAccountsAll(tx, 0)
	require.NoError(t, err)
	require.Equal(t, 5, len(paods))

	// expect:
	//
	// addr | rnd | status
	// -----|-----|--------
	//    B |   1 |      1
	//    B |   3 |      0
	//    C |   3 |      1
	//    A |   1 |      1
	//    A |   2 |      0

	checkAddrB := func() {
		require.Equal(t, int64(2), paods[0].rowid)
		require.Equal(t, basics.Round(1), paods[0].updRound)
		require.Equal(t, addrB, paods[0].addr)
		require.Equal(t, int64(4), paods[1].rowid)
		require.Equal(t, basics.Round(3), paods[1].updRound)
		require.Equal(t, addrB, paods[1].addr)
	}

	checkAddrC := func() {
		require.Equal(t, int64(5), paods[2].rowid)
		require.Equal(t, basics.Round(3), paods[2].updRound)
		require.Equal(t, addrC, paods[2].addr)
	}

	checkAddrA := func() {
		require.Equal(t, int64(1), paods[3].rowid)
		require.Equal(t, basics.Round(1), paods[3].updRound)
		require.Equal(t, addrA, paods[3].addr)
		require.Equal(t, int64(3), paods[4].rowid)
		require.Equal(t, basics.Round(2), paods[4].updRound)
		require.Equal(t, addrA, paods[4].addr)
	}

	checkAddrB()
	checkAddrC()
	checkAddrA()

	paods, err = onlineAccountsAll(tx, 3)
	require.NoError(t, err)
	require.Equal(t, 5, len(paods))
	checkAddrB()
	checkAddrC()
	checkAddrA()

	paods, err = onlineAccountsAll(tx, 2)
	require.NoError(t, err)
	require.Equal(t, 3, len(paods))
	checkAddrB()
	checkAddrC()

	paods, err = onlineAccountsAll(tx, 1)
	require.NoError(t, err)
	require.Equal(t, 2, len(paods))
	checkAddrB()

	paods, rnd, err = queries.lookupOnlineHistory(addrA)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), rnd)
	require.Equal(t, 2, len(paods))
	require.Equal(t, int64(1), paods[0].rowid)
	require.Equal(t, basics.Round(1), paods[0].updRound)
	require.Equal(t, int64(3), paods[1].rowid)
	require.Equal(t, basics.Round(2), paods[1].updRound)

	paods, rnd, err = queries.lookupOnlineHistory(addrB)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), rnd)
	require.Equal(t, 2, len(paods))
	require.Equal(t, int64(2), paods[0].rowid)
	require.Equal(t, basics.Round(1), paods[0].updRound)
	require.Equal(t, int64(4), paods[1].rowid)
	require.Equal(t, basics.Round(3), paods[1].updRound)

	paods, rnd, err = queries.lookupOnlineHistory(addrC)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), rnd)
	require.Equal(t, 1, len(paods))
	require.Equal(t, int64(5), paods[0].rowid)
	require.Equal(t, basics.Round(3), paods[0].updRound)
}

type mockOnlineAccountsWriter struct {
	rowid int64
}

func (w *mockOnlineAccountsWriter) insertOnlineAccount(addr basics.Address, normBalance uint64, data baseOnlineAccountData, updRound uint64, voteLastValid uint64) (rowid int64, err error) {
	w.rowid++
	return w.rowid, nil
}

func (w *mockOnlineAccountsWriter) close() {}

func TestAccountOnlineAccountsNewRound(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	writer := &mockOnlineAccountsWriter{rowid: 100}

	updates := compactOnlineAccountDeltas{}
	addrA := ledgertesting.RandomAddress()
	addrB := ledgertesting.RandomAddress()
	addrC := ledgertesting.RandomAddress()
	addrD := ledgertesting.RandomAddress()
	addrE := ledgertesting.RandomAddress()

	// acct A is empty
	deltaA := onlineAccountDelta{
		address: addrA,
	}
	// acct B is new and offline
	deltaB := onlineAccountDelta{
		address: addrB,
		newAcct: []baseOnlineAccountData{{
			MicroAlgos: basics.MicroAlgos{Raw: 200_000_000},
		}},
		updRound:  []uint64{1},
		newStatus: []basics.Status{basics.Offline},
	}
	// acct C is new and online
	deltaC := onlineAccountDelta{
		address: addrC,
		newAcct: []baseOnlineAccountData{{
			MicroAlgos:     basics.MicroAlgos{Raw: 300_000_000},
			baseVotingData: baseVotingData{VoteFirstValid: 500},
		}},
		newStatus: []basics.Status{basics.Online},
		updRound:  []uint64{2},
	}
	// acct D is old and went offline
	deltaD := onlineAccountDelta{
		address: addrD,
		oldAcct: persistedOnlineAccountData{
			addr: addrD,
			accountData: baseOnlineAccountData{
				MicroAlgos:     basics.MicroAlgos{Raw: 400_000_000},
				baseVotingData: baseVotingData{VoteFirstValid: 500},
			},
			rowid: 1,
		},
		newAcct: []baseOnlineAccountData{{
			MicroAlgos: basics.MicroAlgos{Raw: 400_000_000},
		}},
		newStatus: []basics.Status{basics.Offline},
		updRound:  []uint64{3},
	}

	// acct E is old online
	deltaE := onlineAccountDelta{
		address: addrE,
		oldAcct: persistedOnlineAccountData{
			addr: addrE,
			accountData: baseOnlineAccountData{
				MicroAlgos:     basics.MicroAlgos{Raw: 500_000_000},
				baseVotingData: baseVotingData{VoteFirstValid: 500},
			},
			rowid: 2,
		},
		newAcct: []baseOnlineAccountData{{
			MicroAlgos:     basics.MicroAlgos{Raw: 500_000_000},
			baseVotingData: baseVotingData{VoteFirstValid: 600},
		}},
		newStatus: []basics.Status{basics.Online},
		updRound:  []uint64{4},
	}

	updates.deltas = append(updates.deltas, deltaA, deltaB, deltaC, deltaD, deltaE)
	lastUpdateRound := basics.Round(1)
	updated, err := onlineAccountsNewRoundImpl(writer, updates, proto, lastUpdateRound)
	require.NoError(t, err)

	require.Len(t, updated, 3)
	require.Equal(t, updated[0].addr, addrC)
	require.Equal(t, updated[1].addr, addrD)
	require.Equal(t, updated[2].addr, addrE)

	// check errors: new online with empty voting data
	deltaC.newStatus[0] = basics.Online
	deltaC.newAcct[0].VoteFirstValid = 0
	updates.deltas = []onlineAccountDelta{deltaC}
	_, err = onlineAccountsNewRoundImpl(writer, updates, proto, lastUpdateRound)
	require.Error(t, err)

	// check errors: new non-online with non-empty voting data
	deltaB.newStatus[0] = basics.Offline
	deltaB.newAcct[0].VoteFirstValid = 1
	updates.deltas = []onlineAccountDelta{deltaB}
	_, err = onlineAccountsNewRoundImpl(writer, updates, proto, lastUpdateRound)
	require.Error(t, err)

	// check errors: new online with empty voting data
	deltaD.newStatus[0] = basics.Online
	updates.deltas = []onlineAccountDelta{deltaD}
	_, err = onlineAccountsNewRoundImpl(writer, updates, proto, lastUpdateRound)
	require.Error(t, err)
}

func TestAccountOnlineAccountsNewRoundFlip(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	writer := &mockOnlineAccountsWriter{rowid: 100}

	updates := compactOnlineAccountDeltas{}
	addrA := ledgertesting.RandomAddress()
	addrB := ledgertesting.RandomAddress()
	addrC := ledgertesting.RandomAddress()

	// acct A is new, offline and then online
	deltaA := onlineAccountDelta{
		address: addrA,
		newAcct: []baseOnlineAccountData{
			{
				MicroAlgos: basics.MicroAlgos{Raw: 100_000_000},
			},
			{
				MicroAlgos:     basics.MicroAlgos{Raw: 100_000_000},
				baseVotingData: baseVotingData{VoteFirstValid: 100},
			},
		},
		updRound:  []uint64{1, 2},
		newStatus: []basics.Status{basics.Offline, basics.Online},
	}
	// acct B is new and online and then offline
	deltaB := onlineAccountDelta{
		address: addrB,
		newAcct: []baseOnlineAccountData{
			{
				MicroAlgos:     basics.MicroAlgos{Raw: 200_000_000},
				baseVotingData: baseVotingData{VoteFirstValid: 200},
			},
			{
				MicroAlgos: basics.MicroAlgos{Raw: 200_000_000},
			},
		},
		updRound:  []uint64{3, 4},
		newStatus: []basics.Status{basics.Online, basics.Offline},
	}
	// acct C is old online, then online and then offline
	deltaC := onlineAccountDelta{
		address: addrC,
		oldAcct: persistedOnlineAccountData{
			addr: addrC,
			accountData: baseOnlineAccountData{
				MicroAlgos:     basics.MicroAlgos{Raw: 300_000_000},
				baseVotingData: baseVotingData{VoteFirstValid: 300},
			},
			rowid: 1,
		},
		newAcct: []baseOnlineAccountData{
			{
				MicroAlgos:     basics.MicroAlgos{Raw: 300_000_000},
				baseVotingData: baseVotingData{VoteFirstValid: 301},
			},
			{
				MicroAlgos: basics.MicroAlgos{Raw: 300_000_000},
			},
		},
		newStatus: []basics.Status{basics.Online, basics.Offline},
		updRound:  []uint64{5, 6},
	}

	updates.deltas = append(updates.deltas, deltaA, deltaB, deltaC)
	lastUpdateRound := basics.Round(1)
	updated, err := onlineAccountsNewRoundImpl(writer, updates, proto, lastUpdateRound)
	require.NoError(t, err)

	require.Len(t, updated, 5)
	require.Equal(t, updated[0].addr, addrA)
	require.Equal(t, updated[1].addr, addrB)
	require.Equal(t, updated[2].addr, addrB)
	require.Equal(t, updated[3].addr, addrC)
	require.Equal(t, updated[4].addr, addrC)
}

func TestAccountOnlineRoundParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	var accts map[basics.Address]basics.AccountData
	accountsInitTest(t, tx, accts, protocol.ConsensusCurrentVersion)

	// entry i is for round i+1 since db initialized with entry for round 0
	const maxRounds = 40 // any number
	onlineRoundParams := make([]ledgercore.OnlineRoundParamsData, maxRounds)
	for i := range onlineRoundParams {
		onlineRoundParams[i].OnlineSupply = uint64(i + 1)
		onlineRoundParams[i].CurrentProtocol = protocol.ConsensusCurrentVersion
		onlineRoundParams[i].RewardsLevel = uint64(i + 1)
	}

	err = accountsPutOnlineRoundParams(tx, onlineRoundParams, 1)
	require.NoError(t, err)

	dbOnlineRoundParams, endRound, err := accountsOnlineRoundParams(tx)
	require.NoError(t, err)
	require.Equal(t, maxRounds+1, len(dbOnlineRoundParams)) // +1 comes from init state
	require.Equal(t, onlineRoundParams, dbOnlineRoundParams[1:])
	require.Equal(t, maxRounds, int(endRound))

	err = accountsPruneOnlineRoundParams(tx, 10)
	require.NoError(t, err)

	dbOnlineRoundParams, endRound, err = accountsOnlineRoundParams(tx)
	require.NoError(t, err)
	require.Equal(t, onlineRoundParams[9:], dbOnlineRoundParams)
	require.Equal(t, maxRounds, int(endRound))
}

func TestRowidsToChunkedArgs(t *testing.T) {
	partitiontest.PartitionTest(t)

	res := rowidsToChunkedArgs([]int64{1})
	require.Equal(t, 1, cap(res))
	require.Equal(t, 1, len(res))
	require.Equal(t, 1, cap(res[0]))
	require.Equal(t, 1, len(res[0]))
	require.Equal(t, []interface{}{int64(1)}, res[0])

	input := make([]int64, 999)
	for i := 0; i < len(input); i++ {
		input[i] = int64(i)
	}
	res = rowidsToChunkedArgs(input)
	require.Equal(t, 1, cap(res))
	require.Equal(t, 1, len(res))
	require.Equal(t, 999, cap(res[0]))
	require.Equal(t, 999, len(res[0]))
	for i := 0; i < len(input); i++ {
		require.Equal(t, interface{}(int64(i)), res[0][i])
	}

	input = make([]int64, 1001)
	for i := 0; i < len(input); i++ {
		input[i] = int64(i)
	}
	res = rowidsToChunkedArgs(input)
	require.Equal(t, 2, cap(res))
	require.Equal(t, 2, len(res))
	require.Equal(t, 999, cap(res[0]))
	require.Equal(t, 999, len(res[0]))
	require.Equal(t, 2, cap(res[1]))
	require.Equal(t, 2, len(res[1]))
	for i := 0; i < 999; i++ {
		require.Equal(t, interface{}(int64(i)), res[0][i])
	}
	j := 0
	for i := 999; i < len(input); i++ {
		require.Equal(t, interface{}(int64(i)), res[1][j])
		j++
	}

	input = make([]int64, 2*999)
	for i := 0; i < len(input); i++ {
		input[i] = int64(i)
	}
	res = rowidsToChunkedArgs(input)
	require.Equal(t, 2, cap(res))
	require.Equal(t, 2, len(res))
	require.Equal(t, 999, cap(res[0]))
	require.Equal(t, 999, len(res[0]))
	require.Equal(t, 999, cap(res[1]))
	require.Equal(t, 999, len(res[1]))
	for i := 0; i < 999; i++ {
		require.Equal(t, interface{}(int64(i)), res[0][i])
	}
	j = 0
	for i := 999; i < len(input); i++ {
		require.Equal(t, interface{}(int64(i)), res[1][j])
		j++
	}
}

// TestAccountDBTxTailLoad checks txtailNewRound and loadTxTail delete and load right data
func TestAccountDBTxTailLoad(t *testing.T) {
	partitiontest.PartitionTest(t)

	const inMem = true
	dbs, _ := dbOpenTest(t, inMem)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	err = accountsCreateTxTailTable(context.Background(), tx)
	require.NoError(t, err)

	// insert 1500 rounds and retain past 1001
	startRound := basics.Round(1)
	endRound := basics.Round(1500)
	roundData := make([][]byte, 1500)
	const retainSize = 1001
	for i := startRound; i <= endRound; i++ {
		data := txTailRound{Hdr: bookkeeping.BlockHeader{TimeStamp: int64(i)}}
		roundData[i-1] = protocol.Encode(&data)
	}
	forgetBefore := (endRound + 1).SubSaturate(retainSize)
	err = txtailNewRound(context.Background(), tx, startRound, roundData, forgetBefore)
	require.NoError(t, err)

	data, _, baseRound, err := loadTxTail(context.Background(), tx, endRound)
	require.NoError(t, err)
	require.Len(t, data, retainSize)
	require.Equal(t, basics.Round(endRound-retainSize+1), baseRound) // 500...1500

	for i, entry := range data {
		require.Equal(t, int64(i+int(baseRound)), entry.Hdr.TimeStamp)
	}
}

// TestOnlineAccountsDeletion checks the onlineAccountsDelete preseves online accounts entries
// and deleted only expired offline and online rows
// Round    1   2   3   4   5   6   7
// Acct A  On     Off          On
// Acct B          On              On
// Expectations:
// onlineAccountsDelete(1): A online
// onlineAccountsDelete(2): A online
// onlineAccountsDelete(3): A offline, B online
// etc
func TestOnlineAccountsDeletion(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	var accts map[basics.Address]basics.AccountData
	accountsInitTest(t, tx, accts, protocol.ConsensusCurrentVersion)

	updates := compactOnlineAccountDeltas{}
	addrA := ledgertesting.RandomAddress()
	addrB := ledgertesting.RandomAddress()

	deltaA := onlineAccountDelta{
		address: addrA,
		newAcct: []baseOnlineAccountData{
			{
				MicroAlgos:     basics.MicroAlgos{Raw: 100_000_000},
				baseVotingData: baseVotingData{VoteFirstValid: 100},
			},
			{
				MicroAlgos: basics.MicroAlgos{Raw: 100_000_000},
			},
			{
				MicroAlgos:     basics.MicroAlgos{Raw: 100_000_000},
				baseVotingData: baseVotingData{VoteFirstValid: 600},
			},
		},
		updRound:  []uint64{1, 3, 6},
		newStatus: []basics.Status{basics.Online, basics.Offline, basics.Online},
	}
	// acct B is new and online and then offline
	deltaB := onlineAccountDelta{
		address: addrB,
		newAcct: []baseOnlineAccountData{
			{
				MicroAlgos:     basics.MicroAlgos{Raw: 200_000_000},
				baseVotingData: baseVotingData{VoteFirstValid: 300},
			},
			{
				MicroAlgos:     basics.MicroAlgos{Raw: 200_000_000},
				baseVotingData: baseVotingData{VoteFirstValid: 700},
			},
		},
		updRound:  []uint64{3, 7},
		newStatus: []basics.Status{basics.Online, basics.Online},
	}

	updates.deltas = append(updates.deltas, deltaA, deltaB)
	writer, err := makeOnlineAccountsSQLWriter(tx, updates.len() > 0)
	if err != nil {
		return
	}
	defer writer.close()

	lastUpdateRound := basics.Round(10)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	updated, err := onlineAccountsNewRoundImpl(writer, updates, proto, lastUpdateRound)
	require.NoError(t, err)
	require.Len(t, updated, 5)

	queries, err := onlineAccountsInitDbQueries(tx)
	require.NoError(t, err)

	var count int64
	var history []persistedOnlineAccountData
	var validThrough basics.Round
	for _, rnd := range []basics.Round{1, 2, 3} {
		err = onlineAccountsDelete(tx, rnd)
		require.NoError(t, err)

		err = tx.QueryRow("SELECT COUNT(1) FROM onlineaccounts").Scan(&count)
		require.NoError(t, err)
		require.Equal(t, int64(5), count)

		history, validThrough, err = queries.lookupOnlineHistory(addrA)
		require.NoError(t, err)
		require.Equal(t, basics.Round(0), validThrough) // not set
		require.Len(t, history, 3)
		history, validThrough, err = queries.lookupOnlineHistory(addrB)
		require.NoError(t, err)
		require.Equal(t, basics.Round(0), validThrough)
		require.Len(t, history, 2)
	}

	for _, rnd := range []basics.Round{4, 5, 6, 7} {
		err = onlineAccountsDelete(tx, rnd)
		require.NoError(t, err)

		err = tx.QueryRow("SELECT COUNT(1) FROM onlineaccounts").Scan(&count)
		require.NoError(t, err)
		require.Equal(t, int64(3), count)

		history, validThrough, err = queries.lookupOnlineHistory(addrA)
		require.NoError(t, err)
		require.Equal(t, basics.Round(0), validThrough)
		require.Len(t, history, 1)
		history, validThrough, err = queries.lookupOnlineHistory(addrB)
		require.NoError(t, err)
		require.Equal(t, basics.Round(0), validThrough)
		require.Len(t, history, 2)
	}

	for _, rnd := range []basics.Round{8, 9} {
		err = onlineAccountsDelete(tx, rnd)
		require.NoError(t, err)

		err = tx.QueryRow("SELECT COUNT(1) FROM onlineaccounts").Scan(&count)
		require.NoError(t, err)
		require.Equal(t, int64(2), count)

		history, validThrough, err = queries.lookupOnlineHistory(addrA)
		require.NoError(t, err)
		require.Equal(t, basics.Round(0), validThrough)
		require.Len(t, history, 1)
		history, validThrough, err = queries.lookupOnlineHistory(addrB)
		require.NoError(t, err)
		require.Equal(t, basics.Round(0), validThrough)
		require.Len(t, history, 1)
	}
}

// Test functions operating on catchpointfirststageinfo table.
func TestCatchpointFirstStageInfoTable(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := dbOpenTest(t, true)
	defer dbs.Close()

	ctx := context.Background()

	err := accountsCreateCatchpointFirstStageInfoTable(ctx, dbs.Wdb.Handle)
	require.NoError(t, err)

	for _, round := range []basics.Round{4, 6, 8} {
		info := catchpointFirstStageInfo{
			TotalAccounts: uint64(round) * 10,
		}
		err = insertOrReplaceCatchpointFirstStageInfo(ctx, dbs.Wdb.Handle, round, &info)
		require.NoError(t, err)
	}

	for _, round := range []basics.Round{4, 6, 8} {
		info, exists, err := selectCatchpointFirstStageInfo(ctx, dbs.Rdb.Handle, round)
		require.NoError(t, err)
		require.True(t, exists)

		infoExpected := catchpointFirstStageInfo{
			TotalAccounts: uint64(round) * 10,
		}
		require.Equal(t, infoExpected, info)
	}

	_, exists, err := selectCatchpointFirstStageInfo(ctx, dbs.Rdb.Handle, 7)
	require.NoError(t, err)
	require.False(t, exists)

	rounds, err := selectOldCatchpointFirstStageInfoRounds(ctx, dbs.Rdb.Handle, 6)
	require.NoError(t, err)
	require.Equal(t, []basics.Round{4, 6}, rounds)

	err = deleteOldCatchpointFirstStageInfo(ctx, dbs.Wdb.Handle, 6)
	require.NoError(t, err)

	rounds, err = selectOldCatchpointFirstStageInfoRounds(ctx, dbs.Rdb.Handle, 9)
	require.NoError(t, err)
	require.Equal(t, []basics.Round{8}, rounds)
}

func TestUnfinishedCatchpointsTable(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := dbOpenTest(t, true)
	defer dbs.Close()

	err := accountsCreateUnfinishedCatchpointsTable(
		context.Background(), dbs.Wdb.Handle)
	require.NoError(t, err)

	var d3 crypto.Digest
	rand.Read(d3[:])
	err = insertUnfinishedCatchpoint(context.Background(), dbs.Wdb.Handle, 3, d3)
	require.NoError(t, err)

	var d5 crypto.Digest
	rand.Read(d5[:])
	err = insertUnfinishedCatchpoint(context.Background(), dbs.Wdb.Handle, 5, d5)
	require.NoError(t, err)

	ret, err := selectUnfinishedCatchpoints(context.Background(), dbs.Rdb.Handle)
	require.NoError(t, err)
	expected := []unfinishedCatchpointRecord{
		{
			round:     3,
			blockHash: d3,
		},
		{
			round:     5,
			blockHash: d5,
		},
	}
	require.Equal(t, expected, ret)

	err = deleteUnfinishedCatchpoint(context.Background(), dbs.Wdb.Handle, 3)
	require.NoError(t, err)

	ret, err = selectUnfinishedCatchpoints(context.Background(), dbs.Rdb.Handle)
	require.NoError(t, err)
	expected = []unfinishedCatchpointRecord{
		{
			round:     5,
			blockHash: d5,
		},
	}
	require.Equal(t, expected, ret)
}

func TestRemoveOfflineStateProofID(t *testing.T) {
	partitiontest.PartitionTest(t)

	accts := ledgertesting.RandomAccounts(20, true)
	expectedAccts := make(map[basics.Address]basics.AccountData)
	for addr, acct := range accts {
		rand.Read(acct.StateProofID[:])
		accts[addr] = acct

		expectedAcct := acct
		if acct.Status != basics.Online {
			expectedAcct.StateProofID = merklesignature.Commitment{}
		}
		expectedAccts[addr] = expectedAcct

	}

	buildDB := func(accounts map[basics.Address]basics.AccountData) (db.Pair, *sql.Tx) {
		dbs, _ := dbOpenTest(t, true)
		setDbLogging(t, dbs)

		tx, err := dbs.Wdb.Handle.Begin()
		require.NoError(t, err)

		// this is the same seq as accountsInitTest makes but it stops
		// before the online accounts table creation to generate a trie and commit it
		_, err = accountsInit(tx, accounts, config.Consensus[protocol.ConsensusCurrentVersion])
		require.NoError(t, err)

		err = accountsAddNormalizedBalance(tx, config.Consensus[protocol.ConsensusCurrentVersion])
		require.NoError(t, err)

		err = accountsCreateResourceTable(context.Background(), tx)
		require.NoError(t, err)

		err = performResourceTableMigration(context.Background(), tx, nil)
		require.NoError(t, err)

		return dbs, tx
	}

	dbs, tx := buildDB(accts)
	defer dbs.Close()
	defer tx.Rollback()

	// make second copy of DB to prepare exepected/fixed merkle trie
	expectedDBs, expectedTx := buildDB(expectedAccts)
	defer expectedDBs.Close()
	defer expectedTx.Rollback()

	// create account hashes
	computeRootHash := func(tx *sql.Tx, expected bool) (crypto.Digest, error) {
		rows, err := tx.Query("SELECT address, data FROM accountbase")
		require.NoError(t, err)
		defer rows.Close()

		mc, err := MakeMerkleCommitter(tx, false)
		require.NoError(t, err)
		trie, err := merkletrie.MakeTrie(mc, TrieMemoryConfig)
		require.NoError(t, err)

		var addr basics.Address
		for rows.Next() {
			var addrbuf []byte
			var encodedAcctData []byte
			err = rows.Scan(&addrbuf, &encodedAcctData)
			require.NoError(t, err)
			copy(addr[:], addrbuf)
			var ba baseAccountData
			err = protocol.Decode(encodedAcctData, &ba)
			require.NoError(t, err)
			if expected && ba.Status != basics.Online {
				require.Equal(t, merklesignature.Commitment{}, ba.StateProofID)
			}
			addHash := accountHashBuilderV6(addr, &ba, encodedAcctData)
			added, err := trie.Add(addHash)
			require.NoError(t, err)
			require.True(t, added)
		}
		_, err = trie.Evict(true)
		require.NoError(t, err)
		return trie.RootHash()
	}
	oldRoot, err := computeRootHash(tx, false)
	require.NoError(t, err)
	require.NotEmpty(t, oldRoot)

	expectedRoot, err := computeRootHash(expectedTx, true)
	require.NoError(t, err)
	require.NotEmpty(t, expectedRoot)

	err = accountsCreateOnlineAccountsTable(context.Background(), tx)
	require.NoError(t, err)
	err = performOnlineAccountsTableMigration(context.Background(), tx, nil, nil)
	require.NoError(t, err)

	// get the new hash and ensure it does not match to the old one (data migrated)
	mc, err := MakeMerkleCommitter(tx, false)
	require.NoError(t, err)
	trie, err := merkletrie.MakeTrie(mc, TrieMemoryConfig)
	require.NoError(t, err)

	newRoot, err := trie.RootHash()
	require.NoError(t, err)
	require.NotEmpty(t, newRoot)

	require.NotEqual(t, oldRoot, newRoot)
	require.Equal(t, expectedRoot, newRoot)

	rows, err := tx.Query("SELECT addrid, data FROM accountbase")
	require.NoError(t, err)
	defer rows.Close()

	for rows.Next() {
		var addrid sql.NullInt64
		var encodedAcctData []byte
		err = rows.Scan(&addrid, &encodedAcctData)
		require.NoError(t, err)
		var ba baseAccountData
		err = protocol.Decode(encodedAcctData, &ba)
		require.NoError(t, err)
		if ba.Status != basics.Online {
			require.True(t, ba.StateProofID.IsEmpty())
		}
	}
}

func randomBaseAccountData() baseAccountData {
	vd := baseVotingData{
		VoteFirstValid:  basics.Round(crypto.RandUint64()),
		VoteLastValid:   basics.Round(crypto.RandUint64()),
		VoteKeyDilution: crypto.RandUint64(),
	}
	crypto.RandBytes(vd.VoteID[:])
	crypto.RandBytes(vd.StateProofID[:])
	crypto.RandBytes(vd.SelectionID[:])

	baseAD := baseAccountData{
		Status:                     basics.Online,
		MicroAlgos:                 basics.MicroAlgos{Raw: crypto.RandUint64()},
		RewardsBase:                crypto.RandUint64(),
		RewardedMicroAlgos:         basics.MicroAlgos{Raw: crypto.RandUint64()},
		AuthAddr:                   ledgertesting.RandomAddress(),
		TotalAppSchemaNumUint:      crypto.RandUint64(),
		TotalAppSchemaNumByteSlice: crypto.RandUint64(),
		TotalExtraAppPages:         uint32(crypto.RandUint63() % uint64(math.MaxUint32)),
		TotalAssetParams:           crypto.RandUint64(),
		TotalAssets:                crypto.RandUint64(),
		TotalAppParams:             crypto.RandUint64(),
		TotalAppLocalStates:        crypto.RandUint64(),
		baseVotingData:             vd,
		UpdateRound:                crypto.RandUint64(),
	}

	return baseAD
}

func TestEncodedBaseAccountDataSize(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	baseAD := randomBaseAccountData()
	encoded := baseAD.MarshalMsg(nil)
	require.GreaterOrEqual(t, MaxEncodedBaseAccountDataSize, len(encoded))
}

func makeString(len int) string {
	s := ""
	for i := 0; i < len; i++ {
		s += string(byte(i))
	}
	return s
}

func randomAssetResourceData() resourcesData {
	currentConsensusParams := config.Consensus[protocol.ConsensusCurrentVersion]

	// resourcesData is suiteable for keeping asset params, holding, app params, app local state
	// but only asset + holding or app + local state can appear there
	rdAsset := resourcesData{
		Total:         crypto.RandUint64(),
		Decimals:      uint32(crypto.RandUint63() % uint64(math.MaxUint32)),
		DefaultFrozen: true,
		// MetadataHash
		UnitName:  makeString(currentConsensusParams.MaxAssetUnitNameBytes),
		AssetName: makeString(currentConsensusParams.MaxAssetNameBytes),
		URL:       makeString(currentConsensusParams.MaxAssetURLBytes),
		Manager:   ledgertesting.RandomAddress(),
		Reserve:   ledgertesting.RandomAddress(),
		Freeze:    ledgertesting.RandomAddress(),
		Clawback:  ledgertesting.RandomAddress(),

		Amount: crypto.RandUint64(),
		Frozen: true,
	}
	crypto.RandBytes(rdAsset.MetadataHash[:])

	return rdAsset
}

func randomAppResourceData() resourcesData {
	currentConsensusParams := config.Consensus[protocol.ConsensusCurrentVersion]

	rdApp := resourcesData{

		SchemaNumUint:      crypto.RandUint64(),
		SchemaNumByteSlice: crypto.RandUint64(),
		// KeyValue

		// ApprovalProgram
		// ClearStateProgram
		// GlobalState
		LocalStateSchemaNumUint:       crypto.RandUint64(),
		LocalStateSchemaNumByteSlice:  crypto.RandUint64(),
		GlobalStateSchemaNumUint:      crypto.RandUint64(),
		GlobalStateSchemaNumByteSlice: crypto.RandUint64(),
		ExtraProgramPages:             uint32(crypto.RandUint63() % uint64(math.MaxUint32)),

		ResourceFlags: 255,
		UpdateRound:   crypto.RandUint64(),
	}

	// MaxAvailableAppProgramLen is conbined size of approval and clear state since it is bound by proto.MaxAppTotalProgramLen
	rdApp.ApprovalProgram = make([]byte, config.MaxAvailableAppProgramLen/2)
	crypto.RandBytes(rdApp.ApprovalProgram)
	rdApp.ClearStateProgram = make([]byte, config.MaxAvailableAppProgramLen/2)
	crypto.RandBytes(rdApp.ClearStateProgram)

	maxGlobalState := make(basics.TealKeyValue, currentConsensusParams.MaxGlobalSchemaEntries)
	for globalKey := uint64(0); globalKey < currentConsensusParams.MaxGlobalSchemaEntries; globalKey++ {
		prefix := fmt.Sprintf("%d|", globalKey)
		padding := makeString(currentConsensusParams.MaxAppKeyLen - len(prefix))
		maxKey := prefix + padding
		maxValue := basics.TealValue{
			Type:  basics.TealBytesType,
			Bytes: makeString(currentConsensusParams.MaxAppSumKeyValueLens - len(maxKey)),
		}
		maxGlobalState[maxKey] = maxValue
	}

	maxLocalState := make(basics.TealKeyValue, currentConsensusParams.MaxLocalSchemaEntries)
	for localKey := uint64(0); localKey < currentConsensusParams.MaxLocalSchemaEntries; localKey++ {
		prefix := fmt.Sprintf("%d|", localKey)
		padding := makeString(currentConsensusParams.MaxAppKeyLen - len(prefix))
		maxKey := prefix + padding
		maxValue := basics.TealValue{
			Type:  basics.TealBytesType,
			Bytes: makeString(currentConsensusParams.MaxAppSumKeyValueLens - len(maxKey)),
		}
		maxLocalState[maxKey] = maxValue
	}

	rdApp.GlobalState = maxGlobalState
	rdApp.KeyValue = maxLocalState

	return rdApp
}

func TestEncodedBaseResourceSize(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// resourcesData is suiteable for keeping asset params, holding, app params, app local state
	// but only asset + holding or app + local state can appear there
	rdAsset := randomAssetResourceData()
	rdApp := randomAppResourceData()

	encodedAsset := rdAsset.MarshalMsg(nil)
	encodedApp := rdApp.MarshalMsg(nil)

	require.Less(t, len(encodedAsset), len(encodedApp))
	require.GreaterOrEqual(t, MaxEncodedBaseResourceDataSize, len(encodedApp))
}
