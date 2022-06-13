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
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

func accountsInitTest(tb testing.TB, tx *sql.Tx, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool) {
	newDB, err := accountsInit(tx, initAccounts, proto)
	require.NoError(tb, err)

	err = accountsAddNormalizedBalance(tx, proto)
	require.NoError(tb, err)

	err = accountsCreateResourceTable(context.Background(), tx)
	require.NoError(tb, err)

	err = performResourceTableMigration(context.Background(), tx, nil)
	require.NoError(tb, err)

	return newDB
}

func checkAccounts(t *testing.T, tx *sql.Tx, rnd basics.Round, accts map[basics.Address]basics.AccountData) {
	r, err := accountsRound(tx)
	require.NoError(t, err)
	require.Equal(t, r, rnd)

	aq, err := accountsInitDbQueries(tx, tx)
	require.NoError(t, err)
	defer aq.close()

	var totalOnline, totalOffline, totalNotPart uint64

	for addr, data := range accts {
		expected := ledgercore.ToAccountData(data)
		pad, err := aq.lookup(addr)
		require.NoError(t, err)
		d := pad.accountData.GetLedgerCoreAccountData()
		require.Equal(t, d, expected)

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

	for i := 0; i < len(onlineAccounts); i++ {
		dbtop, err := accountsOnlineTop(tx, 0, uint64(i), proto)
		require.NoError(t, err)
		require.Equal(t, i, len(dbtop))

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
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	accts := ledgertesting.RandomAccounts(20, true)
	newDB := accountsInitTest(t, tx, accts, proto)
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
	accountsInitTest(t, tx, accts, proto)
	checkAccounts(t, tx, 0, accts)
	totals, err := accountsTotals(tx, false)
	require.NoError(t, err)

	// used to determine how many creatables element will be in the test per iteration
	numElementsPerSegment := 10

	// lastCreatableID stores asset or app max used index to get rid of conflicts
	lastCreatableID := crypto.RandUint64() % 512
	ctbsList, randomCtbs := randomCreatables(numElementsPerSegment)
	expectedDbImage := make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
	var baseAccounts lruAccounts
	var baseResources lruResources
	var newacctsTotals map[basics.Address]ledgercore.AccountData
	baseAccounts.init(nil, 100, 80)
	baseResources.init(nil, 100, 80)
	for i := 1; i < 10; i++ {
		var updates ledgercore.AccountDeltas
		updates, newacctsTotals, _, lastCreatableID = ledgertesting.RandomDeltasFull(20, accts, 0, lastCreatableID)
		totals = ledgertesting.CalculateNewRoundAccountTotals(t, updates, 0, proto, accts, totals)
		accts = applyPartialDeltas(accts, updates)
		ctbsWithDeletes := randomCreatableSampling(i, ctbsList, randomCtbs,
			expectedDbImage, numElementsPerSegment)

		updatesCnt := makeCompactAccountDeltas([]ledgercore.AccountDeltas{updates}, basics.Round(i), true, baseAccounts)
		resourceUpdatesCnt := makeCompactResourceDeltas([]ledgercore.AccountDeltas{updates}, basics.Round(i), true, baseAccounts, baseResources)

		err = updatesCnt.accountsLoadOld(tx)
		require.NoError(t, err)

		knownAddresses := make(map[basics.Address]int64)
		for _, delta := range updatesCnt.deltas {
			knownAddresses[delta.oldAcct.addr] = delta.oldAcct.rowid
		}

		err = resourceUpdatesCnt.resourcesLoadOld(tx, knownAddresses)
		require.NoError(t, err)

		err = accountsPutTotals(tx, totals, false)
		require.NoError(t, err)
		updatedAccts, updatesResources, err := accountsNewRound(tx, updatesCnt, resourceUpdatesCnt, nil, ctbsWithDeletes, proto, basics.Round(i))
		require.NoError(t, err)
		require.Equal(t, updatesCnt.len(), len(updatedAccts))
		numResUpdates := 0
		for _, rs := range updatesResources {
			numResUpdates += len(rs)
		}
		require.Equal(t, resourceUpdatesCnt.len(), numResUpdates)
		err = updateAccountsRound(tx, basics.Round(i))
		require.NoError(t, err)

		checkAccounts(t, tx, basics.Round(i), accts)
		checkCreatables(t, tx, i, expectedDbImage)
	}

	// test the accounts totals
	var updates ledgercore.AccountDeltas
	for addr, acctData := range newacctsTotals {
		updates.Upsert(addr, acctData)
	}

	expectedTotals := ledgertesting.CalculateNewRoundAccountTotals(t, updates, 0, proto, nil, ledgercore.AccountTotals{})
	actualTotals, err := accountsTotals(tx, false)
	require.NoError(t, err)
	require.Equal(t, expectedTotals, actualTotals)

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
		accountsInitTest(t, tx, accts, proto)
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

			updatedAccts, updatesResources, err := accountsNewRound(tx, outAccountDeltas, outResourcesDeltas, nil, nil, proto, basics.Round(lastRound))
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
		})
	}
}

func TestAccountStorageWithStateProofID(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	accts := ledgertesting.RandomAccounts(20, false)
	_ = accountsInitTest(t, tx, accts, proto)
	checkAccounts(t, tx, 0, accts)
	require.True(t, allAccountsHaveStateProofPKs(accts))
}

func allAccountsHaveStateProofPKs(accts map[basics.Address]basics.AccountData) bool {
	for _, data := range accts {
		if data.StateProofID.IsEmpty() {
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
	crypto.RandBytes(stateProofID[:])
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
			StateProofID:       stateProofID,
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
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	dbs, fn := dbOpenTest(b, inMemory)
	setDbLogging(b, dbs)
	defer cleanupTestDb(dbs, fn, inMemory)

	accounts := benchmarkInitBalances(b, b.N, dbs, proto)

	qs, err := accountsInitDbQueries(dbs.Rdb.Handle, dbs.Wdb.Handle)
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
	crypto.RandBytes(stateProofID[:])

	err := dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		accountsInitTest(t, tx, make(map[basics.Address]basics.AccountData), config.Consensus[protocol.ConsensusCurrentVersion])

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
				StateProofID:       stateProofID,
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
		accountsInitTest(t, tx, make(map[basics.Address]basics.AccountData), config.Consensus[protocol.ConsensusCurrentVersion])
		return nil
	})
	require.NoError(t, err)
	qs, err := accountsInitDbQueries(dbs.Rdb.Handle, dbs.Wdb.Handle)
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
		var balances catchpointFileBalancesChunkV6
		balances.Balances = make([]encodedBalanceRecordV6, chunkSize)
		for i := uint64(0); i < chunkSize; i++ {
			var randomAccount encodedBalanceRecordV6
			accountData := baseAccountData{RewardsBase: accountsLoaded + i}
			accountData.MicroAlgos.Raw = crypto.RandUint63()
			randomAccount.AccountData = protocol.Encode(&accountData)
			crypto.RandBytes(randomAccount.Address[:])
			if ascendingOrder {
				binary.LittleEndian.PutUint64(randomAccount.Address[:], accountsLoaded+i)
			}
			balances.Balances[i] = randomAccount
		}
		balanceLoopDuration := time.Since(balancesLoopStart)
		last64KAccountCreationTime += balanceLoopDuration
		accountsGenerationDuration += balanceLoopDuration

		normalizedAccountBalances, err := prepareNormalizedBalancesV6(balances.Balances, proto)
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
	a.False(rd.IsEmptyAppFields())
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
	a.False(rd.IsEmptyAppFields())
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
	a.False(rd.IsEmptyAppFields())
	a.False(rd.IsEmpty())

	// 8. both do not exist
	rd = makeResourcesData(0)
	a.False(rd.IsApp())
	a.False(rd.IsOwning())
	a.False(rd.IsHolding())
	a.True(rd.IsEmptyAppFields())
	a.True(rd.IsEmpty())

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
		expectedEncoding := `{"Status":0,"MicroAlgos":{"Raw":0},"RewardsBase":0,"RewardedMicroAlgos":{"Raw":0},"AuthAddr":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ","TotalAppSchemaNumUint":0,"TotalAppSchemaNumByteSlice":0,"TotalExtraAppPages":0,"TotalAssetParams":0,"TotalAssets":0,"TotalAppParams":0,"TotalAppLocalStates":0,"VoteID":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"SelectionID":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"VoteFirstValid":0,"VoteLastValid":0,"VoteKeyDilution":0,"StateProofID":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"UpdateRound":0}`
		require.NoError(t, err)
		require.Equal(t, expectedEncoding, string(encoding))
	}
	t.Run("Positive", positiveTesting)
	t.Run("Negative", negativeTesting)
	t.Run("Structure", structureTesting)

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
		accountsInitTest(t, tx, make(map[basics.Address]basics.AccountData), config.Consensus[protocol.ConsensusCurrentVersion])

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

	kvStore map[string]string

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

func (m *mockAccountWriter) upsertKvPair(key string, value string) error {
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
				updatedAccounts, updatedResources, err := accountsNewRoundImpl(
					&mock2, acctVariant, resVariant, nil, nil, config.ConsensusParams{}, latestRound,
				)
				a.NoError(err)
				a.Equal(3, len(updatedAccounts))
				a.Equal(3, len(updatedResources))
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

	updatedAccounts, updatedResources, err := accountsNewRoundImpl(
		&mock, acctDeltas, resDeltas, nil, nil, config.ConsensusParams{}, latestRound,
	)
	a.NoError(err)
	a.Equal(3, len(updatedAccounts))
	a.Equal(2, len(updatedResources))

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
