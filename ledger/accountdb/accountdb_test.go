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

package accountdb

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
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
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

	err = performOnlineAccountsTableMigration(context.Background(), tx, nil)
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

	return newDB
}

func checkAccounts(t *testing.T, tx *sql.Tx, rnd basics.Round, accts map[basics.Address]basics.AccountData) {
	r, err := AccountsRound(tx)
	require.NoError(t, err)
	require.Equal(t, r, rnd)

	aq, err := AccountsInitDbQueries(tx)
	require.NoError(t, err)
	defer aq.Close()

	var totalOnline, totalOffline, totalNotPart uint64

	for addr, data := range accts {
		expected := ledgercore.ToAccountData(data)
		pad, err := aq.Lookup(addr)
		require.NoError(t, err)
		d := pad.AccountData.GetLedgerCoreAccountData()
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

	totals, err := AccountsTotals(context.Background(), tx, false)
	require.NoError(t, err)
	require.Equal(t, totalOnline, totals.Online.Money.Raw, "mismatching total online money")
	require.Equal(t, totalOffline, totals.Offline.Money.Raw)
	require.Equal(t, totalNotPart, totals.NotParticipating.Money.Raw)
	require.Equal(t, totalOnline+totalOffline, totals.Participating().Raw)
	require.Equal(t, totalOnline+totalOffline+totalNotPart, totals.All().Raw)

	d, err := aq.Lookup(ledgertesting.RandomAddress())
	require.NoError(t, err)
	require.Equal(t, rnd, d.Round)
	require.Equal(t, d.AccountData, BaseAccountData{})

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	onlineAccounts := make(map[basics.Address]*ledgercore.OnlineAccount)
	for addr, data := range accts {
		if data.Status == basics.Online {
			ad := ledgercore.ToAccountData(data)
			onlineAccounts[addr] = AccountDataToOnline(addr, &ad, proto)
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
		dbtop, err := AccountsOnlineTop(tx, rnd, 0, uint64(i), proto)
		require.NoError(t, err)
		require.Equal(t, i, len(dbtop))

		for j := 0; j < i; j++ {
			_, ok := dbtop[testtop[j].Address]
			require.True(t, ok)
		}
	}

	top, err := AccountsOnlineTop(tx, rnd, 0, uint64(len(onlineAccounts)+1), proto)
	require.NoError(t, err)
	require.Equal(t, len(top), len(onlineAccounts))
}

func TestAccountDBInit(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs, _ := ledgertesting.DbOpenTest(t, true)
	ledgertesting.SetDbLogging(t, dbs)
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

func TestAccountDBRound(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs, _ := ledgertesting.DbOpenTest(t, true)
	ledgertesting.SetDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	accts := ledgertesting.RandomAccounts(20, true)
	accountsInitTest(t, tx, accts, protocol.ConsensusCurrentVersion)
	checkAccounts(t, tx, 0, accts)
	totals, err := AccountsTotals(context.Background(), tx, false)
	require.NoError(t, err)
	expectedOnlineRoundParams, endRound, err := AccountsOnlineRoundParams(tx)
	require.NoError(t, err)
	require.Equal(t, 1, len(expectedOnlineRoundParams))
	require.Equal(t, 0, int(endRound))

	// used to determine how many creatables element will be in the test per iteration
	numElementsPerSegment := 10

	// lastCreatableID stores asset or app max used Index to get rid of conflicts
	lastCreatableID := basics.CreatableIndex(crypto.RandUint64() % 512)
	ctbsList, randomCtbs := ledgertesting.RandomCreatables(numElementsPerSegment)
	expectedDbImage := make(map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
	var baseAccounts LRUAccounts
	var baseResources LRUResources
	var baseOnlineAccounts LRUOnlineAccounts
	var newacctsTotals map[basics.Address]ledgercore.AccountData
	baseAccounts.Init(nil, 100, 80)
	baseResources.Init(nil, 100, 80)
	baseOnlineAccounts.Init(nil, 100, 80)
	for i := 1; i < 10; i++ {
		var updates ledgercore.AccountDeltas
		updates, newacctsTotals, _ = ledgertesting.RandomDeltasFull(20, accts, 0, &lastCreatableID)
		totals = ledgertesting.CalculateNewRoundAccountTotals(t, updates, 0, proto, accts, totals)
		accts = ledgertesting.ApplyPartialDeltas(accts, updates)
		ctbsWithDeletes := ledgertesting.RandomCreatableSampling(i, ctbsList, randomCtbs,
			expectedDbImage, numElementsPerSegment)

		oldBase := i - 1
		updatesCnt := MakeCompactAccountDeltas([]ledgercore.AccountDeltas{updates}, basics.Round(oldBase), true, baseAccounts)
		resourceUpdatesCnt := MakeCompactResourceDeltas([]ledgercore.AccountDeltas{updates}, basics.Round(oldBase), true, baseAccounts, baseResources)
		updatesOnlineCnt := MakeCompactOnlineAccountDeltas([]ledgercore.AccountDeltas{updates}, basics.Round(oldBase), baseOnlineAccounts)

		err = updatesCnt.AccountsLoadOld(tx)
		require.NoError(t, err)

		err = updatesOnlineCnt.AccountsLoadOld(tx)
		require.NoError(t, err)

		knownAddresses := make(map[basics.Address]int64)
		for _, delta := range updatesCnt.Deltas {
			knownAddresses[delta.OldAcct.Addr] = delta.OldAcct.Rowid
		}

		err = resourceUpdatesCnt.ResourcesLoadOld(tx, knownAddresses)
		require.NoError(t, err)

		err = AccountsPutTotals(tx, totals, false)
		require.NoError(t, err)
		onlineRoundParams := ledgercore.OnlineRoundParamsData{RewardsLevel: totals.RewardsLevel, OnlineSupply: totals.Online.Money.Raw, CurrentProtocol: protocol.ConsensusCurrentVersion}
		err = AccountsPutOnlineRoundParams(tx, []ledgercore.OnlineRoundParamsData{onlineRoundParams}, basics.Round(i))
		require.NoError(t, err)
		expectedOnlineRoundParams = append(expectedOnlineRoundParams, onlineRoundParams)

		updatedAccts, updatesResources, err := AccountsNewRound(tx, updatesCnt, resourceUpdatesCnt, ctbsWithDeletes, proto, basics.Round(i))
		require.NoError(t, err)
		require.Equal(t, updatesCnt.Len(), len(updatedAccts))
		numResUpdates := 0
		for _, rs := range updatesResources {
			numResUpdates += len(rs)
		}
		require.Equal(t, resourceUpdatesCnt.Len(), numResUpdates)

		updatedOnlineAccts, err := OnlineAccountsNewRound(tx, updatesOnlineCnt, proto, basics.Round(i))
		require.NoError(t, err)

		err = UpdateAccountsRound(tx, basics.Round(i))
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
	actualTotals, err := AccountsTotals(context.Background(), tx, false)
	require.NoError(t, err)
	require.Equal(t, expectedTotals, actualTotals)

	actualOnlineRoundParams, endRound, err := AccountsOnlineRoundParams(tx)
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

		dbs, _ := ledgertesting.DbOpenTest(t, true)
		ledgertesting.SetDbLogging(t, dbs)
		defer dbs.Close()

		tx, err := dbs.Wdb.Handle.Begin()
		require.NoError(t, err)
		defer tx.Rollback()

		accts := ledgertesting.RandomAccounts(1, true)
		accountsInitTest(t, tx, accts, protocol.ConsensusCurrentVersion)
		addr := ledgertesting.RandomAddress()

		// lastCreatableID stores asset or app max used Index to get rid of conflicts
		var baseAccounts LRUAccounts
		var baseResources LRUResources
		baseAccounts.Init(nil, 100, 80)
		baseResources.Init(nil, 100, 80)

		t.Run(fmt.Sprintf("test%d", i), func(t *testing.T) {

			accountDeltas, numAcctDeltas, numResDeltas := test(addr)
			lastRound := uint64(len(accountDeltas) + 1)

			outAccountDeltas := MakeCompactAccountDeltas(accountDeltas, basics.Round(1), true, baseAccounts)
			require.Equal(t, 1, len(outAccountDeltas.Deltas))
			require.Equal(t, AccountDelta{NewAcct: BaseAccountData{UpdateRound: lastRound}, NAcctDeltas: numAcctDeltas, Address: addr}, outAccountDeltas.Deltas[0])
			require.Equal(t, 1, len(outAccountDeltas.misses))

			outResourcesDeltas := MakeCompactResourceDeltas(accountDeltas, basics.Round(1), true, baseAccounts, baseResources)
			require.Equal(t, 1, len(outResourcesDeltas.deltas))
			require.Equal(t,
				ResourceDelta{
					OldResource: PersistedResourcesData{Aidx: 100}, NewResource: makeResourcesData(lastRound - 1),
					NAcctDeltas: numResDeltas, Address: addr,
				},
				outResourcesDeltas.deltas[0],
			)
			require.Equal(t, 1, len(outAccountDeltas.misses))

			err = outAccountDeltas.AccountsLoadOld(tx)
			require.NoError(t, err)

			knownAddresses := make(map[basics.Address]int64)
			for _, delta := range outAccountDeltas.Deltas {
				knownAddresses[delta.OldAcct.Addr] = delta.OldAcct.Rowid
			}

			err = outResourcesDeltas.ResourcesLoadOld(tx, knownAddresses)
			require.NoError(t, err)

			updatedAccts, updatesResources, err := AccountsNewRound(tx, outAccountDeltas, outResourcesDeltas, nil, proto, basics.Round(lastRound))
			require.NoError(t, err)
			require.Equal(t, 1, len(updatedAccts)) // we store empty even for deleted accounts
			require.Equal(t,
				PersistedAccountData{Addr: addr, Round: basics.Round(lastRound)},
				updatedAccts[0],
			)

			require.Equal(t, 1, len(updatesResources[addr])) // we store empty even for deleted resources
			require.Equal(t,
				PersistedResourcesData{Addrid: 0, Aidx: 100, Data: makeResourcesData(0), Round: basics.Round(lastRound)},
				updatesResources[addr][0],
			)
		})
	}
}

func TestAccountStorageWithStateProofID(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := ledgertesting.DbOpenTest(t, true)
	ledgertesting.SetDbLogging(t, dbs)
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
	dbs, fn := ledgertesting.DbOpenTest(b, inMemory)
	ledgertesting.SetDbLogging(b, dbs)
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
	dbs, fn := ledgertesting.DbOpenTest(b, inMemory)
	ledgertesting.SetDbLogging(b, dbs)
	defer cleanupTestDb(dbs, fn, inMemory)

	accounts := benchmarkInitBalances(b, b.N, dbs, protocol.ConsensusCurrentVersion)

	qs, err := AccountsInitDbQueries(dbs.Rdb.Handle)
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
		_, err = qs.Lookup(addr)
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
		dbs, fn := ledgertesting.DbOpenTest(b, false)
		ledgertesting.SetDbLogging(b, dbs)
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
			replaceStmt, err := tx.Prepare("INSERT INTO accountbase (Address, normalizedonlinebalance, data) VALUES (?, ?, ?)")
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
		rows, err := tx.Query("SELECT rowid, Address FROM accountbase")
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
		preparedUpdate, err := tx.Prepare("UPDATE accountbase SET data = ? WHERE Address = ?")
		require.NoError(b, err)
		defer preparedUpdate.Close()
		// updates accounts by Address
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
		// updates accounts by Address
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
	dbs, _ := ledgertesting.DbOpenTest(t, true)
	ledgertesting.SetDbLogging(t, dbs)
	defer dbs.Close()

	secrets := crypto.GenerateOneTimeSignatureSecrets(15, 500)
	pubVrfKey, _ := crypto.VrfKeygenFromSeed([32]byte{0, 1, 2, 3})
	var stateProofID merklesignature.Verifier
	crypto.RandBytes(stateProofID[:])

	err := dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		accountsInitTest(t, tx, make(map[basics.Address]basics.AccountData), protocol.ConsensusCurrentVersion)

		for _, oldAccData := range oldEncodedAccountsData {
			addr := ledgertesting.RandomAddress()
			_, err = tx.ExecContext(ctx, "INSERT INTO accountbase (Address, data) VALUES (?, ?)", addr[:], oldAccData)
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

			_, err = tx.ExecContext(ctx, "INSERT INTO accountbase (Address, data) VALUES (?, ?)", addr[:], protocol.Encode(&accData))
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

	dbs, _ := ledgertesting.DbOpenTest(t, true)
	ledgertesting.SetDbLogging(t, dbs)
	defer dbs.Close()

	err := dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		accountsInitTest(t, tx, make(map[basics.Address]basics.AccountData), protocol.ConsensusCurrentVersion)
		return nil
	})
	require.NoError(t, err)
	qs, err := AccountsInitDbQueries(dbs.Rdb.Handle)
	require.NoError(t, err)
	require.NotNil(t, qs.listCreatablesStmt)
	qs.Close()
	require.Nil(t, qs.listCreatablesStmt)
	qs.Close()
	require.Nil(t, qs.listCreatablesStmt)
}

// upsert updates existing or inserts a new entry
func (a *CompactResourcesDeltas) upsert(delta ResourceDelta) {
	if idx, exist := a.cache[ledgercore.AccountCreatable{Address: delta.Address, Index: delta.OldResource.Aidx}]; exist {
		a.deltas[idx] = delta
		return
	}
	a.insert(delta)
}

// upsertOld updates existing or inserts a new partial entry with only old field filled
func (a *CompactAccountDeltas) upsertOld(old PersistedAccountData) {
	addr := old.Addr
	if idx, exist := a.cache[addr]; exist {
		a.Deltas[idx].OldAcct = old
		return
	}
	a.insert(AccountDelta{OldAcct: old, Address: old.Addr})
}

// upsert updates existing or inserts a new entry
func (a *CompactAccountDeltas) upsert(addr basics.Address, delta AccountDelta) {
	if idx, exist := a.cache[addr]; exist { // nil map lookup is OK
		a.Deltas[idx] = delta
		return
	}
	a.insert(delta)
}
func TestCompactAccountDeltas(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	ad := CompactAccountDeltas{}
	data, idx := ad.get(basics.Address{})
	a.Equal(-1, idx)
	a.Equal(AccountDelta{}, data)

	addr := ledgertesting.RandomAddress()
	data, idx = ad.get(addr)
	a.Equal(-1, idx)
	a.Equal(AccountDelta{}, data)

	a.Zero(ad.Len())
	a.Panics(func() { ad.GetByIdx(0) })

	sample1 := AccountDelta{NewAcct: BaseAccountData{MicroAlgos: basics.MicroAlgos{Raw: 123}}, Address: addr}
	ad.upsert(addr, sample1)
	data, idx = ad.get(addr)
	a.NotEqual(-1, idx)
	a.Equal(sample1, data)

	a.Equal(1, ad.Len())
	data = ad.GetByIdx(0)
	a.Equal(addr, data.Address)
	a.Equal(sample1, data)

	sample2 := AccountDelta{NewAcct: BaseAccountData{MicroAlgos: basics.MicroAlgos{Raw: 456}}, Address: addr}
	ad.upsert(addr, sample2)
	data, idx = ad.get(addr)
	a.NotEqual(-1, idx)
	a.Equal(sample2, data)

	a.Equal(1, ad.Len())
	data = ad.GetByIdx(0)
	a.Equal(addr, data.Address)
	a.Equal(sample2, data)

	ad.update(idx, sample2)
	data, idx2 := ad.get(addr)
	a.Equal(idx, idx2)
	a.Equal(sample2, data)

	a.Equal(1, ad.Len())
	data = ad.GetByIdx(0)
	a.Equal(addr, data.Address)
	a.Equal(sample2, data)

	old1 := PersistedAccountData{Addr: addr, AccountData: BaseAccountData{MicroAlgos: basics.MicroAlgos{Raw: 789}}}
	ad.upsertOld(old1)
	a.Equal(1, ad.Len())
	data = ad.GetByIdx(0)
	a.Equal(addr, data.Address)
	a.Equal(AccountDelta{NewAcct: sample2.NewAcct, OldAcct: old1, Address: addr}, data)

	addr1 := ledgertesting.RandomAddress()
	old2 := PersistedAccountData{Addr: addr1, AccountData: BaseAccountData{MicroAlgos: basics.MicroAlgos{Raw: 789}}}
	ad.upsertOld(old2)
	a.Equal(2, ad.Len())
	data = ad.GetByIdx(0)
	a.Equal(addr, data.Address)
	a.Equal(AccountDelta{NewAcct: sample2.NewAcct, OldAcct: old1, Address: addr}, data)

	data = ad.GetByIdx(1)
	a.Equal(addr1, data.OldAcct.Addr)
	a.Equal(AccountDelta{OldAcct: old2, Address: addr1}, data)

	// apply old on empty delta object, expect no changes
	ad.updateOld(0, old2)
	a.Equal(2, ad.Len())
	data = ad.GetByIdx(0)
	a.Equal(addr, data.Address)
	a.Equal(AccountDelta{NewAcct: sample2.NewAcct, OldAcct: old2, Address: addr}, data)

	addr2 := ledgertesting.RandomAddress()
	sample2.Address = addr2
	idx = ad.insert(sample2)
	a.Equal(3, ad.Len())
	a.Equal(2, idx)
	data = ad.GetByIdx(idx)
	a.Equal(addr2, data.Address)
	a.Equal(sample2, data)
}

// upsertOld updates existing or inserts a new partial entry with only old field filled
func (a *CompactResourcesDeltas) upsertOld(addr basics.Address, old PersistedResourcesData) {
	if idx, exist := a.cache[ledgercore.AccountCreatable{Address: addr, Index: old.Aidx}]; exist {
		a.deltas[idx].OldResource = old
		return
	}
	idx := a.insert(ResourceDelta{OldResource: old, Address: addr})
	a.deltas[idx].Address = addr
}
func TestCompactResourceDeltas(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	ad := CompactResourcesDeltas{}
	data, idx := ad.get(basics.Address{}, 0)
	a.Equal(-1, idx)
	a.Equal(ResourceDelta{}, data)

	addr := ledgertesting.RandomAddress()
	data, idx = ad.get(addr, 0)
	a.Equal(-1, idx)
	a.Equal(ResourceDelta{}, data)

	a.Zero(ad.Len())
	a.Panics(func() { ad.GetByIdx(0) })

	sample1 := ResourceDelta{NewResource: resourcesData{Total: 123}, Address: addr, OldResource: PersistedResourcesData{Aidx: 1}}
	ad.upsert(sample1)
	data, idx = ad.get(addr, 1)
	a.NotEqual(-1, idx)
	a.Equal(sample1, data)

	a.Equal(1, ad.Len())
	data = ad.GetByIdx(0)
	a.Equal(addr, data.Address)
	a.Equal(sample1, data)

	sample2 := ResourceDelta{NewResource: resourcesData{Total: 456}, Address: addr, OldResource: PersistedResourcesData{Aidx: 1}}
	ad.upsert(sample2)
	data, idx = ad.get(addr, 1)
	a.NotEqual(-1, idx)
	a.Equal(sample2, data)

	a.Equal(1, ad.Len())
	data = ad.GetByIdx(0)
	a.Equal(addr, data.Address)
	a.Equal(sample2, data)

	ad.update(idx, sample2)
	data, idx2 := ad.get(addr, 1)
	a.Equal(idx, idx2)
	a.Equal(sample2, data)

	a.Equal(1, ad.Len())
	data = ad.GetByIdx(0)
	a.Equal(addr, data.Address)
	a.Equal(sample2, data)

	old1 := PersistedResourcesData{Addrid: 111, Aidx: 1, Data: resourcesData{Total: 789}}
	ad.upsertOld(addr, old1)
	a.Equal(1, ad.Len())
	data = ad.GetByIdx(0)
	a.Equal(addr, data.Address)
	a.Equal(ResourceDelta{NewResource: sample2.NewResource, OldResource: old1, Address: addr}, data)

	addr1 := ledgertesting.RandomAddress()
	old2 := PersistedResourcesData{Addrid: 222, Aidx: 2, Data: resourcesData{Total: 789}}
	ad.upsertOld(addr1, old2)
	a.Equal(2, ad.Len())
	data = ad.GetByIdx(0)
	a.Equal(addr, data.Address)
	a.Equal(ResourceDelta{NewResource: sample2.NewResource, OldResource: old1, Address: addr}, data)

	data = ad.GetByIdx(1)
	a.Equal(addr1, data.Address)
	a.Equal(ResourceDelta{OldResource: old2, Address: addr1}, data)

	ad.updateOld(0, old2)
	a.Equal(2, ad.Len())
	data = ad.GetByIdx(0)
	a.Equal(addr, data.Address)
	a.Equal(ResourceDelta{NewResource: sample2.NewResource, OldResource: old2, Address: addr}, data)

	addr2 := ledgertesting.RandomAddress()
	sample2.OldResource.Aidx = 2
	sample2.Address = addr2
	idx = ad.insert(sample2)
	a.Equal(3, ad.Len())
	a.Equal(2, idx)
	data = ad.GetByIdx(idx)
	a.Equal(addr2, data.Address)
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
		var ba BaseAccountData
		require.True(t, ba.IsEmpty())
		for i := 0; i < 20; i++ {
			h := crypto.Hash([]byte{byte(i)})
			rnd := binary.BigEndian.Uint64(h[:])
			ba.UpdateRound = rnd
			require.True(t, ba.IsEmpty())
		}
	}
	var empty BaseAccountData
	negativeTesting := func(t *testing.T) {
		for i := 0; i < 10000; i++ {
			randObj, _ := protocol.RandomizeObjectField(&BaseAccountData{})
			ba := randObj.(*BaseAccountData)
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

func TestBaseOnlineAccountDataIsEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)

	positiveTesting := func(t *testing.T) {
		var ba BaseOnlineAccountData
		require.True(t, ba.IsEmpty())
		require.True(t, ba.IsVotingEmpty())
		ba.MicroAlgos.Raw = 100
		require.True(t, ba.IsVotingEmpty())
		ba.RewardsBase = 200
		require.True(t, ba.IsVotingEmpty())
	}
	var empty BaseOnlineAccountData
	negativeTesting := func(t *testing.T) {
		for i := 0; i < 10; i++ {
			randObj, _ := protocol.RandomizeObjectField(&BaseOnlineAccountData{})
			ba := randObj.(*BaseOnlineAccountData)
			if *ba == empty {
				continue
			}
			require.False(t, ba.IsEmpty(), "base account : %v", ba)
			break
		}
		{
			var ba BaseOnlineAccountData
			ba.MicroAlgos.Raw = 100
			require.False(t, ba.IsEmpty())
		}
		{
			var ba BaseOnlineAccountData
			ba.RewardsBase = 200
			require.False(t, ba.IsEmpty())
		}
	}
	structureTesting := func(t *testing.T) {
		encoding, err := json.Marshal(&empty)
		expectedEncoding := `{"VoteID":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"SelectionID":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"VoteFirstValid":0,"VoteLastValid":0,"VoteKeyDilution":0,"StateProofID":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"MicroAlgos":{"Raw":0},"RewardsBase":0}`
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

	var ba BaseOnlineAccountData
	ba.SetCoreAccountData(ledgercore.ToAccountData(data))

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

	bv.SetCoreAccountData(ledgercore.ToAccountData(data))

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

	require.Equal(t, 4, reflect.TypeOf(BaseOnlineAccountData{}).NumField(), "update all getters and setters for BaseOnlineAccountData and change the field count")
}

func TestBaseVotingDataReflect(t *testing.T) {
	partitiontest.PartitionTest(t)

	require.Equal(t, 7, reflect.TypeOf(baseVotingData{}).NumField(), "update all getters and setters for baseVotingData and change the field count")
}

func TestLookupAccountAddressFromAddressID(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := ledgertesting.DbOpenTest(t, true)
	ledgertesting.SetDbLogging(t, dbs)
	defer dbs.Close()

	addrs := make([]basics.Address, 100)
	for i := range addrs {
		addrs[i] = ledgertesting.RandomAddress()
	}
	addrsids := make(map[basics.Address]int64)
	err := dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		accountsInitTest(t, tx, make(map[basics.Address]basics.AccountData), protocol.ConsensusCurrentVersion)

		for i := range addrs {
			res, err := tx.ExecContext(ctx, "INSERT INTO accountbase (Address, data) VALUES (?, ?)", addrs[i][:], []byte{12, 3, 4})
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
			retAddr, err := LookupAccountAddressFromAddressID(ctx, tx, addrid)
			if err != nil {
				return err
			}
			if retAddr != addr {
				return fmt.Errorf("mismatching addresses")
			}
		}
		// test fail case:
		retAddr, err := LookupAccountAddressFromAddressID(ctx, tx, -1)

		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("unexpected error : %w", err)
		}
		if !retAddr.IsZero() {
			return fmt.Errorf("unexpected Address; should have been empty")
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

func (m *mockAccountWriter) lookup(addr basics.Address) (pad PersistedAccountData, ok bool, err error) {
	rowid, ok := m.addresses[addr]
	if !ok {
		return
	}
	data, ok := m.accounts[rowid]
	if !ok {
		err = fmt.Errorf("not found %s", addr.String())
		return
	}
	pad.AccountData.SetCoreAccountData(data)
	pad.Addr = addr
	pad.Rowid = rowid
	return
}

func (m *mockAccountWriter) lookupResource(addr basics.Address, cidx basics.CreatableIndex) (prd PersistedResourcesData, ok bool, err error) {
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
		prd.Data.SetAppLocalState(*res.AppLocalState)
	}
	if res.AppParams != nil {
		prd.Data.SetAppParams(*res.AppParams, prd.Data.IsHolding())
	}
	if res.AssetHolding != nil {
		prd.Data.SetAssetHolding(*res.AssetHolding)
	}
	if res.AssetParams != nil {
		prd.Data.SetAssetParams(*res.AssetParams, prd.Data.IsHolding())
	}
	prd.Addrid = rowid
	prd.Aidx = cidx
	return
}

func (m *mockAccountWriter) insertAccount(addr basics.Address, normBalance uint64, data BaseAccountData) (rowid int64, err error) {
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

func (m *mockAccountWriter) updateAccount(rowid int64, normBalance uint64, data BaseAccountData) (rowsAffected int64, err error) {
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
	prd := PersistedResourcesData{Data: data}
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
	prd := PersistedResourcesData{Data: data}
	new := prd.AccountResource()
	if new == old {
		return 0, nil
	}
	m.resources[key] = new
	return 1, nil
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

func compactAccountDeltasPermutations(a *require.Assertions, cad CompactAccountDeltas) []CompactAccountDeltas {
	a.Empty(cad.misses)

	size := cad.Len()
	result := make([]CompactAccountDeltas, 0, factorial(size))

	perms := permHeap(size)
	// remap existing deltas to permutated one
	for _, perm := range perms {
		new := CompactAccountDeltas{}
		new.cache = make(map[basics.Address]int, size)
		new.Deltas = make([]AccountDelta, size)
		for i, k := range perm {
			new.Deltas[k] = cad.Deltas[i]
		}
		for key, i := range cad.cache {
			new.cache[key] = perm[i]
		}
		result = append(result, new)
	}

	// ensure remapping
	for _, new := range result {
		for key, idx := range new.cache {
			d1 := cad.GetByIdx(cad.cache[key])
			d2 := new.GetByIdx(idx)
			a.Equal(d1, d2)
		}
	}

	return result
}

func compactResourcesDeltasPermutations(a *require.Assertions, crd CompactResourcesDeltas) []CompactResourcesDeltas {

	size := crd.Len()
	result := make([]CompactResourcesDeltas, 0, factorial(size))

	perms := permHeap(size)
	// remap existing deltas to permutated one
	for _, perm := range perms {
		new := CompactResourcesDeltas{}
		new.cache = make(map[ledgercore.AccountCreatable]int, size)
		new.deltas = make([]ResourceDelta, size)
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
			d1 := crd.GetByIdx(crd.cache[key])
			d2 := new.GetByIdx(idx)
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
// at 16541788 YF5 Address had clear state txn for 22045503, and close out txn for the entire account (one acct delta, one res delta)
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
	var baseAccounts LRUAccounts
	baseAccounts.Init(nil, 100, 80)

	pad, ok, err := mock.lookup(addr1)
	a.NoError(err)
	a.True(ok)
	baseAccounts.Write(pad)
	pad, ok, err = mock.lookup(observer)
	a.NoError(err)
	a.True(ok)
	baseAccounts.Write(pad)
	baseAccounts.Write(PersistedAccountData{Addr: addr2})

	acctDeltas := MakeCompactAccountDeltas(updates, dbRound, false, baseAccounts)
	a.Empty(acctDeltas.misses)
	a.Equal(3, acctDeltas.Len())

	// we want to have (addr1, aidx) and (observer, aidx)
	var baseResources LRUResources
	baseResources.Init(nil, 100, 80)

	prd, ok, err := mock.lookupResource(addr1, basics.CreatableIndex(aidx))
	a.NoError(err)
	a.True(ok)
	baseResources.Write(prd, addr1)
	prd, ok, err = mock.lookupResource(observer, basics.CreatableIndex(aidx))
	a.NoError(err)
	a.True(ok)
	baseResources.Write(prd, observer)

	resDeltas := MakeCompactResourceDeltas(updates, dbRound, false, baseAccounts, baseResources)
	a.Equal(1, len(resDeltas.misses)) // (addr2, aidx) does not exist
	a.Equal(3, resDeltas.Len())       // (addr1, aidx), (observer, aidx) found

	acctVariants := compactAccountDeltasPermutations(a, acctDeltas)
	resVariants := compactResourcesDeltasPermutations(a, resDeltas)
	for i, acctVariant := range acctVariants {
		for j, resVariant := range resVariants {
			t.Run(fmt.Sprintf("acct-perm-%d|res-perm-%d", i, j), func(t *testing.T) {
				a := require.New(t)
				mock2 := mock.clone()
				updatedAccounts, updatedResources, err := accountsNewRoundImpl(
					&mock2, acctVariant, resVariant, nil, config.ConsensusParams{}, latestRound,
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

	var baseAccounts LRUAccounts
	baseAccounts.Init(nil, 100, 80)
	var baseResources LRUResources
	baseResources.Init(nil, 100, 80)

	pad, ok, err := mock.lookup(addr1)
	a.NoError(err)
	a.True(ok)
	baseAccounts.Write(pad)
	pad, ok, err = mock.lookup(observer)
	a.NoError(err)
	a.True(ok)
	baseAccounts.Write(pad)
	baseAccounts.Write(PersistedAccountData{Addr: addr2}) // put an empty record for addr2 to get rid of lookups

	acctDeltas := MakeCompactAccountDeltas(updates, dbRound, false, baseAccounts)
	a.Empty(acctDeltas.misses)
	a.Equal(3, acctDeltas.Len())

	// we want to have (addr1, aidx) and (observer, aidx)
	prd, ok, err := mock.lookupResource(addr1, basics.CreatableIndex(aidx))
	a.NoError(err)
	a.True(ok)
	baseResources.Write(prd, addr1)
	prd, ok, err = mock.lookupResource(observer, basics.CreatableIndex(aidx))
	a.NoError(err)
	a.True(ok)
	baseResources.Write(prd, observer)

	resDeltas := MakeCompactResourceDeltas(updates, dbRound, false, baseAccounts, baseResources)
	a.Equal(1, len(resDeltas.misses)) // (addr2, aidx) does not exist
	a.Equal(2, resDeltas.Len())       // (addr1, aidx) found

	updatedAccounts, updatedResources, err := accountsNewRoundImpl(
		&mock, acctDeltas, resDeltas, nil, config.ConsensusParams{}, latestRound,
	)
	a.NoError(err)
	a.Equal(3, len(updatedAccounts))
	a.Equal(2, len(updatedResources))

	// one deletion entry for pre-existing account addr1, and one entry for in-memory account addr2
	// in base accounts updates and in resources updates
	addressesToCheck := map[basics.Address]bool{addr1: true, addr2: true}
	matches := 0
	for _, upd := range updatedAccounts {
		if addressesToCheck[upd.Addr] {
			a.Equal(int64(0), upd.Rowid)
			a.Empty(upd.AccountData)
			matches++
		}
	}
	a.Equal(len(addressesToCheck), matches)

	for addr := range addressesToCheck {
		upd := updatedResources[addr]
		a.Equal(1, len(upd))
		a.Equal(int64(0), upd[0].Addrid)
		a.Equal(basics.CreatableIndex(aidx), upd[0].Aidx)
		a.Equal(makeResourcesData(uint64(0)), upd[0].Data)
	}
}

// TestAccountTopOnline ensures accountsOnlineTop return a right subset of accounts
// from the history table.
// Start with two online accounts A, B at round 1
// At round 2 make A offline.
// At round 3 make B offline and add a new online account C.
// Ensure
// - for round 1 A and B returned
// - for round 2 only B returned
// - for round 3 only C returned
// The test also checks accountsDbQueries.lookupOnline
func TestAccountOnlineQueries(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	dbs, _ := ledgertesting.DbOpenTest(t, true)
	ledgertesting.SetDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	var accts map[basics.Address]basics.AccountData
	accountsInitTest(t, tx, accts, protocol.ConsensusCurrentVersion)
	totals, err := AccountsTotals(context.Background(), tx, false)
	require.NoError(t, err)

	var baseAccounts LRUAccounts
	var baseResources LRUResources
	var baseOnlineAccounts LRUOnlineAccounts
	baseAccounts.Init(nil, 100, 80)
	baseResources.Init(nil, 100, 80)
	baseOnlineAccounts.Init(nil, 100, 80)

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
		accts = ledgertesting.ApplyPartialDeltas(accts, updates)

		oldBase := rnd - 1
		updatesCnt := MakeCompactAccountDeltas([]ledgercore.AccountDeltas{updates}, oldBase, true, baseAccounts)
		updatesOnlineCnt := MakeCompactOnlineAccountDeltas([]ledgercore.AccountDeltas{updates}, oldBase, baseOnlineAccounts)

		err = updatesCnt.AccountsLoadOld(tx)
		require.NoError(t, err)

		err = updatesOnlineCnt.AccountsLoadOld(tx)
		require.NoError(t, err)

		err = AccountsPutTotals(tx, totals, false)
		require.NoError(t, err)
		updatedAccts, _, err := AccountsNewRound(tx, updatesCnt, CompactResourcesDeltas{}, map[basics.CreatableIndex]ledgercore.ModifiedCreatable{}, proto, rnd)
		require.NoError(t, err)
		require.Equal(t, updatesCnt.Len(), len(updatedAccts))

		updatedOnlineAccts, err := OnlineAccountsNewRound(tx, updatesOnlineCnt, proto, rnd)
		require.NoError(t, err)
		require.NotEmpty(t, updatedOnlineAccts)

		err = UpdateAccountsRound(tx, rnd)
		require.NoError(t, err)
	}

	addRound(1, delta1)
	addRound(2, delta2)
	addRound(3, delta3)

	queries, err := OnlineAccountsInitDbQueries(tx)
	require.NoError(t, err)

	// check round 1
	rnd := basics.Round(1)
	online, err := AccountsOnlineTop(tx, rnd, 0, 10, proto)
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

	paod, err := queries.LookupOnline(addrA, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrA, paod.Addr)
	require.Equal(t, dataA1.AccountBaseData.MicroAlgos, paod.AccountData.MicroAlgos)
	require.Equal(t, voteIDA, paod.AccountData.VoteID)

	paod, err = queries.LookupOnline(addrB, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrB, paod.Addr)
	require.Equal(t, dataB1.AccountBaseData.MicroAlgos, paod.AccountData.MicroAlgos)
	require.Equal(t, voteIDB, paod.AccountData.VoteID)

	paod, err = queries.LookupOnline(addrC, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrC, paod.Addr)
	require.Empty(t, paod.AccountData)

	// check round 2
	rnd = basics.Round(2)
	online, err = AccountsOnlineTop(tx, rnd, 0, 10, proto)
	require.NoError(t, err)
	require.Equal(t, 1, len(online))
	require.NotContains(t, online, addrA)
	require.NotContains(t, online, addrC)

	onlineAcctB, ok = online[addrB]
	require.True(t, ok)
	require.NotNil(t, onlineAcctB)
	require.Equal(t, addrB, onlineAcctB.Address)
	require.Equal(t, dataB1.AccountBaseData.MicroAlgos, onlineAcctB.MicroAlgos)

	paod, err = queries.LookupOnline(addrA, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrA, paod.Addr)
	require.Empty(t, paod.AccountData)

	paod, err = queries.LookupOnline(addrB, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrB, paod.Addr)
	require.Equal(t, dataB1.AccountBaseData.MicroAlgos, paod.AccountData.MicroAlgos)
	require.Equal(t, voteIDB, paod.AccountData.VoteID)

	paod, err = queries.LookupOnline(addrC, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrC, paod.Addr)
	require.Empty(t, paod.AccountData)

	// check round 3
	rnd = basics.Round(3)
	online, err = AccountsOnlineTop(tx, rnd, 0, 10, proto)
	require.NoError(t, err)
	require.Equal(t, 1, len(online))
	require.NotContains(t, online, addrA)
	require.NotContains(t, online, addrB)

	onlineAcctC, ok := online[addrC]
	require.True(t, ok)
	require.NotNil(t, onlineAcctC)
	require.Equal(t, addrC, onlineAcctC.Address)
	require.Equal(t, dataC3.AccountBaseData.MicroAlgos, onlineAcctC.MicroAlgos)

	paod, err = queries.LookupOnline(addrA, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrA, paod.Addr)
	require.Empty(t, paod.AccountData)

	paod, err = queries.LookupOnline(addrB, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrB, paod.Addr)
	require.Empty(t, paod.AccountData)

	paod, err = queries.LookupOnline(addrC, rnd)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), paod.round)
	require.Equal(t, addrC, paod.Addr)
	require.Equal(t, dataC3.AccountBaseData.MicroAlgos, paod.AccountData.MicroAlgos)
	require.Equal(t, voteIDC, paod.AccountData.VoteID)

	paods, err := OnlineAccountsAll(tx, 0)
	require.NoError(t, err)
	require.Equal(t, 5, len(paods))

	require.Equal(t, int64(2), paods[0].Rowid)
	require.Equal(t, basics.Round(1), paods[0].UpdRound)
	require.Equal(t, addrB, paods[0].Addr)
	require.Equal(t, int64(4), paods[1].Rowid)
	require.Equal(t, basics.Round(3), paods[1].UpdRound)
	require.Equal(t, addrB, paods[1].Addr)

	require.Equal(t, int64(5), paods[2].Rowid)
	require.Equal(t, basics.Round(3), paods[2].UpdRound)
	require.Equal(t, addrC, paods[2].Addr)

	require.Equal(t, int64(1), paods[3].Rowid)
	require.Equal(t, basics.Round(1), paods[3].UpdRound)
	require.Equal(t, addrA, paods[3].Addr)
	require.Equal(t, int64(3), paods[4].Rowid)
	require.Equal(t, basics.Round(2), paods[4].UpdRound)
	require.Equal(t, addrA, paods[4].Addr)

	paods, rnd, err = queries.LookupOnlineHistory(addrA)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), rnd)
	require.Equal(t, 2, len(paods))
	require.Equal(t, int64(1), paods[0].Rowid)
	require.Equal(t, basics.Round(1), paods[0].UpdRound)
	require.Equal(t, int64(3), paods[1].Rowid)
	require.Equal(t, basics.Round(2), paods[1].UpdRound)

	paods, rnd, err = queries.LookupOnlineHistory(addrB)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), rnd)
	require.Equal(t, 2, len(paods))
	require.Equal(t, int64(2), paods[0].Rowid)
	require.Equal(t, basics.Round(1), paods[0].UpdRound)
	require.Equal(t, int64(4), paods[1].Rowid)
	require.Equal(t, basics.Round(3), paods[1].UpdRound)

	paods, rnd, err = queries.LookupOnlineHistory(addrC)
	require.NoError(t, err)
	require.Equal(t, basics.Round(3), rnd)
	require.Equal(t, 1, len(paods))
	require.Equal(t, int64(5), paods[0].Rowid)
	require.Equal(t, basics.Round(3), paods[0].UpdRound)
}

type mockOnlineAccountsWriter struct {
	rowid int64
}

func (w *mockOnlineAccountsWriter) insertOnlineAccount(addr basics.Address, normBalance uint64, data BaseOnlineAccountData, updRound uint64, voteLastValid uint64) (rowid int64, err error) {
	w.rowid++
	return w.rowid, nil
}

func (w *mockOnlineAccountsWriter) close() {}

func TestAccountOnlineAccountsNewRound(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	writer := &mockOnlineAccountsWriter{rowid: 100}

	updates := CompactOnlineAccountDeltas{}
	addrA := ledgertesting.RandomAddress()
	addrB := ledgertesting.RandomAddress()
	addrC := ledgertesting.RandomAddress()
	addrD := ledgertesting.RandomAddress()
	addrE := ledgertesting.RandomAddress()

	// acct A is empty
	deltaA := OnlineAccountDelta{
		Address: addrA,
	}
	// acct B is new and offline
	deltaB := OnlineAccountDelta{
		Address: addrB,
		newAcct: []BaseOnlineAccountData{{
			MicroAlgos: basics.MicroAlgos{Raw: 200_000_000},
		}},
		updRound:  []uint64{1},
		newStatus: []basics.Status{basics.Offline},
	}
	// acct C is new and online
	deltaC := OnlineAccountDelta{
		Address: addrC,
		newAcct: []BaseOnlineAccountData{{
			MicroAlgos:     basics.MicroAlgos{Raw: 300_000_000},
			baseVotingData: baseVotingData{VoteFirstValid: 500},
		}},
		newStatus: []basics.Status{basics.Online},
		updRound:  []uint64{2},
	}
	// acct D is old and went offline
	deltaD := OnlineAccountDelta{
		Address: addrD,
		oldAcct: PersistedOnlineAccountData{
			Addr: addrD,
			AccountData: BaseOnlineAccountData{
				MicroAlgos:     basics.MicroAlgos{Raw: 400_000_000},
				baseVotingData: baseVotingData{VoteFirstValid: 500},
			},
			Rowid: 1,
		},
		newAcct: []BaseOnlineAccountData{{
			MicroAlgos: basics.MicroAlgos{Raw: 400_000_000},
		}},
		newStatus: []basics.Status{basics.Offline},
		updRound:  []uint64{3},
	}

	// acct E is old online
	deltaE := OnlineAccountDelta{
		Address: addrE,
		oldAcct: PersistedOnlineAccountData{
			Addr: addrE,
			AccountData: BaseOnlineAccountData{
				MicroAlgos:     basics.MicroAlgos{Raw: 500_000_000},
				baseVotingData: baseVotingData{VoteFirstValid: 500},
			},
			Rowid: 2,
		},
		newAcct: []BaseOnlineAccountData{{
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
	require.Equal(t, updated[0].Addr, addrC)
	require.Equal(t, updated[1].Addr, addrD)
	require.Equal(t, updated[2].Addr, addrE)

	// check errors: new online with empty voting data
	deltaC.newStatus[0] = basics.Online
	deltaC.newAcct[0].VoteFirstValid = 0
	updates.deltas = []OnlineAccountDelta{deltaC}
	_, err = onlineAccountsNewRoundImpl(writer, updates, proto, lastUpdateRound)
	require.Error(t, err)

	// TODO: restore after migrating offline accounts and clearing state proof PK
	// // check errors: new non-online with non-empty voting data
	// deltaB.newStatus[0] = basics.Offline
	// deltaB.NewAcct[0].VoteFirstValid = 1
	// updates.deltas = []onlineAccountDelta{deltaB}
	// _, err = OnlineAccountsNewRoundImpl(writer, updates, proto, lastUpdateRound)
	// require.Error(t, err)

	// check errors: new online with empty voting data
	deltaD.newStatus[0] = basics.Online
	updates.deltas = []OnlineAccountDelta{deltaD}
	_, err = onlineAccountsNewRoundImpl(writer, updates, proto, lastUpdateRound)
	require.Error(t, err)
}

func TestAccountOnlineAccountsNewRoundFlip(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	writer := &mockOnlineAccountsWriter{rowid: 100}

	updates := CompactOnlineAccountDeltas{}
	addrA := ledgertesting.RandomAddress()
	addrB := ledgertesting.RandomAddress()
	addrC := ledgertesting.RandomAddress()

	// acct A is new, offline and then online
	deltaA := OnlineAccountDelta{
		Address: addrA,
		newAcct: []BaseOnlineAccountData{
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
	deltaB := OnlineAccountDelta{
		Address: addrB,
		newAcct: []BaseOnlineAccountData{
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
	deltaC := OnlineAccountDelta{
		Address: addrC,
		oldAcct: PersistedOnlineAccountData{
			Addr: addrC,
			AccountData: BaseOnlineAccountData{
				MicroAlgos:     basics.MicroAlgos{Raw: 300_000_000},
				baseVotingData: baseVotingData{VoteFirstValid: 300},
			},
			Rowid: 1,
		},
		newAcct: []BaseOnlineAccountData{
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
	require.Equal(t, updated[0].Addr, addrA)
	require.Equal(t, updated[1].Addr, addrB)
	require.Equal(t, updated[2].Addr, addrB)
	require.Equal(t, updated[3].Addr, addrC)
	require.Equal(t, updated[4].Addr, addrC)
}

func TestAccountOnlineRoundParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := ledgertesting.DbOpenTest(t, true)
	ledgertesting.SetDbLogging(t, dbs)
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

	err = AccountsPutOnlineRoundParams(tx, onlineRoundParams, 1)
	require.NoError(t, err)

	dbOnlineRoundParams, endRound, err := AccountsOnlineRoundParams(tx)
	require.NoError(t, err)
	require.Equal(t, maxRounds+1, len(dbOnlineRoundParams)) // +1 comes from init state
	require.Equal(t, onlineRoundParams, dbOnlineRoundParams[1:])
	require.Equal(t, maxRounds, int(endRound))

	err = AccountsPruneOnlineRoundParams(tx, 10)
	require.NoError(t, err)

	dbOnlineRoundParams, endRound, err = AccountsOnlineRoundParams(tx)
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
	dbs, _ := ledgertesting.DbOpenTest(t, inMem)
	ledgertesting.SetDbLogging(t, dbs)
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
		data := TxTailRound{Hdr: bookkeeping.BlockHeader{TimeStamp: int64(i)}}
		roundData[i-1] = protocol.Encode(&data)
	}
	forgetBefore := (endRound + 1).SubSaturate(retainSize)
	err = TxTailNewRound(context.Background(), tx, startRound, roundData, forgetBefore)
	require.NoError(t, err)

	data, _, baseRound, err := LoadTxTail(context.Background(), tx, endRound)
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

	dbs, _ := ledgertesting.DbOpenTest(t, true)
	ledgertesting.SetDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	var accts map[basics.Address]basics.AccountData
	accountsInitTest(t, tx, accts, protocol.ConsensusCurrentVersion)

	updates := CompactOnlineAccountDeltas{}
	addrA := ledgertesting.RandomAddress()
	addrB := ledgertesting.RandomAddress()

	deltaA := OnlineAccountDelta{
		Address: addrA,
		newAcct: []BaseOnlineAccountData{
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
	deltaB := OnlineAccountDelta{
		Address: addrB,
		newAcct: []BaseOnlineAccountData{
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
	writer, err := makeOnlineAccountsSQLWriter(tx, updates.Len() > 0)
	if err != nil {
		return
	}
	defer writer.close()

	lastUpdateRound := basics.Round(10)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	updated, err := onlineAccountsNewRoundImpl(writer, updates, proto, lastUpdateRound)
	require.NoError(t, err)
	require.Len(t, updated, 5)

	queries, err := OnlineAccountsInitDbQueries(tx)
	require.NoError(t, err)

	var count int64
	var history []PersistedOnlineAccountData
	var validThrough basics.Round
	for _, rnd := range []basics.Round{1, 2, 3} {
		err = OnlineAccountsDelete(tx, rnd)
		require.NoError(t, err)

		err = tx.QueryRow("SELECT COUNT(1) FROM onlineaccounts").Scan(&count)
		require.NoError(t, err)
		require.Equal(t, int64(5), count)

		history, validThrough, err = queries.LookupOnlineHistory(addrA)
		require.NoError(t, err)
		require.Equal(t, basics.Round(0), validThrough) // not set
		require.Len(t, history, 3)
		history, validThrough, err = queries.LookupOnlineHistory(addrB)
		require.NoError(t, err)
		require.Equal(t, basics.Round(0), validThrough)
		require.Len(t, history, 2)
	}

	for _, rnd := range []basics.Round{4, 5, 6, 7} {
		err = OnlineAccountsDelete(tx, rnd)
		require.NoError(t, err)

		err = tx.QueryRow("SELECT COUNT(1) FROM onlineaccounts").Scan(&count)
		require.NoError(t, err)
		require.Equal(t, int64(3), count)

		history, validThrough, err = queries.LookupOnlineHistory(addrA)
		require.NoError(t, err)
		require.Equal(t, basics.Round(0), validThrough)
		require.Len(t, history, 1)
		history, validThrough, err = queries.LookupOnlineHistory(addrB)
		require.NoError(t, err)
		require.Equal(t, basics.Round(0), validThrough)
		require.Len(t, history, 2)
	}

	for _, rnd := range []basics.Round{8, 9} {
		err = OnlineAccountsDelete(tx, rnd)
		require.NoError(t, err)

		err = tx.QueryRow("SELECT COUNT(1) FROM onlineaccounts").Scan(&count)
		require.NoError(t, err)
		require.Equal(t, int64(2), count)

		history, validThrough, err = queries.LookupOnlineHistory(addrA)
		require.NoError(t, err)
		require.Equal(t, basics.Round(0), validThrough)
		require.Len(t, history, 1)
		history, validThrough, err = queries.LookupOnlineHistory(addrB)
		require.NoError(t, err)
		require.Equal(t, basics.Round(0), validThrough)
		require.Len(t, history, 1)
	}
}

// Test functions operating on catchpointfirststageinfo table.
func TestCatchpointFirstStageInfoTable(t *testing.T) {
	dbs, _ := ledgertesting.DbOpenTest(t, true)
	defer dbs.Close()

	ctx := context.Background()

	err := accountsCreateCatchpointFirstStageInfoTable(ctx, dbs.Wdb.Handle)
	require.NoError(t, err)

	for _, round := range []basics.Round{4, 6, 8} {
		info := CatchpointFirstStageInfo{
			TotalAccounts: uint64(round) * 10,
		}
		err = InsertOrReplaceCatchpointFirstStageInfo(ctx, dbs.Wdb.Handle, round, &info)
		require.NoError(t, err)
	}

	for _, round := range []basics.Round{4, 6, 8} {
		info, exists, err := SelectCatchpointFirstStageInfo(ctx, dbs.Rdb.Handle, round)
		require.NoError(t, err)
		require.True(t, exists)

		infoExpected := CatchpointFirstStageInfo{
			TotalAccounts: uint64(round) * 10,
		}
		require.Equal(t, infoExpected, info)
	}

	_, exists, err := SelectCatchpointFirstStageInfo(ctx, dbs.Rdb.Handle, 7)
	require.NoError(t, err)
	require.False(t, exists)

	rounds, err := SelectOldCatchpointFirstStageInfoRounds(ctx, dbs.Rdb.Handle, 6)
	require.NoError(t, err)
	require.Equal(t, []basics.Round{4, 6}, rounds)

	err = DeleteOldCatchpointFirstStageInfo(ctx, dbs.Wdb.Handle, 6)
	require.NoError(t, err)

	rounds, err = SelectOldCatchpointFirstStageInfoRounds(ctx, dbs.Rdb.Handle, 9)
	require.NoError(t, err)
	require.Equal(t, []basics.Round{8}, rounds)
}

func TestUnfinishedCatchpointsTable(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := ledgertesting.DbOpenTest(t, true)
	defer dbs.Close()

	err := accountsCreateUnfinishedCatchpointsTable(
		context.Background(), dbs.Wdb.Handle)
	require.NoError(t, err)

	var d3 crypto.Digest
	rand.Read(d3[:])
	err = InsertUnfinishedCatchpoint(context.Background(), dbs.Wdb.Handle, 3, d3)
	require.NoError(t, err)

	var d5 crypto.Digest
	rand.Read(d5[:])
	err = InsertUnfinishedCatchpoint(context.Background(), dbs.Wdb.Handle, 5, d5)
	require.NoError(t, err)

	ret, err := SelectUnfinishedCatchpoints(context.Background(), dbs.Rdb.Handle)
	require.NoError(t, err)
	expected := []unfinishedCatchpointRecord{
		{
			Round:     3,
			BlockHash: d3,
		},
		{
			Round:     5,
			BlockHash: d5,
		},
	}
	require.Equal(t, expected, ret)

	err = DeleteUnfinishedCatchpoint(context.Background(), dbs.Wdb.Handle, 3)
	require.NoError(t, err)

	ret, err = SelectUnfinishedCatchpoints(context.Background(), dbs.Rdb.Handle)
	require.NoError(t, err)
	expected = []unfinishedCatchpointRecord{
		{
			Round:     5,
			BlockHash: d5,
		},
	}
	require.Equal(t, expected, ret)
}
