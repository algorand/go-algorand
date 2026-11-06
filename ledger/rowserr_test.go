// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	storetesting "github.com/algorand/go-algorand/ledger/store/testing"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/sqlitedriver"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

// The tests in this file check that errors which end iteration over the trackerdb
// iterators early are returned, rather than treated as the end of the table. Each one
// swaps a table for a view that fails partway through a query; see
// sqlitedriver.ReplaceTableWithFailingViewTest.

// rowsErrTestStore returns a tracker store initialized with one online account and one KV
// pair, so the kvstore, onlineaccounts, and onlineroundparamstail tables all have rows.
// The returned db.Pair gives tests raw access to the same database.
func rowsErrTestStore(t *testing.T) (trackerdb.Store, db.Pair) {
	dbs, _ := storetesting.DbOpenTest(t, false)
	storetesting.SetDbLogging(t, dbs)
	store := sqlitedriver.MakeStore(dbs)
	t.Cleanup(store.Close)

	var addr basics.Address
	crypto.RandBytes(addr[:])
	ad := ledgertesting.RandomOnlineAccountData(0)
	accts := map[basics.Address]basics.AccountData{addr: ad}
	// An explicit transaction, rather than Atomic, so a failed assertion inside
	// AccountsInitTest still rolls it back and store.Close does not wait on the connection.
	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()
	sqlitedriver.AccountsInitTest(t, tx, accts, protocol.ConsensusCurrentVersion)
	_, err = tx.Exec("INSERT INTO kvstore(key, value) VALUES (?, ?)", []byte("key"), []byte("value"))
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	return store, dbs
}

func TestRowsErrCalculateVerificationHash(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("onlineaccounts", func(t *testing.T) {
		t.Parallel()
		store, dbs := rowsErrTestStore(t)
		_, cnt, err := calculateVerificationHash(context.Background(), store.MakeOrderedOnlineAccountsIter, 0, false)
		require.NoError(t, err)
		require.EqualValues(t, 1, cnt)

		sqlitedriver.ReplaceTableWithFailingViewTest(t, dbs.Wdb.Handle, "onlineaccounts")
		_, _, err = calculateVerificationHash(context.Background(), store.MakeOrderedOnlineAccountsIter, 0, false)
		require.ErrorContains(t, err, sqlitedriver.FailingViewErrorTest)
	})

	t.Run("onlineroundparamstail", func(t *testing.T) {
		t.Parallel()
		store, dbs := rowsErrTestStore(t)
		_, cnt, err := calculateVerificationHash(context.Background(), store.MakeOnlineRoundParamsIter, 0, false)
		require.NoError(t, err)
		require.NotZero(t, cnt)

		sqlitedriver.ReplaceTableWithFailingViewTest(t, dbs.Wdb.Handle, "onlineroundparamstail")
		_, _, err = calculateVerificationHash(context.Background(), store.MakeOnlineRoundParamsIter, 0, false)
		require.ErrorContains(t, err, sqlitedriver.FailingViewErrorTest)
	})
}

func TestRowsErrCatchpointFileWriter(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	params := config.Consensus[protocol.ConsensusCurrentVersion]
	require.True(t, params.EnableCatchpointsWithOnlineAccounts)

	// readDatabaseStep reads the tables in stages; each case marks the earlier stages done so
	// the step goes straight to the table under test. The writer is built directly because
	// makeCatchpointFileWriter counts the rows of every table, which would fail first.
	for _, table := range []string{"kvstore", "onlineaccounts", "onlineroundparamstail"} {
		t.Run(table, func(t *testing.T) {
			t.Parallel()
			store, dbs := rowsErrTestStore(t)
			readStep := func() (CatchpointSnapshotChunkV6, error) {
				return trackerdb.SnapshotResult(store, func(ctx context.Context, tx trackerdb.SnapshotScope) (CatchpointSnapshotChunkV6, error) {
					cw := &catchpointFileWriter{
						ctx:                  ctx,
						tx:                   tx,
						params:               params,
						maxResourcesPerChunk: ResourcesPerCatchpointFileChunk,
						accountsDone:         true,
						kvDone:               table != "kvstore",
						onlineAccountsDone:   table == "onlineroundparamstail",
					}
					defer func() {
						for _, it := range []interface{ Close() }{cw.kvRows, cw.onlineAccountRows, cw.onlineRoundParamsRows} {
							if it != nil {
								it.Close()
							}
						}
					}()
					err := cw.readDatabaseStep(ctx)
					return cw.chunk, err
				})
			}

			chunk, err := readStep()
			require.NoError(t, err)
			require.NotZero(t, len(chunk.KVs)+len(chunk.OnlineAccounts)+len(chunk.OnlineRoundParams))

			sqlitedriver.ReplaceTableWithFailingViewTest(t, dbs.Wdb.Handle, table)
			_, err = readStep()
			require.ErrorContains(t, err, sqlitedriver.FailingViewErrorTest)
		})
	}
}

func TestRowsErrInitializeHashes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// On a fresh database the merkle trie is empty, so initializeHashes rebuilds it from the
	// accounts and then the KVs. Round 0 matches the fresh database's hash round, which keeps
	// it from returning early when catchpoints are disabled.
	initHashes := func(store trackerdb.Store) error {
		ct := &catchpointTracker{log: logging.TestingLog(t)}
		return store.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {
			return ct.initializeHashes(ctx, tx, 0)
		})
	}

	t.Run("ok", func(t *testing.T) {
		t.Parallel()
		store, _ := rowsErrTestStore(t)
		require.NoError(t, initHashes(store))
	})

	t.Run("kvstore", func(t *testing.T) {
		t.Parallel()
		store, dbs := rowsErrTestStore(t)
		sqlitedriver.ReplaceTableWithFailingViewTest(t, dbs.Wdb.Handle, "kvstore")
		require.ErrorContains(t, initHashes(store), sqlitedriver.FailingViewErrorTest)
	})
}
