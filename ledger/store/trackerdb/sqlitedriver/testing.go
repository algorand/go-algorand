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

package sqlitedriver

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// OpenForTesting opens a sqlite db file for testing purposes.
// It set the logging to the  test logger and uses a tmp directory associated to the test for the db.
// The test tmp direction is automatically cleaned up by the golang test framework.
func OpenForTesting(t testing.TB, inMemory bool) (trackerdb.Store, string) {
	fn := fmt.Sprintf("%s/%s.%d", t.TempDir(), strings.ReplaceAll(t.Name(), "/", "."), crypto.RandUint64())

	store, err := Open(fn, inMemory, logging.TestingLog(t))
	require.NoErrorf(t, err, "Filename : %s\nInMemory: %v", fn, inMemory)

	return store, fn
}

// FailingViewErrorTest is the error text SQLite reports when a query reads from a table that
// ReplaceTableWithFailingViewTest has replaced.
const FailingViewErrorTest = "integer overflow"

// ReplaceTableWithFailingViewTest renames table and creates a view with the original name that
// exposes the same columns (and rowid, for rowid tables), but whose WHERE clause SQLite rejects
// with an integer overflow error for every row it scans. Queries against the table still prepare
// and start successfully, but stepping to the first row fails, so rows.Next() returns false and
// rows.Err() reports the error. The table must contain at least one row the query would visit.
// implements Testing interface, test function only
func ReplaceTableWithFailingViewTest(tb testing.TB, e db.Executable, table string) {
	tb.Helper()
	orig := table + "_orig"
	_, err := e.Exec(fmt.Sprintf("ALTER TABLE %s RENAME TO %s", table, orig))
	require.NoError(tb, err)

	// WITHOUT ROWID tables have no rowid to expose; probing is simpler than threading a flag through.
	cols := "rowid AS rowid, *"
	if _, err = e.Exec(fmt.Sprintf("SELECT rowid FROM %s LIMIT 0", orig)); err != nil {
		cols = "*"
	}
	// random() keeps SQLite from folding the expression into a constant, so it is evaluated per row.
	_, err = e.Exec(fmt.Sprintf("CREATE VIEW %s AS SELECT %s FROM %s WHERE abs(-9223372036854775807 - 1 + 0*random()) >= 0", table, cols, orig))
	require.NoError(tb, err)
}

// AccountsInitLightTest initializes an empty database for testing without the extra methods being called.
// implements Testing interface, test function only
func AccountsInitLightTest(tb testing.TB, e db.Executable, initAccounts map[basics.Address]basics.AccountData, rewardUnit uint64) (newDatabase bool, err error) {
	newDB, err := accountsInit(e, initAccounts, rewardUnit)
	require.NoError(tb, err)
	return newDB, err
}

// modifyAcctBaseTest tweaks the database to move backards.
// implements Testing interface, test function only
func modifyAcctBaseTest(e db.Executable) error {
	_, err := e.Exec("update acctrounds set rnd = 1 WHERE id='acctbase' ")
	return err
}

// AccountsInitTest initializes an empty database for testing.
// implements Testing interface, test function only
func AccountsInitTest(tb testing.TB, e db.Executable, initAccounts map[basics.Address]basics.AccountData, cv protocol.ConsensusVersion) (newDatabase bool) {
	newDB, err := accountsInit(e, initAccounts, config.Consensus[cv].RewardUnit)
	require.NoError(tb, err)

	err = accountsAddNormalizedBalance(e, config.Consensus[cv].RewardUnit)
	require.NoError(tb, err)

	err = accountsCreateResourceTable(context.Background(), e)
	require.NoError(tb, err)

	err = performResourceTableMigration(context.Background(), e, nil)
	require.NoError(tb, err)

	err = accountsCreateOnlineAccountsTable(context.Background(), e)
	require.NoError(tb, err)

	err = accountsCreateTxTailTable(context.Background(), e)
	require.NoError(tb, err)

	err = performOnlineAccountsTableMigration(context.Background(), e, nil, nil)
	require.NoError(tb, err)

	// since this is a test that starts from genesis, there is no tail that needs to be migrated.
	// we'll pass a nil here in order to ensure we still call this method, although it would
	// be a noop.
	err = performTxTailTableMigration(context.Background(), nil, db.Accessor{})
	require.NoError(tb, err)

	err = accountsCreateOnlineRoundParamsTable(context.Background(), e)
	require.NoError(tb, err)

	err = performOnlineRoundParamsTailMigration(context.Background(), e, db.Accessor{}, true, cv)
	require.NoError(tb, err)

	err = accountsCreateBoxTable(context.Background(), e)
	require.NoError(tb, err)

	err = performKVStoreNullBlobConversion(context.Background(), e)
	require.NoError(tb, err)

	err = accountsAddCreatableTypeColumn(context.Background(), e, false)
	require.NoError(tb, err)

	return newDB
}

// AccountsUpdateSchemaTest adds some empty tables for tests to work with a "v6" store.
func AccountsUpdateSchemaTest(ctx context.Context, e db.Executable) (err error) {
	if err = accountsCreateOnlineAccountsTable(ctx, e); err != nil {
		return err
	}
	if err = accountsCreateTxTailTable(ctx, e); err != nil {
		return err
	}
	if err = accountsCreateOnlineRoundParamsTable(ctx, e); err != nil {
		return err
	}
	if err = accountsCreateCatchpointFirstStageInfoTable(ctx, e); err != nil {
		return err
	}
	// this line creates kvstore table, even if it is not required in accountDBVersion 6 -> 7
	// or in later version where we need kvstore table, some tests will fail
	if err = accountsCreateBoxTable(ctx, e); err != nil {
		return err
	}
	// this adds the resources table and ctype column, even if it is not required in accountDBVersion 6 -> 7
	// this prevents some tests from failing.
	if err = accountsCreateResourceTable(ctx, e); err != nil {
		return err
	}
	if err = accountsAddCreatableTypeColumn(ctx, e, false); err != nil {
		return err
	}
	return createStateProofVerificationTable(ctx, e)
}
