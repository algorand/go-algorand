// Copyright (C) 2019-2023 Algorand, Inc.
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

package store

import (
	"context"
	"database/sql"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/stretchr/testify/require"
)

// AccountsInitLightTest initializes an empty database for testing without the extra methods being called.
func AccountsInitLightTest(tb testing.TB, tx *sql.Tx, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error) {
	newDB, err := accountsInit(tx, initAccounts, proto)
	require.NoError(tb, err)
	return newDB, err
}

// AccountsInitTest initializes an empty database for testing.
func AccountsInitTest(tb testing.TB, tx *sql.Tx, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
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

// AccountsUpdateSchemaTest adds some empty tables for tests to work with a "v6" store.
func AccountsUpdateSchemaTest(ctx context.Context, tx *sql.Tx) (err error) {
	if err := accountsCreateOnlineAccountsTable(ctx, tx); err != nil {
		return err
	}
	if err := accountsCreateTxTailTable(ctx, tx); err != nil {
		return err
	}
	if err := accountsCreateOnlineRoundParamsTable(ctx, tx); err != nil {
		return err
	}
	if err := accountsCreateCatchpointFirstStageInfoTable(ctx, tx); err != nil {
		return err
	}
	// this line creates kvstore table, even if it is not required in accountDBVersion 6 -> 7
	// or in later version where we need kvstore table, some tests will fail
	if err := accountsCreateBoxTable(ctx, tx); err != nil {
		return err
	}
	return nil
}
