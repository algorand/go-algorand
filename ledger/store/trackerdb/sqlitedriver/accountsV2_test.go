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

package sqlitedriver

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

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

func TestMigration10to11ZeroBytesAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := DbOpenTrackerTest(t, true)
	defer dbs.Close()
	dbs.SetLogger(logging.TestingLog(t))

	// initialize the db and run migrations up to v10 (right before the one we care testing)
	params := trackerdb.Params{}
	err := dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {
		_, err := tx.Testing().RunMigrations(ctx, params, logging.TestingLog(t), 10)
		require.NoError(t, err)

		return nil
	})
	require.NoError(t, err)

	validAddr := ledgertesting.RandomAddress()
	// insert accounts
	err = dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {
		aow, err := tx.MakeAccountsOptimizedWriter(true, false, false, false)
		require.NoError(t, err)

		// insert valid account
		// empty structs product 1-byte records []byte(0x80)
		_, err = aow.InsertAccount(validAddr, 0, trackerdb.BaseAccountData{})
		require.NoError(t, err)

		return nil
	})
	require.NoError(t, err)

	// force insertion of a 0-byte record
	castedDB := dbs.(*trackerSQLStore)
	invalidAddr := ledgertesting.RandomAddress()
	_, err = castedDB.pair.Wdb.Handle.Exec("INSERT INTO accountbase (address, data) VALUES (?, ?)", invalidAddr[:], []byte{})
	require.NoError(t, err)
	// force insertion of a nil data record
	invalidAddr2 := ledgertesting.RandomAddress()
	_, err = castedDB.pair.Wdb.Handle.Exec("INSERT INTO accountbase (address, data) VALUES (?, ?)", invalidAddr2[:], nil)
	require.NoError(t, err)

	// check accounts are both there before migration
	err = dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {
		awr, err := tx.MakeAccountsReaderWriter()
		require.NoError(t, err)

		accountsCount, err := awr.TotalAccounts(ctx)
		require.NoError(t, err)
		require.Equal(t, uint64(3), accountsCount)

		return nil
	})
	require.NoError(t, err)

	// migrate the db to v11 (this will delete empty accounts records)
	params = trackerdb.Params{}
	err = dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {
		_, err := tx.Testing().RunMigrations(ctx, params, logging.TestingLog(t), 11)
		require.NoError(t, err)

		return nil
	})
	require.NoError(t, err)

	// check empty accounts are gone
	err = dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {
		aor, err := tx.Testing().MakeAccountsOptimizedReader()
		require.NoError(t, err)

		awr, err := tx.MakeAccountsReaderWriter()
		require.NoError(t, err)

		// check total accounts
		accountsCount, err := awr.TotalAccounts(ctx)
		require.NoError(t, err)
		require.Equal(t, uint64(1), accountsCount)

		// read the valid record
		pad, err := aor.LookupAccount(validAddr)
		require.NoError(t, err)
		require.NotNil(t, pad.Ref)

		// attempt to read the invalid record
		pad, err = aor.LookupAccount(invalidAddr)
		require.NoError(t, err)
		require.Nil(t, pad.Ref)

		// attempt to read the (other) invalid record
		pad, err = aor.LookupAccount(invalidAddr2)
		require.NoError(t, err)
		require.Nil(t, pad.Ref)

		return nil
	})
	require.NoError(t, err)
}
