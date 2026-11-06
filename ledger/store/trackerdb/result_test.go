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

package trackerdb_test

import (
	"context"
	"testing"

	"github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/sqlitedriver"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// busyOnce returns a function that fails its first attempt with an error the store retries,
// after appending to its result, so a caller that kept that result would see it.
func busyOnce() func() ([]int, error) {
	attempts := 0
	return func() ([]int, error) {
		var res []int
		attempts++
		res = append(res, attempts)
		if attempts == 1 {
			return res, sqlite3.Error{Code: sqlite3.ErrBusy}
		}
		return res, nil
	}
}

func TestStoreResultHelpers(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	store, _ := sqlitedriver.OpenForTesting(t, true)
	defer store.Close()

	attempt := busyOnce()
	res, err := trackerdb.TransactionResult(store, func(ctx context.Context, tx trackerdb.TransactionScope) ([]int, error) {
		return attempt()
	})
	require.NoError(t, err)
	require.Equal(t, []int{2}, res)

	attempt = busyOnce()
	res, err = trackerdb.SnapshotResult(store, func(ctx context.Context, tx trackerdb.SnapshotScope) ([]int, error) {
		return attempt()
	})
	require.NoError(t, err)
	require.Equal(t, []int{2}, res)

	attempt = busyOnce()
	res, err = trackerdb.BatchResult(store, func(ctx context.Context, tx trackerdb.BatchScope) ([]int, error) {
		return attempt()
	})
	require.NoError(t, err)
	require.Equal(t, []int{2}, res)
}
