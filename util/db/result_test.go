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

package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// errBusy is an error that Retry and Atomic retry.
var errBusy = sqlite3.Error{Code: sqlite3.ErrBusy}

// busyOnce returns a function that fails its first attempt with a retryable error after
// appending to its result, so a caller that kept that result would see it.
func busyOnce() func() ([]int, error) {
	attempts := 0
	return func() ([]int, error) {
		var res []int
		attempts++
		res = append(res, attempts)
		if attempts == 1 {
			return res, errBusy
		}
		return res, nil
	}
}

func TestRetryResult(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	attempt := busyOnce()
	res, err := RetryResult(func() ([]int, error) { return attempt() })
	require.NoError(t, err)
	require.Equal(t, []int{2}, res)
}

func TestAtomicResult(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	acc, err := MakeAccessor("atomicresult.db", false, true)
	require.NoError(t, err)
	defer acc.Close()

	attempt := busyOnce()
	res, err := AtomicResult(&acc, func(ctx context.Context, tx *sql.Tx) ([]int, error) {
		return attempt()
	})
	require.NoError(t, err)
	require.Equal(t, []int{2}, res)

	// retryClearFn still runs between attempts.
	attempt = busyOnce()
	cleared := 0
	res, err = AtomicContextResult(context.Background(), &acc, func(ctx context.Context, tx *sql.Tx) ([]int, error) {
		return attempt()
	}, func(context.Context) { cleared++ })
	require.NoError(t, err)
	require.Equal(t, []int{2}, res)
	require.Equal(t, 1, cleared)
}

func TestAtomicResultOnError(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	acc, err := MakeAccessor("atomicresulterr.db", false, true)
	require.NoError(t, err)
	defer acc.Close()

	// When fn fails, its result is returned along with its error.
	errFn := errors.New("fn failed")
	res, err := AtomicResult(&acc, func(ctx context.Context, tx *sql.Tx) ([]int, error) {
		return []int{1}, errFn
	})
	require.ErrorIs(t, err, errFn)
	require.Equal(t, []int{1}, res)

	// When fn succeeds but its transaction is not committed, the result is not returned. Rolling
	// back inside fn makes the commit fail.
	res, err = AtomicResult(&acc, func(ctx context.Context, tx *sql.Tx) ([]int, error) {
		require.NoError(t, tx.Rollback())
		return []int{1}, nil
	})
	require.ErrorIs(t, err, sql.ErrTxDone)
	require.Nil(t, res)
}
