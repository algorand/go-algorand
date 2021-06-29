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

package db

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
   "github.com/algorand/go-algorand/testPartitioning"
)

func testVersioning(t *testing.T, inMemory bool) {
	acc, err := MakeAccessor("fn.db", false, inMemory)
	require.NoError(t, err)
	if !inMemory {
		defer os.Remove("fn.db")
		defer os.Remove("fn.db-shm")
		defer os.Remove("fn.db-wal")
	}

	conn, err := acc.Handle.Conn(context.Background())
	require.NoError(t, err)

	tx, err := conn.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: false})
	require.NoError(t, err)

	ver, err := GetUserVersion(context.Background(), tx)
	require.NoError(t, err)
	require.Equal(t, int32(0), ver)

	previousVersion, err := SetUserVersion(context.Background(), tx, 5)
	require.NoError(t, err)
	require.Equal(t, int32(0), previousVersion)

	previousVersion, err = SetUserVersion(context.Background(), tx, 9)
	require.NoError(t, err)
	require.Equal(t, int32(5), previousVersion)

	// check that expired context doesn't work:
	expiredContext, expiredContextCancelFunc := context.WithCancel(context.Background())
	expiredContextCancelFunc()
	ver, err = GetUserVersion(expiredContext, tx)
	require.Equal(t, expiredContext.Err(), err)
	require.Equal(t, int32(0), ver)

	ver, err = SetUserVersion(expiredContext, tx, 15)
	require.Equal(t, expiredContext.Err(), err)
	require.Equal(t, int32(0), ver)

	tx.Commit()

	tx, err = conn.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: false})
	require.NoError(t, err)

	previousVersion, err = SetUserVersion(context.Background(), tx, 2)
	require.NoError(t, err)
	require.Equal(t, int32(9), previousVersion)

	tx.Rollback()

	tx, err = conn.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: false})
	require.NoError(t, err)

	ver, err = GetUserVersion(context.Background(), tx)
	require.NoError(t, err)
	require.Equal(t, int32(9), ver)

	tx.Commit()

	conn.Close()
	acc.Close()

}

func TestVersioning(t *testing.T) {
   testPartitioning.PartitionTest(t)

	t.Run("InMem", func(t *testing.T) { testVersioning(t, true) })
	t.Run("OnDisk", func(t *testing.T) { testVersioning(t, false) })
}
