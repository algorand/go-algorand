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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
)

func BenchmarkSQLWrites(b *testing.B) {
	b.StopTimer()

	fn := fmt.Sprintf("/tmp/%s.%d.sqlite", b.Name(), crypto.RandUint64())

	wdb, err := MakeAccessor(fn, false, false)
	require.NoError(b, err)

	logging.Base().SetLevel(logging.Error)

	err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("CREATE TABLE t (a integer primary key, b integer)")
		if err != nil {
			return err
		}

		return nil
	})
	require.NoError(b, err)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.Exec("INSERT INTO t (a, b) VALUES (?, ?)", i, i)
			return err
		})
		require.NoError(b, err)
	}
}

func BenchmarkSQLErasableWrites(b *testing.B) {
	b.StopTimer()

	fn := fmt.Sprintf("/tmp/%s.%d.sqlite", b.Name(), crypto.RandUint64())

	wdb, err := MakeErasableAccessor(fn)
	require.NoError(b, err)
	defer wdb.Close()

	logging.Base().SetLevel(logging.Error)

	err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("CREATE TABLE t (a integer primary key, b integer)")
		if err != nil {
			return err
		}

		return nil
	})
	require.NoError(b, err)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.Exec("INSERT INTO t (a, b) VALUES (?, ?)", i, i)
			return err
		})
		require.NoError(b, err)
	}
}

func BenchmarkSQLQueryAPIs(b *testing.B) {
	fn := fmt.Sprintf("%s.%d", b.Name(), crypto.RandUint64())

	rdb, err := MakeAccessor(fn, true, true)
	require.NoError(b, err)

	wdb, err := MakeAccessor(fn, false, true)
	require.NoError(b, err)

	logging.Base().SetLevel(logging.Error)

	err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("CREATE TABLE t (a integer primary key, b integer)")
		if err != nil {
			return err
		}

		return nil
	})
	require.NoError(b, err)

	b.Run("rdb.Atomic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
				var b int
				err := tx.QueryRow("SELECT b FROM t WHERE a=?", i).Scan(&b)
				if err == sql.ErrNoRows {
					return nil
				}
				return err
			})
			require.NoError(b, err)
		}
	})

	b.Run("wdb.Atomic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
				var r int
				err := tx.QueryRow("SELECT b FROM t WHERE a=?", i).Scan(&r)
				if err == sql.ErrNoRows {
					return nil
				}
				return err
			})
			require.NoError(b, err)
		}
	})

	b.Run("rdb.Atomic/Batch", func(b *testing.B) {
		err = rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			for i := 0; i < b.N; i++ {
				var r int
				err := tx.QueryRow("SELECT b FROM t WHERE a=?", i).Scan(&r)
				if err != sql.ErrNoRows && err != nil {
					return err
				}
			}
			return nil
		})
		require.NoError(b, err)
	})

	b.Run("rdb.Atomic/PrepareBatch", func(b *testing.B) {
		err = rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			stmt, err := tx.Prepare("SELECT b FROM t WHERE a=?")
			if err != nil {
				return err
			}

			for i := 0; i < b.N; i++ {
				var r int
				err := stmt.QueryRow(i).Scan(&r)
				if err != sql.ErrNoRows && err != nil {
					return err
				}
			}

			return nil
		})
		require.NoError(b, err)
	})

	b.Run("rdb.Handle.QueryRow", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var r int
			err := rdb.Handle.QueryRow("SELECT b FROM t WHERE a=?", i).Scan(&r)
			if err != sql.ErrNoRows {
				require.NoError(b, err)
			}
		}
	})

	b.Run("rdb.Handle.Conn.QueryRow", func(b *testing.B) {
		ctx := context.Background()

		for i := 0; i < b.N; i++ {
			conn, err := rdb.Handle.Conn(ctx)
			require.NoError(b, err)

			var r int
			err = conn.QueryRowContext(ctx, "SELECT b FROM t WHERE a=?", i).Scan(&r)
			if err != sql.ErrNoRows {
				require.NoError(b, err)
			}

			err = conn.Close()
			require.NoError(b, err)
		}
	})

	b.Run("rdb.Handle.Tx.QueryRow", func(b *testing.B) {
		ctx := context.Background()
		opts := &sql.TxOptions{
			Isolation: sql.LevelSerializable,
			ReadOnly:  true,
		}

		for i := 0; i < b.N; i++ {
			tx, err := rdb.Handle.BeginTx(ctx, opts)
			require.NoError(b, err)

			var r int
			err = tx.QueryRow("SELECT b FROM t WHERE a=?", i).Scan(&r)
			if err != sql.ErrNoRows {
				require.NoError(b, err)
			}

			err = tx.Rollback()
			require.NoError(b, err)
		}
	})

	b.Run("rdb.Handle.Prepare.QueryRow", func(b *testing.B) {
		stmt, err := rdb.Handle.Prepare("SELECT b FROM t WHERE a=?")
		require.NoError(b, err)

		for i := 0; i < b.N; i++ {
			var r int
			err := stmt.QueryRow(i).Scan(&r)
			if err != sql.ErrNoRows {
				require.NoError(b, err)
			}
		}
	})
}
