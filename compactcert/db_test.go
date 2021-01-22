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

package compactcert

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
)

func dbOpenTestRand(t testing.TB, inMemory bool, rnd uint64) (db.Pair, string) {
	fn := fmt.Sprintf("%s.%d", strings.ReplaceAll(t.Name(), "/", "."), rnd)
	dbs, err := db.OpenPair(fn, inMemory)
	require.NoErrorf(t, err, "Filename: %s\nInMemory: %v", fn, inMemory)

	dblogger := logging.TestingLog(t)
	dbs.Rdb.SetLogger(dblogger)
	dbs.Wdb.SetLogger(dblogger)

	return dbs, fn
}

func dbOpenTest(t testing.TB, inMemory bool) (db.Pair, string) {
	return dbOpenTestRand(t, inMemory, crypto.RandUint64())
}

func TestPendingSigDB(t *testing.T) {
	dbs, _ := dbOpenTest(t, true)
	defer dbs.Close()

	err := dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return initDB(tx)
	})
	require.NoError(t, err)

	for r := basics.Round(0); r < basics.Round(100); r++ {
		err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			var psig pendingSig
			crypto.RandBytes(psig.signer[:])
			return addPendingSig(tx, r, psig)
		})
		require.NoError(t, err)

		err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			var psig pendingSig
			crypto.RandBytes(psig.signer[:])
			// watermark signers from this node: 4th byte is zero
			psig.signer[4] = 0
			psig.fromThisNode = true
			return addPendingSig(tx, r, psig)
		})
		require.NoError(t, err)
	}

	for deletedBefore := basics.Round(0); deletedBefore < basics.Round(200); deletedBefore++ {
		err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			return deletePendingSigsBeforeRound(tx, deletedBefore)
		})
		require.NoError(t, err)

		var psigs map[basics.Round][]pendingSig
		var psigsThis map[basics.Round][]pendingSig
		err = dbs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			var err error
			psigs, err = getPendingSigs(tx)
			if err != nil {
				return err
			}

			psigsThis, err = getPendingSigsFromThisNode(tx)
			if err != nil {
				return err
			}

			return nil
		})
		require.NoError(t, err)

		expectedLen := 100 - int(deletedBefore)
		if expectedLen < 0 {
			expectedLen = 0
		}

		require.Equal(t, len(psigs), expectedLen)
		require.Equal(t, len(psigsThis), expectedLen)

		for r := deletedBefore; r < basics.Round(100); r++ {
			require.Equal(t, len(psigs[r]), 2)
			require.Equal(t, len(psigsThis[r]), 1)
			require.Equal(t, psigsThis[r][0].signer[4], byte(0))
		}
	}
}
