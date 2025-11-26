// Copyright (C) 2019-2025 Algorand, Inc.
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

package stateproof

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
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

func TestDbSchemaUpgrade1(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	dbs, _ := dbOpenTest(t, true)
	defer dbs.Close()

	migrations := []db.Migration{
		dbSchemaUpgrade0,
		dbSchemaUpgrade1,
	}

	a.NoError(db.Initialize(dbs.Wdb, migrations[:1]))

	// performing a request on sig db.
	a.NoError(dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var psig pendingSig
		crypto.RandBytes(psig.signer[:])
		return addPendingSig(tx, 0, psig)
	}))

	p := spProver{Prover: &stateproof.Prover{}}
	p.ProvenWeight = 5
	a.ErrorContains(dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return persistProver(tx, 0, &p)
	}), "no such table: provers")

	// migrating the DB to the next version.
	a.NoError(makeStateProofDB(dbs.Wdb))

	a.NoError(dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return persistProver(tx, 0, &p)
	}))

	var p2 spProver
	a.NoError(dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var err error
		p2, err = getProver(tx, 0)
		return err
	}))
	a.Equal(p.ProverPersistedFields, p2.ProverPersistedFields)
}

func TestPendingSigDB(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := dbOpenTest(t, true)
	defer dbs.Close()

	err := makeStateProofDB(dbs.Wdb)
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
			psigs, err = getPendingSigs(tx, basics.Round(100), basics.Round(100), false)
			if err != nil {
				return err
			}

			psigsThis, err = getPendingSigs(tx, basics.Round(100), basics.Round(100), true)
			if err != nil {
				return err
			}

			return nil
		})
		require.NoError(t, err)

		expectedLen := max(100-int(deletedBefore), 0)

		require.Equal(t, len(psigs), expectedLen)
		require.Equal(t, len(psigsThis), expectedLen)

		for r := deletedBefore; r < basics.Round(100); r++ {
			require.Equal(t, len(psigs[r]), 2)
			require.Equal(t, len(psigsThis[r]), 1)
			require.Equal(t, psigsThis[r][0].signer[4], byte(0))
		}
	}
}

func TestSigExistQuery(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := dbOpenTest(t, true)
	defer dbs.Close()

	require.NoError(t, makeStateProofDB(dbs.Wdb))

	n := 8
	var accts []basics.Address
	// setup:
	for r := basics.Round(0); r < basics.Round(n); r++ {
		var psig pendingSig
		crypto.RandBytes(psig.signer[:])
		accts = append(accts, psig.signer)

		require.NoError(t, dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			return addPendingSig(tx, r, psig)
		}))
	}

	// all addresses have signed the message so sigExistsInDB should result with true:
	for r := basics.Round(0); r < basics.Round(n/2); r++ {
		require.NoError(t, dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			exists, err := sigExistsInDB(tx, r, accts[r])
			require.NoError(t, err)
			require.True(t, exists)
			return nil
		}))
	}

	// a "wrongAddress" should not have signatures in the dabase
	require.NoError(t, dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		wrongAddress := accts[0]
		var actCopy basics.Address
		copy(actCopy[:], wrongAddress[:])
		actCopy[0]++
		exists, err := sigExistsInDB(tx, 0, actCopy)
		require.NoError(t, err)
		require.False(t, exists)
		return nil
	}))

	require.NoError(t, dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return deletePendingSigsBeforeRound(tx, basics.Round(n))
	}))

	for r := basics.Round(n / 2); r < basics.Round(n); r++ {
		require.NoError(t, dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			exists, err := sigExistsInDB(tx, r, accts[r])
			require.NoError(t, err)
			require.False(t, exists)
			return nil
		}))
	}
}

func TestProversDB(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	dbs, _ := dbOpenTest(t, true)
	defer dbs.Close()
	err := makeStateProofDB(dbs.Wdb)
	a.NoError(err)

	provers := make([]spProver, 100)
	for i := uint64(0); i < 100; i++ {
		var prover spProver
		prover.Prover = &stateproof.Prover{}
		prover.Round = i
		provers[i] = prover

		err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			return persistProver(tx, basics.Round(i), &provers[i])
		})
		a.NoError(err)
	}

	var count int
	err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		err = tx.QueryRow("SELECT count(1) FROM provers").Scan(&count)
		return err
	})
	a.NoError(err)
	a.Equal(100, count)

	err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return deleteProvers(tx, basics.Round(35))
	})
	a.NoError(err)
	err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		err = tx.QueryRow("SELECT count(1) FROM provers").Scan(&count)
		return err
	})
	a.NoError(err)
	a.Equal(100-35, count)

	var prover spProver
	err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		prover, err = getProver(tx, basics.Round(34))
		return err
	})
	a.ErrorIs(err, sql.ErrNoRows)

	err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		prover, err = getProver(tx, basics.Round(35))
		return err
	})
	a.NoError(err)
	a.Equal(uint64(35), prover.Round)
}

func TestDbProverAlreadyExists(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	dbs, _ := dbOpenTest(t, true)
	defer dbs.Close()
	err := makeStateProofDB(dbs.Wdb)
	a.NoError(err)

	var prover spProver
	var outProv spProver

	prover.Prover = &stateproof.Prover{}
	prover.Round = 2
	prover.Data[3] = 5

	for i := 0; i < 2; i++ {
		err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			return persistProver(tx, basics.Round(2), &prover)
		})
		a.NoError(err)
		err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			outProv, err = getProver(tx, basics.Round(2))
			return err
		})
		a.NoError(err)
		a.Equal(prover.ProverPersistedFields, outProv.ProverPersistedFields)
	}
}
