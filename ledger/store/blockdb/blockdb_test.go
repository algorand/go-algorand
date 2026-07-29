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

package blockdb

import (
	"database/sql"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	storetesting "github.com/algorand/go-algorand/ledger/store/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

var testPoolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var testSinkAddr = basics.Address{0x2c, 0x2a, 0x6c, 0xe9, 0xa9, 0xa7, 0xc2, 0x8c, 0x22, 0x95, 0xfd, 0x32, 0x4f, 0x77, 0xa5, 0x4, 0x8b, 0x42, 0xc2, 0xb7, 0xa8, 0x54, 0x84, 0xb6, 0x80, 0xb1, 0xe1, 0x3d, 0x59, 0x9b, 0xeb, 0x36}

type testBlockEntry struct {
	block bookkeeping.Block
	cert  agreement.Certificate
}

func randomBlock(r basics.Round) testBlockEntry {
	b := bookkeeping.Block{}
	c := agreement.Certificate{}

	b.BlockHeader.Round = r
	b.BlockHeader.TimeStamp = int64(crypto.RandUint64())
	b.RewardsPool = testPoolAddr
	b.FeeSink = testSinkAddr
	c.Round = r

	return testBlockEntry{
		block: b,
		cert:  c,
	}
}

func randomInitChain(proto protocol.ConsensusVersion, nblock int) []testBlockEntry {
	res := make([]testBlockEntry, 0)
	for i := 0; i < nblock; i++ {
		blkent := randomBlock(basics.Round(i))
		blkent.cert = agreement.Certificate{}
		blkent.block.CurrentProtocol = proto
		res = append(res, blkent)
	}
	return res
}

func checkBlockDB(t *testing.T, tx *sql.Tx, blocks []testBlockEntry) {
	next, err := BlockNext(tx)
	require.NoError(t, err)
	require.Equal(t, next, basics.Round(len(blocks)))

	latest, err := BlockLatest(tx)
	if len(blocks) == 0 {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
		require.Equal(t, latest, basics.Round(len(blocks))-1)
	}

	earliest, err := BlockEarliest(tx)
	if len(blocks) == 0 {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
		require.Equal(t, earliest, blocks[0].block.BlockHeader.Round)
	}

	reader, err := NewReader(tx)
	require.NoError(t, err)

	for rnd := basics.Round(0); rnd < basics.Round(len(blocks)); rnd++ {
		blk, err := reader.BlockGet(tx, rnd)
		require.NoError(t, err)
		require.Equal(t, blk, blocks[rnd].block)

		blk, cert, err := reader.BlockGetCert(tx, rnd)
		require.NoError(t, err)
		require.Equal(t, blk, blocks[rnd].block)
		require.Equal(t, cert, blocks[rnd].cert)
	}

	_, err = reader.BlockGet(tx, basics.Round(len(blocks)))
	require.Error(t, err)
}

func blockChainBlocks(be []testBlockEntry) []bookkeeping.Block {
	res := make([]bookkeeping.Block, 0)
	for _, e := range be {
		res = append(res, e.block)
	}
	return res
}

// blockDBTestWindows is the compression windows every blockdb test sweeps
// across: disabled (0), per-row zstd (1), and a small windowed zstd (4).
// N=4 exercises both anchor and continuation rows when a test inserts more
// than N blocks.
var blockDBTestWindows = []uint64{0, 1, 4}

func TestBlockDBEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, window := range blockDBTestWindows {
		t.Run(strconv.FormatUint(window, 10), func(t *testing.T) {
			dbs, _ := storetesting.DbOpenTest(t, true)
			storetesting.SetDbLogging(t, dbs)
			defer dbs.Close()

			tx, err := dbs.Wdb.Handle.Begin()
			require.NoError(t, err)
			defer tx.Rollback()

			err = BlockInit(tx, nil, window)
			require.NoError(t, err)
			checkBlockDB(t, tx, nil)
		})
	}
}

func TestBlockDBInit(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, window := range blockDBTestWindows {
		t.Run(strconv.FormatUint(window, 10), func(t *testing.T) {
			dbs, _ := storetesting.DbOpenTest(t, true)
			storetesting.SetDbLogging(t, dbs)
			defer dbs.Close()

			tx, err := dbs.Wdb.Handle.Begin()
			require.NoError(t, err)
			defer tx.Rollback()

			blocks := randomInitChain(protocol.ConsensusCurrentVersion, 10)

			err = BlockInit(tx, blockChainBlocks(blocks), window)
			require.NoError(t, err)
			checkBlockDB(t, tx, blocks)

			err = BlockInit(tx, blockChainBlocks(blocks), window)
			require.NoError(t, err)
			checkBlockDB(t, tx, blocks)
		})
	}
}

func TestBlockDBAppend(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, window := range blockDBTestWindows {
		t.Run(strconv.FormatUint(window, 10), func(t *testing.T) {
			dbs, _ := storetesting.DbOpenTest(t, true)
			storetesting.SetDbLogging(t, dbs)
			defer dbs.Close()

			tx, err := dbs.Wdb.Handle.Begin()
			require.NoError(t, err)
			defer tx.Rollback()

			blocks := randomInitChain(protocol.ConsensusCurrentVersion, 10)

			err = BlockInit(tx, blockChainBlocks(blocks), window)
			require.NoError(t, err)
			checkBlockDB(t, tx, blocks)

			store, err := NewStore(tx, window)
			require.NoError(t, err)
			defer store.Close()

			for i := 0; i < 10; i++ {
				blkent := randomBlock(basics.Round(len(blocks)))
				err = store.BlockPut(tx, &blkent.block, &blkent.cert)
				require.NoError(t, err)

				blocks = append(blocks, blkent)
				checkBlockDB(t, tx, blocks)
			}
		})
	}
}

// TestBlockDBAddWindowStartMigration verifies BlockInit can bring a pre-compression
// blocks table (no window_start column, rows stored as raw msgp) up to the
// current schema. After the ALTER TABLE migration the rows must still be
// readable through the unified read path, and BlockNext must report the
// preexisting MAX(rnd)+1.
func TestBlockDBAddWindowStartMigration(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := storetesting.DbOpenTest(t, true)
	storetesting.SetDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	// Create the pre-compression schema (no window_start column) and insert two
	// rows of raw msgp, mirroring how an earlier-release DB would look.
	_, err = tx.Exec(`CREATE TABLE blocks (
		rnd integer primary key,
		proto text,
		hdrdata blob,
		blkdata blob,
		certdata blob)`)
	require.NoError(t, err)

	blocks := randomInitChain(protocol.ConsensusCurrentVersion, 2)
	for i := range blocks {
		blk := blocks[i].block
		cert := blocks[i].cert
		_, err = tx.Exec("INSERT INTO blocks (rnd, proto, hdrdata, blkdata, certdata) VALUES (?, ?, ?, ?, ?)",
			blk.Round(),
			blk.CurrentProtocol,
			protocol.Encode(&blk.BlockHeader),
			protocol.Encode(&blk),
			protocol.Encode(&cert),
		)
		require.NoError(t, err)
	}

	// BlockInit should add window_start (NULL on the existing rows) and
	// leave the table otherwise intact. Calling it twice must be a no-op.
	require.NoError(t, BlockInit(tx, nil, 4))
	require.NoError(t, BlockInit(tx, nil, 4))

	hasCol, err := tableHasColumn(tx, "blocks", "window_start")
	require.NoError(t, err)
	require.True(t, hasCol, "window_start column should have been added by migration")

	// Existing rows must remain readable through the unified read path; the
	// inner SELECT picks up NULL window_start and the outer scan collapses
	// to a single-row legacy-raw lookup.
	checkBlockDB(t, tx, blocks)
}

// TestBlockDBMigrateCatchpointBlocks verifies that a leftover catchpointblocks
// table from a partial pre-compression catchpoint catchup is migrated to the new
// schema on startup. Without this migration, a resume that skips
// BlockStartCatchupStaging would carry a column-less catchpointblocks all
// the way through BlockCompleteCatchup and break the post-rename blocks
// table for subsequent BlockPut calls.
func TestBlockDBMigrateCatchpointBlocks(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := storetesting.DbOpenTest(t, true)
	storetesting.SetDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	// Pre-compression catchpointblocks schema (no window_start), as a partial
	// catchup started on an earlier release would have produced.
	_, err = tx.Exec(`CREATE TABLE catchpointblocks (
		rnd integer primary key,
		proto text,
		hdrdata blob,
		blkdata blob,
		certdata blob)`)
	require.NoError(t, err)

	// BlockInit must migrate both blocks and catchpointblocks. The blocks
	// table is created fresh with the new schema, so this exercises the
	// "ALTER if exists" branch of addWindowStartColumn against catchpointblocks.
	require.NoError(t, BlockInit(tx, nil, 4))

	hasCol, err := tableHasColumn(tx, "catchpointblocks", "window_start")
	require.NoError(t, err)
	require.True(t, hasCol, "catchpointblocks must have window_start after migration")

	// Re-running is a no-op (the column-present branch returns early).
	require.NoError(t, BlockInit(tx, nil, 4))
}

// TestBlockDBMigrateCatchpointBlocksNotPresent verifies the migration is a
// no-op when catchpointblocks does not exist, which is the common case (no
// catchpoint catchup in progress).
func TestBlockDBMigrateCatchpointBlocksNotPresent(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := storetesting.DbOpenTest(t, true)
	storetesting.SetDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	require.NoError(t, BlockInit(tx, nil, 0))

	// catchpointblocks must not have been created as a side effect.
	var n int
	err = tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='catchpointblocks'`).Scan(&n)
	require.NoError(t, err)
	require.Equal(t, 0, n)
}
