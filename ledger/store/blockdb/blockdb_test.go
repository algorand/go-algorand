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

	for rnd := basics.Round(0); rnd < basics.Round(len(blocks)); rnd++ {
		blk, err := BlockGet(tx, rnd)
		require.NoError(t, err)
		require.Equal(t, blk, blocks[rnd].block)

		blk, cert, err := BlockGetCert(tx, rnd)
		require.NoError(t, err)
		require.Equal(t, blk, blocks[rnd].block)
		require.Equal(t, cert, blocks[rnd].cert)
	}

	_, err = BlockGet(tx, basics.Round(len(blocks)))
	require.Error(t, err)
}

func blockChainBlocks(be []testBlockEntry) []bookkeeping.Block {
	res := make([]bookkeeping.Block, 0)
	for _, e := range be {
		res = append(res, e.block)
	}
	return res
}

// blockDBTestWindows returns the compression windows every blockdb test case
// should sweep across: the disabled codec, per-row zstd, and a small windowed
// zstd codec. The N=4 case exercises both anchor and continuation rows when
// a test inserts more than N blocks.
func blockDBTestWindows() []uint64 {
	return []uint64{
		0, // disabled: rows stored verbatim
		1, // per-row zstd: each row is its own frame
		4, // windowed: anchor every 4 rounds
	}
}

func windowLabel(window uint64) string {
	switch window {
	case 0:
		return "disabled"
	case 1:
		return "perrow"
	default:
		return "windowed"
	}
}

func TestBlockDBEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, window := range blockDBTestWindows() {
		t.Run(windowLabel(window), func(t *testing.T) {
			dbs, _ := storetesting.DbOpenTest(t, true)
			storetesting.SetDbLogging(t, dbs)
			defer dbs.Close()

			tx, err := dbs.Wdb.Handle.Begin()
			require.NoError(t, err)
			defer tx.Rollback()

			writer := NewBlockWriter(window)
			defer writer.Close()
			err = BlockInit(tx, nil, writer)
			require.NoError(t, err)
			checkBlockDB(t, tx, nil)
		})
	}
}

func TestBlockDBInit(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, window := range blockDBTestWindows() {
		t.Run(windowLabel(window), func(t *testing.T) {
			dbs, _ := storetesting.DbOpenTest(t, true)
			storetesting.SetDbLogging(t, dbs)
			defer dbs.Close()

			tx, err := dbs.Wdb.Handle.Begin()
			require.NoError(t, err)
			defer tx.Rollback()

			blocks := randomInitChain(protocol.ConsensusCurrentVersion, 10)

			writer := NewBlockWriter(window)
			defer writer.Close()
			err = BlockInit(tx, blockChainBlocks(blocks), writer)
			require.NoError(t, err)
			checkBlockDB(t, tx, blocks)

			err = BlockInit(tx, blockChainBlocks(blocks), writer)
			require.NoError(t, err)
			checkBlockDB(t, tx, blocks)
		})
	}
}

func TestBlockDBAppend(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, window := range blockDBTestWindows() {
		t.Run(windowLabel(window), func(t *testing.T) {
			dbs, _ := storetesting.DbOpenTest(t, true)
			storetesting.SetDbLogging(t, dbs)
			defer dbs.Close()

			tx, err := dbs.Wdb.Handle.Begin()
			require.NoError(t, err)
			defer tx.Rollback()

			blocks := randomInitChain(protocol.ConsensusCurrentVersion, 10)

			writer := NewBlockWriter(window)
			defer writer.Close()
			err = BlockInit(tx, blockChainBlocks(blocks), writer)
			require.NoError(t, err)
			checkBlockDB(t, tx, blocks)

			for i := 0; i < 10; i++ {
				blkent := randomBlock(basics.Round(len(blocks)))
				err = BlockPut(tx, &blkent.block, &blkent.cert, writer)
				require.NoError(t, err)

				blocks = append(blocks, blkent)
				checkBlockDB(t, tx, blocks)
			}
		})
	}
}

// TestBlockDBAddWindowStartMigration verifies BlockInit can bring a master
// shaped table (no window_start column, rows stored as raw msgp) up to the
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

	// Create the pre-codec schema (no window_start column) and insert two
	// rows of raw msgp, mirroring how a master-built DB would look.
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
	writer := NewBlockWriter(4)
	defer writer.Close()
	require.NoError(t, BlockInit(tx, nil, writer))
	require.NoError(t, BlockInit(tx, nil, writer))

	var hasWindowStart bool
	rows, err := tx.Query("PRAGMA table_info(blocks)")
	require.NoError(t, err)
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		require.NoError(t, rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk))
		if name == "window_start" {
			hasWindowStart = true
		}
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	require.True(t, hasWindowStart, "window_start column should have been added by migration")

	// Existing rows must remain readable through the unified read path; the
	// inner SELECT picks up NULL window_start and the outer scan collapses
	// to a single-row legacy-raw lookup.
	checkBlockDB(t, tx, blocks)
}
