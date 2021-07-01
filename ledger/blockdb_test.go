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

package ledger

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/testpartitioning"
	"github.com/algorand/go-algorand/util/db"
)

func dbOpenTest(t testing.TB, inMemory bool) (db.Pair, string) {
	fn := fmt.Sprintf("%s.%d", strings.ReplaceAll(t.Name(), "/", "."), crypto.RandUint64())
	dbs, err := db.OpenPair(fn, inMemory)
	require.NoErrorf(t, err, "Filename : %s\nInMemory: %v", fn, inMemory)
	return dbs, fn
}

func randomBlock(r basics.Round) blockEntry {
	b := bookkeeping.Block{}
	c := agreement.Certificate{}

	b.BlockHeader.Round = r
	b.BlockHeader.TimeStamp = int64(crypto.RandUint64())
	b.RewardsPool = testPoolAddr
	b.FeeSink = testSinkAddr
	c.Round = r

	return blockEntry{
		block: b,
		cert:  c,
	}
}

func randomInitChain(proto protocol.ConsensusVersion, nblock int) []blockEntry {
	res := make([]blockEntry, 0)
	for i := 0; i < nblock; i++ {
		blkent := randomBlock(basics.Round(i))
		blkent.cert = agreement.Certificate{}
		blkent.block.CurrentProtocol = proto
		res = append(res, blkent)
	}
	return res
}

func blockChainBlocks(be []blockEntry) []bookkeeping.Block {
	res := make([]bookkeeping.Block, 0)
	for _, e := range be {
		res = append(res, e.block)
	}
	return res
}

func checkBlockDB(t *testing.T, tx *sql.Tx, blocks []blockEntry) {
	next, err := blockNext(tx)
	require.NoError(t, err)
	require.Equal(t, next, basics.Round(len(blocks)))

	latest, err := blockLatest(tx)
	if len(blocks) == 0 {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
		require.Equal(t, latest, basics.Round(len(blocks))-1)
	}

	earliest, err := blockEarliest(tx)
	if len(blocks) == 0 {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
		require.Equal(t, earliest, blocks[0].block.BlockHeader.Round)
	}

	for rnd := basics.Round(0); rnd < basics.Round(len(blocks)); rnd++ {
		blk, err := blockGet(tx, rnd)
		require.NoError(t, err)
		require.Equal(t, blk, blocks[rnd].block)

		blk, cert, err := blockGetCert(tx, rnd)
		require.NoError(t, err)
		require.Equal(t, blk, blocks[rnd].block)
		require.Equal(t, cert, blocks[rnd].cert)
	}

	_, err = blockGet(tx, basics.Round(len(blocks)))
	require.Error(t, err)
}

func setDbLogging(t testing.TB, dbs db.Pair) {
	dblogger := logging.TestingLog(t)
	dbs.Rdb.SetLogger(dblogger)
	dbs.Wdb.SetLogger(dblogger)
}

func TestBlockDBEmpty(t *testing.T) {
	testpartitioning.PartitionTest(t)

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	err = blockInit(tx, nil)
	require.NoError(t, err)
	checkBlockDB(t, tx, nil)
}

func TestBlockDBInit(t *testing.T) {
	testpartitioning.PartitionTest(t)

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	blocks := randomInitChain(protocol.ConsensusCurrentVersion, 10)

	err = blockInit(tx, blockChainBlocks(blocks))
	require.NoError(t, err)
	checkBlockDB(t, tx, blocks)

	err = blockInit(tx, blockChainBlocks(blocks))
	require.NoError(t, err)
	checkBlockDB(t, tx, blocks)
}

func TestBlockDBAppend(t *testing.T) {
	testpartitioning.PartitionTest(t)

	dbs, _ := dbOpenTest(t, true)
	setDbLogging(t, dbs)
	defer dbs.Close()

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	defer tx.Rollback()

	blocks := randomInitChain(protocol.ConsensusCurrentVersion, 10)

	err = blockInit(tx, blockChainBlocks(blocks))
	require.NoError(t, err)
	checkBlockDB(t, tx, blocks)

	for i := 0; i < 10; i++ {
		blkent := randomBlock(basics.Round(len(blocks)))
		err = blockPut(tx, blkent.block, blkent.cert)
		require.NoError(t, err)

		blocks = append(blocks, blkent)
		checkBlockDB(t, tx, blocks)
	}
}
