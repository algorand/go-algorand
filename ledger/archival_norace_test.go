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
//
// +build !race

package ledger

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// This test cannot be run with `go test -race` because other threads
// calling .Unlock() on a deadlock Mutex are incompatible with this
// setting at the top of the test to disable deadlock detection, and
// deadlock detection must be off or this test will be too slow and
// timeout on some test servers.
func TestArchivalFromNonArchival(t *testing.T) {
	// Start in non-archival mode, add 2K blocks, restart in archival mode ensure only genesis block is there
	deadlockDisable := deadlock.Opts.Disable
	deadlock.Opts.Disable = true
	defer func() {
		deadlock.Opts.Disable = deadlockDisable
	}()
	dbTempDir, err := ioutil.TempDir(os.TempDir(), "testdir")
	require.NoError(t, err)
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	dbPrefix := filepath.Join(dbTempDir, dbName)
	defer os.RemoveAll(dbTempDir)

	genesisInitState := getInitState()

	genesisInitState.Block.BlockHeader.GenesisHash = crypto.Digest{}
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusFuture
	genesisInitState.GenesisHash = crypto.Digest{1}
	genesisInitState.Block.BlockHeader.GenesisHash = crypto.Digest{1}

	balanceRecords := []basics.BalanceRecord{}

	for i := 0; i < 50; i++ {
		addr := basics.Address{}
		_, err = rand.Read(addr[:])
		require.NoError(t, err)
		br := basics.BalanceRecord{AccountData: basics.MakeAccountData(basics.Offline, basics.MicroAlgos{Raw: 1234567890}), Addr: addr}
		genesisInitState.Accounts[addr] = br.AccountData
		balanceRecords = append(balanceRecords, br)
	}

	const inMem = false // use persistent storage
	cfg := config.GetDefaultLocal()
	cfg.Archival = false

	log := logging.TestingLog(t)
	l, err := OpenLedger(log, dbPrefix, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	blk := genesisInitState.Block

	const maxBlocks = 2000
	for i := 0; i < maxBlocks; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		blk.Payset = transactions.Payset{}

		for j := 0; j < 5; j++ {
			x := (j + i) % len(balanceRecords)
			creatorEncoded := balanceRecords[x].Addr.String()
			tx, err := makeUnsignedAssetCreateTx(blk.BlockHeader.Round-1, blk.BlockHeader.Round+3, 100, false, creatorEncoded, creatorEncoded, creatorEncoded, creatorEncoded, "m", "m", "", nil)
			require.NoError(t, err)
			tx.Sender = balanceRecords[x].Addr
			stxnib := makeSignedTxnInBlock(tx)
			blk.Payset = append(blk.Payset, stxnib)
			blk.BlockHeader.TxnCounter++
		}

		err := l.AddBlock(blk, agreement.Certificate{})
		require.NoError(t, err)
	}
	l.WaitForCommit(blk.Round())

	var latest, earliest basics.Round
	err = l.blockDBs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		latest, err = blockLatest(tx)
		require.NoError(t, err)

		earliest, err = blockEarliest(tx)
		require.NoError(t, err)
		return err
	})
	require.NoError(t, err)
	require.Equal(t, basics.Round(maxBlocks), latest)
	require.True(t, basics.Round(0) < earliest, fmt.Sprintf("%d < %d", basics.Round(0), earliest))

	// close and reopen the same DB, ensure the DB truncated
	l.Close()

	cfg.Archival = true
	l, err = OpenLedger(log, dbPrefix, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	err = l.blockDBs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		latest, err = blockLatest(tx)
		require.NoError(t, err)

		earliest, err = blockEarliest(tx)
		require.NoError(t, err)
		return err
	})
	require.NoError(t, err)
	require.Equal(t, basics.Round(0), earliest)
	require.Equal(t, basics.Round(0), latest)
}
