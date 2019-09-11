// Copyright (C) 2019 Algorand, Inc.
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
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type wrappedLedger struct {
	l               *Ledger
	minQueriedBlock basics.Round
}

func (wl *wrappedLedger) recordBlockQuery(rnd basics.Round) {
	if rnd < wl.minQueriedBlock {
		wl.minQueriedBlock = rnd
	}
}

func (wl *wrappedLedger) Block(rnd basics.Round) (bookkeeping.Block, error) {
	wl.recordBlockQuery(rnd)
	return wl.l.Block(rnd)
}

func (wl *wrappedLedger) BlockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	wl.recordBlockQuery(rnd)
	return wl.l.BlockHdr(rnd)
}

func (wl *wrappedLedger) blockAux(rnd basics.Round) (bookkeeping.Block, evalAux, error) {
	wl.recordBlockQuery(rnd)
	return wl.l.blockAux(rnd)
}

func (wl *wrappedLedger) trackerEvalVerified(blk bookkeeping.Block, aux evalAux) (stateDelta, error) {
	return wl.l.trackerEvalVerified(blk, aux)
}

func (wl *wrappedLedger) Latest() basics.Round {
	return wl.l.Latest()
}

func (wl *wrappedLedger) trackerDB() dbPair {
	return wl.l.trackerDB()
}

func (wl *wrappedLedger) trackerLog() logging.Logger {
	return wl.l.trackerLog()
}

func getInitState() (genesisInitState InitState) {
	blk := bookkeeping.Block{}
	blk.CurrentProtocol = protocol.ConsensusCurrentVersion
	blk.RewardsPool = testPoolAddr
	blk.FeeSink = testSinkAddr

	accts := make(map[basics.Address]basics.AccountData)
	accts[testPoolAddr] = basics.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 1234567890})
	accts[testSinkAddr] = basics.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 1234567890})

	genesisInitState.Accounts = accts
	genesisInitState.Block = blk
	genesisInitState.GenesisHash = crypto.Digest{}
	return genesisInitState
}

func TestArchival(t *testing.T) {
	// This test ensures that trackers return the correct value from
	// committedUpTo() -- that is, if they return round rnd, then they
	// do not ask for any round before rnd on a subsequent call to
	// loadFromDisk().
	//
	// We generate mostly empty blocks, with the exception of timestamps,
	// which affect participationTracker.committedUpTo()'s return value.

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	genesisInitState := getInitState()
	const inMem = true
	const archival = true
	l, err := OpenLedger(logging.Base(), dbName, inMem, genesisInitState, archival)
	require.NoError(t, err)
	defer l.Close()
	wl := &wrappedLedger{
		l: l,
	}

	nonZeroMinSaves := 0
	blk := genesisInitState.Block

	for i := 0; i < 2000; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		wl.l.AddBlock(blk, agreement.Certificate{})

		// Don't bother checking the trackers every round -- it's too slow..
		if crypto.RandUint64()%23 > 0 {
			continue
		}

		wl.l.WaitForCommit(blk.Round())

		minMinSave, err := checkTrackers(t, wl, blk.Round())
		require.NoError(t, err)
		if err != nil {
			// Return early, to help with iterative debugging
			return
		}

		if minMinSave > 0 {
			nonZeroMinSaves++
		}

		if nonZeroMinSaves > 20 {
			// Every tracker has given the ledger a chance to GC a few blocks
			return
		}
	}

	t.Error("Did not observe every tracker GCing the ledger")
}

func TestArchivalRestart(t *testing.T) {
	// Start in archival mode, add 2K blocks, restart, ensure all blocks are there

	dbTempDir, err := ioutil.TempDir("", "testdir"+t.Name())
	require.NoError(t, err)
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	dbPrefix := filepath.Join(dbTempDir, dbName)
	defer os.RemoveAll(dbTempDir)

	genesisInitState := getInitState()
	const inMem = false // use persistent storage
	const archival = true

	l, err := OpenLedger(logging.Base(), dbPrefix, inMem, genesisInitState, archival)
	require.NoError(t, err)
	blk := genesisInitState.Block

	const maxBlocks = 2000
	for i := 0; i < maxBlocks; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		l.AddBlock(blk, agreement.Certificate{})
	}
	l.WaitForCommit(blk.Round())

	var latest, earliest basics.Round
	err = l.blockDBs.rdb.Atomic(func(tx *sql.Tx) error {
		latest, err = blockLatest(tx)
		require.NoError(t, err)

		earliest, err = blockEarliest(tx)
		require.NoError(t, err)
		return err
	})
	require.NoError(t, err)
	require.Equal(t, basics.Round(maxBlocks), latest)
	require.Equal(t, basics.Round(0), earliest)

	// close and reopen the same DB, ensure latest/earliest are not changed
	l.Close()

	l, err = OpenLedger(logging.Base(), dbPrefix, inMem, genesisInitState, archival)
	require.NoError(t, err)
	defer l.Close()

	err = l.blockDBs.rdb.Atomic(func(tx *sql.Tx) error {
		latest, err = blockLatest(tx)
		require.NoError(t, err)

		earliest, err = blockEarliest(tx)
		require.NoError(t, err)
		return err
	})
	require.NoError(t, err)
	require.Equal(t, basics.Round(maxBlocks), latest)
	require.Equal(t, basics.Round(0), earliest)
}

func TestArchivalFromNonArchival(t *testing.T) {
	// Start in non-archival mode, add 2K blocks, restart in archival mode ensure only genesis block is there

	dbTempDir, err := ioutil.TempDir(os.TempDir(), "testdir")
	require.NoError(t, err)
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	dbPrefix := filepath.Join(dbTempDir, dbName)
	defer os.RemoveAll(dbTempDir)

	genesisInitState := getInitState()
	const inMem = false // use persistent storage
	archival := false

	l, err := OpenLedger(logging.Base(), dbPrefix, inMem, genesisInitState, archival)
	require.NoError(t, err)
	blk := genesisInitState.Block

	const maxBlocks = 2000
	for i := 0; i < maxBlocks; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		l.AddBlock(blk, agreement.Certificate{})
	}
	l.WaitForCommit(blk.Round())

	var latest, earliest basics.Round
	err = l.blockDBs.rdb.Atomic(func(tx *sql.Tx) error {
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

	archival = true
	l, err = OpenLedger(logging.Base(), dbPrefix, inMem, genesisInitState, archival)
	require.NoError(t, err)
	defer l.Close()

	err = l.blockDBs.rdb.Atomic(func(tx *sql.Tx) error {
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

func checkTrackers(t *testing.T, wl *wrappedLedger, rnd basics.Round) (basics.Round, error) {
	minMinSave := rnd

	for _, trk := range wl.l.trackers.trackers {
		wl.l.trackerMu.RLock()
		minSave := trk.committedUpTo(rnd)
		wl.l.trackerMu.RUnlock()
		if minSave < minMinSave {
			minMinSave = minSave
		}

		trackerType := reflect.TypeOf(trk).Elem()
		cleanTracker := reflect.New(trackerType).Interface().(ledgerTracker)
		if trackerType.String() == "ledger.accountUpdates" {
			cleanTracker.(*accountUpdates).initAccounts = wl.l.accts.initAccounts
		}

		wl.minQueriedBlock = rnd

		err := cleanTracker.loadFromDisk(wl)
		require.NoError(t, err)

		// Special case: initAccounts reflects state after block 0,
		// so it's OK to return minSave=0 but query block 1.
		if minSave != wl.minQueriedBlock && minSave != 0 && wl.minQueriedBlock != 1 {
			return minMinSave, fmt.Errorf("tracker %v: committed %d, minSave %d != minQuery %d", trackerType, rnd, minSave, wl.minQueriedBlock)
		}
	}

	return minMinSave, nil
}
