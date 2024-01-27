// Copyright (C) 2019-2024 Algorand, Inc.
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
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/blockdb"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

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

func TestPutBlockTooOld(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisInitState, _, _ := ledgertesting.Genesis(10)

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(logging.Base(), dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	blk := bookkeeping.Block{}
	var cert agreement.Certificate
	err = l.blockQ.putBlock(blk, cert) // try putBlock for a block in a previous round

	expectedErr := &ledgercore.BlockInLedgerError{}
	require.True(t, errors.As(err, expectedErr))

	blkent := randomBlock(1)
	blk = blkent.block
	cert = blkent.cert
	err = l.blockQ.putBlock(blk, cert) // add block for round 1 to blockQueue
	require.NoError(t, err)

	err = l.blockQ.putBlock(blk, cert) // try adding same block again (should fail)
	require.True(t, errors.As(err, expectedErr))
}

// TestGetEncodedBlockCert tests getEncodedBlockCert with valid and invalid round numbers.
func TestGetEncodedBlockCert(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisInitState, _, _ := ledgertesting.Genesis(10)

	const inMem = true
	cfg := config.GetDefaultLocal()
	l, err := OpenLedger(logging.Base(), t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	blkent := randomBlock(1)
	blk := blkent.block
	cert := blkent.cert
	err = l.blockQ.putBlock(blk, cert)
	require.NoError(t, err)

	var blkBytes []byte
	var certBytes []byte

	blkBytes, certBytes, err = l.blockQ.getEncodedBlockCert(0)
	require.Equal(t, protocol.Encode(&genesisInitState.Block), blkBytes)
	require.Equal(t, protocol.Encode(&agreement.Certificate{}), certBytes)
	require.NoError(t, err)

	blkBytes, certBytes, err = l.blockQ.getEncodedBlockCert(1)
	require.Equal(t, protocol.Encode(&blk), blkBytes)
	require.Equal(t, protocol.Encode(&cert), certBytes)
	require.NoError(t, err)

	_, _, err = l.blockQ.getEncodedBlockCert(100) // should not be entry for this round

	expectedErr := &ledgercore.ErrNoEntry{}
	require.True(t, errors.As(err, expectedErr))
}

// it is not great to use trackers here but at the moment there is no abstraction for the ledger
type uptoTracker struct {
	emptyTracker
}

// committedUpTo in the emptyTracker just stores the committed round.
func (t *uptoTracker) committedUpTo(committedRnd basics.Round) (minRound, lookback basics.Round) {
	return 5_000, basics.Round(0)
}

// TestBlockQueueSyncerDeletion ensures that the block queue syncer deletes no more than maxDeletionBatchSize blocks at time
func TestBlockQueueSyncerDeletion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tests := []struct {
		name             string
		expectedEarliest basics.Round
		tracker          ledgerTracker
	}{
		{"max_batch", maxDeletionBatchSize, nil}, // no trackers, max deletion
		{"5k_tracker", 5_000, &uptoTracker{}},    // tracker sets minToSave to 5k
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			const dbMem = true
			blockDBs, err := db.OpenPair(t.Name()+".block.sqlite", dbMem)
			require.NoError(t, err)

			log := logging.TestingLog(t)
			err = blockDBs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
				return initBlocksDB(tx, log, []bookkeeping.Block{}, false)
			})
			require.NoError(t, err)

			// add 15k blocks
			const maxBlocks = maxDeletionBatchSize + maxDeletionBatchSize/2 // 15_000
			err = blockDBs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
				for i := 0; i < maxBlocks; i++ {
					err0 := blockdb.BlockPut(
						tx,
						bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{Round: basics.Round(i)}},
						agreement.Certificate{})
					if err0 != nil {
						return err0
					}
				}
				return nil
			})
			require.NoError(t, err)

			var earliest, latest basics.Round
			err = blockDBs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
				var err0 error
				earliest, err0 = blockdb.BlockEarliest(tx)
				if err0 != nil {
					return err0
				}
				latest, err0 = blockdb.BlockLatest(tx)
				return err0
			})
			require.NoError(t, err)
			require.Equal(t, basics.Round(0), earliest)
			require.Equal(t, basics.Round(maxBlocks-1), latest)

			// trigger deletion and ensure no more than 10k blocks gone
			//make a minimal ledger for blockqueue

			l := &Ledger{
				log:      log,
				blockDBs: blockDBs,
			}
			if test.tracker != nil {
				l.trackers.trackers = append(l.trackers.trackers, test.tracker)
			}
			blockq, _ := newBlockQueue(l)
			err = blockq.start()
			require.NoError(t, err)

			// add a block. Eventually the syncer will called on an empty ledger
			// forcing deleting all 15_000 rounds. The deletion scoping should limit it to 10_000 rounds instead
			err = blockq.putBlock(bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{Round: maxBlocks}}, agreement.Certificate{})
			require.NoError(t, err)

			require.Eventually(t, func() bool {
				var latest basics.Round
				err = blockDBs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
					var err0 error
					latest, err0 = blockdb.BlockLatest(tx)
					return err0
				})
				require.NoError(t, err)
				return latest == maxBlocks
			}, 1*time.Second, 10*time.Millisecond)

			blockq.stop()

			err = blockDBs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
				var err0 error
				earliest, err0 = blockdb.BlockEarliest(tx)
				return err0
			})
			require.NoError(t, err)
			require.Equal(t, test.expectedEarliest, earliest)
		})
	}
}
