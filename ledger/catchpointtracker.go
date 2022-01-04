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
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// trieCachedNodesCount defines how many balances trie nodes we would like to keep around in memory.
// value was calibrated using BenchmarkCalibrateCacheNodeSize
var trieCachedNodesCount = 9000

// merkleCommitterNodesPerPage controls how many nodes will be stored in a single page
// value was calibrated using BenchmarkCalibrateNodesPerPage
var merkleCommitterNodesPerPage = int64(116)

const (
	// trieRebuildAccountChunkSize defines the number of accounts that would get read at a single chunk
	// before added to the trie during trie construction
	trieRebuildAccountChunkSize = 16384
	// trieRebuildCommitFrequency defines the number of accounts that would get added before we call evict to commit the changes and adjust the memory cache.
	trieRebuildCommitFrequency = 65536
	// trieAccumulatedChangesFlush defines the number of pending changes that would be applied to the merkle trie before
	// we attempt to commit them to disk while writing a batch of rounds balances to disk.
	trieAccumulatedChangesFlush = 256
)

// TrieMemoryConfig is the memory configuration setup used for the merkle trie.
var TrieMemoryConfig = merkletrie.MemoryConfig{
	NodesCountPerPage:         merkleCommitterNodesPerPage,
	CachedNodesCount:          trieCachedNodesCount,
	PageFillFactor:            0.95,
	MaxChildrenPagesThreshold: 64,
}

type catchpointTracker struct {
	// dbDirectory is the directory where the ledger and block sql file resides as well as the parent directory for the catchup files to be generated
	dbDirectory string

	// catchpointInterval is the configured interval at which the accountUpdates would generate catchpoint labels and catchpoint files.
	catchpointInterval uint64

	// catchpointFileHistoryLength defines how many catchpoint files we want to store back.
	// 0 means don't store any, -1 mean unlimited and positive number suggest the number of most recent catchpoint files.
	catchpointFileHistoryLength int

	// archivalLedger determines whether the associated ledger was configured as archival ledger or not.
	archivalLedger bool

	// Prepared SQL statements for fast accounts DB lookups.
	accountsq *accountsDbQueries

	// log copied from ledger
	log logging.Logger

	// Connection to the database.
	dbs db.Pair

	// The last catchpoint label that was written to the database. Should always align with what's in the database.
	// note that this is the last catchpoint *label* and not the catchpoint file.
	lastCatchpointLabel string

	// catchpointSlowWriting suggest to the accounts writer that it should finish writing up the catchpoint file ASAP.
	// when this channel is closed, the accounts writer would try and complete the writing as soon as possible.
	// otherwise, it would take it's time and perform periodic sleeps between chunks processing.
	catchpointSlowWriting chan struct{}

	// catchpointWriting help to synchronize the catchpoint file writing. When this atomic variable is 0, no writing is going on.
	// Any non-zero value indicates a catchpoint being written, or scheduled to be written.
	catchpointWriting int32

	// The Trie tracking the current account balances. Always matches the balances that were
	// written to the database.
	balancesTrie *merkletrie.Trie

	// catchpointsMu is the synchronization mutex for accessing the various non-static variables.
	catchpointsMu deadlock.RWMutex

	// roundDigest stores the digest of the block for every round starting with dbRound and every round after it.
	roundDigest []crypto.Digest
}

// initialize initializes the catchpointTracker structure
func (ct *catchpointTracker) initialize(cfg config.Local, dbPathPrefix string) {
	ct.dbDirectory = filepath.Dir(dbPathPrefix)
	ct.archivalLedger = cfg.Archival
	switch cfg.CatchpointTracking {
	case -1:
		ct.catchpointInterval = 0
	default:
		// give a warning, then fall thought
		logging.Base().Warnf("catchpointTracker: the CatchpointTracking field in the config.json file contains an invalid value (%d). The default value of 0 would be used instead.", cfg.CatchpointTracking)
		fallthrough
	case 0:
		if ct.archivalLedger {
			ct.catchpointInterval = cfg.CatchpointInterval
		} else {
			ct.catchpointInterval = 0
		}
	case 1:
		ct.catchpointInterval = cfg.CatchpointInterval
	}

	ct.catchpointFileHistoryLength = cfg.CatchpointFileHistoryLength
	if cfg.CatchpointFileHistoryLength < -1 {
		ct.catchpointFileHistoryLength = -1
	}
}

// GetLastCatchpointLabel retrieves the last catchpoint label that was stored to the database.
func (ct *catchpointTracker) GetLastCatchpointLabel() string {
	ct.catchpointsMu.RLock()
	defer ct.catchpointsMu.RUnlock()
	return ct.lastCatchpointLabel
}

// loadFromDisk loads the state of a tracker from persistent
// storage.  The ledger argument allows loadFromDisk to load
// blocks from the database, or access its own state.  The
// ledgerForTracker interface abstracts away the details of
// ledger internals so that individual trackers can be tested
// in isolation.
func (ct *catchpointTracker) loadFromDisk(l ledgerForTracker, lastBalancesRound basics.Round) (err error) {
	ct.log = l.trackerLog()
	ct.dbs = l.trackerDB()

	ct.roundDigest = nil
	ct.catchpointWriting = 0
	// keep these channel closed if we're not generating catchpoint
	ct.catchpointSlowWriting = make(chan struct{}, 1)
	close(ct.catchpointSlowWriting)

	err = ct.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		err0 := ct.accountsInitializeHashes(ctx, tx, lastBalancesRound)
		if err0 != nil {
			return err0
		}
		return nil
	})

	if err != nil {
		return err
	}

	ct.accountsq, err = accountsInitDbQueries(ct.dbs.Rdb.Handle, ct.dbs.Wdb.Handle)
	if err != nil {
		return
	}

	ct.lastCatchpointLabel, _, err = ct.accountsq.readCatchpointStateString(context.Background(), catchpointStateLastCatchpoint)
	if err != nil {
		return
	}

	writingCatchpointRound, _, err := ct.accountsq.readCatchpointStateUint64(context.Background(), catchpointStateWritingCatchpoint)
	if err != nil {
		return err
	}
	if writingCatchpointRound == 0 || !ct.catchpointEnabled() {
		return nil
	}
	var dbRound basics.Round
	// make sure that the database is at the desired round.
	err = ct.dbs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		dbRound, err = accountsRound(tx)
		return
	})
	if err != nil {
		return err
	}
	if dbRound != basics.Round(writingCatchpointRound) {
		return nil
	}

	blk, err := l.Block(dbRound)
	if err != nil {
		return err
	}
	blockHeaderDigest := blk.Digest()

	ct.generateCatchpoint(context.Background(), basics.Round(writingCatchpointRound), ct.lastCatchpointLabel, blockHeaderDigest, time.Duration(0))
	return nil
}

// newBlock informs the tracker of a new block from round
// rnd and a given ledgercore.StateDelta as produced by BlockEvaluator.
func (ct *catchpointTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	ct.catchpointsMu.Lock()
	defer ct.catchpointsMu.Unlock()
	ct.roundDigest = append(ct.roundDigest, blk.Digest())
}

// committedUpTo implements the ledgerTracker interface for catchpointTracker.
// The method informs the tracker that committedRound and all it's previous rounds have
// been committed to the block database. The method returns what is the oldest round
// number that can be removed from the blocks database as well as the lookback that this
// tracker maintains.
func (ct *catchpointTracker) committedUpTo(rnd basics.Round) (retRound, lookback basics.Round) {
	return rnd, basics.Round(0)
}

func (ct *catchpointTracker) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	var hasMultipleIntermediateCatchpoint, hasIntermediateCatchpoint bool

	newBase := dcr.oldBase + basics.Round(dcr.offset)

	// check if there was a catchpoint between dcc.oldBase+lookback and dcc.oldBase+offset+lookback
	if ct.catchpointInterval > 0 {
		nextCatchpointRound := ((uint64(dcr.oldBase+dcr.lookback) + ct.catchpointInterval) / ct.catchpointInterval) * ct.catchpointInterval

		if nextCatchpointRound < uint64(dcr.oldBase+dcr.lookback)+dcr.offset {
			mostRecentCatchpointRound := (uint64(committedRound) / ct.catchpointInterval) * ct.catchpointInterval
			newBase = basics.Round(nextCatchpointRound) - dcr.lookback
			if mostRecentCatchpointRound > nextCatchpointRound {
				hasMultipleIntermediateCatchpoint = true
				// skip if there is more than one catchpoint in queue
				newBase = basics.Round(mostRecentCatchpointRound) - dcr.lookback
			}
			hasIntermediateCatchpoint = true
		}
	}

	// if we're still writing the previous balances, we can't move forward yet.
	if ct.IsWritingCatchpointFile() {
		// if we hit this path, it means that we're still writing a catchpoint.
		// see if the new delta range contains another catchpoint.
		if hasIntermediateCatchpoint {
			// check if we're already attempting to perform fast-writing.
			select {
			case <-ct.catchpointSlowWriting:
				// yes, we're already doing fast-writing.
			default:
				// no, we're not yet doing fast writing, make it so.
				close(ct.catchpointSlowWriting)
			}
		}
		return nil
	}

	dcr.offset = uint64(newBase - dcr.oldBase)

	// check to see if this is a catchpoint round
	dcr.isCatchpointRound = ct.isCatchpointRound(dcr.offset, dcr.oldBase, dcr.lookback)

	if dcr.isCatchpointRound && ct.archivalLedger {
		// store non-zero ( all ones ) into the catchpointWriting atomic variable to indicate that a catchpoint is being written ( or, queued to be written )
		atomic.StoreInt32(&ct.catchpointWriting, int32(-1))
		ct.catchpointSlowWriting = make(chan struct{}, 1)
		if hasMultipleIntermediateCatchpoint {
			close(ct.catchpointSlowWriting)
		}
	}

	dcr.catchpointWriting = &ct.catchpointWriting

	return dcr
}

// prepareCommit, commitRound and postCommit are called when it is time to commit tracker's data.
// If an error returned the process is aborted.
func (ct *catchpointTracker) prepareCommit(dcc *deferredCommitContext) error {
	ct.catchpointsMu.RLock()
	defer ct.catchpointsMu.RUnlock()
	if dcc.isCatchpointRound {
		dcc.committedRoundDigest = ct.roundDigest[dcc.offset+uint64(dcc.lookback)-1]
	}
	return nil
}

func (ct *catchpointTracker) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) (err error) {
	treeTargetRound := basics.Round(0)
	offset := dcc.offset
	dbRound := dcc.oldBase

	defer func() {
		if err != nil {
			if dcc.isCatchpointRound && ct.archivalLedger {
				atomic.StoreInt32(&ct.catchpointWriting, 0)
			}
		}
	}()

	if ct.catchpointEnabled() {
		var mc *MerkleCommitter
		mc, err = MakeMerkleCommitter(tx, false)
		if err != nil {
			return
		}

		var trie *merkletrie.Trie
		if ct.balancesTrie == nil {
			trie, err = merkletrie.MakeTrie(mc, TrieMemoryConfig)
			if err != nil {
				ct.log.Warnf("unable to create merkle trie during committedUpTo: %v", err)
				return err
			}
			ct.balancesTrie = trie
		} else {
			ct.balancesTrie.SetCommitter(mc)
		}
		treeTargetRound = dbRound + basics.Round(offset)
	}

	if dcc.updateStats {
		dcc.stats.MerkleTrieUpdateDuration = time.Duration(time.Now().UnixNano())
	}

	err = ct.accountsUpdateBalances(dcc.compactAccountDeltas)
	if err != nil {
		return err
	}

	if dcc.updateStats {
		now := time.Duration(time.Now().UnixNano())
		dcc.stats.MerkleTrieUpdateDuration = now - dcc.stats.MerkleTrieUpdateDuration
	}

	err = updateAccountsHashRound(tx, treeTargetRound)
	if err != nil {
		return err
	}

	if dcc.isCatchpointRound {
		dcc.trieBalancesHash, err = ct.balancesTrie.RootHash()
		if err != nil {
			return err
		}
	}
	return nil
}

func (ct *catchpointTracker) postCommit(ctx context.Context, dcc *deferredCommitContext) {
	var err error
	if dcc.isCatchpointRound {
		dcc.catchpointLabel, err = ct.accountsCreateCatchpointLabel(dcc.newBase+dcc.lookback, dcc.roundTotals, dcc.committedRoundDigest, dcc.trieBalancesHash)
		if err != nil {
			ct.log.Warnf("commitRound : unable to create a catchpoint label: %v", err)
		}
	}
	if ct.balancesTrie != nil {
		_, err = ct.balancesTrie.Evict(false)
		if err != nil {
			ct.log.Warnf("merkle trie failed to evict: %v", err)
		}
	}

	if dcc.isCatchpointRound && dcc.catchpointLabel != "" {
		ct.lastCatchpointLabel = dcc.catchpointLabel
	}
	dcc.updatingBalancesDuration = time.Since(dcc.flushTime)

	if dcc.updateStats {
		dcc.stats.MemoryUpdatesDuration = time.Duration(time.Now().UnixNano())
	}

	ct.catchpointsMu.Lock()

	ct.roundDigest = ct.roundDigest[dcc.offset:]

	ct.catchpointsMu.Unlock()
}

func (ct *catchpointTracker) postCommitUnlocked(ctx context.Context, dcc *deferredCommitContext) {
	if dcc.isCatchpointRound && ct.archivalLedger && dcc.catchpointLabel != "" {
		// generate the catchpoint file. This need to be done inline so that it will block any new accounts that from being written.
		// the generateCatchpoint expects that the accounts data would not be modified in the background during it's execution.
		ct.generateCatchpoint(ctx, basics.Round(dcc.offset)+dcc.oldBase+dcc.lookback, dcc.catchpointLabel, dcc.committedRoundDigest, dcc.updatingBalancesDuration)
	}

	// in scheduleCommit, we expect that this function to update the catchpointWriting when
	// it's on a catchpoint round and it's an archival ledger. Doing this in a deferred function
	// here would prevent us from "forgetting" to update this variable later on.
	if dcc.isCatchpointRound && ct.archivalLedger {
		atomic.StoreInt32(dcc.catchpointWriting, 0)
	}
}

// handleUnorderedCommit is a special method for handling deferred commits that are out of order.
// Tracker might update own state in this case. For example, account updates tracker cancels
// scheduled catchpoint writing that deferred commit.
func (ct *catchpointTracker) handleUnorderedCommit(offset uint64, dbRound basics.Round, lookback basics.Round) {
	// if this is an archival ledger, we might need to update the catchpointWriting variable.
	if ct.archivalLedger {
		// determine if this was a catchpoint round
		if ct.isCatchpointRound(offset, dbRound, lookback) {
			// it was a catchpoint round, so update the catchpointWriting to indicate that we're done.
			atomic.StoreInt32(&ct.catchpointWriting, 0)
		}
	}
}

// close terminates the tracker, reclaiming any resources
// like open database connections or goroutines.  close may
// be called even if loadFromDisk() is not called or does
// not succeed.
func (ct *catchpointTracker) close() {

}

// accountsUpdateBalances applies the given compactAccountDeltas to the merkle trie
func (ct *catchpointTracker) accountsUpdateBalances(accountsDeltas compactAccountDeltas) (err error) {
	if !ct.catchpointEnabled() {
		return nil
	}
	var added, deleted bool
	accumulatedChanges := 0

	for i := 0; i < accountsDeltas.len(); i++ {
		addr, delta := accountsDeltas.getByIdx(i)
		if !delta.old.accountData.IsZero() {
			deleteHash := accountHashBuilder(addr, delta.old.accountData, protocol.Encode(&delta.old.accountData))
			deleted, err = ct.balancesTrie.Delete(deleteHash)
			if err != nil {
				return fmt.Errorf("failed to delete hash '%s' from merkle trie for account %v: %w", hex.EncodeToString(deleteHash), addr, err)
			}
			if !deleted {
				ct.log.Warnf("failed to delete hash '%s' from merkle trie for account %v", hex.EncodeToString(deleteHash), addr)
			} else {
				accumulatedChanges++
			}
		}

		if !delta.new.IsZero() {
			addHash := accountHashBuilder(addr, delta.new, protocol.Encode(&delta.new))
			added, err = ct.balancesTrie.Add(addHash)
			if err != nil {
				return fmt.Errorf("attempted to add duplicate hash '%s' to merkle trie for account %v: %w", hex.EncodeToString(addHash), addr, err)
			}
			if !added {
				ct.log.Warnf("attempted to add duplicate hash '%s' to merkle trie for account %v", hex.EncodeToString(addHash), addr)
			} else {
				accumulatedChanges++
			}
		}
	}
	if accumulatedChanges >= trieAccumulatedChangesFlush {
		accumulatedChanges = 0
		_, err = ct.balancesTrie.Commit()
		if err != nil {
			return
		}
	}

	// write it all to disk.
	if accumulatedChanges > 0 {
		_, err = ct.balancesTrie.Commit()
	}

	return
}

// IsWritingCatchpointFile returns true when a catchpoint file is being generated. The function is used by the catchup service
// to avoid memory pressure until the catchpoint file writing is complete.
func (ct *catchpointTracker) IsWritingCatchpointFile() bool {
	return atomic.LoadInt32(&ct.catchpointWriting) != 0
}

// isCatchpointRound returns true if the round at the given offset, dbRound with the provided lookback should be a catchpoint round.
func (ct *catchpointTracker) isCatchpointRound(offset uint64, dbRound basics.Round, lookback basics.Round) bool {
	return ((offset + uint64(lookback+dbRound)) > 0) && (ct.catchpointInterval != 0) && ((uint64((offset + uint64(lookback+dbRound))) % ct.catchpointInterval) == 0)
}

// accountsCreateCatchpointLabel creates a catchpoint label and write it.
func (ct *catchpointTracker) accountsCreateCatchpointLabel(committedRound basics.Round, totals ledgercore.AccountTotals, ledgerBlockDigest crypto.Digest, trieBalancesHash crypto.Digest) (label string, err error) {
	cpLabel := ledgercore.MakeCatchpointLabel(committedRound, ledgerBlockDigest, trieBalancesHash, totals)
	label = cpLabel.String()
	_, err = ct.accountsq.writeCatchpointStateString(context.Background(), catchpointStateLastCatchpoint, label)
	return
}

// generateCatchpoint generates a single catchpoint file
func (ct *catchpointTracker) generateCatchpoint(ctx context.Context, committedRound basics.Round, label string, committedRoundDigest crypto.Digest, updatingBalancesDuration time.Duration) {
	beforeGeneratingCatchpointTime := time.Now()
	catchpointGenerationStats := telemetryspec.CatchpointGenerationEventDetails{
		BalancesWriteTime: uint64(updatingBalancesDuration.Nanoseconds()),
	}

	// the retryCatchpointCreation is used to repeat the catchpoint file generation in case the node crashed / aborted during startup
	// before the catchpoint file generation could be completed.
	retryCatchpointCreation := false
	ct.log.Debugf("accountUpdates: generateCatchpoint: generating catchpoint for round %d", committedRound)
	defer func() {
		if !retryCatchpointCreation {
			// clear the writingCatchpoint flag
			_, err := ct.accountsq.writeCatchpointStateUint64(context.Background(), catchpointStateWritingCatchpoint, uint64(0))
			if err != nil {
				ct.log.Warnf("accountUpdates: generateCatchpoint unable to clear catchpoint state '%s' for round %d: %v", catchpointStateWritingCatchpoint, committedRound, err)
			}
		}
	}()

	_, err := ct.accountsq.writeCatchpointStateUint64(context.Background(), catchpointStateWritingCatchpoint, uint64(committedRound))
	if err != nil {
		ct.log.Warnf("accountUpdates: generateCatchpoint unable to write catchpoint state '%s' for round %d: %v", catchpointStateWritingCatchpoint, committedRound, err)
		return
	}

	relCatchpointFileName := filepath.Join("catchpoints", catchpointRoundToPath(committedRound))
	absCatchpointFileName := filepath.Join(ct.dbDirectory, relCatchpointFileName)

	more := true
	const shortChunkExecutionDuration = 50 * time.Millisecond
	const longChunkExecutionDuration = 1 * time.Second
	var chunkExecutionDuration time.Duration
	select {
	case <-ct.catchpointSlowWriting:
		chunkExecutionDuration = longChunkExecutionDuration
	default:
		chunkExecutionDuration = shortChunkExecutionDuration
	}

	var catchpointWriter *catchpointWriter
	start := time.Now()
	ledgerGeneratecatchpointCount.Inc(nil)
	err = ct.dbs.Rdb.Atomic(func(dbCtx context.Context, tx *sql.Tx) (err error) {
		catchpointWriter = makeCatchpointWriter(ctx, absCatchpointFileName, tx, committedRound, committedRoundDigest, label)
		for more {
			stepCtx, stepCancelFunction := context.WithTimeout(ctx, chunkExecutionDuration)
			writeStepStartTime := time.Now()
			more, err = catchpointWriter.WriteStep(stepCtx)
			// accumulate the actual time we've spent writing in this step.
			catchpointGenerationStats.CPUTime += uint64(time.Since(writeStepStartTime).Nanoseconds())
			stepCancelFunction()
			if more && err == nil {
				// we just wrote some data, but there is more to be written.
				// go to sleep for while.
				// before going to sleep, extend the transaction timeout so that we won't get warnings:
				_, err0 := db.ResetTransactionWarnDeadline(dbCtx, tx, time.Now().Add(1*time.Second))
				if err0 != nil {
					ct.log.Warnf("catchpointTracker: generateCatchpoint: failed to reset transaction warn deadline : %v", err0)
				}
				select {
				case <-time.After(100 * time.Millisecond):
					// increase the time slot allocated for writing the catchpoint, but stop when we get to the longChunkExecutionDuration limit.
					// this would allow the catchpoint writing speed to ramp up while still leaving some cpu available.
					chunkExecutionDuration *= 2
					if chunkExecutionDuration > longChunkExecutionDuration {
						chunkExecutionDuration = longChunkExecutionDuration
					}
				case <-ctx.Done():
					retryCatchpointCreation = true
					err2 := catchpointWriter.Abort()
					if err2 != nil {
						return fmt.Errorf("error removing catchpoint file : %v", err2)
					}
					return nil
				case <-ct.catchpointSlowWriting:
					chunkExecutionDuration = longChunkExecutionDuration
				}
			}
			if err != nil {
				err = fmt.Errorf("unable to create catchpoint : %v", err)
				err2 := catchpointWriter.Abort()
				if err2 != nil {
					ct.log.Warnf("accountUpdates: generateCatchpoint: error removing catchpoint file : %v", err2)
				}
				return
			}
		}
		return
	})
	ledgerGeneratecatchpointMicros.AddMicrosecondsSince(start, nil)

	if err != nil {
		ct.log.Warnf("accountUpdates: generateCatchpoint: %v", err)
		return
	}
	if catchpointWriter == nil {
		ct.log.Warnf("accountUpdates: generateCatchpoint: nil catchpointWriter")
		return
	}

	err = ct.saveCatchpointFile(committedRound, relCatchpointFileName, catchpointWriter.GetSize(), catchpointWriter.GetCatchpoint())
	if err != nil {
		ct.log.Warnf("accountUpdates: generateCatchpoint: unable to save catchpoint: %v", err)
		return
	}
	catchpointGenerationStats.FileSize = uint64(catchpointWriter.GetSize())
	catchpointGenerationStats.WritingDuration = uint64(time.Since(beforeGeneratingCatchpointTime).Nanoseconds())
	catchpointGenerationStats.AccountsCount = catchpointWriter.GetTotalAccounts()
	catchpointGenerationStats.CatchpointLabel = catchpointWriter.GetCatchpoint()
	ct.log.EventWithDetails(telemetryspec.Accounts, telemetryspec.CatchpointGenerationEvent, catchpointGenerationStats)
	ct.log.With("writingDuration", catchpointGenerationStats.WritingDuration).
		With("CPUTime", catchpointGenerationStats.CPUTime).
		With("balancesWriteTime", catchpointGenerationStats.BalancesWriteTime).
		With("accountsCount", catchpointGenerationStats.AccountsCount).
		With("fileSize", catchpointGenerationStats.FileSize).
		With("catchpointLabel", catchpointGenerationStats.CatchpointLabel).
		Infof("Catchpoint file was generated")
}

// catchpointRoundToPath calculate the catchpoint file path for a given round
func catchpointRoundToPath(rnd basics.Round) string {
	irnd := int64(rnd) / 256
	outStr := ""
	for irnd > 0 {
		outStr = filepath.Join(outStr, fmt.Sprintf("%02x", irnd%256))
		irnd = irnd / 256
	}
	outStr = filepath.Join(outStr, strconv.FormatInt(int64(rnd), 10)+".catchpoint")
	return outStr
}

// saveCatchpointFile stores the provided fileName as the stored catchpoint for the given round.
// after a successful insert operation to the database, it would delete up to 2 old entries, as needed.
// deleting 2 entries while inserting single entry allow us to adjust the size of the backing storage and have the
// database and storage realign.
func (ct *catchpointTracker) saveCatchpointFile(round basics.Round, fileName string, fileSize int64, catchpoint string) (err error) {
	if ct.catchpointFileHistoryLength != 0 {
		err = ct.accountsq.storeCatchpoint(context.Background(), round, fileName, catchpoint, fileSize)
		if err != nil {
			ct.log.Warnf("accountUpdates: saveCatchpoint: unable to save catchpoint: %v", err)
			return
		}
	} else {
		err = os.Remove(fileName)
		if err != nil {
			ct.log.Warnf("accountUpdates: saveCatchpoint: unable to remove file (%s): %v", fileName, err)
			return
		}
	}
	if ct.catchpointFileHistoryLength == -1 {
		return
	}
	var filesToDelete map[basics.Round]string
	filesToDelete, err = ct.accountsq.getOldestCatchpointFiles(context.Background(), 2, ct.catchpointFileHistoryLength)
	if err != nil {
		return fmt.Errorf("unable to delete catchpoint file, getOldestCatchpointFiles failed : %v", err)
	}
	for round, fileToDelete := range filesToDelete {
		absCatchpointFileName := filepath.Join(ct.dbDirectory, fileToDelete)
		err = os.Remove(absCatchpointFileName)
		if err == nil || os.IsNotExist(err) {
			// it's ok if the file doesn't exist. just remove it from the database and we'll be good to go.
			err = nil
		} else {
			// we can't delete the file, abort -
			return fmt.Errorf("unable to delete old catchpoint file '%s' : %v", absCatchpointFileName, err)
		}
		err = ct.accountsq.storeCatchpoint(context.Background(), round, "", "", 0)
		if err != nil {
			return fmt.Errorf("unable to delete old catchpoint entry '%s' : %v", fileToDelete, err)
		}
	}
	return
}

// GetCatchpointStream returns a ReadCloseSizer to the catchpoint file associated with the provided round
func (ct *catchpointTracker) GetCatchpointStream(round basics.Round) (ReadCloseSizer, error) {
	dbFileName := ""
	fileSize := int64(0)
	start := time.Now()
	ledgerGetcatchpointCount.Inc(nil)
	err := ct.dbs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		dbFileName, _, fileSize, err = getCatchpoint(tx, round)
		return
	})
	ledgerGetcatchpointMicros.AddMicrosecondsSince(start, nil)
	if err != nil && err != sql.ErrNoRows {
		// we had some sql error.
		return nil, fmt.Errorf("accountUpdates: getCatchpointStream: unable to lookup catchpoint %d: %v", round, err)
	}
	if dbFileName != "" {
		catchpointPath := filepath.Join(ct.dbDirectory, dbFileName)
		file, err := os.OpenFile(catchpointPath, os.O_RDONLY, 0666)
		if err == nil && file != nil {
			return &readCloseSizer{ReadCloser: file, size: fileSize}, nil
		}
		// else, see if this is a file-not-found error
		if os.IsNotExist(err) {
			// the database told us that we have this file.. but we couldn't find it.
			// delete it from the database.
			err := ct.saveCatchpointFile(round, "", 0, "")
			if err != nil {
				ct.log.Warnf("accountUpdates: getCatchpointStream: unable to delete missing catchpoint entry: %v", err)
				return nil, err
			}

			return nil, ledgercore.ErrNoEntry{}
		}
		// it's some other error.
		return nil, fmt.Errorf("accountUpdates: getCatchpointStream: unable to open catchpoint file '%s' %v", catchpointPath, err)
	}

	// if the database doesn't know about that round, see if we have that file anyway:
	fileName := filepath.Join("catchpoints", catchpointRoundToPath(round))
	catchpointPath := filepath.Join(ct.dbDirectory, fileName)
	file, err := os.OpenFile(catchpointPath, os.O_RDONLY, 0666)
	if err == nil && file != nil {
		// great, if found that we should have had this in the database.. add this one now :
		fileInfo, err := file.Stat()
		if err != nil {
			// we couldn't get the stat, so just return with the file.
			return &readCloseSizer{ReadCloser: file, size: -1}, nil
		}

		err = ct.saveCatchpointFile(round, fileName, fileInfo.Size(), "")
		if err != nil {
			ct.log.Warnf("accountUpdates: getCatchpointStream: unable to save missing catchpoint entry: %v", err)
		}
		return &readCloseSizer{ReadCloser: file, size: fileInfo.Size()}, nil
	}
	return nil, ledgercore.ErrNoEntry{}
}

// deleteStoredCatchpoints iterates over the storedcatchpoints table and deletes all the files stored on disk.
// once all the files have been deleted, it would go ahead and remove the entries from the table.
func deleteStoredCatchpoints(ctx context.Context, dbQueries *accountsDbQueries, dbDirectory string) (err error) {
	catchpointsFilesChunkSize := 50
	for {
		fileNames, err := dbQueries.getOldestCatchpointFiles(ctx, catchpointsFilesChunkSize, 0)
		if err != nil {
			return err
		}
		if len(fileNames) == 0 {
			break
		}

		for round, fileName := range fileNames {
			absCatchpointFileName := filepath.Join(dbDirectory, fileName)
			err = os.Remove(absCatchpointFileName)
			if err == nil || os.IsNotExist(err) {
				// it's ok if the file doesn't exist. just remove it from the database and we'll be good to go.
			} else {
				// we can't delete the file, abort -
				return fmt.Errorf("unable to delete old catchpoint file '%s' : %v", absCatchpointFileName, err)
			}
			// clear the entry from the database
			err = dbQueries.storeCatchpoint(ctx, round, "", "", 0)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// accountHashBuilder calculates the hash key used for the trie by combining the account address and the account data
func accountHashBuilder(addr basics.Address, accountData basics.AccountData, encodedAccountData []byte) []byte {
	hash := make([]byte, 4+crypto.DigestSize)
	// write out the lowest 32 bits of the reward base. This should improve the caching of the trie by allowing
	// recent updated to be in-cache, and "older" nodes will be left alone.
	for i, rewards := 3, accountData.RewardsBase; i >= 0; i, rewards = i-1, rewards>>8 {
		// the following takes the rewards & 255 -> hash[i]
		hash[i] = byte(rewards)
	}
	entryHash := crypto.Hash(append(addr[:], encodedAccountData[:]...))
	copy(hash[4:], entryHash[:])
	return hash[:]
}

func (ct *catchpointTracker) catchpointEnabled() bool {
	return ct.catchpointInterval != 0
}

// accountsInitializeHashes initializes account hashes.
// as part of the initialization, it tests if a hash table matches to account base and updates the former.
func (ct *catchpointTracker) accountsInitializeHashes(ctx context.Context, tx *sql.Tx, rnd basics.Round) error {
	hashRound, err := accountsHashRound(tx)
	if err != nil {
		return err
	}

	if hashRound != rnd {
		// if the hashed round is different then the base round, something was modified, and the accounts aren't in sync
		// with the hashes.
		err = resetAccountHashes(tx)
		if err != nil {
			return err
		}
		// if catchpoint is disabled on this node, we could complete the initialization right here.
		if !ct.catchpointEnabled() {
			return nil
		}
	}

	// create the merkle trie for the balances
	committer, err := MakeMerkleCommitter(tx, false)
	if err != nil {
		return fmt.Errorf("accountsInitialize was unable to makeMerkleCommitter: %v", err)
	}

	trie, err := merkletrie.MakeTrie(committer, TrieMemoryConfig)
	if err != nil {
		return fmt.Errorf("accountsInitialize was unable to MakeTrie: %v", err)
	}

	// we might have a database that was previously initialized, and now we're adding the balances trie. In that case, we need to add all the existing balances to this trie.
	// we can figure this out by examining the hash of the root:
	rootHash, err := trie.RootHash()
	if err != nil {
		return fmt.Errorf("accountsInitialize was unable to retrieve trie root hash: %v", err)
	}

	if rootHash.IsZero() {
		ct.log.Infof("accountsInitialize rebuilding merkle trie for round %d", rnd)
		accountBuilderIt := makeOrderedAccountsIter(tx, trieRebuildAccountChunkSize)
		defer accountBuilderIt.Close(ctx)
		startTrieBuildTime := time.Now()
		accountsCount := 0
		lastRebuildTime := startTrieBuildTime
		pendingAccounts := 0
		totalOrderedAccounts := 0
		for {
			accts, processedRows, err := accountBuilderIt.Next(ctx)
			if err == sql.ErrNoRows {
				// the account builder would return sql.ErrNoRows when no more data is available.
				break
			} else if err != nil {
				return err
			}

			if len(accts) > 0 {
				accountsCount += len(accts)
				pendingAccounts += len(accts)
				for _, acct := range accts {
					added, err := trie.Add(acct.digest)
					if err != nil {
						return fmt.Errorf("accountsInitialize was unable to add changes to trie: %v", err)
					}
					if !added {
						ct.log.Warnf("accountsInitialize attempted to add duplicate hash '%s' to merkle trie for account %v", hex.EncodeToString(acct.digest), acct.address)
					}
				}

				if pendingAccounts >= trieRebuildCommitFrequency {
					// this trie Evict will commit using the current transaction.
					// if anything goes wrong, it will still get rolled back.
					_, err = trie.Evict(true)
					if err != nil {
						return fmt.Errorf("accountsInitialize was unable to commit changes to trie: %v", err)
					}
					pendingAccounts = 0
				}

				if time.Since(lastRebuildTime) > 5*time.Second {
					// let the user know that the trie is still being rebuilt.
					ct.log.Infof("accountsInitialize still building the trie, and processed so far %d accounts", accountsCount)
					lastRebuildTime = time.Now()
				}
			} else if processedRows > 0 {
				totalOrderedAccounts += processedRows
				// if it's not ordered, we can ignore it for now; we'll just increase the counters and emit logs periodically.
				if time.Since(lastRebuildTime) > 5*time.Second {
					// let the user know that the trie is still being rebuilt.
					ct.log.Infof("accountsInitialize still building the trie, and hashed so far %d accounts", totalOrderedAccounts)
					lastRebuildTime = time.Now()
				}
			}
		}

		// this trie Evict will commit using the current transaction.
		// if anything goes wrong, it will still get rolled back.
		_, err = trie.Evict(true)
		if err != nil {
			return fmt.Errorf("accountsInitialize was unable to commit changes to trie: %v", err)
		}

		// we've just updated the merkle trie, update the hashRound to reflect that.
		err = updateAccountsHashRound(tx, rnd)
		if err != nil {
			return fmt.Errorf("accountsInitialize was unable to update the account hash round to %d: %v", rnd, err)
		}

		ct.log.Infof("accountsInitialize rebuilt the merkle trie with %d entries in %v", accountsCount, time.Since(startTrieBuildTime))
	}
	ct.balancesTrie = trie
	return nil
}
