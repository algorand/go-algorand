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
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/internal"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-deadlock"
)

// ledgerTracker defines part of the API for any state machine that
// tracks the ledger's blockchain.  In addition to the API below,
// each ledgerTracker provides a tracker-specific read-only API
// (e.g., querying the balance of an account).
//
// A tracker's read-only API must be indexed by rounds, and the
// tracker must be prepared to answer queries for rounds until a
// subsequent call to committedUpTo().
//
// For example, the rewards AVL tree must be prepared to answer
// queries for old rounds, even if the tree has moved on in response
// to newBlock() calls.  It should do so by remembering the precise
// answer for old rounds, until committedUpTo() allows it to GC
// those old answers.
//
// The ledger provides a RWMutex to ensure that the tracker is invoked
// with at most one modification API call (below), OR zero modification
// calls and any number of read-only calls.  If internally the tracker
// modifies state in response to read-only calls, it is the tracker's
// responsibility to ensure thread-safety.
type ledgerTracker interface {
	// loadFromDisk loads the state of a tracker from persistent
	// storage.  The ledger argument allows loadFromDisk to load
	// blocks from the database, or access its own state.  The
	// ledgerForTracker interface abstracts away the details of
	// ledger internals so that individual trackers can be tested
	// in isolation.
	loadFromDisk(ledgerForTracker, basics.Round) error

	// newBlock informs the tracker of a new block from round
	// rnd and a given ledgercore.StateDelta as produced by BlockEvaluator.
	newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta)

	// committedUpTo informs the tracker that the database has
	// committed all blocks up to and including rnd to persistent
	// storage (the SQL database).  This can allow the tracker
	// to garbage-collect state that will not be needed.
	//
	// committedUpTo() returns the round number of the earliest
	// block that this tracker needs to be stored in the ledger
	// for subsequent calls to loadFromDisk().  All blocks with
	// round numbers before that may be deleted to save space,
	// and the tracker is expected to still function after a
	// restart and a call to loadFromDisk().  For example,
	// returning 0 means that no blocks can be deleted.
	committedUpTo(basics.Round) basics.Round

	// prepareCommit, commitRound and postCommit are called when it is time to commit tracker's data.
	// If an error returned the process is aborted.
	prepareCommit(*deferredCommitContext) error
	commitRound(context.Context, *sql.Tx, *deferredCommitContext) error
	postCommit(deferredCommitContext)

	// handleUnorderedCommit is a special method for handling deferred commits that are out of order.
	// Tracker might update own state in this case. For example, account updates tracker cancels
	// scheduled catchpoint writing that deferred commit.
	handleUnorderedCommit(uint64, basics.Round, basics.Round)

	// close terminates the tracker, reclaiming any resources
	// like open database connections or goroutines.  close may
	// be called even if loadFromDisk() is not called or does
	// not succeed.
	close()
}

// ledgerForTracker defines the part of the ledger that a tracker can
// access.  This is particularly useful for testing trackers in isolation.
type ledgerForTracker interface {
	trackerDB() db.Pair
	blockDB() db.Pair
	trackerLog() logging.Logger
	trackerEvalVerified(bookkeeping.Block, internal.LedgerForEvaluator) (ledgercore.StateDelta, error)

	Latest() basics.Round
	Block(basics.Round) (bookkeeping.Block, error)
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	GenesisHash() crypto.Digest
	GenesisProto() config.ConsensusParams
	GenesisAccounts() map[basics.Address]basics.AccountData

	// TODO: temporary?
	scheduleCommit(basics.Round)
	waitAccountsWriting()
}

type trackerRegistry struct {
	trackers []ledgerTracker
	driver   *accountUpdates

	// ctx is the context for the committing go-routine.
	ctx context.Context
	// ctxCancel is the canceling function for canceling the committing go-routine ( i.e. signaling the committing go-routine that it's time to abort )
	ctxCancel context.CancelFunc
	// committedOffset is the offset at which we'd like to persist all the previous account information to disk.
	committedOffset chan deferredCommit
	// commitSyncerClosed is the blocking channel for synchronizing closing the commitSyncer goroutine. Once it's closed, the
	// commitSyncer can be assumed to have aborted.
	commitSyncerClosed chan struct{}

	// accountsWriting provides synchronization around the background writing of account balances.
	accountsWriting sync.WaitGroup

	// dbRound is always exactly accountsRound(),
	// cached to avoid SQL queries.
	dbRound basics.Round

	dbs db.Pair
	log logging.Logger

	mu deadlock.RWMutex
}

type deferredCommitContext struct {
	offset    uint64
	oldBase   basics.Round
	newBase   basics.Round
	lookback  basics.Round
	flushTime time.Time

	genesisProto config.ConsensusParams

	deltas                 []ledgercore.AccountDeltas
	roundTotals            ledgercore.AccountTotals
	compactAccountDeltas   compactAccountDeltas
	compactCreatableDeltas map[basics.CreatableIndex]ledgercore.ModifiedCreatable

	updatedPersistedAccounts []persistedAccountData

	isCatchpointRound    bool
	committedRoundDigest crypto.Digest
	trieBalancesHash     crypto.Digest

	stats       telemetryspec.AccountsUpdateMetrics
	updateStats bool
}

func (tr *trackerRegistry) initialize(au *accountUpdates, l ledgerForTracker, trackers []ledgerTracker) (err error) {
	tr.driver = au

	tr.dbs = l.trackerDB()
	tr.log = l.trackerLog()

	err = tr.dbs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		tr.dbRound, err = accountsRound(tx)
		return err
	})

	if err != nil {
		return err
	}

	tr.ctx, tr.ctxCancel = context.WithCancel(context.Background())
	tr.committedOffset = make(chan deferredCommit, 1)
	tr.commitSyncerClosed = make(chan struct{})
	go tr.commitSyncer(tr.committedOffset)

	tr.trackers = append(tr.trackers, trackers...)
	return
}

func (tr *trackerRegistry) loadFromDisk(l ledgerForTracker) error {
	tr.mu.RLock()
	dbRound := tr.dbRound
	tr.mu.RUnlock()

	for _, lt := range tr.trackers {
		err := lt.loadFromDisk(l, dbRound)
		if err != nil {
			// find the tracker name.
			trackerName := reflect.TypeOf(lt).String()
			return fmt.Errorf("tracker %s failed to loadFromDisk : %v", trackerName, err)
		}
	}

	return nil
}

func (tr *trackerRegistry) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	for _, lt := range tr.trackers {
		lt.newBlock(blk, delta)
	}
}

func (tr *trackerRegistry) committedUpTo(rnd basics.Round) basics.Round {
	minBlock := rnd

	for _, lt := range tr.trackers {
		retain := lt.committedUpTo(rnd)
		if retain < minBlock {
			minBlock = retain
		}
	}

	return minBlock
}

func (tr *trackerRegistry) scheduleCommit(blockqRound basics.Round) {
	tr.mu.RLock()
	dbRound := tr.dbRound
	tr.mu.RUnlock()

	dc := tr.driver.produceCommittingTask(blockqRound, dbRound)
	if dc.offset != 0 {
		tr.accountsWriting.Add(1)
		tr.committedOffset <- dc
	}
}

// waitAccountsWriting waits for all the pending ( or current ) account writing to be completed.
func (tr *trackerRegistry) waitAccountsWriting() {
	tr.accountsWriting.Wait()
}

func (tr *trackerRegistry) close() {
	if tr.ctxCancel != nil {
		tr.ctxCancel()
	}

	// close() is called from reloadLedger() when and trackerRegistry is not initialized yet
	if tr.commitSyncerClosed != nil {
		tr.waitAccountsWriting()
		// this would block until the commitSyncerClosed channel get closed.
		<-tr.commitSyncerClosed
	}

	for _, lt := range tr.trackers {
		lt.close()
	}
	tr.trackers = nil
	tr.driver = nil
}

// commitSyncer is the syncer go-routine function which perform the database updates. Internally, it dequeues deferredCommits and
// send the tasks to commitRound for completing the operation.
func (tr *trackerRegistry) commitSyncer(deferredCommits chan deferredCommit) {
	defer close(tr.commitSyncerClosed)
	for {
		select {
		case committedOffset, ok := <-deferredCommits:
			if !ok {
				return
			}
			tr.commitRound(committedOffset)
		case <-tr.ctx.Done():
			// drain the pending commits queue:
			drained := false
			for !drained {
				select {
				case <-deferredCommits:
					tr.accountsWriting.Done()
				default:
					drained = true
				}
			}
			return
		}
	}
}

func (tr *trackerRegistry) commitRound(dc deferredCommit) {
	defer tr.accountsWriting.Done()

	tr.mu.RLock()

	offset := dc.offset
	dbRound := dc.dbRound
	lookback := dc.lookback

	// we can exit right away, as this is the result of mis-ordered call to committedUpTo.
	if tr.dbRound < dbRound || offset < uint64(tr.dbRound-dbRound) {
		tr.log.Warnf("out of order deferred commit: offset %d, dbRound %d but current tracker DB round is %d", offset, dbRound, tr.dbRound)
		for _, lt := range tr.trackers {
			lt.handleUnorderedCommit(offset, dbRound, lookback)
		}
		tr.mu.RUnlock()
		return
	}

	// adjust the offset according to what happened meanwhile..
	offset -= uint64(tr.dbRound - dbRound)

	// if this iteration need to flush out zero rounds, just return right away.
	// this usecase can happen when two subsequent calls to committedUpTo concludes that the same rounds range need to be
	// flush, without the commitRound have a chance of committing these rounds.
	if offset == 0 {
		tr.mu.RUnlock()
		return
	}

	dbRound = tr.dbRound
	newBase := basics.Round(offset) + dbRound

	dcc := deferredCommitContext{
		offset:    offset,
		oldBase:   dbRound,
		newBase:   newBase,
		lookback:  lookback,
		flushTime: time.Now(),
	}

	for _, lt := range tr.trackers {
		err := lt.prepareCommit(&dcc)
		if err != nil {
			tr.log.Errorf(err.Error())
			tr.mu.RUnlock()
			return
		}
	}
	tr.mu.RUnlock()

	start := time.Now()
	ledgerCommitroundCount.Inc(nil)
	err := tr.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		for _, lt := range tr.trackers {
			err0 := lt.commitRound(ctx, tx, &dcc)
			if err0 != nil {
				return err0
			}
		}

		err = updateAccountsRound(tx, dbRound+basics.Round(offset))
		if err != nil {
			return err
		}

		return nil
	})
	ledgerCommitroundMicros.AddMicrosecondsSince(start, nil)

	if err != nil {
		tr.log.Warnf("unable to advance tracker db snapshot (%d-%d): %v", dbRound, dbRound+basics.Round(offset), err)
		return
	}

	tr.mu.Lock()
	tr.dbRound = newBase
	for _, lt := range tr.trackers {
		lt.postCommit(dcc)
	}
	tr.mu.Unlock()
}
