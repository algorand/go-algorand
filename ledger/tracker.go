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
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
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
	// in isolation. The provided round number represents the
	// current accounts storage round number.
	loadFromDisk(ledgerForTracker, basics.Round) error

	// newBlock informs the tracker of a new block along with
	// a given ledgercore.StateDelta as produced by BlockEvaluator.
	newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta)

	// committedUpTo informs the tracker that the block database has
	// committed all blocks up to and including rnd to persistent
	// storage.  This can allow the tracker
	// to garbage-collect state that will not be needed.
	//
	// committedUpTo() returns the round number of the earliest
	// block that this tracker needs to be stored in the block
	// database for subsequent calls to loadFromDisk().
	// All blocks with round numbers before that may be deleted to
	// save space, and the tracker is expected to still function
	// after a restart and a call to loadFromDisk().
	// For example, returning 0 means that no blocks can be deleted.
	// Separetly, the method returns the lookback that is being
	// maintained by the tracker.
	committedUpTo(basics.Round) (minRound, lookback basics.Round)

	// produceCommittingTask prepares a deferredCommitRange; Preparing a deferredCommitRange is a joint
	// effort, and all the trackers contribute to that effort. All the trackers are being handed a
	// pointer to the deferredCommitRange, and have the ability to either modify it, or return a
	// nil. If nil is returned, the commit would be skipped.
	// The contract:
	// offset must not be greater than the received dcr.offset value of non zero
	// oldBase must not be modifed if non zero
	produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange

	// prepareCommit, commitRound and postCommit are called when it is time to commit tracker's data.
	// If an error returned the process is aborted.

	// prepareCommit aligns the data structures stored in the deferredCommitContext with the current
	// state of the tracker. It allows the tracker to decide what data is going to be persisted
	// on the coming commitRound.
	prepareCommit(*deferredCommitContext) error
	// commitRound is called for each of the trackers after a deferredCommitContext was agreed upon
	// by all the prepareCommit calls. The commitRound is being executed within a single transactional
	// context, and so, if any of the tracker's commitRound calls fails, the transaction is rolled back.
	commitRound(context.Context, trackerdb.TransactionScope, *deferredCommitContext) error
	// postCommit is called only on a successful commitRound. In that case, each of the trackers have
	// the chance to update it's internal data structures, knowing that the given deferredCommitContext
	// has completed. An optional context is provided for long-running operations.
	postCommit(context.Context, *deferredCommitContext)

	// postCommitUnlocked is called only on a successful commitRound. In that case, each of the trackers have
	// the chance to make changes that aren't state-dependent.
	// An optional context is provided for long-running operations.
	postCommitUnlocked(context.Context, *deferredCommitContext)

	// handleUnorderedCommit is a control method for handling deferred commits that are out of order
	// Tracker might update its own state in this case. For example, account updates tracker cancels
	// scheduled catchpoint writing flag for this batch.
	handleUnorderedCommit(*deferredCommitContext)
	// handlePrepareCommitError is a control method for handling self-cleanup or update if any trackers report
	// error during the prepare commit phase of commitRound
	handlePrepareCommitError(*deferredCommitContext)
	// handleCommitError is a control method for handling self-cleanup or update if any trackers report
	// error during the commit phase of commitRound
	handleCommitError(*deferredCommitContext)

	// close terminates the tracker, reclaiming any resources
	// like open database connections or goroutines.  close may
	// be called even if loadFromDisk() is not called or does
	// not succeed.
	close()
}

// ledgerForTracker defines the part of the ledger that a tracker can
// access.  This is particularly useful for testing trackers in isolation.
type ledgerForTracker interface {
	trackerDB() trackerdb.Store
	blockDB() db.Pair
	trackerLog() logging.Logger
	trackerEvalVerified(bookkeeping.Block, eval.LedgerForEvaluator) (ledgercore.StateDelta, error)

	Latest() basics.Round
	Block(basics.Round) (bookkeeping.Block, error)
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	GenesisHash() crypto.Digest
	GenesisProto() config.ConsensusParams
	GenesisProtoVersion() protocol.ConsensusVersion
	GenesisAccounts() map[basics.Address]basics.AccountData
}

type trackerRegistry struct {
	trackers []ledgerTracker
	// these trackers have some exceptional usages in the tracker registry.
	accts       *accountUpdates
	acctsOnline *onlineAccounts
	tail        *txTail

	// ctx is the context for the committing go-routine.
	ctx context.Context
	// ctxCancel is the canceling function for canceling the committing go-routine ( i.e. signaling the committing go-routine that it's time to abort )
	ctxCancel context.CancelFunc

	// deferredCommits is the channel of pending deferred commits
	deferredCommits chan *deferredCommitContext

	// commitSyncerClosed is the blocking channel for synchronizing closing the commitSyncer goroutine. Once it's closed, the
	// commitSyncer can be assumed to have aborted.
	commitSyncerClosed chan struct{}

	// accountsWriting provides synchronization around the background writing of account balances.
	accountsWriting sync.WaitGroup
	// accountsCommitting is set when trackers registry writing accounts into DB.
	accountsCommitting atomic.Bool

	// dbRound is always exactly accountsRound(),
	// cached to avoid SQL queries.
	dbRound basics.Round

	dbs trackerdb.Store
	log logging.Logger

	// the synchronous mode that would be used for the account database.
	synchronousMode db.SynchronousMode

	// the synchronous mode that would be used while the accounts database is being rebuilt.
	accountsRebuildSynchronousMode db.SynchronousMode

	mu deadlock.RWMutex

	// lastFlushTime is the time we last flushed updates to
	// the accounts DB (bumping dbRound).
	lastFlushTime time.Time

	cfg config.Local

	// maxAccountDeltas is a maximum number of in-memory deltas stored by trackers.
	// When exceeded trackerRegistry will attempt to flush, and its Available() method will return false.
	// Too many in-memory deltas could cause the node to run out of memory.
	maxAccountDeltas uint64
}

// defaultMaxAccountDeltas is a default value for maxAccountDeltas.
const defaultMaxAccountDeltas = 256

// deferredCommitRange is used during the calls to produceCommittingTask, and used as a data structure
// to syncronize the various trackers and create a uniformity around which rounds need to be persisted
// next.
type deferredCommitRange struct {
	offset   uint64
	oldBase  basics.Round
	lookback basics.Round
	// lowestRound defines how many rounds of history the voters trackers want to preserve.
	// This value overruns the MaxBalLookback if greater. See lowestRound() for details.
	lowestRound basics.Round

	// catchpointLookback determines the offset from round number to take a snapshot for.
	// i.e. for round X the DB snapshot is taken at X-catchpointLookback
	catchpointLookback uint64

	// pendingDeltas is the number of accounts that were modified within this commit context.
	// note that in this number we might have the same account being modified several times.
	pendingDeltas int

	// True iff we are doing the first stage of catchpoint generation, possibly creating
	// a catchpoint data file, in this commit cycle iteration.
	catchpointFirstStage bool

	// enableGeneratingCatchpointFiles controls whether the node produces catchpoint files or not.
	enableGeneratingCatchpointFiles bool

	// True iff the commit range includes a catchpoint round.
	catchpointSecondStage bool
}

// deferredCommitContext is used in order to synchronize the persistence of a given deferredCommitRange.
// prepareCommit, commitRound and postCommit are all using it to exchange data.
type deferredCommitContext struct {
	deferredCommitRange

	flushTime time.Time

	genesisProto config.ConsensusParams

	roundTotals                ledgercore.AccountTotals
	onlineRoundParams          []ledgercore.OnlineRoundParamsData
	onlineAccountsForgetBefore basics.Round

	compactAccountDeltas   compactAccountDeltas
	compactResourcesDeltas compactResourcesDeltas
	compactKvDeltas        map[string]modifiedKvValue
	compactCreatableDeltas map[basics.CreatableIndex]ledgercore.ModifiedCreatable

	updatedPersistedAccounts  []trackerdb.PersistedAccountData
	updatedPersistedResources map[basics.Address][]trackerdb.PersistedResourcesData
	updatedPersistedKVs       map[string]trackerdb.PersistedKVData

	compactOnlineAccountDeltas     compactOnlineAccountDeltas
	updatedPersistedOnlineAccounts []trackerdb.PersistedOnlineAccountData

	updatingBalancesDuration time.Duration

	// Block hashes for the committed rounds range.
	committedRoundDigests []crypto.Digest

	// Consensus versions for the committed rounds range.
	committedProtocolVersion []protocol.ConsensusVersion

	// on catchpoint rounds, the transaction tail would fill up this field with the hash of the recent 1001 rounds
	// of the txtail data. The catchpointTracker would be able to use that for calculating the catchpoint label.
	txTailHash crypto.Digest

	// serialized rounds deltas to be committed
	txTailDeltas [][]byte

	// txtail rounds deltas history size
	txTailRetainSize uint64

	stats       telemetryspec.AccountsUpdateMetrics
	updateStats bool

	spVerification struct {
		// state proof verification deletion information
		lastDeleteIndex           int
		earliestLastAttestedRound basics.Round

		// state proof verification commit information
		commitContext []verificationCommitContext
	}
}

func (dcc deferredCommitContext) newBase() basics.Round {
	return dcc.oldBase + basics.Round(dcc.offset)
}

var errMissingAccountUpdateTracker = errors.New("trackers replay : called without a valid accounts update tracker")

func (tr *trackerRegistry) initialize(l ledgerForTracker, trackers []ledgerTracker, cfg config.Local) (err error) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.dbs = l.trackerDB()
	tr.log = l.trackerLog()

	tr.maxAccountDeltas = defaultMaxAccountDeltas
	if cfg.MaxAcctLookback > tr.maxAccountDeltas {
		tr.maxAccountDeltas = cfg.MaxAcctLookback + 1
		tr.log.Infof("maxAccountDeltas was overridden to %d because of MaxAcctLookback=%d: this combination might use lots of RAM. To preserve some blocks in blockdb consider using MaxBlockHistoryLookback config option instead of MaxAcctLookback", tr.maxAccountDeltas, cfg.MaxAcctLookback)
	}

	tr.ctx, tr.ctxCancel = context.WithCancel(context.Background())
	tr.deferredCommits = make(chan *deferredCommitContext, 1)
	tr.commitSyncerClosed = make(chan struct{})
	tr.synchronousMode = db.SynchronousMode(cfg.LedgerSynchronousMode)
	tr.accountsRebuildSynchronousMode = db.SynchronousMode(cfg.AccountsRebuildSynchronousMode)
	tr.cfg = cfg
	go tr.commitSyncer(tr.deferredCommits)

	tr.trackers = append([]ledgerTracker{}, trackers...)

	// accountUpdates and onlineAccounts are needed for replaying (called in later in loadFromDisk)
	for _, tracker := range tr.trackers {
		switch t := tracker.(type) {
		case *accountUpdates:
			tr.accts = t
		case *onlineAccounts:
			tr.acctsOnline = t
		case *txTail:
			tr.tail = t
		}
	}

	return
}

func (tr *trackerRegistry) loadFromDisk(l ledgerForTracker) error {
	var dbRound basics.Round
	err := tr.dbs.Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) (err error) {
		ar, err0 := tx.MakeAccountsReader()
		if err0 != nil {
			return err0
		}

		dbRound, err0 = ar.AccountsRound()
		return err0
	})
	if err != nil {
		return err
	}

	tr.mu.RLock()
	tr.dbRound = dbRound
	tr.mu.RUnlock()

	for _, lt := range tr.trackers {
		err0 := lt.loadFromDisk(l, dbRound)
		if err0 != nil {
			// find the tracker name.
			trackerName := reflect.TypeOf(lt).String()
			return fmt.Errorf("tracker %s failed to loadFromDisk : %w", trackerName, err0)
		}
	}

	if err0 := tr.replay(l); err0 != nil {
		return fmt.Errorf("trackers replay failed : %w", err0)
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
	maxLookback := basics.Round(0)
	for _, lt := range tr.trackers {
		retainRound, lookback := lt.committedUpTo(rnd)
		if retainRound < minBlock {
			minBlock = retainRound
		}
		if lookback > maxLookback {
			maxLookback = lookback
		}
	}

	tr.scheduleCommit(rnd, maxLookback)

	return minBlock
}

func (tr *trackerRegistry) produceCommittingTask(blockqRound basics.Round, dbRound basics.Round, cdr *deferredCommitRange) *deferredCommitRange {
	for _, lt := range tr.trackers {
		base := cdr.oldBase
		offset := cdr.offset
		cdr = lt.produceCommittingTask(blockqRound, dbRound, cdr)
		if cdr == nil {
			break
		}
		if offset > 0 && cdr.offset > offset {
			tr.log.Warnf("tracker %T produced offset %d but expected not greater than %d, dbRound %d, latestRound %d", lt, cdr.offset, offset, dbRound, blockqRound)
		}
		if base > 0 && base != cdr.oldBase {
			tr.log.Warnf("tracker %T modified oldBase %d that expected to be %d, dbRound %d, latestRound %d", lt, cdr.oldBase, base, dbRound, blockqRound)
		}
	}
	return cdr
}

func (tr *trackerRegistry) scheduleCommit(blockqRound, maxLookback basics.Round) {
	dcc := &deferredCommitContext{
		deferredCommitRange: deferredCommitRange{
			lookback: maxLookback,
		},
	}

	tr.mu.RLock()
	dbRound := tr.dbRound
	cdr := tr.produceCommittingTask(blockqRound, dbRound, &dcc.deferredCommitRange)
	if cdr != nil {
		dcc.deferredCommitRange = *cdr
	} else {
		dcc = nil
	}
	// If we recently flushed, wait to aggregate some more blocks.
	// ( unless we're creating a catchpoint, in which case we want to flush it right away
	//   so that all the instances of the catchpoint would contain exactly the same data )
	flushTime := time.Now()

	// Some tracker want to flush
	if dcc != nil {
		// skip this flush if none of these conditions met:
		// - has it been at least balancesFlushInterval since the last flush?
		flushIntervalPassed := flushTime.After(tr.lastFlushTime.Add(balancesFlushInterval))
		// - does this commit task also include catchpoint file creation activity for the dcc.oldBase+dcc.offset?
		flushForCatchpoint := dcc.catchpointFirstStage || dcc.catchpointSecondStage
		// - have more than pendingDeltasFlushThreshold accounts been modified since the last flush?
		flushAccounts := dcc.pendingDeltas >= pendingDeltasFlushThreshold
		if !(flushIntervalPassed || flushForCatchpoint || flushAccounts) {
			dcc = nil
		}
	}
	tr.mu.RUnlock()

	if dcc != nil {
		// Increment the waitgroup first, otherwise this goroutine can be interrupted
		// and commitSyncer attempts calling Done() on empty wait group.
		tr.accountsWriting.Add(1)
		select {
		case tr.deferredCommits <- dcc:
		default:
			// Do NOT block if deferredCommits cannot accept this task, skip it.
			// Note: the next attempt will include these rounds plus some extra rounds.
			// The main reason for slow commits is catchpoint file creation (when commitSyncer calls
			// commitRound, which calls postCommitUnlocked). This producer thread is called by
			// blockQueue.syncer() upon successful block DB flush, which calls ledger.notifyCommit()
			// and trackerRegistry.committedUpTo() after taking the trackerMu.Lock().
			// This means a blocking write to deferredCommits will block Ledger reads (TODO use more fine-grained locks).
			// Dropping this dcc allows the blockqueue syncer to continue persisting other blocks
			// and ledger reads to proceed without being blocked by trackerMu lock.
			tr.accountsWriting.Done()
		}
	}
}

// waitAccountsWriting waits for all the pending ( or current ) account writing to be completed.
func (tr *trackerRegistry) waitAccountsWriting() {
	tr.accountsWriting.Wait()
}

func (tr *trackerRegistry) isBehindCommittingDeltas(latest basics.Round) bool {
	tr.mu.RLock()
	dbRound := tr.dbRound
	tr.mu.RUnlock()

	numDeltas := uint64(latest.SubSaturate(dbRound))
	if numDeltas < tr.maxAccountDeltas {
		return false
	}

	// there is a large number of deltas check if commitSyncer is not writing accounts
	return tr.accountsCommitting.Load()
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
	tr.accts = nil
}

// commitSyncer is the syncer go-routine function which perform the database updates. Internally, it dequeues deferredCommits and
// send the tasks to commitRound for completing the operation.
func (tr *trackerRegistry) commitSyncer(deferredCommits chan *deferredCommitContext) {
	defer close(tr.commitSyncerClosed)
	for {
		select {
		case commit, ok := <-deferredCommits:
			if !ok {
				return
			}
			err := tr.commitRound(commit)
			if err != nil {
				tr.log.Warnf("Could not commit round: %v", err)
			}
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

// commitRound commits the given deferredCommitContext via the trackers.
func (tr *trackerRegistry) commitRound(dcc *deferredCommitContext) error {
	defer tr.accountsWriting.Done()
	tr.mu.RLock()

	offset := dcc.offset
	dbRound := dcc.oldBase

	// we can exit right away, as this is the result of mis-ordered call to committedUpTo.
	if tr.dbRound < dbRound || offset < uint64(tr.dbRound-dbRound) {
		tr.log.Warnf("out of order deferred commit: offset %d, dbRound %d but current tracker DB round is %d", offset, dbRound, tr.dbRound)
		for _, lt := range tr.trackers {
			lt.handleUnorderedCommit(dcc)
		}
		tr.mu.RUnlock()
		return nil
	}

	// adjust the offset according to what happened meanwhile..
	offset -= uint64(tr.dbRound - dbRound)

	// if this iteration need to flush out zero rounds, just return right away.
	// this usecase can happen when two subsequent calls to committedUpTo concludes that the same rounds range need to be
	// flush, without the commitRound have a chance of committing these rounds.
	if offset == 0 {
		tr.mu.RUnlock()
		return nil
	}

	dbRound = tr.dbRound
	newBase := basics.Round(offset) + dbRound

	dcc.offset = offset
	dcc.oldBase = dbRound
	dcc.flushTime = time.Now()

	var err error
	for _, lt := range tr.trackers {
		err = lt.prepareCommit(dcc)
		if err != nil {
			tr.log.Errorf(err.Error())
			break
		}
	}
	if err != nil {
		for _, lt := range tr.trackers {
			lt.handlePrepareCommitError(dcc)
		}
		tr.mu.RUnlock()
		return err
	}

	tr.mu.RUnlock()

	start := time.Now()
	ledgerCommitroundCount.Inc(nil)
	err = tr.dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		tr.accountsCommitting.Store(true)
		defer func() {
			tr.accountsCommitting.Store(false)
		}()

		aw, err := tx.MakeAccountsWriter()
		if err != nil {
			return err
		}

		for _, lt := range tr.trackers {
			err0 := lt.commitRound(ctx, tx, dcc)
			if err0 != nil {
				return err0
			}
		}

		return aw.UpdateAccountsRound(dbRound + basics.Round(offset))
	})
	ledgerCommitroundMicros.AddMicrosecondsSince(start, nil)

	if err != nil {

		for _, lt := range tr.trackers {
			lt.handleCommitError(dcc)
		}
		tr.log.Warnf("unable to advance tracker db snapshot (%d-%d): %v", dbRound, dbRound+basics.Round(offset), err)

		// if the error is an IO error, shut down the node.
		var trackerIOErr *trackerdb.ErrIoErr
		if errors.As(err, &trackerIOErr) {
			tr.log.Fatalf("Fatal IO error during CommitRound, exiting: %v", err)
		}

		return err
	}

	tr.mu.Lock()
	tr.dbRound = newBase
	for _, lt := range tr.trackers {
		lt.postCommit(tr.ctx, dcc)
	}
	tr.lastFlushTime = dcc.flushTime
	tr.mu.Unlock()

	for _, lt := range tr.trackers {
		lt.postCommitUnlocked(tr.ctx, dcc)
	}

	return nil
}

// replay fills up the accountUpdates cache with the most recent ~320 blocks ( on normal execution ).
// the method also support balances recovery in cases where the difference between the lastBalancesRound and the lastestBlockRound
// is far greater than 320; in these cases, it would flush to disk periodically in order to avoid high memory consumption.
func (tr *trackerRegistry) replay(l ledgerForTracker) (err error) {
	lastestBlockRound := l.Latest()
	lastBalancesRound := tr.dbRound

	var blk bookkeeping.Block
	var delta ledgercore.StateDelta

	if tr.accts == nil || tr.acctsOnline == nil || tr.tail == nil {
		return errMissingAccountUpdateTracker
	}

	accLedgerEval := accountUpdatesLedgerEvaluator{
		au:   tr.accts,
		ao:   tr.acctsOnline,
		tail: tr.tail,
	}

	if lastBalancesRound < lastestBlockRound {
		accLedgerEval.prevHeader, err = l.BlockHdr(lastBalancesRound)
		if err != nil {
			return fmt.Errorf("trackerRegistry.replay: unable to load block header %d : %w", lastBalancesRound, err)
		}
	}

	skipAccountCacheMessage := make(chan struct{})
	writeAccountCacheMessageCompleted := make(chan struct{})
	defer func() {
		close(skipAccountCacheMessage)
		select {
		case <-writeAccountCacheMessageCompleted:
			if err == nil {
				tr.log.Infof("trackerRegistry.replay completed initializing account data caches")
			}
		default:
		}
	}()

	catchpointInterval := uint64(0)
	for _, tracker := range tr.trackers {
		if catchpointTracker, ok := tracker.(*catchpointTracker); ok {
			catchpointInterval = catchpointTracker.catchpointInterval
			break
		}
	}

	// this goroutine logs a message once if the parent function have not completed in initializingAccountCachesMessageTimeout seconds.
	// the message is important, since we're blocking on the ledger block database here, and we want to make sure that we log a message
	// within the above timeout.
	go func() {
		select {
		case <-time.After(initializingAccountCachesMessageTimeout):
			tr.log.Infof("trackerRegistry.replay is initializing account data caches")
			close(writeAccountCacheMessageCompleted)
		case <-skipAccountCacheMessage:
		}
	}()

	blocksStream := make(chan bookkeeping.Block, initializeCachesReadaheadBlocksStream)
	blockEvalFailed := make(chan struct{}, 1)
	var blockRetrievalError error
	go func() {
		defer close(blocksStream)
		for roundNumber := lastBalancesRound + 1; roundNumber <= lastestBlockRound; roundNumber++ {
			blk, blockRetrievalError = l.Block(roundNumber)
			if blockRetrievalError != nil {
				return
			}
			select {
			case blocksStream <- blk:
			case <-blockEvalFailed:
				return
			}
		}
	}()

	lastFlushedRound := lastBalancesRound
	const accountsCacheLoadingMessageInterval = 5 * time.Second
	lastProgressMessage := time.Now().Add(-accountsCacheLoadingMessageInterval / 2)

	// rollbackSynchronousMode ensures that we switch to "fast writing mode" when we start flushing out rounds to disk, and that
	// we exit this mode when we're done.
	rollbackSynchronousMode := false
	defer func() {
		if rollbackSynchronousMode {
			// restore default synchronous mode
			err0 := tr.dbs.SetSynchronousMode(context.Background(), tr.synchronousMode, tr.synchronousMode >= db.SynchronousModeFull)
			// override the returned error only in case there is no error - since this
			// operation has a lower criticality.
			if err == nil {
				err = err0
			}
		}
	}()

	maxAcctLookback := tr.cfg.MaxAcctLookback

	for blk := range blocksStream {
		delta, err = l.trackerEvalVerified(blk, &accLedgerEval)
		if err != nil {
			close(blockEvalFailed)
			err = fmt.Errorf("trackerRegistry.replay: trackerEvalVerified failed : %w", err)
			return
		}
		tr.newBlock(blk, delta)

		// flush to disk if any of the following applies:
		// 1. if we have loaded up more than initializeCachesRoundFlushInterval rounds since the last time we flushed the data to disk
		// 2. if we completed the loading and we loaded up more than 320 rounds.
		flushIntervalExceed := blk.Round()-lastFlushedRound > initializeCachesRoundFlushInterval
		loadCompleted := (lastestBlockRound == blk.Round() && lastBalancesRound+basics.Round(maxAcctLookback) < lastestBlockRound)
		if flushIntervalExceed || loadCompleted {
			// adjust the last flush time, so that we would not hold off the flushing due to "working too fast"
			tr.lastFlushTime = time.Now().Add(-balancesFlushInterval)

			if !rollbackSynchronousMode {
				// switch to rebuild synchronous mode to improve performance
				err0 := tr.dbs.SetSynchronousMode(context.Background(), tr.accountsRebuildSynchronousMode, tr.accountsRebuildSynchronousMode >= db.SynchronousModeFull)
				if err0 != nil {
					tr.log.Warnf("trackerRegistry.replay was unable to switch to rbuild synchronous mode : %v", err0)
				} else {
					// flip the switch to rollback the synchronous mode once we're done.
					rollbackSynchronousMode = true
				}
			}

			var roundsBehind basics.Round

			// flush the account data
			tr.scheduleCommit(blk.Round(), basics.Round(maxAcctLookback))
			// wait for the writing to complete.
			tr.waitAccountsWriting()

			tr.mu.RLock()
			// The au.dbRound after writing should be ~320 behind the block round (before shorter delta project)
			roundsBehind = blk.Round() - tr.dbRound
			tr.mu.RUnlock()

			// are we farther behind than we need to be? Consider: catchpoint interval, flush interval and max acct lookback.
			if roundsBehind > basics.Round(maxAcctLookback) && roundsBehind > initializeCachesRoundFlushInterval+basics.Round(catchpointInterval) {
				// we're unable to persist changes. This is unexpected, but there is no point in keep trying batching additional changes since any further changes
				// would just accumulate in memory.
				close(blockEvalFailed)
				tr.log.Errorf("trackerRegistry.replay was unable to fill up the account caches accounts round = %d, block round = %d. See above error for more details.", blk.Round()-roundsBehind, blk.Round())
				err = fmt.Errorf("trackerRegistry.replay failed to initialize the account data caches")
				return
			}

			// and once we flushed it to disk, update the lastFlushedRound
			lastFlushedRound = blk.Round()
		}

		// if enough time have passed since the last time we wrote a message to the log file then give the user an update about the progess.
		if time.Since(lastProgressMessage) > accountsCacheLoadingMessageInterval {
			// drop the initial message if we're got to this point since a message saying "still initializing" that comes after "is initializing" doesn't seems to be right.
			select {
			case skipAccountCacheMessage <- struct{}{}:
				// if we got to this point, we should be able to close the writeAccountCacheMessageCompleted channel to have the "completed initializing" message written.
				close(writeAccountCacheMessageCompleted)
			default:
			}
			tr.log.Infof("trackerRegistry.replay is still initializing account data caches, %d rounds loaded out of %d rounds", blk.Round()-lastBalancesRound, lastestBlockRound-lastBalancesRound)
			lastProgressMessage = time.Now()
		}

		// prepare for the next iteration.
		accLedgerEval.prevHeader = *delta.Hdr
	}

	if blockRetrievalError != nil {
		err = blockRetrievalError
	}
	return
}

// getDbRound accesses dbRound with protection by the trackerRegistry's mutex.
func (tr *trackerRegistry) getDbRound() basics.Round {
	tr.mu.RLock()
	dbRound := tr.dbRound
	tr.mu.RUnlock()
	return dbRound
}

// accountUpdatesLedgerEvaluator is a "ledger emulator" which is used *only* by initializeCaches, as a way to shortcut
// the locks taken by the real ledger object when making requests that are being served by the accountUpdates.
// Using this struct allow us to take the tracker lock *before* calling the loadFromDisk, and having the operation complete
// without taking any locks. Note that it's not only the locks performance that is gained : by having the loadFrom disk
// not requiring any external locks, we can safely take a trackers lock on the ledger during reloadLedger, which ensures
// that even during catchpoint catchup mode switch, we're still correctly protected by a mutex.
type accountUpdatesLedgerEvaluator struct {
	// au is the associated accountUpdates structure which invoking the trackerEvalVerified function, passing this structure as input.
	// the accountUpdatesLedgerEvaluator would access the underlying accountUpdates function directly, bypassing the balances mutex lock.
	au *accountUpdates
	// ao is onlineAccounts for voters access
	ao *onlineAccounts
	// txtail allows BlockHdr to serve blockHdr without going to disk
	tail *txTail
	// prevHeader is the previous header to the current one. The usage of this is only in the context of initializeCaches where we iteratively
	// building the ledgercore.StateDelta, which requires a peek on the "previous" header information.
	prevHeader bookkeeping.BlockHeader
}

func (aul *accountUpdatesLedgerEvaluator) FlushCaches() {}

// GenesisHash returns the genesis hash
func (aul *accountUpdatesLedgerEvaluator) GenesisHash() crypto.Digest {
	return aul.au.ledger.GenesisHash()
}

// GenesisProto returns the genesis consensus params
func (aul *accountUpdatesLedgerEvaluator) GenesisProto() config.ConsensusParams {
	return aul.au.ledger.GenesisProto()
}

// VotersForStateProof returns the top online accounts at round rnd.
func (aul *accountUpdatesLedgerEvaluator) VotersForStateProof(rnd basics.Round) (voters *ledgercore.VotersForRound, err error) {
	return aul.ao.voters.VotersForStateProof(rnd)
}

func (aul *accountUpdatesLedgerEvaluator) GetStateProofVerificationContext(_ basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	// Since state proof transaction is not being verified (we only apply the change) during replay, we don't need to implement this function at the moment.
	return nil, fmt.Errorf("accountUpdatesLedgerEvaluator: GetStateProofVerificationContext, needed for state proof verification, is not implemented in accountUpdatesLedgerEvaluator")
}

// BlockHdr returns the header of the given round. When the evaluator is running, it's only referring to the previous header, which is what we
// are providing here. Any attempt to access a different header would get denied.
func (aul *accountUpdatesLedgerEvaluator) BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	if r == aul.prevHeader.Round {
		return aul.prevHeader, nil
	}
	hdr, ok := aul.tail.blockHeader(r)
	if ok {
		return hdr, nil
	}
	return bookkeeping.BlockHeader{}, ledgercore.ErrNoEntry{}
}

// LatestTotals returns the totals of all accounts for the most recent round, as well as the round number
func (aul *accountUpdatesLedgerEvaluator) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	return aul.au.latestTotalsImpl()
}

// CheckDup test to see if the given transaction id/lease already exists. It's not needed by the accountUpdatesLedgerEvaluator and implemented as a stub.
func (aul *accountUpdatesLedgerEvaluator) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error {
	// this is a non-issue since this call will never be made on non-validating evaluation
	return fmt.Errorf("accountUpdatesLedgerEvaluator: tried to check for dup during accountUpdates initialization ")
}

// LookupWithoutRewards returns the account balance for a given address at a given round, without the reward
func (aul *accountUpdatesLedgerEvaluator) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, error) {
	data, validThrough, _, _, err := aul.au.lookupWithoutRewards(rnd, addr, false /*don't sync*/)
	if err != nil {
		return ledgercore.AccountData{}, 0, err
	}

	return data, validThrough, err
}

func (aul *accountUpdatesLedgerEvaluator) LookupAgreement(rnd basics.Round, addr basics.Address) (basics.OnlineAccountData, error) {
	return aul.ao.LookupOnlineAccountData(rnd, addr)
}

func (aul *accountUpdatesLedgerEvaluator) OnlineCirculation(rnd basics.Round, voteRnd basics.Round) (basics.MicroAlgos, error) {
	return aul.ao.onlineCirculation(rnd, voteRnd)
}

func (aul *accountUpdatesLedgerEvaluator) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	r, _, err := aul.au.lookupResource(rnd, addr, basics.CreatableIndex(aidx), basics.AppCreatable, false /* don't sync */)
	return ledgercore.AppResource{AppParams: r.AppParams, AppLocalState: r.AppLocalState}, err
}

func (aul *accountUpdatesLedgerEvaluator) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	r, _, err := aul.au.lookupResource(rnd, addr, basics.CreatableIndex(aidx), basics.AssetCreatable, false /* don't sync */)
	return ledgercore.AssetResource{AssetParams: r.AssetParams, AssetHolding: r.AssetHolding}, err
}

func (aul *accountUpdatesLedgerEvaluator) LookupKv(rnd basics.Round, key string) ([]byte, error) {
	return aul.au.lookupKv(rnd, key, false /* don't sync */)
}

// GetCreatorForRound returns the asset/app creator for a given asset/app index at a given round
func (aul *accountUpdatesLedgerEvaluator) GetCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (creator basics.Address, ok bool, err error) {
	return aul.au.getCreatorForRound(rnd, cidx, ctype, false /* don't sync */)
}
