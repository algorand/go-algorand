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
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// commitRoundNext schedules a commit with as many rounds as possible
func commitRoundNext(l *Ledger) {
	maxAcctLookback := 320
	commitRoundLookback(basics.Round(maxAcctLookback), l)
}

// TestTrackerScheduleCommit checks catchpointTracker.produceCommittingTask does not increase commit offset relative
// to the value set by accountUpdates
func TestTrackerScheduleCommit(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	var bufNewLogger bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&bufNewLogger)

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(1, true)}
	ml := makeMockLedgerForTrackerWithLogger(t, true, 10, protocol.ConsensusCurrentVersion, accts, log)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointTracking = 1
	conf.CatchpointInterval = 10

	au := &accountUpdates{}
	ct := &catchpointTracker{}
	ao := &onlineAccounts{}
	au.initialize(conf)
	paths := DirsAndPrefix{
		ResolvedGenesisDirs: config.ResolvedGenesisDirs{
			CatchpointGenesisDir: ".",
			HotGenesisDir:        ".",
		},
	}
	ct.initialize(conf, paths)
	ao.initialize(conf)

	_, err := trackerDBInitialize(ml, false, ".")
	a.NoError(err)

	ml.trackers.initialize(ml, []ledgerTracker{au, ct, ao, &txTail{}}, conf)
	defer ml.trackers.close()
	err = ml.trackers.loadFromDisk(ml)
	a.NoError(err)
	// close commitSyncer goroutine
	ml.trackers.ctxCancel()
	ml.trackers.ctxCancel = nil
	<-ml.trackers.commitSyncerClosed
	ml.trackers.commitSyncerClosed = nil

	expectedOffset := uint64(99)
	blockqRound := basics.Round(1000)
	lookback := basics.Round(16)
	dbRound := basics.Round(1)

	// prepare deltas and versions
	au.accountsMu.Lock()
	au.deltas = make([]ledgercore.StateDelta, int(blockqRound))
	au.deltasAccum = make([]int, int(blockqRound))
	au.versions = make([]protocol.ConsensusVersion, int(blockqRound))
	ao.deltas = make([]ledgercore.AccountDeltas, int(blockqRound))
	ao.onlineRoundParamsData = make([]ledgercore.OnlineRoundParamsData, int(blockqRound))
	for i := 0; i <= int(expectedOffset); i++ {
		au.versions[i] = protocol.ConsensusCurrentVersion
		ao.onlineRoundParamsData[i] = ledgercore.OnlineRoundParamsData{CurrentProtocol: protocol.ConsensusCurrentVersion}
	}
	for i := int(expectedOffset) + 1; i < len(au.versions); i++ {
		au.versions[i] = protocol.ConsensusFuture
		ao.onlineRoundParamsData[i] = ledgercore.OnlineRoundParamsData{CurrentProtocol: protocol.ConsensusFuture}
	}
	au.accountsMu.Unlock()

	// ensure au and ct produce data we expect
	dcc := &deferredCommitContext{
		deferredCommitRange: deferredCommitRange{
			lookback: lookback,
		},
	}
	cdr := &dcc.deferredCommitRange

	cdr = au.produceCommittingTask(blockqRound, dbRound, cdr)
	a.NotNil(cdr)
	a.Equal(expectedOffset, cdr.offset)

	cdr = ao.produceCommittingTask(blockqRound, dbRound, cdr)
	a.NotNil(cdr)
	a.Equal(expectedOffset, cdr.offset)

	cdr = ct.produceCommittingTask(blockqRound, dbRound, cdr)
	a.NotNil(cdr)
	// before the fix
	// expectedOffset = uint64(blockqRound - lookback - dbRound) // 983
	a.Equal(expectedOffset, cdr.offset)

	// schedule the commit. au is expected to return offset 100 and
	ml.trackers.mu.Lock()
	ml.trackers.dbRound = dbRound
	ml.trackers.lastFlushTime = time.Time{}
	ml.trackers.mu.Unlock()
	ml.trackers.scheduleCommit(blockqRound, lookback)

	a.Equal(1, len(ml.trackers.deferredCommits))
	// before the fix
	// a.Contains(bufNewLogger.String(), "tracker *ledger.catchpointTracker produced offset 983")
	a.NotContains(bufNewLogger.String(), "tracker *ledger.catchpointTracker produced offset")
	dc := <-ml.trackers.deferredCommits
	a.Equal(expectedOffset, dc.offset)
}

type emptyTracker struct {
}

// loadFromDisk is not implemented in the emptyTracker.
func (t *emptyTracker) loadFromDisk(ledgerForTracker, basics.Round) error {
	return nil
}

// newBlock is not implemented in the emptyTracker.
func (t *emptyTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
}

// committedUpTo in the emptyTracker just stores the committed round.
func (t *emptyTracker) committedUpTo(committedRnd basics.Round) (minRound, lookback basics.Round) {
	return 0, basics.Round(0)
}

func (t *emptyTracker) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return dcr
}

// prepareCommit, is not used by the emptyTracker
func (t *emptyTracker) prepareCommit(*deferredCommitContext) error {
	return nil
}

// commitRound is not used by the emptyTracker
func (t *emptyTracker) commitRound(context.Context, trackerdb.TransactionScope, *deferredCommitContext) error {
	return nil
}

func (t *emptyTracker) postCommit(ctx context.Context, dcc *deferredCommitContext) {
}

// postCommitUnlocked implements entry/exit blockers, designed for testing.
func (t *emptyTracker) postCommitUnlocked(ctx context.Context, dcc *deferredCommitContext) {
}

// control functions are not used by the emptyTracker
func (t *emptyTracker) handleUnorderedCommit(dcc *deferredCommitContext) {
}
func (t *emptyTracker) handlePrepareCommitError(dcc *deferredCommitContext) {
}
func (t *emptyTracker) handleCommitError(dcc *deferredCommitContext) {
}

// close is not used by the emptyTracker
func (t *emptyTracker) close() {
}

type ioErrorTracker struct {
	emptyTracker
}

// commitRound is not used by the ioErrorTracker
func (io *ioErrorTracker) commitRound(context.Context, trackerdb.TransactionScope, *deferredCommitContext) error {
	return sqlite3.Error{Code: sqlite3.ErrIoErr}
}

type producePrepareBlockingTracker struct {
	emptyTracker
	produceReleaseLock       chan struct{}
	prepareCommitEntryLock   chan struct{}
	prepareCommitReleaseLock chan struct{}
	cancelTasks              bool
}

func (bt *producePrepareBlockingTracker) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	if bt.cancelTasks {
		return nil
	}

	<-bt.produceReleaseLock
	return dcr
}

// prepareCommit, is not used by the blockingTracker
func (bt *producePrepareBlockingTracker) prepareCommit(*deferredCommitContext) error {
	bt.prepareCommitEntryLock <- struct{}{}
	<-bt.prepareCommitReleaseLock
	return nil
}

func (bt *producePrepareBlockingTracker) reset() {
	bt.prepareCommitEntryLock = make(chan struct{})
	bt.prepareCommitReleaseLock = make(chan struct{})
	bt.prepareCommitReleaseLock = make(chan struct{})
	bt.cancelTasks = false
}

type commitRoundStallingTracker struct {
	emptyTracker
	commitRoundLock chan struct{}
}

// commitRound is not used by the blockingTracker
func (st *commitRoundStallingTracker) commitRound(context.Context, trackerdb.TransactionScope, *deferredCommitContext) error {
	<-st.commitRoundLock
	return nil
}

// TestTrackers_DbRoundDataRace checks for dbRound data race
// when commit scheduling relies on dbRound from the tracker registry but tracker's deltas
// are used in calculations
// 1. Add say 128 + MaxAcctLookback (MaxLookback) blocks and commit
// 2. Add 2*MaxLookback blocks without committing
// 3. Set a block in prepareCommit, and initiate the commit
// 4. Set a block in produceCommittingTask, add a new block and resume the commit
// 5. Resume produceCommittingTask
// 6. The data race and panic happens in block queue syncher thread
func TestTrackers_DbRoundDataRace(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Skip("For manual run when touching ledger locking")

	a := require.New(t)

	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 1)
	const inMem = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)
	cfg := config.GetDefaultLocal()
	ledger, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	a.NoError(err, "could not open ledger")
	defer ledger.Close()

	stallingTracker := &producePrepareBlockingTracker{
		// produceEntryLock:         make(chan struct{}, 10),
		produceReleaseLock:       make(chan struct{}),
		prepareCommitEntryLock:   make(chan struct{}, 10),
		prepareCommitReleaseLock: make(chan struct{}),
	}
	ledger.trackerMu.Lock()
	ledger.trackers.mu.Lock()
	ledger.trackers.trackers = append([]ledgerTracker{stallingTracker}, ledger.trackers.trackers...)
	ledger.trackers.mu.Unlock()
	ledger.trackerMu.Unlock()

	close(stallingTracker.produceReleaseLock)
	close(stallingTracker.prepareCommitReleaseLock)

	targetRound := basics.Round(128) * 5
	blk := genesisInitState.Block
	for i := basics.Round(0); i < targetRound-1; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		err := ledger.AddBlock(blk, agreement.Certificate{})
		a.NoError(err)
	}
	blk.BlockHeader.Round++
	blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
	err = ledger.AddBlock(blk, agreement.Certificate{})
	a.NoError(err)
	commitRoundNext(ledger)
	ledger.trackers.waitAccountsWriting()
	lookback := 320
	// lookback := cfg.MaxAcctLookback
	a.Equal(targetRound-basics.Round(lookback), ledger.trackers.dbRound)

	// build up some non-committed queue
	stallingTracker.cancelTasks = true
	for i := targetRound; i < 2*targetRound; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		err := ledger.AddBlock(blk, agreement.Certificate{})
		a.NoError(err)
	}
	ledger.WaitForCommit(2*targetRound - 1)

	stallingTracker.reset()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		commitRoundNext(ledger)
		wg.Done()
	}()

	<-stallingTracker.prepareCommitEntryLock
	stallingTracker.produceReleaseLock = make(chan struct{})

	blk.BlockHeader.Round++
	blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
	err = ledger.AddBlock(blk, agreement.Certificate{})
	a.NoError(err)
	// the notifyCommit -> committedUpTo -> scheduleCommit chain
	// is called right after the cond var, so wait until that moment
	ledger.WaitForCommit(2 * targetRound)

	// let the commit to complete
	close(stallingTracker.prepareCommitReleaseLock)
	wg.Wait()

	// unblock the notifyCommit (scheduleCommit) goroutine
	stallingTracker.cancelTasks = true
	close(stallingTracker.produceReleaseLock)
}

func TestTrackers_CommitRoundIOError(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 1)
	const inMem = true
	log := logging.TestingLogWithoutFatalExit(t)
	log.SetLevel(logging.Warn)
	cfg := config.GetDefaultLocal()
	ledger, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	a.NoError(err, "could not open ledger")
	defer ledger.Close()

	// flip the flag when the exit handler is called,
	// which happens when Fatal logging is called
	var flag atomic.Bool
	logging.RegisterExitHandler(func() {
		flag.Store(true)
	})

	io := &ioErrorTracker{}
	ledger.trackerMu.Lock()
	ledger.trackers.mu.Lock()
	ledger.trackers.trackers = append([]ledgerTracker{io}, ledger.trackers.trackers...)
	ledger.trackers.mu.Unlock()
	ledger.trackerMu.Unlock()

	// create update content which would trigger a commit
	targetRound := basics.Round(100)
	blk := genesisInitState.Block
	for i := basics.Round(0); i < targetRound-1; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		err := ledger.AddBlock(blk, agreement.Certificate{})
		a.NoError(err)
	}
	blk.BlockHeader.Round++
	blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
	err = ledger.AddBlock(blk, agreement.Certificate{})
	a.NoError(err)

	// confirm that after 100 blocks, the scheduled commit generated an error
	// which triggered Fatal logging (and would therefore call any registered exit handlers)
	a.True(flag.Load())
}

// TestTrackers_BusyCommitting ensures trackerRegistry.busy() is set when commitRound is in progress
func TestTrackers_BusyCommitting(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 1)
	const inMem = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)
	cfg := config.GetDefaultLocal()
	ledger, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	a.NoError(err)
	defer ledger.Close()

	// quit the commitSyncer goroutine
	ledger.trackers.ctxCancel()
	ledger.trackers.ctxCancel = nil
	<-ledger.trackers.commitSyncerClosed
	ledger.trackers.commitSyncerClosed = nil

	tracker := &commitRoundStallingTracker{
		commitRoundLock: make(chan struct{}),
	}
	ledger.trackerMu.Lock()
	ledger.trackers.mu.Lock()
	ledger.trackers.trackers = append([]ledgerTracker{tracker}, ledger.trackers.trackers...)
	ledger.trackers.lastFlushTime = time.Time{}
	ledger.trackers.mu.Unlock()
	ledger.trackerMu.Unlock()

	// add some blocks
	blk := genesisInitState.Block
	for i := basics.Round(0); i < basics.Round(cfg.MaxAcctLookback)+1; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp++
		ledger.trackers.newBlock(blk, ledgercore.StateDelta{})
	}

	// manually trigger a commit
	ledger.trackers.committedUpTo(blk.BlockHeader.Round)
	dcc := <-ledger.trackers.deferredCommits
	go func() {
		err = ledger.trackers.commitRound(dcc)
		a.NoError(err)
	}()

	// commitRoundStallingTracker blocks commitRound in the goroutine above, wait few secs to ensure the trackerRegistry has set busy()
	a.Eventually(func() bool {
		return ledger.trackers.accountsCommitting.Load()
	}, 3*time.Second, 50*time.Millisecond)
	close(tracker.commitRoundLock)
	ledger.trackers.waitAccountsWriting()
	a.False(ledger.trackers.accountsCommitting.Load())
}

func TestTrackers_InitializeMaxAccountDeltas(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	accts := setupAccts(20)
	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()
	tr := trackerRegistry{}

	cfg := config.GetDefaultLocal()
	err := tr.initialize(ml, []ledgerTracker{}, cfg)
	a.NoError(err)
	// quit the commitSyncer goroutine
	tr.ctxCancel()
	tr.ctxCancel = nil
	<-tr.commitSyncerClosed
	tr.commitSyncerClosed = nil
	a.Equal(uint64(defaultMaxAccountDeltas), tr.maxAccountDeltas)

	cfg.MaxAcctLookback = defaultMaxAccountDeltas + 100
	err = tr.initialize(ml, []ledgerTracker{}, cfg)
	a.NoError(err)
	// quit the commitSyncer goroutine
	tr.ctxCancel()
	tr.ctxCancel = nil
	<-tr.commitSyncerClosed
	tr.commitSyncerClosed = nil
	a.Equal(cfg.MaxAcctLookback+1, tr.maxAccountDeltas)
}

func TestTrackers_IsBehindCommittingDeltas(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	tr := trackerRegistry{
		accts:            &accountUpdates{},
		maxAccountDeltas: defaultMaxAccountDeltas,
	}

	latest := basics.Round(0)
	a.False(tr.isBehindCommittingDeltas(latest))

	// no deltas but busy committing => not behind
	tr.accountsCommitting.Store(true)
	a.False(tr.isBehindCommittingDeltas(latest))
	tr.accountsCommitting.Store(false)

	// lots of deltas but not committing => not behind
	latest = basics.Round(defaultMaxAccountDeltas + 10)
	tr.dbRound = 0
	a.False(tr.isBehindCommittingDeltas(latest))

	// lots of deltas and committing => behind
	tr.accountsCommitting.Store(true)
	a.True(tr.isBehindCommittingDeltas(latest))
}

func TestTrackers_AccountUpdatesLedgerEvaluatorNoBlockHdr(t *testing.T) {
	partitiontest.PartitionTest(t)

	aul := &accountUpdatesLedgerEvaluator{
		prevHeader: bookkeeping.BlockHeader{},
		tail:       &txTail{},
	}
	hdr, err := aul.BlockHdr(99)
	require.Error(t, err)
	require.Equal(t, ledgercore.ErrNoEntry{}, err)
	require.Equal(t, bookkeeping.BlockHeader{}, hdr)
}
