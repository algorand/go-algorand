// Copyright (C) 2019-2022 Algorand, Inc.
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
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestIsWritingCatchpointFile(t *testing.T) {
	partitiontest.PartitionTest(t)

	ct := &catchpointTracker{}

	ct.catchpointDataWriting = -1
	ans := ct.IsWritingCatchpointDataFile()
	require.True(t, ans)

	ct.catchpointDataWriting = 0
	ans = ct.IsWritingCatchpointDataFile()
	require.False(t, ans)
}

func newCatchpointTracker(tb testing.TB, l *mockLedgerForTracker, conf config.Local, dbPathPrefix string) *catchpointTracker {
	au := &accountUpdates{}
	ct := &catchpointTracker{}
	ao := &onlineAccounts{}
	au.initialize(conf)
	ct.initialize(conf, dbPathPrefix)
	ao.initialize(conf)
	_, err := trackerDBInitialize(l, ct.catchpointEnabled(), dbPathPrefix)
	require.NoError(tb, err)

	err = l.trackers.initialize(l, []ledgerTracker{au, ct, ao, &txTail{}}, conf)
	require.NoError(tb, err)
	err = l.trackers.loadFromDisk(l)
	require.NoError(tb, err)
	return ct
}

func TestGetCatchpointStream(t *testing.T) {
	partitiontest.PartitionTest(t)

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}

	ml := makeMockLedgerForTracker(t, true, 10, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	ct := newCatchpointTracker(t, ml, conf, ".")
	defer ct.close()

	filesToCreate := 4

	temporaryDirectory := t.TempDir()
	catchpointsDirectory := filepath.Join(temporaryDirectory, CatchpointDirName)
	err := os.Mkdir(catchpointsDirectory, 0777)
	require.NoError(t, err)

	ct.dbDirectory = temporaryDirectory

	// Create the catchpoint files with dummy data
	for i := 0; i < filesToCreate; i++ {
		fileName := filepath.Join(CatchpointDirName, fmt.Sprintf("%d.catchpoint", i))
		data := []byte{byte(i), byte(i + 1), byte(i + 2)}
		err = os.WriteFile(filepath.Join(temporaryDirectory, fileName), data, 0666)
		require.NoError(t, err)

		// Store the catchpoint into the database
		err := storeCatchpoint(context.Background(), ml.dbs.Wdb.Handle, basics.Round(i), fileName, "", int64(len(data)))
		require.NoError(t, err)
	}

	dataRead := make([]byte, 3)
	var n int

	// File on disk, and database has the record
	reader, err := ct.GetCatchpointStream(basics.Round(1))
	require.NoError(t, err)
	n, err = reader.Read(dataRead)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	outData := []byte{1, 2, 3}
	require.Equal(t, outData, dataRead)
	len, err := reader.Size()
	require.NoError(t, err)
	require.Equal(t, int64(3), len)

	// File deleted, but record in the database
	err = os.Remove(filepath.Join(temporaryDirectory, CatchpointDirName, "2.catchpoint"))
	require.NoError(t, err)
	reader, err = ct.GetCatchpointStream(basics.Round(2))
	require.Equal(t, ledgercore.ErrNoEntry{}, err)
	require.Nil(t, reader)

	// File on disk, but database lost the record
	err = storeCatchpoint(context.Background(), ml.dbs.Wdb.Handle, basics.Round(3), "", "", 0)
	require.NoError(t, err)
	reader, err = ct.GetCatchpointStream(basics.Round(3))
	require.NoError(t, err)
	n, err = reader.Read(dataRead)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	outData = []byte{3, 4, 5}
	require.Equal(t, outData, dataRead)

	err = deleteStoredCatchpoints(context.Background(), ml.dbs.Wdb.Handle, ct.dbDirectory)
	require.NoError(t, err)
}

// TestAcctUpdatesDeleteStoredCatchpoints - The goal of this test is to verify that the deleteStoredCatchpoints function works correctly.
// It does so by filling up the storedcatchpoints with dummy catchpoint file entries, as well as creating these dummy files on disk.
// ( the term dummy is only because these aren't real catchpoint files, but rather a zero-length file ). Then, the test calls the function
// and ensures that it did not error, the catchpoint files were correctly deleted, and that deleteStoredCatchpoints contains no more
// entries.
func TestAcctUpdatesDeleteStoredCatchpoints(t *testing.T) {
	partitiontest.PartitionTest(t)

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}

	temporaryDirectory := t.TempDir()
	ml := makeMockLedgerForTracker(t, true, 10, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	ct := newCatchpointTracker(t, ml, conf, ".")
	defer ct.close()
	ct.dbDirectory = temporaryDirectory

	dummyCatchpointFilesToCreate := 42

	dummyCatchpointFiles := make([]string, dummyCatchpointFilesToCreate)
	for i := 0; i < dummyCatchpointFilesToCreate; i++ {
		file := fmt.Sprintf("%s%c%d%c%d%cdummy_catchpoint_file-%d",
			CatchpointDirName, os.PathSeparator,
			i/10, os.PathSeparator,
			i/2, os.PathSeparator,
			i)
		absFile := filepath.Join(temporaryDirectory, file)
		dummyCatchpointFiles[i] = absFile
		err := os.MkdirAll(path.Dir(absFile), 0755)
		require.NoError(t, err)
		f, err := os.Create(absFile)
		require.NoError(t, err)
		err = f.Close()
		require.NoError(t, err)
		err = storeCatchpoint(context.Background(), ml.dbs.Wdb.Handle, basics.Round(i), file, "", 0)
		require.NoError(t, err)
	}

	err := deleteStoredCatchpoints(context.Background(), ml.dbs.Wdb.Handle, ct.dbDirectory)
	require.NoError(t, err)

	// ensure that all the files were deleted.
	for _, file := range dummyCatchpointFiles {
		_, err := os.Open(file)
		require.True(t, os.IsNotExist(err))
	}
	fileNames, err := getOldestCatchpointFiles(context.Background(), ml.dbs.Rdb.Handle, dummyCatchpointFilesToCreate, 0)
	require.NoError(t, err)
	require.Equal(t, 0, len(fileNames))
}

// The test validate that when algod boots up it cleans empty catchpoint directories.
// It is done by creating empty directories in the catchpoint root directory.
// When algod boots up it should remove those directories.
func TestSchemaUpdateDeleteStoredCatchpoints(t *testing.T) {
	partitiontest.PartitionTest(t)

	// we don't want to run this test before the binary is compiled against the latest database upgrade schema.
	if accountDBVersion < 6 {
		return
	}
	temporaryDirectroy := t.TempDir()
	tempCatchpointDir := filepath.Join(temporaryDirectroy, CatchpointDirName)

	// creating empty catchpoint directories
	emptyDirPath := path.Join(tempCatchpointDir, "2f", "e1")
	err := os.MkdirAll(emptyDirPath, 0755)
	require.NoError(t, err)
	emptyDirPath = path.Join(tempCatchpointDir, "2e", "e1")
	err = os.MkdirAll(emptyDirPath, 0755)
	require.NoError(t, err)
	emptyDirPath = path.Join(tempCatchpointDir, "14", "2e", "e1")
	err = os.MkdirAll(emptyDirPath, 0755)
	require.NoError(t, err)

	// creating catchpoint file

	catchpointFilePath := path.Join(tempCatchpointDir, "14", "2e", "e4", "dummy_catchpoint_file")
	err = os.MkdirAll(path.Dir(catchpointFilePath), 0755)
	require.NoError(t, err)
	f, err := os.Create(catchpointFilePath)
	require.NoError(t, err)
	f.Close()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}

	ml := makeMockLedgerForTracker(t, true, 10, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	ct := &catchpointTracker{}
	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	ct.initialize(conf, ".")
	defer ct.close()
	ct.dbDirectory = temporaryDirectroy

	_, err = trackerDBInitialize(ml, true, ct.dbDirectory)
	require.NoError(t, err)

	emptyDirs, err := getEmptyDirs(tempCatchpointDir)
	require.NoError(t, err)
	onlyTempDirEmpty := len(emptyDirs) == 0
	require.Equal(t, onlyTempDirEmpty, true)
}

func getNumberOfCatchpointFilesInDir(catchpointDir string) (int, error) {
	numberOfCatchpointFiles := 0
	err := filepath.Walk(catchpointDir, func(path string, d os.FileInfo, err error) error {
		if !d.IsDir() && strings.HasSuffix(path, ".catchpoint") {
			numberOfCatchpointFiles++
		}
		return nil
	})
	return numberOfCatchpointFiles, err
}

// The goal of this test is to check that we are saving at most X catchpoint files.
// If algod needs to create a new catchpoint file it will delete the oldest.
// In addition, when deleting old catchpoint files an empty directory should be deleted
// as well.
func TestRecordCatchpointFile(t *testing.T) {
	partitiontest.PartitionTest(t)

	temporaryDirectory := t.TempDir()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}
	ml := makeMockLedgerForTracker(t, true, 10, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	ct := &catchpointTracker{}
	conf := config.GetDefaultLocal()

	conf.CatchpointFileHistoryLength = 3
	conf.Archival = true
	ct.initialize(conf, ".")
	defer ct.close()
	ct.dbDirectory = temporaryDirectory

	_, err := trackerDBInitialize(ml, true, ct.dbDirectory)
	require.NoError(t, err)

	err = ct.loadFromDisk(ml, ml.Latest())
	require.NoError(t, err)

	for _, round := range []basics.Round{2000000, 3000010, 3000015, 3000020} {
		accountsRound := round - 1

		_, _, biggestChunkLen, err := ct.generateCatchpointData(
			context.Background(), accountsRound, time.Second)
		require.NoError(t, err)

		err = ct.createCatchpoint(context.Background(), accountsRound, round, catchpointFirstStageInfo{BiggestChunkLen: biggestChunkLen}, crypto.Digest{})
		require.NoError(t, err)
	}

	numberOfCatchpointFiles, err := getNumberOfCatchpointFilesInDir(temporaryDirectory)
	require.NoError(t, err)
	require.Equal(t, conf.CatchpointFileHistoryLength, numberOfCatchpointFiles)

	emptyDirs, err := getEmptyDirs(temporaryDirectory)
	require.NoError(t, err)
	onlyCatchpointDirEmpty := len(emptyDirs) == 0 ||
		(len(emptyDirs) == 1 && emptyDirs[0] == temporaryDirectory)
	require.Equalf(t, onlyCatchpointDirEmpty, true, "Directories: %v", emptyDirs)
}

func BenchmarkLargeCatchpointDataWriting(b *testing.B) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(5, true)}

	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	accts[0][testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	accts[0][testSinkAddr] = sinkdata

	ml := makeMockLedgerForTracker(b, true, 10, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ct := catchpointTracker{}
	ct.initialize(cfg, ".")

	temporaryDirectroy := b.TempDir()
	catchpointsDirectory := filepath.Join(temporaryDirectroy, CatchpointDirName)
	err := os.Mkdir(catchpointsDirectory, 0777)
	require.NoError(b, err)

	ct.dbDirectory = temporaryDirectroy

	err = ct.loadFromDisk(ml, 0)
	require.NoError(b, err)
	defer ct.close()

	// at this point, the database was created. We want to fill the accounts data
	accountsNumber := 6000000 * b.N
	err = ml.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		for i := 0; i < accountsNumber-5-2; { // subtract the account we've already created above, plus the sink/reward
			var updates compactAccountDeltas
			for k := 0; i < accountsNumber-5-2 && k < 1024; k++ {
				addr := ledgertesting.RandomAddress()
				acctData := baseAccountData{}
				acctData.MicroAlgos.Raw = 1
				updates.upsert(addr, accountDelta{newAcct: acctData})
				i++
			}

			_, _, _, err = accountsNewRound(tx, updates, compactResourcesDeltas{}, nil, nil, proto, basics.Round(1))
			if err != nil {
				return
			}
		}

		return updateAccountsHashRound(ctx, tx, 1)
	})
	require.NoError(b, err)

	b.ResetTimer()
	ct.generateCatchpointData(context.Background(), basics.Round(0), time.Second)
	b.StopTimer()
	b.ReportMetric(float64(accountsNumber), "accounts")
}

func TestReproducibleCatchpointLabels(t *testing.T) {
	partitiontest.PartitionTest(t)

	if runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" {
		t.Skip("This test is too slow on ARM and causes travis builds to time out")
	}
	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestReproducibleCatchpointLabels")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	protoParams.EnableOnlineAccountCatchpoints = true
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}
	rewardsLevels := []uint64{0}

	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = 100 * 1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	accts[0][testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	accts[0][testSinkAddr] = sinkdata

	ml := makeMockLedgerForTracker(t, false, 1, testProtocolVersion, accts)
	defer ml.Close()

	cfg := config.GetDefaultLocal()
	cfg.CatchpointInterval = 50
	cfg.CatchpointTracking = 1
	ct := newCatchpointTracker(t, ml, cfg, ".")
	au := ml.trackers.accts
	defer ct.close()

	rewardLevel := uint64(0)

	const testCatchpointLabelsCount = 5

	// lastCreatableID stores asset or app max used index to get rid of conflicts
	lastCreatableID := basics.CreatableIndex(crypto.RandUint64() % 512)
	knownCreatables := make(map[basics.CreatableIndex]bool)
	catchpointLabels := make(map[basics.Round]string)
	ledgerHistory := make(map[basics.Round]*mockLedgerForTracker)
	roundDeltas := make(map[basics.Round]ledgercore.StateDelta)
	numCatchpointsCreated := 0
	i := basics.Round(0)
	lastCatchpointLabel := ""

	for numCatchpointsCreated < testCatchpointLabelsCount {
		i++
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		var updates ledgercore.AccountDeltas
		var totals map[basics.Address]ledgercore.AccountData
		base := accts[i-1]
		updates, totals = ledgertesting.RandomDeltasBalancedFull(1, base, rewardLevel, &lastCreatableID)
		prevRound, prevTotals, err := au.LatestTotals()
		require.Equal(t, i-1, prevRound)
		require.NoError(t, err)

		newPool := totals[testPoolAddr]
		newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
		updates.Upsert(testPoolAddr, newPool)
		totals[testPoolAddr] = newPool
		curTotals := accumulateTotals(t, protocol.ConsensusCurrentVersion, []map[basics.Address]ledgercore.AccountData{totals}, rewardLevel)
		require.Equal(t, prevTotals.All(), curTotals.All())
		newAccts := applyPartialDeltas(base, updates)

		newTotals := ledgertesting.CalculateNewRoundAccountTotals(t, updates, rewardLevel, protoParams, base, prevTotals)
		require.Equal(t, newTotals.All(), curTotals.All())

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: basics.Round(i),
			},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = testProtocolVersion
		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.Accts.MergeAccounts(updates)
		delta.Creatables = creatablesFromUpdates(base, updates, knownCreatables)
		delta.Totals = newTotals

		ml.trackers.newBlock(blk, delta)
		ml.trackers.committedUpTo(i)
		ml.addMockBlock(blockEntry{block: blk}, delta)
		accts = append(accts, newAccts)
		rewardsLevels = append(rewardsLevels, rewardLevel)
		roundDeltas[i] = delta

		// If we made a catchpoint, save the label.
		if (uint64(i) >= cfg.MaxAcctLookback) && (uint64(i)-cfg.MaxAcctLookback > protoParams.CatchpointLookback) && ((uint64(i)-cfg.MaxAcctLookback)%cfg.CatchpointInterval == 0) {
			ml.trackers.waitAccountsWriting()
			catchpointLabels[i] = ct.GetLastCatchpointLabel()
			require.NotEqual(t, lastCatchpointLabel, catchpointLabels[i])
			lastCatchpointLabel = catchpointLabels[i]
			ledgerHistory[i] = ml.fork(t)
			defer ledgerHistory[i].Close()
			numCatchpointsCreated++
		}

		// Let catchpoint data generation finish so that nothing gets skipped.
		for ct.IsWritingCatchpointDataFile() {
			time.Sleep(time.Millisecond)
		}
	}
	lastRound := i

	// Test in reverse what happens when we try to repeat the exact same blocks.
	// Start off with the catchpoint before the last one.
	for startingRound := lastRound - basics.Round(cfg.CatchpointInterval); uint64(startingRound) > protoParams.CatchpointLookback; startingRound -= basics.Round(cfg.CatchpointInterval) {
		au.close()
		ml2 := ledgerHistory[startingRound]
		require.NotNil(t, ml2)

		ct2 := newCatchpointTracker(t, ml2, cfg, ".")
		defer ct2.close()
		for i := startingRound + 1; i <= lastRound; i++ {
			blk := bookkeeping.Block{
				BlockHeader: bookkeeping.BlockHeader{
					Round: basics.Round(i),
				},
			}
			blk.RewardsLevel = rewardsLevels[i]
			blk.CurrentProtocol = testProtocolVersion
			delta := roundDeltas[i]

			ml2.trackers.newBlock(blk, delta)
			ml2.trackers.committedUpTo(i)

			// if this is a catchpoint round, check the label.
			if (uint64(i) >= cfg.MaxAcctLookback) && (uint64(i)-cfg.MaxAcctLookback > protoParams.CatchpointLookback) && ((uint64(i)-cfg.MaxAcctLookback)%cfg.CatchpointInterval == 0) {
				ml2.trackers.waitAccountsWriting()
				require.Equal(t, catchpointLabels[i], ct2.GetLastCatchpointLabel())
			}

			// Let catchpoint data generation finish so that nothing gets skipped.
			for ct.IsWritingCatchpointDataFile() {
				time.Sleep(time.Millisecond)
			}
		}
	}

	// test to see that after loadFromDisk, all the tracker content is lost ( as expected )
	require.NotZero(t, len(ct.roundDigest))
	require.NoError(t, ct.loadFromDisk(ml, ml.Latest()))
	require.Zero(t, len(ct.roundDigest))
	require.Zero(t, ct.catchpointDataWriting)
	select {
	case _, closed := <-ct.catchpointDataSlowWriting:
		require.False(t, closed)
	default:
		require.FailNow(t, "The catchpointDataSlowWriting should have been a closed channel; it seems to be a nil ?!")
	}
}

// blockingTracker is a testing tracker used to test "what if" a tracker would get blocked.
type blockingTracker struct {
	postCommitUnlockedEntryLock   chan struct{}
	postCommitUnlockedReleaseLock chan struct{}
	postCommitEntryLock           chan struct{}
	postCommitReleaseLock         chan struct{}
	committedUpToRound            int64
	alwaysLock                    bool
	shouldLockPostCommit          bool
}

// loadFromDisk is not implemented in the blockingTracker.
func (bt *blockingTracker) loadFromDisk(ledgerForTracker, basics.Round) error {
	return nil
}

// newBlock is not implemented in the blockingTracker.
func (bt *blockingTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
}

// committedUpTo in the blockingTracker just stores the committed round.
func (bt *blockingTracker) committedUpTo(committedRnd basics.Round) (minRound, lookback basics.Round) {
	atomic.StoreInt64(&bt.committedUpToRound, int64(committedRnd))
	return committedRnd, basics.Round(0)
}

// produceCommittingTask is not used by the blockingTracker
func (bt *blockingTracker) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return dcr
}

// prepareCommit, is not used by the blockingTracker
func (bt *blockingTracker) prepareCommit(*deferredCommitContext) error {
	return nil
}

// commitRound is not used by the blockingTracker
func (bt *blockingTracker) commitRound(context.Context, *sql.Tx, *deferredCommitContext) error {
	return nil
}

// postCommit implements entry/exit blockers, designed for testing.
func (bt *blockingTracker) postCommit(ctx context.Context, dcc *deferredCommitContext) {
	if bt.alwaysLock || dcc.catchpointFirstStage || bt.shouldLockPostCommit {
		bt.postCommitEntryLock <- struct{}{}
		<-bt.postCommitReleaseLock
	}
}

// postCommitUnlocked implements entry/exit blockers, designed for testing.
func (bt *blockingTracker) postCommitUnlocked(ctx context.Context, dcc *deferredCommitContext) {
	if bt.alwaysLock || dcc.catchpointFirstStage {
		bt.postCommitUnlockedEntryLock <- struct{}{}
		<-bt.postCommitUnlockedReleaseLock
	}
}

// handleUnorderedCommit is not used by the blockingTracker
func (bt *blockingTracker) handleUnorderedCommit(*deferredCommitContext) {
}

// close is not used by the blockingTracker
func (bt *blockingTracker) close() {
}

func TestCatchpointTrackerNonblockingCatchpointWriting(t *testing.T) {
	partitiontest.PartitionTest(t)

	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestReproducibleCatchpointLabels")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.EnableOnlineAccountCatchpoints = true
	protoParams.CatchpointLookback = protoParams.MaxBalLookback
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	genesisInitState, _ := ledgertesting.GenerateInitState(t, testProtocolVersion, 10)
	const inMem = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	cfg.CatchpointInterval = 2
	ledger, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err, "could not open ledger")
	defer ledger.Close()

	writeStallingTracker := &blockingTracker{
		postCommitUnlockedEntryLock:   make(chan struct{}),
		postCommitUnlockedReleaseLock: make(chan struct{}),
		postCommitEntryLock:           make(chan struct{}),
		postCommitReleaseLock:         make(chan struct{}),
	}
	ledger.trackerMu.Lock()
	ledger.trackers.mu.Lock()
	ledger.trackers.trackers = append(ledger.trackers.trackers, writeStallingTracker)
	ledger.trackers.mu.Unlock()
	ledger.trackerMu.Unlock()

	// Create the first `cfg.MaxAcctLookback` blocks for which account updates tracker
	// will skip committing.
	for rnd := ledger.Latest() + 1; rnd <= basics.Round(cfg.MaxAcctLookback); rnd++ {
		err = ledger.addBlockTxns(t, genesisInitState.Accounts, []transactions.SignedTxn{}, transactions.ApplyData{})
		require.NoError(t, err)
	}

	// make sure to get to a first stage catchpoint round, and block the writing there.
	for {
		err = ledger.addBlockTxns(t, genesisInitState.Accounts, []transactions.SignedTxn{}, transactions.ApplyData{})
		require.NoError(t, err)
		if (uint64(ledger.Latest())+protoParams.CatchpointLookback)%
			cfg.CatchpointInterval == 0 {
			// release the entry lock for postCommit
			<-writeStallingTracker.postCommitEntryLock

			// release the exit lock for postCommit
			writeStallingTracker.postCommitReleaseLock <- struct{}{}

			// wait until we're blocked by the stalling tracker.
			<-writeStallingTracker.postCommitUnlockedEntryLock
			break
		}
	}

	// write additional block, so that the block queue would trigger that too
	err = ledger.addBlockTxns(t, genesisInitState.Accounts, []transactions.SignedTxn{}, transactions.ApplyData{})
	require.NoError(t, err)
	// wait for the committedUpToRound to be called with the correct round number.
	for {
		committedUpToRound := atomic.LoadInt64(&writeStallingTracker.committedUpToRound)
		if basics.Round(committedUpToRound) == ledger.Latest() {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}

	lookupDone := make(chan struct{})
	// now that we've blocked the tracker, try to call LookupAgreement and confirm it returns almost immediately
	go func() {
		defer close(lookupDone)
		ledger.LookupAgreement(ledger.Latest(), genesisInitState.Block.FeeSink)
	}()

	select {
	case <-lookupDone:
		// we expect it not to get stuck, even when the postCommitUnlocked is stuck.
	case <-time.After(25 * time.Second):
		require.FailNow(t, "The LookupAgreement wasn't getting blocked as expected by the blocked tracker")
	}
	// let the goroutines complete.
	// release the exit lock for postCommit
	writeStallingTracker.postCommitUnlockedReleaseLock <- struct{}{}

	// test false positive : we want to ensure that without releasing the postCommit lock, the LookupAgreement would not be able to return within 1 second.

	// make sure to get to a first stage catchpoint round, and block the writing there.
	for {
		err = ledger.addBlockTxns(t, genesisInitState.Accounts, []transactions.SignedTxn{}, transactions.ApplyData{})
		require.NoError(t, err)
		if (uint64(ledger.Latest())+protoParams.CatchpointLookback)%
			cfg.CatchpointInterval == 0 {
			// release the entry lock for postCommit
			<-writeStallingTracker.postCommitEntryLock
			break
		}
	}
	// write additional block, so that the block queue would trigger that too
	err = ledger.addBlockTxns(t, genesisInitState.Accounts, []transactions.SignedTxn{}, transactions.ApplyData{})
	require.NoError(t, err)
	// wait for the committedUpToRound to be called with the correct round number.
	for {
		committedUpToRound := atomic.LoadInt64(&writeStallingTracker.committedUpToRound)
		if basics.Round(committedUpToRound) == ledger.Latest() {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}

	lookupDone = make(chan struct{})
	// now that we've blocked the tracker, try to call LookupAgreement and confirm it's not returning within 1 second.
	go func() {
		defer close(lookupDone)
		ledger.LookupAgreement(ledger.Latest(), genesisInitState.Block.FeeSink)
	}()

	select {
	case <-lookupDone:
		require.FailNow(t, "The LookupAgreement wasn't getting blocked as expected by the blocked tracker")
	case <-time.After(5 * time.Second):
		// this one was "stuck" for over five second ( as expected )
	}
	// let the goroutines complete.
	// release the exit lock for postCommit
	writeStallingTracker.postCommitReleaseLock <- struct{}{}

	// wait until we're blocked by the stalling tracker.
	<-writeStallingTracker.postCommitUnlockedEntryLock
	// release the blocker.
	writeStallingTracker.postCommitUnlockedReleaseLock <- struct{}{}

	// confirm that we get released quickly.
	select {
	case <-lookupDone:
		// now that all the blocker have been removed, we should be able to complete
		// the LookupAgreement call.
	case <-time.After(30 * time.Second):
		require.FailNow(t, "The LookupAgreement wasn't getting release as expected by the blocked tracker")
	}
}

func TestCalculateFirstStageRounds(t *testing.T) {
	partitiontest.PartitionTest(t)

	type TestCase struct {
		// input
		oldBase                            basics.Round
		offset                             uint64
		accountDataResourceSeparationRound basics.Round
		catchpointInterval                 uint64
		catchpointLookback                 uint64
		// output
		hasIntermediateFirstStageRound          bool
		hasMultipleIntermediateFirstStageRounds bool
		retOffset                               uint64
	}
	testCases := []TestCase{
		{0, 6, 1, 10, 3, false, false, 6},
		{0, 7, 1, 10, 3, true, false, 7},
		{0, 16, 1, 10, 3, true, false, 7},
		{0, 17, 1, 10, 3, true, true, 17},
		{7, 9, 1, 10, 3, false, false, 9},
		{7, 10, 1, 10, 3, true, false, 10},
		{7, 19, 1, 10, 3, true, false, 10},
		{7, 20, 1, 10, 3, true, true, 20},
		{1, 1, 1, 10, 169, false, false, 1},
		{1, 9, 1, 10, 169, false, false, 9},
		{1, 10, 1, 10, 169, true, false, 10},
		{1, 22, 1, 10, 169, true, true, 20},
		{1, 95, 100, 1, 3, false, false, 95},
		{1, 96, 100, 1, 3, true, false, 96},
		{1, 97, 100, 1, 3, true, true, 97},
		{1, 97, 99, 10, 3, true, false, 96},
		{29680, 1, 1, 10000, 320, false, false, 1},
		{29679, 1, 1, 10000, 320, true, false, 1},
		{29678, 10003, 1, 10000, 320, true, true, 10002},
		{79680, 7320, 1, 10000, 320, false, false, 7320},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			hasIntermediateFirstStageRound, hasMultipleIntermediateFirstStageRounds, offset :=
				calculateFirstStageRounds(
					testCase.oldBase, testCase.offset, testCase.accountDataResourceSeparationRound,
					testCase.catchpointInterval, testCase.catchpointLookback)
			require.Equal(
				t, testCase.hasIntermediateFirstStageRound, hasIntermediateFirstStageRound)
			require.Equal(
				t, testCase.hasMultipleIntermediateFirstStageRounds,
				hasMultipleIntermediateFirstStageRounds)
			require.Equal(t, testCase.retOffset, offset)
		})
	}
}

func TestCalculateCatchpointRounds(t *testing.T) {
	partitiontest.PartitionTest(t)

	type TestCase struct {
		// input
		min                basics.Round
		max                basics.Round
		catchpointInterval uint64
		// output
		output []basics.Round
	}
	testCases := []TestCase{
		{1, 0, 10, nil},
		{0, 0, 10, []basics.Round{0}},
		{11, 19, 10, nil},
		{11, 20, 10, []basics.Round{20}},
		{11, 29, 10, []basics.Round{20}},
		{11, 30, 10, []basics.Round{20, 30}},
		{10, 20, 10, []basics.Round{10, 20}},
		{79_680 + 1, 87_000, 10_000, []basics.Round{80_000}},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			rounds := calculateCatchpointRounds(
				testCase.min, testCase.max, testCase.catchpointInterval)
			require.Equal(t, testCase.output, rounds)
		})
	}
}

// Test that pruning first stage catchpoint database records and catchpoint data files
// works.
func TestFirstStageInfoPruning(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion :=
		protocol.ConsensusVersion("test-protocol-TestFirstStageInfoPruning")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	protoParams.EnableOnlineAccountCatchpoints = true
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}

	ml := makeMockLedgerForTracker(t, false, 1, testProtocolVersion, accts)
	defer ml.Close()

	cfg := config.GetDefaultLocal()
	cfg.CatchpointInterval = 4
	cfg.CatchpointTracking = 2
	ct := newCatchpointTracker(t, ml, cfg, ".")
	defer ct.close()

	temporaryDirectory := t.TempDir()
	catchpointsDirectory := filepath.Join(temporaryDirectory, CatchpointDirName)
	err := os.Mkdir(catchpointsDirectory, 0777)
	require.NoError(t, err)

	ct.dbDirectory = temporaryDirectory

	expectedNumEntries := protoParams.CatchpointLookback / cfg.CatchpointInterval

	numCatchpointsCreated := uint64(0)
	i := basics.Round(0)
	lastCatchpointLabel := ""

	for numCatchpointsCreated < expectedNumEntries {
		i++

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: basics.Round(i),
				UpgradeState: bookkeeping.UpgradeState{
					CurrentProtocol: testProtocolVersion,
				},
			},
		}
		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, 0, 0)

		ml.trackers.newBlock(blk, delta)
		ml.trackers.committedUpTo(i)
		ml.addMockBlock(blockEntry{block: blk}, delta)

		if (uint64(i) >= cfg.MaxAcctLookback) && (uint64(i)-cfg.MaxAcctLookback > protoParams.CatchpointLookback) && ((uint64(i)-cfg.MaxAcctLookback)%cfg.CatchpointInterval == 0) {
			ml.trackers.waitAccountsWriting()
			catchpointLabel := ct.GetLastCatchpointLabel()
			require.NotEqual(t, lastCatchpointLabel, catchpointLabel)
			lastCatchpointLabel = catchpointLabel
			numCatchpointsCreated++
		}

		// Let catchpoint data generation finish so that nothing gets skipped.
		for ct.IsWritingCatchpointDataFile() {
			time.Sleep(time.Millisecond)
		}
	}

	numEntries := uint64(0)
	i -= basics.Round(cfg.MaxAcctLookback)
	for i > 0 {
		_, recordExists, err := selectCatchpointFirstStageInfo(
			context.Background(), ct.dbs.Rdb.Handle, i)
		require.NoError(t, err)

		catchpointDataFilePath :=
			filepath.Join(catchpointsDirectory, makeCatchpointDataFilePath(i))
		_, err = os.Stat(catchpointDataFilePath)
		if errors.Is(err, os.ErrNotExist) {
			require.False(t, recordExists, i)
		} else {
			require.NoError(t, err)
			require.True(t, recordExists, i)
			numEntries++
		}

		i--
	}

	require.Equal(t, expectedNumEntries, numEntries)
}

// Test that on startup the catchpoint tracker restarts catchpoint's first stage if
// there is an unfinished first stage record in the database.
func TestFirstStagePersistence(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion :=
		protocol.ConsensusVersion("test-protocol-TestFirstStagePersistence")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	protoParams.EnableOnlineAccountCatchpoints = true
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}

	ml := makeMockLedgerForTracker(t, false, 1, testProtocolVersion, accts)
	defer ml.Close()

	tempDirectory := t.TempDir()
	catchpointsDirectory := filepath.Join(tempDirectory, CatchpointDirName)

	cfg := config.GetDefaultLocal()
	cfg.CatchpointInterval = 4
	cfg.CatchpointTracking = 2
	cfg.MaxAcctLookback = 0
	ct := newCatchpointTracker(
		t, ml, cfg, filepath.Join(tempDirectory, config.LedgerFilenamePrefix))
	defer ct.close()

	// Add blocks until the first catchpoint first stage round.
	firstStageRound := basics.Round(4)
	for i := basics.Round(1); i <= firstStageRound; i++ {
		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: i,
				UpgradeState: bookkeeping.UpgradeState{
					CurrentProtocol: testProtocolVersion,
				},
			},
		}
		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, 0, 0)

		ml.trackers.newBlock(blk, delta)
		ml.trackers.committedUpTo(i)
		ml.addMockBlock(blockEntry{block: blk}, delta)
	}

	ml.trackers.waitAccountsWriting()

	// Check that the data file exists.
	catchpointDataFilePath :=
		filepath.Join(catchpointsDirectory, makeCatchpointDataFilePath(firstStageRound))
	info, err := os.Stat(catchpointDataFilePath)
	require.NoError(t, err)

	// Override file.
	err = os.WriteFile(catchpointDataFilePath, []byte{0}, info.Mode().Perm())
	require.NoError(t, err)

	// Copy the database.
	ct.close()
	ml2 := ml.fork(t)
	require.NotNil(t, ml2)
	defer ml2.Close()
	ml.Close()

	// Insert unfinished first stage record.
	err = writeCatchpointStateUint64(
		context.Background(), ml2.dbs.Wdb.Handle, catchpointStateWritingFirstStageInfo, 1)
	require.NoError(t, err)

	// Delete the database record.
	err = deleteOldCatchpointFirstStageInfo(
		context.Background(), ml2.dbs.Wdb.Handle, firstStageRound)
	require.NoError(t, err)

	// Create a catchpoint tracker and let it restart catchpoint's first stage.
	ct2 := newCatchpointTracker(
		t, ml2, cfg, filepath.Join(tempDirectory, config.LedgerFilenamePrefix))
	defer ct2.close()

	// Check that the catchpoint data file was rewritten.
	info, err = os.Stat(catchpointDataFilePath)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(1))

	// Check that the database record exists.
	_, exists, err := selectCatchpointFirstStageInfo(
		context.Background(), ml2.dbs.Rdb.Handle, firstStageRound)
	require.NoError(t, err)
	require.True(t, exists)

	// Check that the unfinished first stage record is deleted.
	v, err := readCatchpointStateUint64(
		context.Background(), ml2.dbs.Rdb.Handle, catchpointStateWritingFirstStageInfo)
	require.NoError(t, err)
	require.Zero(t, v)
}

// Test that on startup the catchpoint tracker restarts catchpoint's second stage if
// there is an unfinished catchpoint record in the database.
func TestSecondStagePersistence(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion :=
		protocol.ConsensusVersion("test-protocol-TestFirstStagePersistence")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	protoParams.EnableOnlineAccountCatchpoints = true
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}

	ml := makeMockLedgerForTracker(t, false, 1, testProtocolVersion, accts)
	defer ml.Close()

	tempDirectory := t.TempDir()
	catchpointsDirectory := filepath.Join(tempDirectory, CatchpointDirName)

	cfg := config.GetDefaultLocal()
	cfg.CatchpointInterval = 4
	cfg.CatchpointTracking = 2
	cfg.MaxAcctLookback = 0
	ct := newCatchpointTracker(
		t, ml, cfg, filepath.Join(tempDirectory, config.LedgerFilenamePrefix))
	defer ct.close()

	secondStageRound := basics.Round(36)
	firstStageRound := secondStageRound - basics.Round(protoParams.CatchpointLookback)
	catchpointDataFilePath :=
		filepath.Join(catchpointsDirectory, makeCatchpointDataFilePath(firstStageRound))
	var firstStageInfo catchpointFirstStageInfo
	var catchpointData []byte

	// Add blocks until the first catchpoint round.
	for i := basics.Round(1); i <= secondStageRound; i++ {
		if i == secondStageRound {
			// Save first stage info and data file.
			var exists bool
			var err error
			firstStageInfo, exists, err = selectCatchpointFirstStageInfo(
				context.Background(), ml.dbs.Rdb.Handle, firstStageRound)
			require.NoError(t, err)
			require.True(t, exists)

			catchpointData, err = os.ReadFile(catchpointDataFilePath)
			require.NoError(t, err)
		}

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: i,
				UpgradeState: bookkeeping.UpgradeState{
					CurrentProtocol: testProtocolVersion,
				},
			},
		}
		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, 0, 0)

		ml.trackers.newBlock(blk, delta)
		ml.trackers.committedUpTo(i)
		ml.addMockBlock(blockEntry{block: blk}, delta)

		// Let catchpoint data generation finish so that nothing gets skipped.
		for ct.IsWritingCatchpointDataFile() {
			time.Sleep(time.Millisecond)
		}
	}

	ml.trackers.waitAccountsWriting()

	// Check that the data file exists.
	catchpointFilePath :=
		filepath.Join(catchpointsDirectory, makeCatchpointFilePath(secondStageRound))
	info, err := os.Stat(catchpointFilePath)
	require.NoError(t, err)

	// Override file.
	err = os.WriteFile(catchpointFilePath, []byte{0}, info.Mode().Perm())
	require.NoError(t, err)

	// Copy the database.
	ct.close()
	ml2 := ml.fork(t)
	require.NotNil(t, ml2)
	defer ml2.Close()
	ml.Close()

	// Restore the (first stage) catchpoint data file.
	err = os.WriteFile(catchpointDataFilePath, catchpointData, 0644)
	require.NoError(t, err)

	// Restore the first stage database record.
	err = insertOrReplaceCatchpointFirstStageInfo(
		context.Background(), ml2.dbs.Wdb.Handle, firstStageRound, &firstStageInfo)
	require.NoError(t, err)

	// Insert unfinished catchpoint record.
	err = insertUnfinishedCatchpoint(
		context.Background(), ml2.dbs.Wdb.Handle, secondStageRound, crypto.Digest{})
	require.NoError(t, err)

	// Delete the catchpoint file database record.
	err = storeCatchpoint(
		context.Background(), ml2.dbs.Wdb.Handle, secondStageRound, "", "", 0)
	require.NoError(t, err)

	// Create a catchpoint tracker and let it restart catchpoint's second stage.
	ct2 := newCatchpointTracker(
		t, ml2, cfg, filepath.Join(tempDirectory, config.LedgerFilenamePrefix))
	defer ct2.close()

	// Check that the catchpoint data file was rewritten.
	info, err = os.Stat(catchpointFilePath)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(1))

	// Check that the database record exists.
	filename, _, _, err := getCatchpoint(
		context.Background(), ml2.dbs.Rdb.Handle, secondStageRound)
	require.NoError(t, err)
	require.NotEmpty(t, filename)

	// Check that the unfinished catchpoint database record is deleted.
	unfinishedCatchpoints, err := selectUnfinishedCatchpoints(
		context.Background(), ml2.dbs.Rdb.Handle)
	require.NoError(t, err)
	require.Empty(t, unfinishedCatchpoints)
}

// Test that when catchpoint's first stage record is unavailable
// (e.g. catchpoints were disabled at first stage), the unfinished catchpoint
// database record is deleted.
func TestSecondStageDeletesUnfinishedCatchpointRecord(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion :=
		protocol.ConsensusVersion("test-protocol-TestFirstStagePersistence")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	protoParams.EnableOnlineAccountCatchpoints = true
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}

	ml := makeMockLedgerForTracker(t, false, 1, testProtocolVersion, accts)
	defer ml.Close()

	tempDirectory := t.TempDir()

	cfg := config.GetDefaultLocal()
	cfg.CatchpointInterval = 4
	cfg.CatchpointTracking = 0
	cfg.MaxAcctLookback = 0
	ct := newCatchpointTracker(
		t, ml, cfg, filepath.Join(tempDirectory, config.LedgerFilenamePrefix))
	defer ct.close()

	secondStageRound := basics.Round(36)

	// Add blocks that preceed the first catchpoint round.
	for i := basics.Round(1); i < secondStageRound; i++ {
		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: i,
				UpgradeState: bookkeeping.UpgradeState{
					CurrentProtocol: testProtocolVersion,
				},
			},
		}
		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, 0, 0)

		ml.trackers.newBlock(blk, delta)
		ml.trackers.committedUpTo(i)
		ml.addMockBlock(blockEntry{block: blk}, delta)
	}
	ml.trackers.waitAccountsWriting()

	// Copy the database.
	ct.close()
	ml2 := ml.fork(t)
	require.NotNil(t, ml2)
	defer ml2.Close()
	ml.Close()

	// Configure a new catchpoint tracker with catchpoints enabled.
	cfg.CatchpointTracking = 2
	ct2 := newCatchpointTracker(
		t, ml2, cfg, filepath.Join(tempDirectory, config.LedgerFilenamePrefix))
	defer ct2.close()

	// Add the last block.
	{
		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: secondStageRound,
				UpgradeState: bookkeeping.UpgradeState{
					CurrentProtocol: testProtocolVersion,
				},
			},
		}
		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, 0, 0)

		ml2.trackers.newBlock(blk, delta)
		ml2.trackers.committedUpTo(secondStageRound)
		ml2.addMockBlock(blockEntry{block: blk}, delta)
	}
	ml2.trackers.waitAccountsWriting()

	// Check that the unfinished catchpoint database record is deleted.
	unfinishedCatchpoints, err := selectUnfinishedCatchpoints(
		context.Background(), ml2.dbs.Rdb.Handle)
	require.NoError(t, err)
	require.Empty(t, unfinishedCatchpoints)
}

// Test that on startup the catchpoint tracker deletes the unfinished catchpoint
// database record when the first stage database record is missing.
func TestSecondStageDeletesUnfinishedCatchpointRecordAfterRestart(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion :=
		protocol.ConsensusVersion("test-protocol-TestFirstStagePersistence")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	protoParams.EnableOnlineAccountCatchpoints = true
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}

	ml := makeMockLedgerForTracker(t, false, 1, testProtocolVersion, accts)
	defer ml.Close()

	cfg := config.GetDefaultLocal()
	cfg.CatchpointInterval = 4
	cfg.CatchpointTracking = 0
	cfg.MaxAcctLookback = 0
	ct := newCatchpointTracker(t, ml, cfg, ".")
	defer ct.close()

	secondStageRound := basics.Round(36)
	firstStageRound := secondStageRound - basics.Round(protoParams.CatchpointLookback)

	// Add blocks until the first catchpoint round.
	for i := basics.Round(1); i <= secondStageRound; i++ {
		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: i,
				UpgradeState: bookkeeping.UpgradeState{
					CurrentProtocol: testProtocolVersion,
				},
			},
		}
		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, 0, 0)

		ml.trackers.newBlock(blk, delta)
		ml.trackers.committedUpTo(i)
		ml.addMockBlock(blockEntry{block: blk}, delta)

		// Let catchpoint data generation finish so that nothing gets skipped.
		for ct.IsWritingCatchpointDataFile() {
			time.Sleep(time.Millisecond)
		}
	}

	ml.trackers.waitAccountsWriting()

	// Copy the database.
	ct.close()
	ml2 := ml.fork(t)
	require.NotNil(t, ml2)
	defer ml2.Close()
	ml.Close()

	// Sanity check: first stage record should be deleted.
	_, exists, err := selectCatchpointFirstStageInfo(
		context.Background(), ml2.dbs.Rdb.Handle, firstStageRound)
	require.NoError(t, err)
	require.False(t, exists)

	// Insert unfinished catchpoint record.
	err = insertUnfinishedCatchpoint(
		context.Background(), ml2.dbs.Wdb.Handle, secondStageRound, crypto.Digest{})
	require.NoError(t, err)

	// Create a catchpoint tracker and let it restart catchpoint's second stage.
	ct2 := newCatchpointTracker(t, ml2, cfg, ".")
	defer ct2.close()

	// Check that the unfinished catchpoint database record is deleted.
	unfinishedCatchpoints, err := selectUnfinishedCatchpoints(
		context.Background(), ml2.dbs.Rdb.Handle)
	require.NoError(t, err)
	require.Empty(t, unfinishedCatchpoints)
}
