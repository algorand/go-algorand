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
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestIsWritingCatchpointFile(t *testing.T) {
	partitiontest.PartitionTest(t)

	ct := &catchpointTracker{}

	ct.catchpointWriting = -1
	ans := ct.IsWritingCatchpointFile()
	require.True(t, ans)

	ct.catchpointWriting = 0
	ans = ct.IsWritingCatchpointFile()
	require.False(t, ans)
}

func newCatchpointTracker(tb testing.TB, l *mockLedgerForTracker, conf config.Local, dbPathPrefix string) *catchpointTracker {
	au := &accountUpdates{}
	ct := &catchpointTracker{}
	au.initialize(conf)
	ct.initialize(conf, dbPathPrefix)
	_, err := trackerDBInitialize(l, ct.catchpointEnabled(), dbPathPrefix)
	require.NoError(tb, err)

	err = l.trackers.initialize(l, []ledgerTracker{au, ct}, conf)
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

	temporaryDirectroy, err := ioutil.TempDir(os.TempDir(), CatchpointDirName)
	require.NoError(t, err)
	defer func() {
		os.RemoveAll(temporaryDirectroy)
	}()
	catchpointsDirectory := filepath.Join(temporaryDirectroy, CatchpointDirName)
	err = os.Mkdir(catchpointsDirectory, 0777)
	require.NoError(t, err)

	ct.dbDirectory = temporaryDirectroy

	// Create the catchpoint files with dummy data
	for i := 0; i < filesToCreate; i++ {
		fileName := filepath.Join(CatchpointDirName, fmt.Sprintf("%d.catchpoint", i))
		data := []byte{byte(i), byte(i + 1), byte(i + 2)}
		err = ioutil.WriteFile(filepath.Join(temporaryDirectroy, fileName), data, 0666)
		require.NoError(t, err)

		// Store the catchpoint into the database
		err := ct.accountsq.storeCatchpoint(context.Background(), basics.Round(i), fileName, "", int64(len(data)))
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
	err = os.Remove(filepath.Join(temporaryDirectroy, CatchpointDirName, "2.catchpoint"))
	require.NoError(t, err)
	reader, err = ct.GetCatchpointStream(basics.Round(2))
	require.Equal(t, ledgercore.ErrNoEntry{}, err)
	require.Nil(t, reader)

	// File on disk, but database lost the record
	err = ct.accountsq.storeCatchpoint(context.Background(), basics.Round(3), "", "", 0)
	require.NoError(t, err)
	reader, err = ct.GetCatchpointStream(basics.Round(3))
	require.NoError(t, err)
	n, err = reader.Read(dataRead)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	outData = []byte{3, 4, 5}
	require.Equal(t, outData, dataRead)

	err = deleteStoredCatchpoints(context.Background(), ct.accountsq, ct.dbDirectory)
	require.NoError(t, err)
}

// TestAcctUpdatesDeleteStoredCatchpoints - The goal of this test is to verify that the deleteStoredCatchpoints function works correctly.
// it doing so by filling up the storedcatchpoints with dummy catchpoint file entries, as well as creating these dummy files on disk.
// ( the term dummy is only because these aren't real catchpoint files, but rather a zero-length file ). Then, the test call the function
// and ensures that it did not errored, the catchpoint files were correctly deleted, and that deleteStoredCatchpoints contains no more
// entries.
func TestAcctUpdatesDeleteStoredCatchpoints(t *testing.T) {
	partitiontest.PartitionTest(t)

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}

	temporaryDirectroy, err := ioutil.TempDir(os.TempDir(), CatchpointDirName)

	require.NoError(t, err)
	defer func() {
		os.RemoveAll(temporaryDirectroy)
	}()
	ml := makeMockLedgerForTracker(t, true, 10, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	ct := newCatchpointTracker(t, ml, conf, ".")
	defer ct.close()
	ct.dbDirectory = temporaryDirectroy

	dummyCatchpointFilesToCreate := 42

	dummyCatchpointFiles := make([]string, dummyCatchpointFilesToCreate)
	for i := 0; i < dummyCatchpointFilesToCreate; i++ {
		file := fmt.Sprintf("%s%c%d%c%d%cdummy_catchpoint_file-%d",
			CatchpointDirName, os.PathSeparator,
			i/10, os.PathSeparator,
			i/2, os.PathSeparator,
			i)
		absFile := filepath.Join(temporaryDirectroy, file)
		dummyCatchpointFiles[i] = absFile
		err := os.MkdirAll(path.Dir(absFile), 0755)
		require.NoError(t, err)
		f, err := os.Create(absFile)
		require.NoError(t, err)
		err = f.Close()
		require.NoError(t, err)
		err = ct.accountsq.storeCatchpoint(context.Background(), basics.Round(i), file, "", 0)
		require.NoError(t, err)
	}

	err = deleteStoredCatchpoints(context.Background(), ct.accountsq, ct.dbDirectory)
	require.NoError(t, err)

	// ensure that all the files were deleted.
	for _, file := range dummyCatchpointFiles {
		_, err := os.Open(file)
		require.True(t, os.IsNotExist(err))
	}
	fileNames, err := ct.accountsq.getOldestCatchpointFiles(context.Background(), dummyCatchpointFilesToCreate, 0)
	require.NoError(t, err)
	require.Equal(t, 0, len(fileNames))
}

// The test validate that when algod boots up it cleans empty catchpoint directories.
// it is done be creating empty directories in the catchpoint root directory.
// When algod boots up it should remove those directories
func TestSchemaUpdateDeleteStoredCatchpoints(t *testing.T) {
	partitiontest.PartitionTest(t)

	// we don't want to run this test before the binary is compiled against the latest database upgrade schema.
	if accountDBVersion < 6 {
		return
	}
	temporaryDirectroy, err := ioutil.TempDir(os.TempDir(), CatchpointDirName)
	require.NoError(t, err)
	defer func() {
		os.RemoveAll(temporaryDirectroy)
	}()
	tempCatchpointDir := filepath.Join(temporaryDirectroy, CatchpointDirName)

	// creating empty catchpoint directories
	emptyDirPath := path.Join(tempCatchpointDir, "2f", "e1")
	err = os.MkdirAll(emptyDirPath, 0755)
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
		if !d.IsDir() {
			numberOfCatchpointFiles++
		}
		return nil
	})
	return numberOfCatchpointFiles, err
}

// The goal in this test is to check that we are saving at most X catchpoint files. If algod needs to create a new catchfile it will delete
// the oldest. In addtion, when deleting old catchpoint files an empty directory should be deleted as well.
func TestSaveCatchpointFile(t *testing.T) {
	partitiontest.PartitionTest(t)

	temporaryDirectroy, err := ioutil.TempDir(os.TempDir(), CatchpointDirName)
	require.NoError(t, err)
	defer func() {
		os.RemoveAll(temporaryDirectroy)
	}()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}
	ml := makeMockLedgerForTracker(t, true, 10, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	ct := &catchpointTracker{}
	conf := config.GetDefaultLocal()

	conf.CatchpointFileHistoryLength = 3
	ct.initialize(conf, ".")
	defer ct.close()
	ct.dbDirectory = temporaryDirectroy

	_, err = trackerDBInitialize(ml, true, ct.dbDirectory)
	require.NoError(t, err)

	err = ct.loadFromDisk(ml, ml.Latest())
	require.NoError(t, err)

	ct.generateCatchpoint(context.Background(), basics.Round(2000000), "0#ABC1", crypto.Digest{}, time.Second)
	ct.generateCatchpoint(context.Background(), basics.Round(3000010), "0#ABC2", crypto.Digest{}, time.Second)
	ct.generateCatchpoint(context.Background(), basics.Round(3000015), "0#ABC3", crypto.Digest{}, time.Second)
	ct.generateCatchpoint(context.Background(), basics.Round(3000020), "0#ABC4", crypto.Digest{}, time.Second)

	numberOfCatchpointFiles, err := getNumberOfCatchpointFilesInDir(temporaryDirectroy)
	require.NoError(t, err)
	require.Equal(t, numberOfCatchpointFiles, conf.CatchpointFileHistoryLength)

	emptyDirs, err := getEmptyDirs(temporaryDirectroy)
	require.NoError(t, err)
	onlyCatchpointDirEmpty := len(emptyDirs) == 0 ||
		(len(emptyDirs) == 1 && emptyDirs[0] == temporaryDirectroy)
	require.Equalf(t, onlyCatchpointDirEmpty, true, "Directories: %v", emptyDirs)
}

func BenchmarkLargeCatchpointWriting(b *testing.B) {
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

	temporaryDirectroy, err := ioutil.TempDir(os.TempDir(), CatchpointDirName)
	require.NoError(b, err)
	defer func() {
		os.RemoveAll(temporaryDirectroy)
	}()
	catchpointsDirectory := filepath.Join(temporaryDirectroy, CatchpointDirName)
	err = os.Mkdir(catchpointsDirectory, 0777)
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
				acctData := basics.AccountData{}
				acctData.MicroAlgos.Raw = 1
				updates.upsert(addr, accountDelta{new: acctData})
				i++
			}

			_, err = accountsNewRound(tx, updates, nil, proto, basics.Round(1))
			if err != nil {
				return
			}
		}

		return updateAccountsHashRound(tx, 1)
	})
	require.NoError(b, err)

	b.ResetTimer()
	ct.generateCatchpoint(context.Background(), basics.Round(0), "0#ABCD", crypto.Digest{}, time.Second)
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
	protoParams.MaxBalLookback = 32
	protoParams.SeedLookback = 2
	protoParams.SeedRefreshInterval = 8
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
	lastCreatableID := crypto.RandUint64() % 512
	knownCreatables := make(map[basics.CreatableIndex]bool)
	catchpointLabels := make(map[basics.Round]string)
	ledgerHistory := make(map[basics.Round]*mockLedgerForTracker)
	roundDeltas := make(map[basics.Round]ledgercore.StateDelta)
	for i := basics.Round(1); i <= basics.Round(testCatchpointLabelsCount*cfg.CatchpointInterval); i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		var updates ledgercore.NewAccountDeltas
		var totals map[basics.Address]ledgercore.AccountData
		base := accts[i-1]
		updates, totals, lastCreatableID = ledgertesting.RandomDeltasBalancedFull(1, base, rewardLevel, lastCreatableID)
		prevTotals, err := au.Totals(basics.Round(i - 1))
		require.NoError(t, err)

		newPool := totals[testPoolAddr]
		newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
		updates.Upsert(testPoolAddr, newPool)
		totals[testPoolAddr] = newPool
		newAccts := applyPartialDeltas(base, updates)

		newTotals := ledgertesting.CalculateNewRoundAccountTotals(t, updates, rewardLevel, protoParams, base, prevTotals)

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: basics.Round(i),
			},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = testProtocolVersion
		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.NewAccts.MergeAccounts(updates)
		delta.Creatables = creatablesFromUpdates(base, updates, knownCreatables)
		delta.Totals = newTotals

		ml.trackers.newBlock(blk, delta)
		ml.trackers.committedUpTo(i)
		ml.addMockBlock(blockEntry{block: blk}, delta)
		accts = append(accts, newAccts)
		rewardsLevels = append(rewardsLevels, rewardLevel)
		roundDeltas[i] = delta

		// if this is a catchpoint round, save the label.
		if uint64(i)%cfg.CatchpointInterval == 0 {
			ml.trackers.waitAccountsWriting()
			catchpointLabels[i] = ct.GetLastCatchpointLabel()
			ledgerHistory[i] = ml.fork(t)
			defer ledgerHistory[i].Close()
		}
	}

	// test in revese what happens when we try to repeat the exact same blocks.
	// start off with the catchpoint before the last one
	startingRound := basics.Round((testCatchpointLabelsCount - 1) * cfg.CatchpointInterval)
	for ; startingRound > basics.Round(cfg.CatchpointInterval); startingRound -= basics.Round(cfg.CatchpointInterval) {
		au.close()
		ml2 := ledgerHistory[startingRound]

		ct2 := newCatchpointTracker(t, ml2, cfg, ".")
		defer ct2.close()
		for i := startingRound + 1; i <= basics.Round(testCatchpointLabelsCount*cfg.CatchpointInterval); i++ {
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
			if uint64(i)%cfg.CatchpointInterval == 0 {
				ml2.trackers.waitAccountsWriting()
				require.Equal(t, catchpointLabels[i], ct2.GetLastCatchpointLabel())
			}
		}
	}

	// test to see that after loadFromDisk, all the tracker content is lost ( as expected )
	require.NotZero(t, len(ct.roundDigest))
	require.NoError(t, ct.loadFromDisk(ml, ml.Latest()))
	require.Zero(t, len(ct.roundDigest))
	require.Zero(t, ct.catchpointWriting)
	select {
	case _, closed := <-ct.catchpointSlowWriting:
		require.False(t, closed)
	default:
		require.FailNow(t, "The catchpointSlowWriting should have been a closed channel; it seems to be a nil ?!")
	}
}

func TestCatchpointTrackerPrepareCommit(t *testing.T) {
	partitiontest.PartitionTest(t)

	ct := &catchpointTracker{}
	const maxOffset = 40
	const maxLookback = 320
	ct.roundDigest = make([]crypto.Digest, maxOffset+maxLookback)
	for i := 0; i < len(ct.roundDigest); i++ {
		ct.roundDigest[i] = crypto.Hash([]byte{byte(i), byte(i / 256)})
	}
	dcc := &deferredCommitContext{}
	for offset := uint64(1); offset < maxOffset; offset++ {
		dcc.offset = offset
		for lookback := basics.Round(0); lookback < maxLookback; lookback += 20 {
			dcc.lookback = lookback
			for _, isCatchpointRound := range []bool{false, true} {
				dcc.isCatchpointRound = isCatchpointRound
				require.NoError(t, ct.prepareCommit(dcc))
				if isCatchpointRound {
					expectedRound := offset + uint64(lookback) - 1
					expectedHash := crypto.Hash([]byte{byte(expectedRound), byte(expectedRound / 256)})
					require.Equal(t, expectedHash[:], dcc.committedRoundDigest[:])
				}
			}
		}
	}
}
