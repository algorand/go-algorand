// Copyright (C) 2019-2025 Algorand, Inc.
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
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// assert catchpointTracker implements the trackerCommitLifetimeHandlers interface
var _ trackerCommitLifetimeHandlers = &catchpointTracker{}

func TestCatchpointIsWritingCatchpointFile(t *testing.T) {
	partitiontest.PartitionTest(t)

	ct := &catchpointTracker{}

	ct.catchpointDataWriting.Store(-1)
	ans := ct.isWritingCatchpointDataFile()
	require.True(t, ans)

	ct.catchpointDataWriting.Store(0)
	ans = ct.isWritingCatchpointDataFile()
	require.False(t, ans)
}

func newCatchpointTracker(tb testing.TB, l *mockLedgerForTracker, conf config.Local, dbPathPrefix string) *catchpointTracker {
	return newCatchpointTrackerWithPaths(tb, l, conf, dbPathPrefix, dbPathPrefix)
}

func newCatchpointTrackerWithPaths(tb testing.TB, l *mockLedgerForTracker, conf config.Local, hotPath string, coldPath string) *catchpointTracker {
	au := &accountUpdates{}
	ct := &catchpointTracker{}
	ao := &onlineAccounts{}
	au.initialize(conf)
	paths := DirsAndPrefix{
		ResolvedGenesisDirs: config.ResolvedGenesisDirs{
			CatchpointGenesisDir: coldPath,
			HotGenesisDir:        hotPath,
		},
	}
	ct.initialize(conf, paths)
	ao.initialize(conf)
	_, err := trackerDBInitialize(l, ct.catchpointEnabled(), hotPath)
	require.NoError(tb, err)

	err = l.trackers.initialize(l, []ledgerTracker{au, ct, ao, &txTail{}}, conf)
	require.NoError(tb, err)
	err = l.trackers.loadFromDisk(l)
	require.NoError(tb, err)
	return ct
}

func TestCatchpointGetCatchpointStream(t *testing.T) {
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
	catchpointsDirectory := filepath.Join(temporaryDirectory, trackerdb.CatchpointDirName)
	err := os.Mkdir(catchpointsDirectory, 0777)
	require.NoError(t, err)

	ct.dbDirectory = temporaryDirectory
	ct.tmpDir = temporaryDirectory

	// Create the catchpoint files with dummy data
	for i := 0; i < filesToCreate; i++ {
		fileName := filepath.Join(trackerdb.CatchpointDirName, fmt.Sprintf("%d.catchpoint", i))
		data := []byte{byte(i), byte(i + 1), byte(i + 2)}
		err = os.WriteFile(filepath.Join(temporaryDirectory, fileName), data, 0666)
		require.NoError(t, err)

		// Store the catchpoint into the database
		err := ct.catchpointStore.StoreCatchpoint(context.Background(), basics.Round(i), fileName, "", int64(len(data)))
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
	err = os.Remove(filepath.Join(temporaryDirectory, trackerdb.CatchpointDirName, "2.catchpoint"))
	require.NoError(t, err)
	reader, err = ct.GetCatchpointStream(basics.Round(2))
	require.Equal(t, ledgercore.ErrNoEntry{}, err)
	require.Nil(t, reader)

	// File on disk, but database lost the record
	err = ct.catchpointStore.StoreCatchpoint(context.Background(), basics.Round(3), "", "", 0)
	require.NoError(t, err)
	reader, err = ct.GetCatchpointStream(basics.Round(3))
	require.NoError(t, err)
	n, err = reader.Read(dataRead)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	outData = []byte{3, 4, 5}
	require.Equal(t, outData, dataRead)

	err = ct.catchpointStore.DeleteStoredCatchpoints(context.Background(), ct.dbDirectory)
	require.NoError(t, err)
}

// TestCatchpointsDeleteStored - The goal of this test is to verify that the deleteStoredCatchpoints function works correctly.
// It does so by filling up the storedcatchpoints with dummy catchpoint file entries, as well as creating these dummy files on disk.
// ( the term dummy is only because these aren't real catchpoint files, but rather a zero-length file ). Then, the test calls the function
// and ensures that it did not error, the catchpoint files were correctly deleted, and that deleteStoredCatchpoints contains no more
// entries.
func TestCatchpointsDeleteStored(t *testing.T) {
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
	ct.tmpDir = temporaryDirectory

	dummyCatchpointFilesToCreate := 42

	dummyCatchpointFiles := make([]string, dummyCatchpointFilesToCreate)
	for i := 0; i < dummyCatchpointFilesToCreate; i++ {
		file := fmt.Sprintf("%s%c%d%c%d%cdummy_catchpoint_file-%d",
			trackerdb.CatchpointDirName, os.PathSeparator,
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
		err = ct.catchpointStore.StoreCatchpoint(context.Background(), basics.Round(i), file, "", 0)
		require.NoError(t, err)
	}

	err := ct.catchpointStore.DeleteStoredCatchpoints(context.Background(), ct.dbDirectory)
	require.NoError(t, err)

	// ensure that all the files were deleted.
	for _, file := range dummyCatchpointFiles {
		_, err := os.Open(file)
		require.True(t, os.IsNotExist(err))
	}
	fileNames, err := ct.catchpointStore.GetOldestCatchpointFiles(context.Background(), dummyCatchpointFilesToCreate, 0)
	require.NoError(t, err)
	require.Equal(t, 0, len(fileNames))
}

// The test validate that when algod boots up it cleans empty catchpoint directories.
// It is done by creating empty directories in the catchpoint root directory.
// When algod boots up it should remove those directories.
func TestCatchpointsDeleteStoredOnSchemaUpdate(t *testing.T) {
	partitiontest.PartitionTest(t)

	// we don't want to run this test before the binary is compiled against the latest database upgrade schema.
	if trackerdb.AccountDBVersion < 6 {
		return
	}
	temporaryDirectroy := t.TempDir()
	tempCatchpointDir := filepath.Join(temporaryDirectroy, trackerdb.CatchpointDirName)

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
	paths := DirsAndPrefix{
		ResolvedGenesisDirs: config.ResolvedGenesisDirs{
			CatchpointGenesisDir: ".",
			HotGenesisDir:        ".",
		},
	}
	ct.initialize(conf, paths)
	defer ct.close()
	ct.dbDirectory = temporaryDirectroy
	ct.tmpDir = temporaryDirectroy

	_, err = trackerDBInitialize(ml, true, ct.dbDirectory)
	require.NoError(t, err)

	emptyDirs, err := trackerdb.GetEmptyDirs(tempCatchpointDir)
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

func calculateStateProofVerificationHash(t *testing.T, ml *mockLedgerForTracker) crypto.Digest {
	var digest crypto.Digest
	err := ml.dbs.Snapshot(func(dbCtx context.Context, tx trackerdb.SnapshotScope) (err error) {
		rawData, err := tx.MakeSpVerificationCtxReader().GetAllSPContexts(dbCtx)
		require.NoError(t, err)

		wrappedData := catchpointStateProofVerificationContext{Data: rawData}
		digest = crypto.HashObj(wrappedData)
		return nil
	})
	require.NoError(t, err)
	return digest
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
	paths := DirsAndPrefix{
		ResolvedGenesisDirs: config.ResolvedGenesisDirs{
			CatchpointGenesisDir: ".",
			HotGenesisDir:        ".",
		},
	}
	ct.initialize(conf, paths)
	defer ct.close()
	ct.dbDirectory = temporaryDirectory
	ct.tmpDir = temporaryDirectory

	_, err := trackerDBInitialize(ml, true, ct.dbDirectory)
	require.NoError(t, err)

	err = ct.loadFromDisk(ml, ml.Latest())
	require.NoError(t, err)

	for _, round := range []basics.Round{2000000, 3000010, 3000015, 3000020} {
		accountsRound := round - 1
		createCatchpoint(t, ct, accountsRound, ml, round)
	}

	numberOfCatchpointFiles, err := getNumberOfCatchpointFilesInDir(temporaryDirectory)
	require.NoError(t, err)
	require.Equal(t, conf.CatchpointFileHistoryLength, numberOfCatchpointFiles)

	emptyDirs, err := trackerdb.GetEmptyDirs(temporaryDirectory)
	require.NoError(t, err)
	onlyCatchpointDirEmpty := len(emptyDirs) == 0 ||
		(len(emptyDirs) == 1 && emptyDirs[0] == temporaryDirectory)
	require.Equalf(t, onlyCatchpointDirEmpty, true, "Directories: %v", emptyDirs)
}

func createCatchpoint(t *testing.T, ct *catchpointTracker, accountsRound basics.Round, ml *mockLedgerForTracker, round basics.Round) {
	spVerificationEncodedData, stateProofVerificationHash, err := ct.getSPVerificationData()
	require.NoError(t, err)

	proto := protocol.ConsensusCurrentVersion
	var catchpointGenerationStats telemetryspec.CatchpointGenerationEventDetails
	_, _, _, _, _, biggestChunkLen, err := ct.generateCatchpointData(
		context.Background(), config.Consensus[proto], accountsRound, 0, &catchpointGenerationStats, spVerificationEncodedData)
	require.NoError(t, err)

	require.Equal(t, calculateStateProofVerificationHash(t, ml), stateProofVerificationHash)

	err = ct.createCatchpoint(
		context.Background(), accountsRound, round,
		trackerdb.CatchpointFirstStageInfo{BiggestChunkLen: biggestChunkLen},
		crypto.Digest{}, proto)
	require.NoError(t, err)
}

// TestCatchpointCommitErrorHandling exists to confirm that when an error occurs during catchpoint generation,
// the catchpoint tracker will clear the appropriate state - specifically, the balancesTrie will be cleared,
// and the balancesTrie will remain functional if loaded from disk, or if lazily loaded during commitRound
func TestCatchpointCommitErrorHandling(t *testing.T) {
	partitiontest.PartitionTest(t)

	temporaryDirectory := t.TempDir()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}
	ml := makeMockLedgerForTracker(t, true, 10, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	ct := &catchpointTracker{}
	conf := config.GetDefaultLocal()

	conf.Archival = true
	paths := DirsAndPrefix{
		ResolvedGenesisDirs: config.ResolvedGenesisDirs{
			CatchpointGenesisDir: ".",
			HotGenesisDir:        ".",
		},
	}
	ct.initialize(conf, paths)

	defer ct.close()
	ct.dbDirectory = temporaryDirectory
	ct.tmpDir = temporaryDirectory

	_, err := trackerDBInitialize(ml, true, ct.dbDirectory)
	require.NoError(t, err)

	err = ct.loadFromDisk(ml, ml.Latest())
	require.NoError(t, err)

	txn, err := ml.dbs.BeginTransaction(context.Background())
	require.NoError(t, err)
	dcc := deferredCommitContext{
		compactKvDeltas: map[string]modifiedKvValue{"key": {data: []byte("value")}},
	}

	// before commitRound is called, record the trie RootHash
	require.NotNil(t, ct.balancesTrie)
	root1, err := ct.balancesTrie.RootHash()
	require.NoError(t, err)

	ct.commitRound(context.Background(), txn, &dcc)

	txn.Commit()

	// after commitRound is called, confirm the RootHash has changed
	root2, err := ct.balancesTrie.RootHash()
	require.NoError(t, err)
	require.NotEqual(t, root1, root2)

	// demonstrate that handleUnordered does not restore the trie
	ct.handleUnorderedCommit(&dcc)
	root2a, err := ct.balancesTrie.RootHash()
	require.NoError(t, err)
	require.Equal(t, root2, root2a)

	// demonstrate that handlePrepareCommitError does not restore the trie
	ct.handlePrepareCommitError(&dcc)
	root2b, err := ct.balancesTrie.RootHash()
	require.NoError(t, err)
	require.Equal(t, root2, root2b)

	// now have the ct handle a commit error
	ct.handleCommitError(&dcc)
	// after error handling, the trie should be nil
	require.Nil(t, ct.balancesTrie)

	// after reloading from disk, the trie should be equal to root1
	err = ct.loadFromDisk(ml, ml.Latest())
	require.NoError(t, err)
	root3, err := ct.balancesTrie.RootHash()
	require.NoError(t, err)
	require.Equal(t, root1, root3)

	// also demonstrate that lazy initialization allows a nil trie to go back to root2 immediately after error if the same delta is applied
	txn, err = ml.dbs.BeginTransaction(context.Background())
	require.NoError(t, err)
	ct.handleCommitError(&dcc) // clear trie
	require.Nil(t, ct.balancesTrie)
	ct.commitRound(context.Background(), txn, &dcc)
	txn.Commit()
	root4, err := ct.balancesTrie.RootHash()
	require.NoError(t, err)
	require.Equal(t, root2, root4)
}

// TestCatchpointFileWithLargeSpVerification makes sure that CatchpointFirstStageInfo.BiggestChunkLen is calculated based on state proof verification contexts
// as well as other chunks in the catchpoint files.
func TestCatchpointFileWithLargeSpVerification(t *testing.T) {
	partitiontest.PartitionTest(t)

	temporaryDirectory := t.TempDir()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}
	ml := makeMockLedgerForTracker(t, true, 10, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	ct := &catchpointTracker{}
	conf := config.GetDefaultLocal()

	conf.Archival = true
	paths := DirsAndPrefix{
		ResolvedGenesisDirs: config.ResolvedGenesisDirs{
			CatchpointGenesisDir: ".",
			HotGenesisDir:        ".",
		},
	}
	ct.initialize(conf, paths)

	defer ct.close()
	ct.dbDirectory = temporaryDirectory
	ct.tmpDir = temporaryDirectory

	_, err := trackerDBInitialize(ml, true, ct.dbDirectory)
	require.NoError(t, err)

	err = ct.loadFromDisk(ml, ml.Latest())
	require.NoError(t, err)

	//  create catpoint with no sp verification data
	round := basics.Round(2000000)
	createCatchpoint(t, ct, round-1, ml, round)

	numberOfCatchpointFiles, err := getNumberOfCatchpointFilesInDir(temporaryDirectory)
	require.NoError(t, err)
	require.Equal(t, 1, numberOfCatchpointFiles)
	//  create catpoint with 2 sp verification data
	writeDummySpVerification(t, 0, 3, ml)

	round = basics.Round(3000000)
	createCatchpoint(t, ct, round-1, ml, round)

	numberOfCatchpointFiles, err = getNumberOfCatchpointFilesInDir(temporaryDirectory)
	require.NoError(t, err)
	require.Equal(t, 2, numberOfCatchpointFiles)

	//  create catpoint with 500 sp verification data - the sp verification chunk should be the largest
	writeDummySpVerification(t, 4, 500, ml)

	round = basics.Round(4000000)
	createCatchpoint(t, ct, round-1, ml, round)

	numberOfCatchpointFiles, err = getNumberOfCatchpointFilesInDir(temporaryDirectory)
	require.NoError(t, err)
	require.Equal(t, 3, numberOfCatchpointFiles)
}

func writeDummySpVerification(t *testing.T, nextIndexForContext uint64, numberOfContexts uint64, ml *mockLedgerForTracker) {
	err := ml.dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {

		contexts := make([]*ledgercore.StateProofVerificationContext, numberOfContexts)
		for i := uint64(0); i < numberOfContexts; i++ {
			e := ledgercore.StateProofVerificationContext{}
			e.LastAttestedRound = basics.Round(nextIndexForContext + i)
			contexts[i] = &e
		}
		return tx.MakeSpVerificationCtxWriter().StoreSPContexts(ctx, contexts[:])
	})
	require.NoError(t, err)
}

func BenchmarkLargeCatchpointDataWriting(b *testing.B) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(5, true)}
	addSinkAndPoolAccounts(accts)

	ml := makeMockLedgerForTracker(b, true, 10, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ct := catchpointTracker{}
	paths := DirsAndPrefix{
		ResolvedGenesisDirs: config.ResolvedGenesisDirs{
			CatchpointGenesisDir: ".",
			HotGenesisDir:        ".",
		},
	}
	ct.initialize(cfg, paths)

	temporaryDirectroy := b.TempDir()
	catchpointsDirectory := filepath.Join(temporaryDirectroy, trackerdb.CatchpointDirName)
	err := os.Mkdir(catchpointsDirectory, 0777)
	require.NoError(b, err)

	ct.dbDirectory = temporaryDirectroy
	ct.tmpDir = temporaryDirectroy

	err = ct.loadFromDisk(ml, 0)
	require.NoError(b, err)
	defer ct.close()

	// at this point, the database was created. We want to fill the accounts data
	accountsNumber := 6000000 * b.N
	err = ml.dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		aw, err := tx.MakeAccountsWriter()
		if err != nil {
			return err
		}

		for i := 0; i < accountsNumber-5-2; { // subtract the account we've already created above, plus the sink/reward
			var updates compactAccountDeltas
			for k := 0; i < accountsNumber-5-2 && k < 1024; k++ {
				addr := ledgertesting.RandomAddress()
				acctData := trackerdb.BaseAccountData{}
				acctData.MicroAlgos.Raw = 1
				updates.upsert(addr, accountDelta{newAcct: acctData})
				i++
			}

			_, _, _, err = accountsNewRound(tx, updates, compactResourcesDeltas{}, nil, nil, proto, basics.Round(1))
			if err != nil {
				return
			}
		}

		return aw.UpdateAccountsHashRound(ctx, 1)
	})
	require.NoError(b, err)

	var catchpointGenerationStats telemetryspec.CatchpointGenerationEventDetails
	encodedSPData, _, err := ct.getSPVerificationData()
	require.NoError(b, err)
	b.ResetTimer()
	ct.generateCatchpointData(context.Background(), proto, 0, 0, &catchpointGenerationStats, encodedSPData)
	b.StopTimer()
	b.ReportMetric(float64(accountsNumber), "accounts")
}

func TestCatchpointReproducibleLabels(t *testing.T) {
	partitiontest.PartitionTest(t)

	if runtime.GOARCH == "arm" {
		t.Skip("This test is too slow on ARM and causes CI builds to time out")
	}

	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestReproducibleCatchpointLabels")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	protoParams.EnableCatchpointsWithSPContexts = true
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}
	addSinkAndPoolAccounts(accts)
	rewardsLevels := []uint64{0}

	ml := makeMockLedgerForTracker(t, false, 1, testProtocolVersion, accts)
	defer ml.Close()

	cfg := config.GetDefaultLocal()
	cfg.MaxAcctLookback = 2
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

	isCatchpointRound := func(rnd basics.Round) bool {
		return (uint64(rnd) >= cfg.MaxAcctLookback) &&
			(uint64(rnd)-cfg.MaxAcctLookback > protoParams.CatchpointLookback) &&
			((uint64(rnd)-cfg.MaxAcctLookback)%cfg.CatchpointInterval == 0)
	}
	isDataFileRound := func(rnd basics.Round) bool {
		return ((uint64(rnd)-cfg.MaxAcctLookback+protoParams.CatchpointLookback)%cfg.CatchpointInterval == 0)
	}

	i := basics.Round(0)
	numCatchpointsCreated := 0
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

		ml.addBlock(blockEntry{block: blk}, delta)
		accts = append(accts, newAccts)
		rewardsLevels = append(rewardsLevels, rewardLevel)
		roundDeltas[i] = delta

		// determine if there is a data file round and commit
		if isDataFileRound(i) || isCatchpointRound(i) {
			ml.trackers.committedUpTo(i)
			ml.trackers.waitAccountsWriting()

			// Let catchpoint data generation finish so that nothing gets skipped.
			for ct.isWritingCatchpointDataFile() {
				time.Sleep(time.Millisecond)
			}
		}

		// If we made a catchpoint, save the label.
		if isCatchpointRound(i) {
			catchpointLabels[i] = ct.GetLastCatchpointLabel()
			require.NotEmpty(t, catchpointLabels[i])
			require.NotEqual(t, lastCatchpointLabel, catchpointLabels[i])
			lastCatchpointLabel = catchpointLabels[i]
			ledgerHistory[i] = ml.fork(t)
			defer ledgerHistory[i].Close()
			numCatchpointsCreated++
		}
	}
	lastRound := i

	// Test in reverse what happens when we try to repeat the exact same blocks.
	// Start off with the catchpoint before the last one.
	for rnd := lastRound - basics.Round(cfg.CatchpointInterval); uint64(rnd) > protoParams.CatchpointLookback; rnd -= basics.Round(cfg.CatchpointInterval) {
		au.close()
		ml2 := ledgerHistory[rnd]
		require.NotNil(t, ml2)

		cfg2 := cfg
		// every other iteration modify CatchpointTracking to ensure labels generation does not depends on catchpoint file creation
		if rnd%2 == 0 {
			cfg2.CatchpointTracking = int64(crypto.RandUint63())%2 + 1 //values 1 or 2
		}
		ct2 := newCatchpointTracker(t, ml2, cfg2, ".")
		defer ct2.close()
		for i := rnd + 1; i <= lastRound; i++ {
			blk := bookkeeping.Block{
				BlockHeader: bookkeeping.BlockHeader{
					Round: basics.Round(i),
				},
			}
			blk.RewardsLevel = rewardsLevels[i]
			blk.CurrentProtocol = testProtocolVersion
			delta := roundDeltas[i]

			ml2.addBlock(blockEntry{block: blk}, delta)

			if isDataFileRound(i) || isCatchpointRound(i) {
				ml2.trackers.committedUpTo(i)
				ml2.trackers.waitAccountsWriting()
				// Let catchpoint data generation finish so that nothing gets skipped.
				for ct.isWritingCatchpointDataFile() {
					time.Sleep(time.Millisecond)
				}
			}
			// if this is a catchpoint round, check the label.
			if isCatchpointRound(i) {
				require.Equal(t, catchpointLabels[i], ct2.GetLastCatchpointLabel())
			}
		}
	}

	// test to see that after loadFromDisk, all the tracker content is lost ( as expected )
	require.NotZero(t, len(ct.roundDigest))
	require.NotZero(t, len(ct.consensusVersion))
	require.NoError(t, ct.loadFromDisk(ml, ml.Latest()))
	require.Zero(t, len(ct.roundDigest))
	require.Zero(t, len(ct.consensusVersion))
	require.Zero(t, ct.catchpointDataWriting.Load())
	select {
	case _, closed := <-ct.catchpointDataSlowWriting:
		require.False(t, closed)
	default:
		require.FailNow(t, "The catchpointDataSlowWriting should have been a closed channel; it seems to be a nil ?!")
	}
}

// TestCatchpointBackwardCompatibleLabels checks labels before and after EnableCatchpointsWithSPContexts was introduced.
func TestCatchpointBackwardCompatibleLabels(t *testing.T) {
	partitiontest.PartitionTest(t)

	temporaryDirectory := t.TempDir()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}
	ml := makeMockLedgerForTracker(t, true, 10, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	ct := &catchpointTracker{enableGeneratingCatchpointFiles: false}
	conf := config.GetDefaultLocal()

	conf.Archival = true
	paths := DirsAndPrefix{
		ResolvedGenesisDirs: config.ResolvedGenesisDirs{
			CatchpointGenesisDir: ".",
			HotGenesisDir:        ".",
		},
	}
	ct.initialize(conf, paths)

	defer ct.close()
	ct.dbDirectory = temporaryDirectory
	ct.tmpDir = temporaryDirectory

	_, err := trackerDBInitialize(ml, true, ct.dbDirectory)
	require.NoError(t, err)

	err = ct.loadFromDisk(ml, ml.Latest())
	require.NoError(t, err)

	// create catpoint with the latest version of the code
	round := basics.Round(2000)

	protos := []protocol.ConsensusVersion{protocol.ConsensusCurrentVersion, protocol.ConsensusV37, protocol.ConsensusV36}
	labels := make([]string, len(protos))
	for i, proto := range protos {
		err = ct.createCatchpoint(
			context.Background(), round-1, round,
			trackerdb.CatchpointFirstStageInfo{},
			crypto.Digest{}, proto)
		require.NoError(t, err)
		require.NotEmpty(t, ct.lastCatchpointLabel)
		labels[i] = ct.lastCatchpointLabel
	}
	require.NotEqual(t, labels[0], labels[1])
	require.Equal(t, labels[1], labels[2])
}

// blockingTracker is a testing tracker used to test "what if" a tracker would get blocked.
type blockingTracker struct {
	emptyTracker
	postCommitUnlockedEntryLock   chan struct{}
	postCommitUnlockedReleaseLock chan struct{}
	postCommitEntryLock           chan struct{}
	postCommitReleaseLock         chan struct{}
	committedUpToRound            atomic.Int64
	alwaysLock                    atomic.Bool
	shouldLockPostCommit          atomic.Bool
	shouldLockPostCommitUnlocked  atomic.Bool
}

// committedUpTo in the blockingTracker just stores the committed round.
func (bt *blockingTracker) committedUpTo(committedRnd basics.Round) (minRound, lookback basics.Round) {
	bt.committedUpToRound.Store(int64(committedRnd))
	return committedRnd, basics.Round(0)
}

// postCommit implements entry/exit blockers, designed for testing.
func (bt *blockingTracker) postCommit(ctx context.Context, dcc *deferredCommitContext) {
	if bt.alwaysLock.Load() || dcc.catchpointFirstStage || bt.shouldLockPostCommit.Load() {
		bt.postCommitEntryLock <- struct{}{}
		<-bt.postCommitReleaseLock
	}
}

// postCommitUnlocked implements entry/exit blockers, designed for testing.
func (bt *blockingTracker) postCommitUnlocked(ctx context.Context, dcc *deferredCommitContext) {
	if bt.alwaysLock.Load() || dcc.catchpointFirstStage || bt.shouldLockPostCommitUnlocked.Load() {
		bt.postCommitUnlockedEntryLock <- struct{}{}
		<-bt.postCommitUnlockedReleaseLock
	}
}

func TestCatchpointTrackerNonblockingCatchpointWriting(t *testing.T) {
	partitiontest.PartitionTest(t)

	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestCatchpointTrackerNonblockingCatchpointWriting")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.EnableCatchpointsWithSPContexts = true
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
		committedUpToRound := writeStallingTracker.committedUpToRound.Load()
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
		committedUpToRound := writeStallingTracker.committedUpToRound.Load()
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

// TestCatchpointTrackerWaitNotBlocking checks a tracker with long postCommitUnlocked does not block blockq (notifyCommit) goroutine
func TestCatchpointTrackerWaitNotBlocking(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisInitState, _ := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 10)
	const inMem = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer ledger.Close()

	writeStallingTracker := &blockingTracker{
		postCommitUnlockedEntryLock:   make(chan struct{}),
		postCommitUnlockedReleaseLock: make(chan struct{}),
	}
	writeStallingTracker.shouldLockPostCommitUnlocked.Store(true)
	ledger.trackerMu.Lock()
	ledger.trackers.mu.Lock()
	ledger.trackers.trackers = append(ledger.trackers.trackers, writeStallingTracker)
	ledger.trackers.mu.Unlock()
	ledger.trackerMu.Unlock()

	startRound := ledger.Latest() + 1
	endRound := basics.Round(20)
	addBlockDone := make(chan struct{})

	// release the blocking tracker when the test is done
	defer func() {
		// unblocking from another goroutine is a bit complicated:
		// this function should not quit until postCommitUnlockedReleaseLock is consumed
		// to do that, write to it first and do not exit until consumed,
		// otherwise we might exit and leave the tracker registry's syncer goroutine blocked
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			writeStallingTracker.postCommitUnlockedReleaseLock <- struct{}{}
			wg.Done()
		}()

		// consume to unblock
		<-writeStallingTracker.postCommitUnlockedEntryLock
		// disable further blocking
		writeStallingTracker.shouldLockPostCommitUnlocked.Store(false)

		// wait the writeStallingTracker.postCommitUnlockedReleaseLock passes
		wg.Wait()

		// at the end, what while the addBlock goroutine finishes
		// consume to unblock
		<-addBlockDone
	}()

	// tracker commits are now blocked, add some blocks
	timer := time.NewTimer(1 * time.Second)
	go func() {
		defer close(addBlockDone)
		blk := genesisInitState.Block
		for rnd := startRound; rnd <= endRound; rnd++ {
			blk.BlockHeader.Round = rnd
			blk.BlockHeader.TimeStamp = int64(blk.BlockHeader.Round)
			err := ledger.AddBlock(blk, agreement.Certificate{})
			require.NoError(t, err)
		}
	}()

	select {
	case <-timer.C:
		require.FailNow(t, "timeout")
	case <-addBlockDone:
	}

	// switch context one more time to give the blockqueue syncer to run
	time.Sleep(1 * time.Millisecond)

	// ensure Ledger.Wait() is non-blocked for all rounds except the last one (due to possible races)
	for rnd := startRound; rnd < endRound; rnd++ {
		done := ledger.Wait(rnd)
		select {
		case <-done:
		default:
			require.FailNow(t, fmt.Sprintf("Wait(%d) is blocked", rnd))
		}
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

// TestCatchpointFirstStageInfoPruning checks pruning first stage catchpoint database records and catchpoint data files.
// The test makes a catchpoint tracker and adds blocks into a mock ledger
// until it reaches expected number of catchpoint. Then checks if database records match to data files existence.
// Additional effect is that there are much more data files written during the process than catchpoints at the very end of the test
// because of automatic pruning so check that most data files are removed confirms pruning works.
func TestCatchpointFirstStageInfoPruning(t *testing.T) {
	partitiontest.PartitionTest(t)

	tempDir := t.TempDir()
	var tests = []struct {
		hotPath  string
		coldPath string
	}{
		{"", ""},
		{"hot", "cold"},
	}

	for _, test := range tests {
		var testName string
		if test.hotPath == test.coldPath {
			testName = "dirs=same"
		} else {
			testName = "dirs=different"
		}
		t.Run(testName, func(t *testing.T) {
			test.hotPath = filepath.Join(tempDir, test.hotPath)
			test.coldPath = filepath.Join(tempDir, test.coldPath)
			for _, path := range []string{test.hotPath, test.coldPath} {
				_, err := os.Stat(path)
				if errors.Is(err, os.ErrNotExist) {
					err := os.MkdirAll(path, 0777)
					require.NoError(t, err)
				}
			}

			dataFileDirectory := filepath.Join(test.hotPath, trackerdb.CatchpointDirName)
			err := os.Mkdir(dataFileDirectory, 0777)
			require.NoError(t, err)

			// create new protocol version, which has lower lookback
			testProtocolVersion :=
				protocol.ConsensusVersion("test-protocol-TestFirstStageInfoPruning")
			protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
			protoParams.CatchpointLookback = 32
			protoParams.EnableCatchpointsWithSPContexts = true
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
			ct := newCatchpointTrackerWithPaths(t, ml, cfg, test.hotPath, test.coldPath)
			defer ct.close()

			expectedNumEntries := protoParams.CatchpointLookback / cfg.CatchpointInterval

			isCatchpointRound := func(rnd basics.Round) bool {
				return (uint64(rnd) >= cfg.MaxAcctLookback) &&
					(uint64(rnd)-cfg.MaxAcctLookback > protoParams.CatchpointLookback) &&
					((uint64(rnd)-cfg.MaxAcctLookback)%cfg.CatchpointInterval == 0)
			}
			isDataFileRound := func(rnd basics.Round) bool {
				return ((uint64(rnd)-cfg.MaxAcctLookback+protoParams.CatchpointLookback)%cfg.CatchpointInterval == 0)
			}

			numCatchpointsCreated := uint64(0)
			numDataFilesWritten := uint64(0)
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

				ml.addBlock(blockEntry{block: blk}, delta)

				if isDataFileRound(i) || isCatchpointRound(i) {
					ml.trackers.committedUpTo(i)
					ml.trackers.waitAccountsWriting()
					// Let catchpoint data generation finish so that nothing gets skipped.
					for ct.isWritingCatchpointDataFile() {
						time.Sleep(time.Millisecond)
					}
					numDataFilesWritten++
				}

				if isCatchpointRound(i) {
					catchpointLabel := ct.GetLastCatchpointLabel()
					require.NotEqual(t, lastCatchpointLabel, catchpointLabel)
					lastCatchpointLabel = catchpointLabel
					numCatchpointsCreated++
				}
			}

			numEntries := uint64(0)
			i -= basics.Round(cfg.MaxAcctLookback)
			for i > 0 {
				_, recordExists, err := ct.catchpointStore.SelectCatchpointFirstStageInfo(context.Background(), i)
				require.NoError(t, err)

				catchpointDataFilePath := filepath.Join(dataFileDirectory, makeCatchpointDataFilePath(i))
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
			require.Greater(t, numDataFilesWritten, numEntries)
		})
	}
}

// Test that on startup the catchpoint tracker restarts catchpoint's first stage if
// there is an unfinished first stage record in the database.
func TestCatchpointFirstStagePersistence(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion :=
		protocol.ConsensusVersion("test-protocol-TestFirstStagePersistence")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	protoParams.EnableCatchpointsWithSPContexts = true
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}

	ml := makeMockLedgerForTracker(t, false, 1, testProtocolVersion, accts)
	defer ml.Close()

	tempDirectory := t.TempDir()
	catchpointsDirectory := filepath.Join(tempDirectory, trackerdb.CatchpointDirName)

	cfg := config.GetDefaultLocal()
	cfg.CatchpointInterval = 4
	cfg.CatchpointTracking = 2
	cfg.MaxAcctLookback = 0
	ct := newCatchpointTracker(t, ml, cfg, tempDirectory)
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

		ml.addBlock(blockEntry{block: blk}, delta)
	}
	ml.trackers.committedUpTo(firstStageRound)
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

	cps2, err := ml2.dbs.MakeCatchpointReaderWriter()
	require.NoError(t, err)

	// Insert unfinished first stage record.
	err = cps2.WriteCatchpointStateUint64(
		context.Background(), trackerdb.CatchpointStateWritingFirstStageInfo, 1)
	require.NoError(t, err)

	// Delete the database record.
	err = cps2.DeleteOldCatchpointFirstStageInfo(context.Background(), firstStageRound)
	require.NoError(t, err)

	// Create a catchpoint tracker and let it restart catchpoint's first stage.
	ct2 := newCatchpointTracker(t, ml2, cfg, tempDirectory)
	defer ct2.close()

	// Check that the catchpoint data file was rewritten.
	info, err = os.Stat(catchpointDataFilePath)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(1))

	// Check that the database record exists.
	_, exists, err := ct2.catchpointStore.SelectCatchpointFirstStageInfo(context.Background(), firstStageRound)
	require.NoError(t, err)
	require.True(t, exists)

	// Check that the unfinished first stage record is deleted.
	v, err := ct2.catchpointStore.ReadCatchpointStateUint64(
		context.Background(), trackerdb.CatchpointStateWritingFirstStageInfo)
	require.NoError(t, err)
	require.Zero(t, v)
}

// Test that on startup the catchpoint tracker restarts catchpoint's second stage if
// there is an unfinished catchpoint record in the database.
func TestCatchpointSecondStagePersistence(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion :=
		protocol.ConsensusVersion("test-protocol-TestFirstStagePersistence")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	protoParams.EnableCatchpointsWithSPContexts = true
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}

	ml := makeMockLedgerForTracker(t, false, 1, testProtocolVersion, accts)
	defer ml.Close()

	tempDirectory := t.TempDir()
	catchpointsDirectory := filepath.Join(tempDirectory, trackerdb.CatchpointDirName)

	cfg := config.GetDefaultLocal()
	cfg.CatchpointInterval = 4
	cfg.CatchpointTracking = 2
	cfg.MaxAcctLookback = 0
	ct := newCatchpointTracker(t, ml, cfg, tempDirectory)
	defer ct.close()

	isCatchpointRound := func(rnd basics.Round) bool {
		return (uint64(rnd) >= cfg.MaxAcctLookback) &&
			(uint64(rnd)-cfg.MaxAcctLookback > protoParams.CatchpointLookback) &&
			((uint64(rnd)-cfg.MaxAcctLookback)%cfg.CatchpointInterval == 0)
	}
	isDataFileRound := func(rnd basics.Round) bool {
		return ((uint64(rnd)-cfg.MaxAcctLookback+protoParams.CatchpointLookback)%cfg.CatchpointInterval == 0)
	}

	secondStageRound := basics.Round(36)
	firstStageRound := secondStageRound - basics.Round(protoParams.CatchpointLookback)
	catchpointDataFilePath :=
		filepath.Join(catchpointsDirectory, makeCatchpointDataFilePath(firstStageRound))
	var firstStageInfo trackerdb.CatchpointFirstStageInfo
	var catchpointData []byte

	// Add blocks until the first catchpoint round.
	for i := basics.Round(1); i <= secondStageRound; i++ {
		if i == secondStageRound {
			// Save first stage info and data file.
			var exists bool
			var err error
			firstStageInfo, exists, err = ct.catchpointStore.SelectCatchpointFirstStageInfo(context.Background(), firstStageRound)
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

		ml.addBlock(blockEntry{block: blk}, delta)

		if isDataFileRound(i) || isCatchpointRound(i) {
			ml.trackers.committedUpTo(i)
			ml.trackers.waitAccountsWriting()
			// Let catchpoint data generation finish so that nothing gets skipped.
			for ct.isWritingCatchpointDataFile() {
				time.Sleep(time.Millisecond)
			}
		}
	}

	// Check that the data file exists.
	catchpointFilePath :=
		filepath.Join(catchpointsDirectory, trackerdb.MakeCatchpointFilePath(secondStageRound))
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

	cw2, err := ml2.dbs.MakeCatchpointWriter()
	require.NoError(t, err)

	// Restore the first stage database record.
	err = cw2.InsertOrReplaceCatchpointFirstStageInfo(context.Background(), firstStageRound, &firstStageInfo)
	require.NoError(t, err)

	// Insert unfinished catchpoint record.
	err = cw2.InsertUnfinishedCatchpoint(
		context.Background(), secondStageRound, crypto.Digest{})
	require.NoError(t, err)

	// Delete the catchpoint file database record.
	err = cw2.StoreCatchpoint(
		context.Background(), secondStageRound, "", "", 0)
	require.NoError(t, err)

	// Create a catchpoint tracker and let it restart catchpoint's second stage.
	ct2 := newCatchpointTracker(t, ml2, cfg, tempDirectory)
	defer ct2.close()

	// Check that the catchpoint data file was rewritten.
	info, err = os.Stat(catchpointFilePath)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(1))

	// Check that the database record exists.
	filename, _, _, err := ct2.catchpointStore.GetCatchpoint(
		context.Background(), secondStageRound)
	require.NoError(t, err)
	require.NotEmpty(t, filename)

	// Check that the unfinished catchpoint database record is deleted.
	unfinishedCatchpoints, err := ct2.catchpointStore.SelectUnfinishedCatchpoints(
		context.Background())
	require.NoError(t, err)
	require.Empty(t, unfinishedCatchpoints)
}

// Test that when catchpoint's first stage record is unavailable
// (e.g. catchpoints were disabled at first stage), the unfinished catchpoint
// database record is deleted.
func TestCatchpointSecondStageDeletesUnfinishedCatchpointRecord(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion :=
		protocol.ConsensusVersion("test-protocol-TestFirstStagePersistence")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	protoParams.EnableCatchpointsWithSPContexts = true
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
	ct := newCatchpointTracker(t, ml, cfg, tempDirectory)
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
		ml.addToBlockQueue(blockEntry{block: blk}, delta)
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
	ct2 := newCatchpointTracker(t, ml2, cfg, tempDirectory)
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
		ml2.addToBlockQueue(blockEntry{block: blk}, delta)
	}
	ml2.trackers.waitAccountsWriting()

	// Check that the unfinished catchpoint database record is deleted.
	unfinishedCatchpoints, err := ct2.catchpointStore.SelectUnfinishedCatchpoints(
		context.Background())
	require.NoError(t, err)
	require.Empty(t, unfinishedCatchpoints)
}

// Test that on startup the catchpoint tracker deletes the unfinished catchpoint
// database record when the first stage database record is missing.
func TestCatchpointSecondStageDeletesUnfinishedCatchpointRecordAfterRestart(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion :=
		protocol.ConsensusVersion("test-protocol-TestFirstStagePersistence")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	protoParams.EnableCatchpointsWithSPContexts = true
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
		ml.addToBlockQueue(blockEntry{block: blk}, delta)

		// Let catchpoint data generation finish so that nothing gets skipped.
		for ct.isWritingCatchpointDataFile() {
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

	cps2, err := ml2.dbs.MakeCatchpointReaderWriter()
	require.NoError(t, err)

	// Sanity check: first stage record should be deleted.
	_, exists, err := cps2.SelectCatchpointFirstStageInfo(context.Background(), firstStageRound)
	require.NoError(t, err)
	require.False(t, exists)

	// Insert unfinished catchpoint record.
	err = cps2.InsertUnfinishedCatchpoint(
		context.Background(), secondStageRound, crypto.Digest{})
	require.NoError(t, err)

	// Create a catchpoint tracker and let it restart catchpoint's second stage.
	ct2 := newCatchpointTracker(t, ml2, cfg, ".")
	defer ct2.close()

	// Check that the unfinished catchpoint database record is deleted.
	unfinishedCatchpoints, err := ct2.catchpointStore.SelectUnfinishedCatchpoints(
		context.Background())
	require.NoError(t, err)
	require.Empty(t, unfinishedCatchpoints)
}

// TestHashContract confirms the account, resource, and KV hashing algorithm
// remains unchanged by comparing a newly calculated hash against a
// known-to-be-correct hex-encoded hash.
//
// When the test fails a hash equality check, it implies a hash calculated
// before the change != hash calculated now.  Accepting the new hash risks
// breaking backwards compatibility.
//
// The test also confirms each HashKind has at least 1 test case.  The check
// defends against the addition of a hashed data type without test coverage.
func TestHashContract(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type testCase struct {
		genHash          func() []byte
		expectedHex      string
		expectedHashKind trackerdb.HashKind
	}

	accountCase := func(genHash func() []byte, expectedHex string) testCase {
		return testCase{
			genHash, expectedHex, trackerdb.AccountHK,
		}
	}

	resourceAssetCase := func(genHash func() []byte, expectedHex string) testCase {
		return testCase{
			genHash, expectedHex, trackerdb.AssetHK,
		}
	}

	resourceAppCase := func(genHash func() []byte, expectedHex string) testCase {
		return testCase{
			genHash, expectedHex, trackerdb.AppHK,
		}
	}

	kvCase := func(genHash func() []byte, expectedHex string) testCase {
		return testCase{
			genHash, expectedHex, trackerdb.KvHK,
		}
	}

	a := basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}

	accounts := []testCase{
		accountCase(
			func() []byte {
				b := trackerdb.BaseAccountData{
					UpdateRound: 1024,
				}
				return trackerdb.AccountHashBuilderV6(a, &b, protocol.Encode(&b))
			},
			"0000040000c3c39a72c146dc6bcb87b499b63ef730145a8fe4a187c96e9a52f74ef17f54",
		),
		accountCase(
			func() []byte {
				b := trackerdb.BaseAccountData{
					RewardsBase: 10000,
				}
				return trackerdb.AccountHashBuilderV6(a, &b, protocol.Encode(&b))
			},
			"0000271000804b58bcc81190c3c7343c1db9c737621ff0438104bdd20a25d12aa4e9b6e5",
		),
	}

	resourceAssets := []testCase{
		resourceAssetCase(
			func() []byte {
				r := trackerdb.ResourcesData{
					Amount:    1000,
					Decimals:  3,
					AssetName: "test",
					Manager:   a,
				}

				bytes, err := trackerdb.ResourcesHashBuilderV6(&r, a, 7, 1024, protocol.Encode(&r))
				require.NoError(t, err)
				return bytes
			},
			"0000040001ca4157130516bd7f120cef4b3a28715e464d9a29f7575db9b2173b4eccd18e",
		),
	}

	resourceApps := []testCase{
		resourceAppCase(
			func() []byte {
				r := trackerdb.ResourcesData{
					ApprovalProgram:          []byte{1, 3, 10, 15},
					ClearStateProgram:        []byte{15, 10, 3, 1},
					LocalStateSchemaNumUint:  2,
					GlobalStateSchemaNumUint: 2,
				}

				bytes, err := trackerdb.ResourcesHashBuilderV6(&r, a, 7, 1024, protocol.Encode(&r))
				require.NoError(t, err)
				return bytes
			},
			"00000400023547567f3234873b48fd4152f296a92ae260b024b93c2408f35caccff57c32",
		),
	}

	kvs := []testCase{
		kvCase(
			func() []byte {
				return trackerdb.KvHashBuilderV6("sample key", []byte("sample value"))
			},
			"0000000003cca3d1a8d7d724daa445c795ad277a7a64b351b4b9407f738841282f9c348b",
		),
	}

	allCases := append(append(append(accounts, resourceAssets...), resourceApps...), kvs...)
	for i, tc := range allCases {
		t.Run(fmt.Sprintf("index=%d", i), func(t *testing.T) {
			h := tc.genHash()
			require.Equal(t, byte(tc.expectedHashKind), h[trackerdb.HashKindEncodingIndex])
			require.Equal(t, tc.expectedHex, hex.EncodeToString(h))
		})
	}

	hasTestCoverageForKind := func(hk trackerdb.HashKind) bool {
		for _, c := range allCases {
			if c.expectedHashKind == hk {
				return true
			}
		}
		return false
	}

	require.True(t, strings.HasPrefix(trackerdb.HashKind(255).String(), "HashKind("))
	for i := byte(0); i < 255; i++ {
		if !strings.HasPrefix(trackerdb.HashKind(i).String(), "HashKind(") {
			require.True(t, hasTestCoverageForKind(trackerdb.HashKind(i)), fmt.Sprintf("Missing test coverage for HashKind ordinal value = %d", i))
		}
	}
}

// TestCatchpoint_FastUpdates tests catchpoint label writing data race
func TestCatchpointFastUpdates(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusFuture]

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}
	addSinkAndPoolAccounts(accts)
	rewardsLevels := []uint64{0}

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.CatchpointTracking = 1
	initialBlocksCount := basics.Round(conf.MaxAcctLookback)
	ml := makeMockLedgerForTracker(t, true, initialBlocksCount, protocol.ConsensusFuture, accts)
	defer ml.Close()

	ct := newCatchpointTracker(t, ml, conf, ".")
	au := ml.trackers.accts
	ao := ml.trackers.acctsOnline

	// Remove the txtail from the list of trackers since it causes a data race that
	// wouldn't be observed under normal execution because commitedUpTo and newBlock
	// are protected by the tracker mutex.
	trackers := make([]ledgerTracker, 0, len(ml.trackers.trackers))
	for _, tracker := range ml.trackers.trackers {
		if _, ok := tracker.(*txTail); !ok {
			trackers = append(trackers, tracker)
		}
	}
	ml.trackers.trackers = trackers

	// cover 10 genesis blocks
	rewardLevel := uint64(0)
	for i := basics.Round(1); i < initialBlocksCount; i++ {
		accts = append(accts, accts[0])
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}

	checkAcctUpdates(t, au, ao, 0, basics.Round(initialBlocksCount)-1, accts, rewardsLevels, proto)

	wg := sync.WaitGroup{}

	lastRound := basics.Round(0)
	for i := basics.Round(initialBlocksCount); i < basics.Round(proto.CatchpointLookback+15); i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		updates, totals := ledgertesting.RandomDeltasBalanced(1, accts[i-1], rewardLevel)
		prevRound, prevTotals, err := au.LatestTotals()
		require.Equal(t, i-1, prevRound)
		require.NoError(t, err)

		newPool := totals[testPoolAddr]
		newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
		updates.Upsert(testPoolAddr, newPool)
		totals[testPoolAddr] = newPool
		newAccts := applyPartialDeltas(accts[i-1], updates)

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: basics.Round(i),
			},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = protocol.ConsensusFuture

		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.Accts.MergeAccounts(updates)
		delta.Totals = accumulateTotals(t, protocol.ConsensusCurrentVersion, []map[basics.Address]ledgercore.AccountData{totals}, rewardLevel)
		ml.addBlock(blockEntry{block: blk}, delta)
		accts = append(accts, newAccts)
		rewardsLevels = append(rewardsLevels, rewardLevel)

		wg.Add(1)
		go func(round basics.Round) {
			defer wg.Done()
			ml.trackers.committedUpTo(round)
		}(i)
		lastRound = i
	}
	wg.Wait()
	ml.trackers.waitAccountsWriting()

	for ml.trackers.getDbRound() <= basics.Round(proto.CatchpointLookback) {
		// db round stuck <= 320? likely committedUpTo dropped some commit tasks, due to deferredCommits channel full
		// so give it another try
		ml.trackers.committedUpTo(lastRound)
		require.Eventually(t, func() bool {
			//ml.trackers.waitAccountsWriting()
			return ml.trackers.getDbRound() > basics.Round(proto.CatchpointLookback)
		}, 5*time.Second, 100*time.Millisecond)
	}

	require.NotEmpty(t, ct.GetLastCatchpointLabel())
}

// TestCatchpoint_LargeAccountCountCatchpointGeneration creates a ledger containing a large set of accounts ( i.e. 100K accounts )
// and attempts to have the catchpoint tracker create the associated catchpoint. It's designed precisely around setting an
// environment which would quickly ( i.e. after 32 rounds ) would start producing catchpoints.
func TestCatchpointLargeAccountCountCatchpointGeneration(t *testing.T) {
	partitiontest.PartitionTest(t)

	if strings.ToUpper(os.Getenv("CIRCLECI")) == "TRUE" || testing.Short() {
		t.Skip("This test is too slow on CI executors: cannot repack catchpoint")
	}

	// The next operations are heavy on the memory.
	// Garbage collection helps prevent trashing
	runtime.GC()

	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestLargeAccountCountCatchpointGeneration")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 16
	protoParams.EnableCatchpointsWithSPContexts = true
	config.Consensus[testProtocolVersion] = protoParams
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(100000, true)}
	addSinkAndPoolAccounts(accts)
	rewardsLevels := []uint64{0}

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 32
	conf.CatchpointTracking = 1
	conf.Archival = true
	initialBlocksCount := basics.Round(conf.MaxAcctLookback)
	ml := makeMockLedgerForTracker(t, true, initialBlocksCount, testProtocolVersion, accts)
	defer ml.Close()

	ct := newCatchpointTracker(t, ml, conf, ".")
	temporaryDirectory := t.TempDir()
	catchpointsDirectory := filepath.Join(temporaryDirectory, trackerdb.CatchpointDirName)
	err := os.Mkdir(catchpointsDirectory, 0777)
	require.NoError(t, err)
	defer os.RemoveAll(catchpointsDirectory)

	ct.dbDirectory = temporaryDirectory

	au := ml.trackers.accts

	// cover 10 genesis blocks
	rewardLevel := uint64(0)
	for i := basics.Round(1); i < initialBlocksCount; i++ {
		accts = append(accts, accts[0])
		rewardsLevels = append(rewardsLevels, rewardLevel)
	}

	start := basics.Round(initialBlocksCount)
	min := max(conf.CatchpointInterval, protoParams.CatchpointLookback)
	end := basics.Round(min + conf.MaxAcctLookback + 3) // few more rounds to commit and generate the second stage
	for i := start; i < end; i++ {
		rewardLevelDelta := crypto.RandUint64() % 5
		rewardLevel += rewardLevelDelta
		updates, totals := ledgertesting.RandomDeltasBalanced(1, accts[i-1], rewardLevel)

		prevRound, prevTotals, err := au.LatestTotals()
		require.Equal(t, i-1, prevRound)
		require.NoError(t, err)

		newPool := totals[testPoolAddr]
		newPool.MicroAlgos.Raw -= prevTotals.RewardUnits() * rewardLevelDelta
		updates.Upsert(testPoolAddr, newPool)
		totals[testPoolAddr] = newPool
		newAccts := applyPartialDeltas(accts[i-1], updates)

		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: basics.Round(i),
			},
		}
		blk.RewardsLevel = rewardLevel
		blk.CurrentProtocol = testProtocolVersion

		delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
		delta.Accts.MergeAccounts(updates)
		ml.addBlock(blockEntry{block: blk}, delta)
		accts = append(accts, newAccts)
		rewardsLevels = append(rewardsLevels, rewardLevel)

		ml.trackers.committedUpTo(i)
		if i%2 == 1 || i == end-1 {
			ml.trackers.waitAccountsWriting()
		}
	}

	require.NotEmpty(t, ct.GetLastCatchpointLabel())

	// Garbage collection helps prevent trashing for next tests
	runtime.GC()
}

func TestMakeCatchpointFilePath(t *testing.T) {
	partitiontest.PartitionTest(t)

	type testCase struct {
		round                      int
		expectedDataFilePath       string
		expectedCatchpointFilePath string
	}

	tcs := []testCase{
		{10, "10.data", "10.catchpoint"},
		{100, "100.data", "100.catchpoint"},
		// MakeCatchpointFilePath divides the round by 256 to create subdirecories
		{257, "257.data", "01/257.catchpoint"},
		{511, "511.data", "01/511.catchpoint"},
		{512, "512.data", "02/512.catchpoint"},
		// 256 * 256 = 65536
		{65536, "65536.data", "00/01/65536.catchpoint"},
		{65537, "65537.data", "00/01/65537.catchpoint"},
		// 645536 * 3 = 193609728
		{193609727, "193609727.data", "3f/8a/0b/193609727.catchpoint"},
		{193609728, "193609728.data", "40/8a/0b/193609728.catchpoint"},
		// 256 * 256 * 256 = 16777216
		{16777216, "16777216.data", "00/00/01/16777216.catchpoint"},
	}

	for _, tc := range tcs {
		require.Equal(t, tc.expectedCatchpointFilePath, trackerdb.MakeCatchpointFilePath(basics.Round(tc.round)))
		require.Equal(t, tc.expectedDataFilePath, makeCatchpointDataFilePath(basics.Round(tc.round)))
	}

}

// Test a case where in-memory SQLite, combined with fast locking (improved performance, or no
// deadlock detection) and concurrent reads (from transaction evaluation, stake lookups, etc) can
// cause the SQLite implementation in util/db/dbutil.go to retry the function looping over all
// tracker commitRound implementations. Since catchpointtracker' commitRound updates a merkle trie's
// DB storage and its in-memory cache, the retry can cause the the balancesTrie's cache to become
// corrupted and out of sync with the DB (which uses transaction rollback between retries). The
// merkle trie corruption manifests as error log messages like:
//   - "attempted to add duplicate hash 'X' to merkle trie for account Y"
//   - "failed to delete hash 'X' from merkle trie for account Y"
//
// So we assert that those errors do not occur after the fix in #6190.
//
//nolint:paralleltest // deadlock detection is globally disabled, so this test is not parallel-safe
func TestCatchpointTrackerFastRoundsDBRetry(t *testing.T) {
	partitiontest.PartitionTest(t)

	var bufNewLogger bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&bufNewLogger)

	// disabling deadlock detection globally causes the race detector to go off, but this
	// bug can still happen even when deadlock detection is not disabled
	//deadlock.Opts.Disable = true // disable deadlock detection during this test
	//defer func() { deadlock.Opts.Disable = false }()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis(func(cfg *ledgertesting.GenesisCfg) {
		cfg.OnlineCount = 1
		ledgertesting.TurnOffRewards(cfg)
	})
	cfg := config.GetDefaultLocal()
	dl := NewDoubleLedger(t, genBalances, protocol.ConsensusFuture, cfg, simpleLedgerLogger(log)) // in-memory SQLite
	defer dl.Close()

	appSrc := main(`int 1; int 1; ==; assert`)
	app := dl.fundedApp(addrs[1], 1_000_000, appSrc)

	makeTxn := func() *txntest.Txn {
		return &txntest.Txn{
			Type:          "appl",
			Sender:        addrs[2],
			ApplicationID: app,
			Note:          ledgertesting.RandomNote(),
		}
	}

	for vb := dl.fullBlock(makeTxn()); vb.Block().Round() <= 1500; vb = dl.fullBlock(makeTxn()) {
		nextRnd := vb.Block().Round() + 1
		_, err := dl.generator.OnlineCirculation(nextRnd.SubSaturate(320), nextRnd)
		require.NoError(t, err)
		require.Empty(t, vb.Block().ExpiredParticipationAccounts)
		require.Empty(t, vb.Block().AbsentParticipationAccounts)
	}

	// assert that no corruption of merkle trie happened due to DB retries leaving
	// incorrect state in the merkle trie cache.
	require.NotContains(t, bufNewLogger.String(), "to merkle trie for account", "Merkle trie was corrupted!")
}
