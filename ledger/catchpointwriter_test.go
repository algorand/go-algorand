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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/msgp/msgp"
)

func TestCatchpointFileBalancesChunkEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// check a low number of balances/kvs/resources
	// otherwise it would take forever to serialize/deserialize
	const numChunkEntries = BalancesPerCatchpointFileChunk / 50
	require.Greater(t, numChunkEntries, 1)

	const numResources = ResourcesPerCatchpointFileChunk / 10000
	require.Greater(t, numResources, 1)

	baseAD := randomBaseAccountData()
	encodedBaseAD := baseAD.MarshalMsg(nil)

	resources := make(map[uint64]msgp.Raw, numResources/10)
	rdApp := randomAppResourceData()
	encodedResourceData := rdApp.MarshalMsg(nil)
	for i := uint64(0); i < numResources; i++ {
		resources[i] = encodedResourceData
	}
	balance := encodedBalanceRecordV6{
		Address:     ledgertesting.RandomAddress(),
		AccountData: encodedBaseAD,
		Resources:   resources,
	}
	balances := make([]encodedBalanceRecordV6, numChunkEntries)
	kv := encodedKVRecordV6{
		Key:   make([]byte, encodedKVRecordV6MaxKeyLength),
		Value: make([]byte, encodedKVRecordV6MaxValueLength),
	}
	crypto.RandBytes(kv.Key[:])
	crypto.RandBytes(kv.Value[:])
	kvs := make([]encodedKVRecordV6, numChunkEntries)

	for i := 0; i < numChunkEntries; i++ {
		balances[i] = balance
		kvs[i] = kv
	}

	chunk1 := catchpointFileChunkV6{}
	chunk1.Balances = balances
	chunk1.KVs = kvs
	encodedChunk := chunk1.MarshalMsg(nil)

	var chunk2 catchpointFileChunkV6
	_, err := chunk2.UnmarshalMsg(encodedChunk)
	require.NoError(t, err)

	require.Equal(t, chunk1, chunk2)
}

func TestBasicCatchpointWriter(t *testing.T) {
	partitiontest.PartitionTest(t)
	// t.Parallel() NO! config.Consensus is modified

	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestBasicCatchpointWriter")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	config.Consensus[testProtocolVersion] = protoParams
	temporaryDirectory := t.TempDir()
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()
	accts := ledgertesting.RandomAccounts(300, false)

	ml := makeMockLedgerForTracker(t, true, 10, testProtocolVersion, []map[basics.Address]basics.AccountData{accts})
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au, _ := newAcctUpdates(t, ml, conf)
	err := au.loadFromDisk(ml, 0)
	require.NoError(t, err)
	au.close()
	fileName := filepath.Join(temporaryDirectory, "15.data")

	readDb := ml.trackerDB().Rdb
	err = readDb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		writer, err := makeCatchpointWriter(context.Background(), fileName, tx, ResourcesPerCatchpointFileChunk)
		if err != nil {
			return err
		}
		for {
			more, err := writer.WriteStep(context.Background())
			require.NoError(t, err)
			if !more {
				break
			}
		}
		return
	})
	require.NoError(t, err)

	// load the file from disk.
	fileContent, err := os.ReadFile(fileName)
	require.NoError(t, err)
	compressorReader, err := catchpointStage1Decoder(bytes.NewBuffer(fileContent))
	require.NoError(t, err)
	defer compressorReader.Close()
	tarReader := tar.NewReader(compressorReader)

	header, err := tarReader.Next()
	require.NoError(t, err)

	balancesBlockBytes := make([]byte, header.Size)
	readComplete := int64(0)

	for readComplete < header.Size {
		bytesRead, err := tarReader.Read(balancesBlockBytes[readComplete:])
		readComplete += int64(bytesRead)
		if err != nil {
			if err == io.EOF {
				if readComplete == header.Size {
					break
				}
				require.NoError(t, err)
			}
			break
		}
	}

	require.Equal(t, "balances.1.msgpack", header.Name)

	var chunk catchpointFileChunkV6
	err = protocol.Decode(balancesBlockBytes, &chunk)
	require.NoError(t, err)
	require.Equal(t, uint64(len(accts)), uint64(len(chunk.Balances)))

	_, err = tarReader.Next()
	require.Equal(t, io.EOF, err)
}

func testWriteCatchpoint(t *testing.T, rdb db.Accessor, datapath string, filepath string, maxResourcesPerChunk int) CatchpointFileHeader {
	var totalAccounts uint64
	var totalChunks uint64
	var biggestChunkLen uint64
	var accountsRnd basics.Round
	var totals ledgercore.AccountTotals
	if maxResourcesPerChunk <= 0 {
		maxResourcesPerChunk = ResourcesPerCatchpointFileChunk
	}

	err := rdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		writer, err := makeCatchpointWriter(context.Background(), datapath, tx, maxResourcesPerChunk)
		if err != nil {
			return err
		}
		for {
			more, err := writer.WriteStep(context.Background())
			require.NoError(t, err)
			if !more {
				break
			}
		}
		totalAccounts = writer.totalAccounts
		totalChunks = writer.chunkNum
		biggestChunkLen = writer.biggestChunkLen
		accountsRnd, err = accountsRound(tx)
		if err != nil {
			return
		}
		totals, err = accountsTotals(ctx, tx, false)
		return
	})
	require.NoError(t, err)
	blocksRound := accountsRnd + 1
	blockHeaderDigest := crypto.Hash([]byte{1, 2, 3})
	catchpointLabel := fmt.Sprintf("%d#%v", blocksRound, blockHeaderDigest) // this is not a correct way to create a label, but it's good enough for this unit test
	catchpointFileHeader := CatchpointFileHeader{
		Version:           CatchpointFileVersionV6,
		BalancesRound:     accountsRnd,
		BlocksRound:       blocksRound,
		Totals:            totals,
		TotalAccounts:     totalAccounts,
		TotalChunks:       totalChunks,
		Catchpoint:        catchpointLabel,
		BlockHeaderDigest: blockHeaderDigest,
	}
	err = repackCatchpoint(
		context.Background(), catchpointFileHeader, biggestChunkLen,
		datapath, filepath)
	require.NoError(t, err)

	l := testNewLedgerFromCatchpoint(t, filepath)
	defer l.Close()

	return catchpointFileHeader
}

func TestCatchpointReadDatabaseOverflowSingleAccount(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestFullCatchpointWriter")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	config.Consensus[testProtocolVersion] = protoParams
	temporaryDirectory := t.TempDir()
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	maxResourcesPerChunk := 5

	accts := ledgertesting.RandomAccounts(1, false)
	// force acct to have overflowing number of resources
	assetIndex := 1000
	for addr, acct := range accts {
		if acct.AssetParams == nil {
			acct.AssetParams = make(map[basics.AssetIndex]basics.AssetParams, 0)
			accts[addr] = acct
		}
		for i := uint64(0); i < 20; i++ {
			ap := ledgertesting.RandomAssetParams()
			acct.AssetParams[basics.AssetIndex(assetIndex)] = ap
			assetIndex++
		}
	}

	ml := makeMockLedgerForTracker(t, true, 10, testProtocolVersion, []map[basics.Address]basics.AccountData{accts})
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au, _ := newAcctUpdates(t, ml, conf)
	err := au.loadFromDisk(ml, 0)
	require.NoError(t, err)
	au.close()
	catchpointDataFilePath := filepath.Join(temporaryDirectory, "15.data")
	readDb := ml.trackerDB().Rdb

	err = readDb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		expectedTotalAccounts := uint64(1)
		totalAccountsWritten := uint64(0)
		totalResources := 0
		totalChunks := 0
		var expectedTotalResources int
		cw, err := makeCatchpointWriter(context.Background(), catchpointDataFilePath, tx, maxResourcesPerChunk)
		err = cw.tx.QueryRowContext(cw.ctx, "SELECT count(1) FROM resources").Scan(&expectedTotalResources)
		if err != nil {
			return err
		}
		// repeat this until read all accts
		for totalAccountsWritten < expectedTotalAccounts {
			cw.chunk.Balances = nil
			err := cw.readDatabaseStep(cw.ctx, cw.tx)
			if err != nil {
				return err
			}
			totalAccountsWritten += cw.chunk.numAccounts
			numResources := 0
			for _, balance := range cw.chunk.Balances {
				numResources += len(balance.Resources)
			}
			if numResources > maxResourcesPerChunk {
				return fmt.Errorf("too many resources in this chunk: found %d resources, maximum %d resources", numResources, maxResourcesPerChunk)
			}
			totalResources += numResources
			totalChunks++
		}

		if totalChunks <= 1 {
			return fmt.Errorf("expected more than one chunk due to overflow")
		}

		if expectedTotalResources != totalResources {
			return fmt.Errorf("total resources did not match: expected %d, actual %d", expectedTotalResources, totalResources)
		}

		return
	})

	require.NoError(t, err)
}

func TestCatchpointReadDatabaseOverflowAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestFullCatchpointWriter")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	config.Consensus[testProtocolVersion] = protoParams
	temporaryDirectory := t.TempDir()
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	const maxResourcesPerChunk = 5

	accts := ledgertesting.RandomAccounts(5, false)
	// force each acct to have overflowing number of resources
	assetIndex := 1000
	for addr, acct := range accts {
		if acct.AssetParams == nil {
			acct.AssetParams = make(map[basics.AssetIndex]basics.AssetParams, 0)
			accts[addr] = acct
		}
		for i := uint64(0); i < 20; i++ {
			ap := ledgertesting.RandomAssetParams()
			acct.AssetParams[basics.AssetIndex(assetIndex)] = ap
			assetIndex++
		}
	}

	ml := makeMockLedgerForTracker(t, true, 10, testProtocolVersion, []map[basics.Address]basics.AccountData{accts})
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au, _ := newAcctUpdates(t, ml, conf)
	err := au.loadFromDisk(ml, 0)
	require.NoError(t, err)
	au.close()
	catchpointDataFilePath := filepath.Join(temporaryDirectory, "15.data")
	readDb := ml.trackerDB().Rdb

	err = readDb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		expectedTotalAccounts, err := totalAccounts(ctx, tx)
		if err != nil {
			return err
		}
		totalAccountsWritten := uint64(0)
		totalResources := 0
		var expectedTotalResources int
		cw, err := makeCatchpointWriter(context.Background(), catchpointDataFilePath, tx, maxResourcesPerChunk)
		require.NoError(t, err)
		err = cw.tx.QueryRowContext(cw.ctx, "SELECT count(1) FROM resources").Scan(&expectedTotalResources)
		if err != nil {
			return err
		}
		// repeat this until read all accts
		for totalAccountsWritten < expectedTotalAccounts {
			cw.chunk.Balances = nil
			err := cw.readDatabaseStep(cw.ctx, cw.tx)
			if err != nil {
				return err
			}
			totalAccountsWritten += cw.chunk.numAccounts
			numResources := 0
			for _, balance := range cw.chunk.Balances {
				numResources += len(balance.Resources)
			}
			if numResources > maxResourcesPerChunk {
				return fmt.Errorf("too many resources in this chunk: found %d resources, maximum %d resources", numResources, maxResourcesPerChunk)
			}
			totalResources += numResources
		}

		if expectedTotalResources != totalResources {
			return fmt.Errorf("total resources did not match: expected %d, actual %d", expectedTotalResources, totalResources)
		}

		return
	})

	require.NoError(t, err)
}

func TestFullCatchpointWriterOverflowAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestFullCatchpointWriter")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	config.Consensus[testProtocolVersion] = protoParams
	temporaryDirectory := t.TempDir()
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := ledgertesting.RandomAccounts(BalancesPerCatchpointFileChunk*3, false)
	ml := makeMockLedgerForTracker(t, true, 10, testProtocolVersion, []map[basics.Address]basics.AccountData{accts})
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au, _ := newAcctUpdates(t, ml, conf)
	err := au.loadFromDisk(ml, 0)
	require.NoError(t, err)
	au.close()
	catchpointDataFilePath := filepath.Join(temporaryDirectory, "15.data")
	catchpointFilePath := filepath.Join(temporaryDirectory, "15.catchpoint")
	const maxResourcesPerChunk = 5
	testWriteCatchpoint(t, ml.trackerDB().Rdb, catchpointDataFilePath, catchpointFilePath, maxResourcesPerChunk)

	l := testNewLedgerFromCatchpoint(t, catchpointFilePath)
	defer l.Close()

	// verify that the account data aligns with what we originally stored :
	for addr, acct := range accts {
		acctData, validThrough, _, err := l.LookupLatest(addr)
		require.NoErrorf(t, err, "failed to lookup for account %v after restoring from catchpoint", addr)
		require.Equal(t, acct, acctData)
		require.Equal(t, basics.Round(0), validThrough)
	}

	err = l.reloadLedger()
	require.NoError(t, err)

	// now manually construct the MT and ensure the reading makeOrderedAccountsIter works as expected:
	// no errors on read, hashes match
	ctx := context.Background()
	tx, err := l.trackerDBs.Wdb.Handle.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	require.NoError(t, err)
	defer tx.Rollback()

	// save the existing hash
	committer, err := MakeMerkleCommitter(tx, false)
	require.NoError(t, err)
	trie, err := merkletrie.MakeTrie(committer, TrieMemoryConfig)
	require.NoError(t, err)

	h1, err := trie.RootHash()
	require.NoError(t, err)
	require.NotEmpty(t, h1)

	// reset hashes
	err = resetAccountHashes(ctx, tx)
	require.NoError(t, err)

	// rebuild the MT
	committer, err = MakeMerkleCommitter(tx, false)
	require.NoError(t, err)
	trie, err = merkletrie.MakeTrie(committer, TrieMemoryConfig)
	require.NoError(t, err)

	h, err := trie.RootHash()
	require.NoError(t, err)
	require.Zero(t, h)

	iter := makeOrderedAccountsIter(tx, trieRebuildAccountChunkSize)
	defer iter.Close(ctx)
	for {
		accts, _, err := iter.Next(ctx)
		if err == sql.ErrNoRows {
			// the account builder would return sql.ErrNoRows when no more data is available.
			err = nil
			break
		} else if err != nil {
			require.NoError(t, err)
		}

		if len(accts) > 0 {
			for _, acct := range accts {
				added, err := trie.Add(acct.digest)
				require.NoError(t, err)
				require.True(t, added)
			}
		}
	}
	require.NoError(t, err)
	h2, err := trie.RootHash()
	require.NoError(t, err)
	require.NotEmpty(t, h2)

	require.Equal(t, h1, h2)
}

func testNewLedgerFromCatchpoint(t *testing.T, filepath string) *Ledger {
	// create a ledger.
	var initState ledgercore.InitState
	initState.Block.CurrentProtocol = protocol.ConsensusCurrentVersion
	conf := config.GetDefaultLocal()
	l, err := OpenLedger(logging.TestingLog(t), t.Name()+"FromCatchpoint", true, initState, conf)
	require.NoError(t, err)
	accessor := MakeCatchpointCatchupAccessor(l, l.log)

	err = accessor.ResetStagingBalances(context.Background(), true)
	require.NoError(t, err)

	// load the file from disk.
	fileContent, err := os.ReadFile(filepath)
	require.NoError(t, err)
	gzipReader, err := gzip.NewReader(bytes.NewBuffer(fileContent))
	require.NoError(t, err)
	tarReader := tar.NewReader(gzipReader)
	var catchupProgress CatchpointCatchupAccessorProgress
	defer gzipReader.Close()
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			break
		}
		balancesBlockBytes := make([]byte, header.Size)
		readComplete := int64(0)

		for readComplete < header.Size {
			bytesRead, err := tarReader.Read(balancesBlockBytes[readComplete:])
			readComplete += int64(bytesRead)
			if err != nil {
				if err == io.EOF {
					if readComplete == header.Size {
						break
					}
					require.NoError(t, err)
				}
				break
			}
		}
		err = accessor.ProcessStagingBalances(context.Background(), header.Name, balancesBlockBytes, &catchupProgress)
		require.NoError(t, err)
	}

	err = accessor.BuildMerkleTrie(context.Background(), nil)
	require.NoError(t, err)

	err = l.trackerDBs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		err := applyCatchpointStagingBalances(ctx, tx, 0, 0)
		return err
	})
	require.NoError(t, err)
	return l
}

func TestFullCatchpointWriter(t *testing.T) {
	partitiontest.PartitionTest(t)
	// t.Parallel() NO! config.Consensus is modified

	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestFullCatchpointWriter")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	config.Consensus[testProtocolVersion] = protoParams
	temporaryDirectory := t.TempDir()
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := ledgertesting.RandomAccounts(BalancesPerCatchpointFileChunk*3, false)
	ml := makeMockLedgerForTracker(t, true, 10, testProtocolVersion, []map[basics.Address]basics.AccountData{accts})
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au, _ := newAcctUpdates(t, ml, conf)
	err := au.loadFromDisk(ml, 0)
	require.NoError(t, err)
	au.close()

	catchpointDataFilePath := filepath.Join(temporaryDirectory, "15.data")
	catchpointFilePath := filepath.Join(temporaryDirectory, "15.catchpoint")
	testWriteCatchpoint(t, ml.trackerDB().Rdb, catchpointDataFilePath, catchpointFilePath, 0)

	l := testNewLedgerFromCatchpoint(t, catchpointFilePath)
	defer l.Close()
	// verify that the account data aligns with what we originally stored :
	for addr, acct := range accts {
		acctData, validThrough, _, err := l.LookupLatest(addr)
		require.NoErrorf(t, err, "failed to lookup for account %v after restoring from catchpoint", addr)
		require.Equal(t, acct, acctData)
		require.Equal(t, basics.Round(0), validThrough)
	}
}

func TestExactAccountChunk(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	dl := NewDoubleLedger(t, genBalances, protocol.ConsensusFuture)
	defer dl.Close()

	pay := txntest.Txn{
		Type:   "pay",
		Sender: addrs[0],
		Amount: 1_000_000,
	}
	// There are 12 accounts in the NewTestGenesis, so we create more so that we
	// have exactly one chunk's worth, to make sure that works without an empty
	// chunk between accounts and kvstore.
	for i := 0; i < (BalancesPerCatchpointFileChunk - 12); i++ {
		newacctpay := pay
		newacctpay.Receiver = ledgertesting.RandomAddress()
		dl.fullBlock(&newacctpay)
	}

	// At least 32 more blocks so that we catchpoint after the accounts exist
	for i := 0; i < 40; i++ {
		selfpay := pay
		selfpay.Receiver = addrs[0]
		selfpay.Note = ledgertesting.RandomNote()
		dl.fullBlock(&selfpay)
	}

	tempDir := t.TempDir()

	catchpointDataFilePath := filepath.Join(tempDir, t.Name()+".data")
	catchpointFilePath := filepath.Join(tempDir, t.Name()+".catchpoint.tar.gz")

	cph := testWriteCatchpoint(t, dl.validator.trackerDB().Rdb, catchpointDataFilePath, catchpointFilePath, 0)
	require.EqualValues(t, cph.TotalChunks, 1)

	l := testNewLedgerFromCatchpoint(t, catchpointFilePath)
	defer l.Close()
}

func TestCatchpointAfterTxns(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	dl := NewDoubleLedger(t, genBalances, protocol.ConsensusFuture)
	defer dl.Close()

	boxApp := dl.fundedApp(addrs[1], 1_000_000, boxAppSource)
	callBox := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[2],
		ApplicationID: boxApp,
	}

	makeBox := callBox.Args("create", "xxx")
	makeBox.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("xxx")}}
	dl.txn(makeBox)

	pay := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: addrs[1],
		Amount:   100000,
	}
	// There are 12 accounts in the NewTestGenesis, plus 1 app account, so we
	// create more so that we have exactly one chunk's worth, to make sure that
	// works without an empty chunk between accounts and kvstore.
	for i := 0; i < (BalancesPerCatchpointFileChunk - 13); i++ {
		newacctpay := pay
		newacctpay.Receiver = ledgertesting.RandomAddress()
		dl.fullBlock(&newacctpay)
	}
	for i := 0; i < 40; i++ {
		dl.fullBlock(pay.Noted(strconv.Itoa(i)))
	}

	tempDir := t.TempDir()

	catchpointDataFilePath := filepath.Join(tempDir, t.Name()+".data")
	catchpointFilePath := filepath.Join(tempDir, t.Name()+".catchpoint.tar.gz")

	cph := testWriteCatchpoint(t, dl.validator.trackerDB().Rdb, catchpointDataFilePath, catchpointFilePath, 0)
	require.EqualValues(t, 2, cph.TotalChunks)

	l := testNewLedgerFromCatchpoint(t, catchpointFilePath)
	defer l.Close()
	values, err := l.LookupKeysByPrefix(l.Latest(), "bx:", 10)
	require.NoError(t, err)
	require.Len(t, values, 1)

	// Add one more account
	newacctpay := pay
	last := ledgertesting.RandomAddress()
	newacctpay.Receiver = last
	dl.fullBlock(&newacctpay)

	// Write and read back in, and ensure even the last effect exists.
	cph = testWriteCatchpoint(t, dl.validator.trackerDB().Rdb, catchpointDataFilePath, catchpointFilePath, 0)
	require.EqualValues(t, cph.TotalChunks, 2) // Still only 2 chunks, as last was in a recent block

	// Drive home the point that `last` is _not_ included in the catchpoint by inspecting balance read from catchpoint.
	{
		l = testNewLedgerFromCatchpoint(t, catchpointFilePath)
		defer l.Close()
		_, _, algos, err := l.LookupLatest(last)
		require.NoError(t, err)
		require.Equal(t, basics.MicroAlgos{}, algos)
	}

	for i := 0; i < 40; i++ { // Advance so catchpoint sees the txns
		dl.fullBlock(pay.Noted(strconv.Itoa(i)))
	}

	cph = testWriteCatchpoint(t, dl.validator.trackerDB().Rdb, catchpointDataFilePath, catchpointFilePath, 0)
	require.EqualValues(t, cph.TotalChunks, 3)

	l = testNewLedgerFromCatchpoint(t, catchpointFilePath)
	defer l.Close()
	values, err = l.LookupKeysByPrefix(l.Latest(), "bx:", 10)
	require.NoError(t, err)
	require.Len(t, values, 1)

	// Confirm `last` balance is now available in the catchpoint.
	{
		// Since fast catchup consists of multiple steps and the test only performs catchpoint reads, the resulting ledger is incomplete.
		// That's why the assertion ignores rewards and does _not_ use `LookupLatest`.
		ad, _, err := l.LookupWithoutRewards(0, last)
		require.NoError(t, err)
		require.Equal(t, basics.MicroAlgos{Raw: 100_000}, ad.MicroAlgos)
	}
}

func TestEncodedKVRecordV6Allocbounds(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for version, params := range config.Consensus {
		require.GreaterOrEqualf(t, uint64(encodedKVRecordV6MaxValueLength), params.MaxBoxSize, "Allocbound constant no longer valid as of consensus version %s", version)
		longestPossibleBoxName := string(make([]byte, params.MaxAppKeyLen))
		longestPossibleKey := logic.MakeBoxKey(basics.AppIndex(math.MaxUint64), longestPossibleBoxName)
		require.GreaterOrEqualf(t, encodedKVRecordV6MaxValueLength, len(longestPossibleKey), "Allocbound constant no longer valid as of consensus version %s", version)
	}
}

func TestEncodedKVDataSize(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	currentConsensusParams := config.Consensus[protocol.ConsensusCurrentVersion]

	require.GreaterOrEqual(t, encodedKVRecordV6MaxKeyLength, currentConsensusParams.MaxAppKeyLen)
	require.GreaterOrEqual(t, uint64(encodedKVRecordV6MaxValueLength), currentConsensusParams.MaxBoxSize)

	kvEntry := encodedKVRecordV6{
		Key:   make([]byte, encodedKVRecordV6MaxKeyLength),
		Value: make([]byte, encodedKVRecordV6MaxValueLength),
	}

	crypto.RandBytes(kvEntry.Key[:])
	crypto.RandBytes(kvEntry.Value[:])

	encoded := kvEntry.MarshalMsg(nil)
	require.GreaterOrEqual(t, MaxEncodedKVDataSize, len(encoded))

}
