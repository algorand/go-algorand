// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package verify

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-algorand/util/metrics"
)

var droppedFromPool = metrics.MakeCounter(metrics.MetricName{Name: "test_streamVerifierTestCore_messages_dropped_pool", Description: "Test streamVerifierTestCore messages dropped from pool"})

func streamVerifierTestCore(txnGroups [][]transactions.SignedTxn, badTxnGroups map[uint64]struct{},
	expectedError error, t *testing.T) (sv *execpool.StreamToBatch) {

	numOfTxnGroups := len(txnGroups)
	verificationPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, t)
	defer verificationPool.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	cache := MakeVerifiedTransactionCache(50000)

	defer cancel()

	inputChan := make(chan execpool.InputJob)
	resultChan := make(chan *VerificationResult, txBacklogSize)
	droppedChan := make(chan *UnverifiedTxnSigJob)
	ep, err := MakeSigVerifyJobProcessor(&DummyLedgerForSignature{}, cache, resultChan, droppedChan)
	require.NoError(t, err)
	sv = execpool.MakeStreamToBatch(inputChan, verificationPool, ep)
	sv.Start(ctx)

	wg := sync.WaitGroup{}

	errChan := make(chan error)
	var badSigResultCounter int
	var goodSigResultCounter int

	wg.Add(1)
	go processResults(ctx, errChan, resultChan, numOfTxnGroups, badTxnGroups, &badSigResultCounter, &goodSigResultCounter, &wg)

	wg.Add(1)
	// send txn groups to be verified
	go func() {
		defer wg.Done()
		for _, tg := range txnGroups {
			inputChan <- &UnverifiedTxnSigJob{TxnGroup: tg, BacklogMessage: nil}
		}
	}()

	for err := range errChan {
		require.ErrorContains(t, err, expectedError.Error())
	}

	wg.Wait()

	verifyResults(txnGroups, badTxnGroups, cache, badSigResultCounter, goodSigResultCounter, t)
	return sv
}

func processResults(ctx context.Context, errChan chan<- error, resultChan <-chan *VerificationResult,
	numOfTxnGroups int, badTxnGroups map[uint64]struct{},
	badSigResultCounter, goodSigResultCounter *int, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(errChan)
	// process the results
	for x := 0; x < numOfTxnGroups; x++ {
		select {
		case <-ctx.Done():
		case result := <-resultChan:
			u, _ := binary.Uvarint(result.TxnGroup[0].Txn.Note)
			if _, has := badTxnGroups[u]; has {
				(*badSigResultCounter)++
				if result.Err == nil {
					err := fmt.Errorf("%dth (%d)transaction varified with a bad sig", x, u)
					errChan <- err
					return
				}
				// we expected an error, but it is not the general crypto error
				if result.Err != crypto.ErrBatchHasFailedSigs {
					errChan <- result.Err
				}
			} else {
				(*goodSigResultCounter)++
				if result.Err != nil {
					errChan <- result.Err
				}
			}
		}
	}
}

func verifyResults(txnGroups [][]transactions.SignedTxn, badTxnGroups map[uint64]struct{},
	cache VerifiedTransactionCache,
	badSigResultCounter, goodSigResultCounter int, t *testing.T) {
	// check if all txns have been checked.
	require.Equal(t, len(txnGroups), badSigResultCounter+goodSigResultCounter)
	require.Equal(t, len(badTxnGroups), badSigResultCounter)

	// check the cached transactions
	// note that the result of each verified txn group is send before the batch is added to the cache
	// the test does not know if the batch is not added to the cache yet, so some elts might be missing from the cache
	unverifiedGroups := cache.GetUnverifiedTransactionGroups(txnGroups, spec, protocol.ConsensusCurrentVersion)
	require.GreaterOrEqual(t, len(unverifiedGroups), badSigResultCounter)
	for _, txn := range unverifiedGroups {
		u, _ := binary.Uvarint(txn[0].Txn.Note)
		delete(badTxnGroups, u)
	}
	require.Empty(t, badTxnGroups, "unverifiedGroups should have all the transactions with invalid sigs")
}

func getSignedTransactions(numOfTxns, maxGrpSize, noteOffset int, badTxnProb float32) (txnGroups [][]transactions.SignedTxn, badTxnGroups map[uint64]struct{}) {

	_, signedTxn, secrets, addrs := generateTestObjects(numOfTxns, 20, noteOffset, 50)
	txnGroups = generateTransactionGroups(maxGrpSize, signedTxn, secrets, addrs)

	badTxnGroups = make(map[uint64]struct{})

	for tgi := range txnGroups {
		if rand.Float32() < badTxnProb {
			// make a bad sig
			t := rand.Intn(len(txnGroups[tgi]))
			txnGroups[tgi][t].Sig[0] = txnGroups[tgi][t].Sig[0] + 1
			u, _ := binary.Uvarint(txnGroups[tgi][0].Txn.Note)
			badTxnGroups[u] = struct{}{}
		}
	}
	return

}

// TestStreamToBatch tests the basic functionality
func TestStreamToBatch(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfTxns := 4000
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, protoMaxGroupSize, 0, 0.5)

	sv := streamVerifierTestCore(txnGroups, badTxnGroups, nil, t)
	sv.WaitForStop()
}

// TestStreamToBatchCases tests various valid and invalid transaction signature cases
func TestStreamToBatchCases(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfTxns := 10
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, 1, 0, 0)
	mod := 1

	// txn with 0 sigs
	txnGroups[mod][0].Sig = crypto.Signature{}
	u, _ := binary.Uvarint(txnGroups[mod][0].Txn.Note)
	badTxnGroups[u] = struct{}{}
	sv := streamVerifierTestCore(txnGroups, badTxnGroups, errTxnSigHasNoSig, t)
	sv.WaitForStop()
	mod++

	_, signedTxns, secrets, addrs := generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxns, secrets, addrs)
	badTxnGroups = make(map[uint64]struct{})

	// invalid stateproof txn
	txnGroups[mod][0].Sig = crypto.Signature{}
	txnGroups[mod][0].Txn.Type = protocol.StateProofTx
	txnGroups[mod][0].Txn.Header.Sender = transactions.StateProofSender
	u, _ = binary.Uvarint(txnGroups[mod][0].Txn.Note)
	badTxnGroups[u] = struct{}{}
	errFeeMustBeZeroInStateproofTxn := errors.New("fee must be zero in state-proof transaction")
	sv = streamVerifierTestCore(txnGroups, badTxnGroups, errFeeMustBeZeroInStateproofTxn, t)
	sv.WaitForStop()
	mod++

	_, signedTxns, secrets, addrs = generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxns, secrets, addrs)
	badTxnGroups = make(map[uint64]struct{})

	// acceptable stateproof txn
	txnGroups[mod][0].Sig = crypto.Signature{}
	txnGroups[mod][0].Txn.Note = nil
	txnGroups[mod][0].Txn.Type = protocol.StateProofTx
	txnGroups[mod][0].Txn.Header.Fee = basics.MicroAlgos{Raw: 0}
	txnGroups[mod][0].Txn.Header.Sender = transactions.StateProofSender
	txnGroups[mod][0].Txn.PaymentTxnFields = transactions.PaymentTxnFields{}
	sv = streamVerifierTestCore(txnGroups, badTxnGroups, nil, t)
	sv.WaitForStop()
	mod++

	// multisig
	_, mSigTxn, _, _ := generateMultiSigTxn(1, 6, 50, t)
	txnGroups[mod] = mSigTxn
	sv = streamVerifierTestCore(txnGroups, badTxnGroups, nil, t)
	sv.WaitForStop()
	mod++

	_, signedTxn, secrets, addrs := generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxn, secrets, addrs)
	badTxnGroups = make(map[uint64]struct{})

	// logicsig
	// add a simple logic that verifies this condition:
	// sha256(arg0) == base64decode(5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=)
	op, err := logic.AssembleString(`arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==`)
	require.NoError(t, err)
	s := rand.Intn(len(secrets))
	txnGroups[mod][0].Sig = crypto.Signature{}
	txnGroups[mod][0].Txn.Sender = addrs[s]
	txnGroups[mod][0].Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
	txnGroups[mod][0].Lsig.Logic = op.Program
	program := logic.Program(op.Program)
	txnGroups[mod][0].Lsig.Sig = secrets[s].Sign(program)
	sv = streamVerifierTestCore(txnGroups, badTxnGroups, nil, t)
	sv.WaitForStop()
	mod++

	// bad lgicsig
	s = rand.Intn(len(secrets))
	txnGroups[mod][0].Sig = crypto.Signature{}
	txnGroups[mod][0].Txn.Sender = addrs[s]
	txnGroups[mod][0].Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
	txnGroups[mod][0].Lsig.Args[0][0]++
	txnGroups[mod][0].Lsig.Logic = op.Program
	txnGroups[mod][0].Lsig.Sig = secrets[s].Sign(program)
	u, _ = binary.Uvarint(txnGroups[mod][0].Txn.Note)
	badTxnGroups[u] = struct{}{}
	sv = streamVerifierTestCore(txnGroups, badTxnGroups, errors.New("rejected by logic"), t)
	sv.WaitForStop()
	mod++

	_, signedTxn, secrets, addrs = generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxn, secrets, addrs)
	badTxnGroups = make(map[uint64]struct{})

	// txn with sig and msig
	txnGroups[mod][0].Msig = mSigTxn[0].Msig
	u, _ = binary.Uvarint(txnGroups[mod][0].Txn.Note)
	badTxnGroups[u] = struct{}{}
	sv = streamVerifierTestCore(txnGroups, badTxnGroups, errTxnSigNotWellFormed, t)
	sv.WaitForStop()
}

// TestStreamToBatchIdel starts the verifer and sends nothing, to trigger the timer, then sends a txn
func TestStreamToBatchIdel(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfTxns := 1
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, protoMaxGroupSize, 0, 0.5)

	sv := streamVerifierTestCore(txnGroups, badTxnGroups, nil, t)
	sv.WaitForStop()
}

func TestGetNumberOfBatchableSigsInGroup(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfTxns := 10
	txnGroups, _ := getSignedTransactions(numOfTxns, 1, 0, 0)
	mod := 1

	// txn with 0 sigs
	txnGroups[mod][0].Sig = crypto.Signature{}
	batchSigs, err := UnverifiedTxnSigJob{TxnGroup: txnGroups[mod]}.GetNumberOfBatchableItems()
	require.ErrorIs(t, err, errTxnSigHasNoSig)
	require.Equal(t, uint64(0), batchSigs)
	mod++

	_, signedTxns, secrets, addrs := generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxns, secrets, addrs)
	batchSigs, err = UnverifiedTxnSigJob{TxnGroup: txnGroups[mod]}.GetNumberOfBatchableItems()
	require.NoError(t, err)
	require.Equal(t, uint64(1), batchSigs)

	// stateproof txn
	txnGroups[mod][0].Sig = crypto.Signature{}
	txnGroups[mod][0].Txn.Type = protocol.StateProofTx
	txnGroups[mod][0].Txn.Header.Sender = transactions.StateProofSender
	batchSigs, err = UnverifiedTxnSigJob{TxnGroup: txnGroups[mod]}.GetNumberOfBatchableItems()
	require.NoError(t, err)
	require.Equal(t, uint64(0), batchSigs)
	mod++

	// multisig
	_, mSigTxn, _, _ := generateMultiSigTxn(1, 6, 50, t)

	batchSigs, err = UnverifiedTxnSigJob{TxnGroup: mSigTxn}.GetNumberOfBatchableItems()
	require.NoError(t, err)
	require.Equal(t, uint64(2), batchSigs)
	mod++

	_, signedTxn, secrets, addrs := generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxn, secrets, addrs)

	// logicsig
	op, err := logic.AssembleString(`arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==`)
	require.NoError(t, err)
	s := rand.Intn(len(secrets))
	txnGroups[mod][0].Sig = crypto.Signature{}
	txnGroups[mod][0].Txn.Sender = addrs[s]
	txnGroups[mod][0].Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
	txnGroups[mod][0].Lsig.Logic = op.Program
	program := logic.Program(op.Program)
	txnGroups[mod][0].Lsig.Sig = secrets[s].Sign(program)
	batchSigs, err = UnverifiedTxnSigJob{TxnGroup: txnGroups[mod]}.GetNumberOfBatchableItems()
	require.NoError(t, err)
	require.Equal(t, uint64(0), batchSigs)
	mod++

	// txn with sig and msig
	_, signedTxn, secrets, addrs = generateTestObjects(numOfTxns, 20, 0, 50)
	txnGroups = generateTransactionGroups(1, signedTxn, secrets, addrs)
	txnGroups[mod][0].Msig = mSigTxn[0].Msig
	batchSigs, err = UnverifiedTxnSigJob{TxnGroup: txnGroups[mod]}.GetNumberOfBatchableItems()
	require.ErrorIs(t, err, errTxnSigNotWellFormed)
	require.Equal(t, uint64(0), batchSigs)
}

// TestStreamToBatchPoolShutdown tests what happens when the exec pool shuts down
func TestStreamToBatchPoolShutdown(t *testing.T) { //nolint:paralleltest // Not parallel because it depends on the default logger
	partitiontest.PartitionTest(t)

	// only one transaction should be sufficient for the batch verifier
	// to realize the pool is terminated and to shut down
	numOfTxns := 1
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, protoMaxGroupSize, 0, 0.5)

	// check the logged information
	var logBuffer bytes.Buffer
	log := logging.Base()
	log.SetOutput(&logBuffer)
	log.SetLevel(logging.Info)

	// prepare the stream verifier
	numOfTxnGroups := len(txnGroups)
	verificationPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, t)
	_, buffLen := verificationPool.BufferSize()

	// make sure the pool is shut down and the buffer is full
	holdTasks := make(chan any)
	for x := 0; x < buffLen+runtime.NumCPU(); x++ {
		verificationPool.EnqueueBacklog(context.Background(),
			func(arg any) any { <-holdTasks; return nil }, nil, nil)
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Shutdown will block until all tasks held by holdTasks is released
		verificationPool.Shutdown()
	}()
	// release the tasks
	close(holdTasks)
	wg.Wait()

	// Send more tasks to fill the queueof the backlog worker after the consumer shuts down
	for x := 0; x < 100; x++ {
		verificationPool.EnqueueBacklog(context.Background(),
			func(arg any) any { <-holdTasks; return nil }, nil, nil)
	}

	// make sure the EnqueueBacklogis returning err
	for x := 0; x < 10; x++ {
		err := verificationPool.EnqueueBacklog(context.Background(),
			func(arg any) any { return nil }, nil, nil)
		require.Error(t, err, fmt.Sprintf("x = %d", x))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cache := MakeVerifiedTransactionCache(50000)

	inputChan := make(chan execpool.InputJob)
	resultChan := make(chan *VerificationResult, txBacklogSize)
	droppedChan := make(chan *UnverifiedTxnSigJob)
	ep, err := MakeSigVerifyJobProcessor(&DummyLedgerForSignature{}, cache, resultChan, droppedChan)
	require.NoError(t, err)
	sv := execpool.MakeStreamToBatch(inputChan, verificationPool, ep)
	sv.Start(ctx)

	errChan := make(chan error)

	var badSigResultCounter int
	var goodSigResultCounter int

	wg.Add(1)
	go processResults(ctx, errChan, resultChan, numOfTxnGroups, badTxnGroups, &badSigResultCounter, &goodSigResultCounter, &wg)

	// When the exec pool shuts down, the batch verifier should gracefully stop
	// cancel the context so that the test can terminate
	wg.Add(1)
	go func() {
		defer wg.Done()
		sv.WaitForStop()
		cancel()
	}()

	wg.Add(1)
	// send txn groups to be verified
	go func() {
		defer wg.Done()
	outer:
		for _, tg := range txnGroups {
			select {
			case <-ctx.Done():
				break outer
			case inputChan <- &UnverifiedTxnSigJob{TxnGroup: tg, BacklogMessage: nil}:
			}
		}
	}()
	for err := range errChan {
		require.ErrorIs(t, err, execpool.ErrShuttingDownError)
	}
	require.Contains(t, logBuffer.String(), "addBatchToThePoolNow: EnqueueBacklog returned an error and StreamToBatch will stop: context canceled")
	wg.Wait()

	verifyResults(txnGroups, badTxnGroups, cache, badSigResultCounter, goodSigResultCounter, t)
}

// TestStreamToBatchRestart tests what happens when the context is canceled
func TestStreamToBatchRestart(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfTxns := 1000
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, 1, 0, 0.5)

	// prepare the stream verifier
	numOfTxnGroups := len(txnGroups)
	verificationPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, t)
	defer verificationPool.Shutdown()

	cache := MakeVerifiedTransactionCache(50)

	inputChan := make(chan execpool.InputJob)
	resultChan := make(chan *VerificationResult, txBacklogSize)
	droppedChan := make(chan *UnverifiedTxnSigJob)

	ctx, cancel := context.WithCancel(context.Background())
	ep, err := MakeSigVerifyJobProcessor(&DummyLedgerForSignature{}, cache, resultChan, droppedChan)
	require.NoError(t, err)
	sv := execpool.MakeStreamToBatch(inputChan, verificationPool, ep)
	sv.Start(ctx)

	errChan := make(chan error)

	var badSigResultCounter int
	var goodSigResultCounter int

	ctx2, cancel2 := context.WithCancel(context.Background())

	wg := sync.WaitGroup{}
	wg.Add(1)
	go processResults(ctx2, errChan, resultChan, numOfTxnGroups, badTxnGroups, &badSigResultCounter, &goodSigResultCounter, &wg)

	wg.Add(1)
	// send txn groups to be verified
	go func() {
		defer wg.Done()
	outer:
		for i, tg := range txnGroups {
			if (i+1)%10 == 0 {
				cancel()
				sv.WaitForStop()
				ctx, cancel = context.WithCancel(context.Background())
				sv.Start(ctx)
			}
			select {
			case <-ctx2.Done():
				break outer
			case inputChan <- &UnverifiedTxnSigJob{TxnGroup: tg, BacklogMessage: nil}:
			}
		}
		cancel()
	}()
	for err := range errChan {
		require.ErrorIs(t, err, execpool.ErrShuttingDownError)
	}
	wg.Wait()
	sv.WaitForStop()
	cancel2() // not necessary, but the golint will want to see this

	verifyResults(txnGroups, badTxnGroups, cache, badSigResultCounter, goodSigResultCounter, t)
}

// TestBlockWatcher runs multiple goroutines to check the concurency and correctness of the block watcher
func TestStreamToBatchBlockWatcher(t *testing.T) {
	partitiontest.PartitionTest(t)
	blkHdr := createDummyBlockHeader()
	nbw := MakeNewBlockWatcher(blkHdr)
	startingRound := blkHdr.Round

	wg := sync.WaitGroup{}
	count := 100

	wg.Add(1)
	go func() {
		defer wg.Done()
		for x := 0; x < 100; x++ {
			blkHdr.Round++
			nbw.OnNewBlock(bookkeeping.Block{BlockHeader: blkHdr}, ledgercore.StateDelta{})
			time.Sleep(10 * time.Millisecond)
			nbw.OnNewBlock(bookkeeping.Block{BlockHeader: blkHdr}, ledgercore.StateDelta{})
		}
	}()

	bhStore := make(map[basics.Round]*bookkeeping.BlockHeader)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			bh := nbw.getBlockHeader()
			bhStore[bh.Round] = bh
			if bh.Round == startingRound+10 {
				break
			}
		}
	}()
	wg.Wait()
	bh := nbw.getBlockHeader()
	require.Equal(t, uint64(startingRound)+uint64(count), uint64(bh.Round))
	// There should be no inconsistency after new blocks are added
	for r, bh := range bhStore {
		require.Equal(t, r, bh.Round)
	}
}

func getSaturatedExecPool(t *testing.T) (execpool.BacklogPool, chan any) {
	verificationPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, t)
	_, buffLen := verificationPool.BufferSize()

	// make the buffer full to control when the tasks get executed
	holdTasks := make(chan any)
	for x := 0; x < buffLen+runtime.NumCPU()+1; x++ {
		verificationPool.EnqueueBacklog(context.Background(),
			func(arg any) any {
				<-holdTasks
				return nil
			}, nil, nil)
	}
	return verificationPool, holdTasks
}

// TestStreamToBatchCtxCancel tests the termination when the ctx is canceled
// To make sure that the batchingLoop is still working on a batch when the
// ctx is cancled, this test first saturates the exec pool buffer, then
// sends a txn and immediately cancels the ctx so that the batch is not
// passed to the exec pool yet, but is in batchingLoop
func TestStreamToBatchCtxCancel(t *testing.T) {
	partitiontest.PartitionTest(t)

	verificationPool, holdTasks := getSaturatedExecPool(t)
	defer verificationPool.Shutdown()
	ctx, cancel := context.WithCancel(context.Background())
	cache := MakeVerifiedTransactionCache(50)
	inputChan := make(chan execpool.InputJob)
	resultChan := make(chan *VerificationResult, txBacklogSize)
	droppedChan := make(chan *UnverifiedTxnSigJob)
	ep, err := MakeSigVerifyJobProcessor(&DummyLedgerForSignature{}, cache, resultChan, droppedChan)
	require.NoError(t, err)
	sv := execpool.MakeStreamToBatch(inputChan, verificationPool, ep)
	sv.Start(ctx)

	var result *VerificationResult
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		// no verification tasks should be executed
		// one result should be returned
		result = <-resultChan
	}()

	// send batchSizeBlockLimit after the exec pool buffer is full
	numOfTxns := 1
	txnGroups, _ := getSignedTransactions(numOfTxns, 1, 0, 0.5)
	inputChan <- &UnverifiedTxnSigJob{TxnGroup: txnGroups[0], BacklogMessage: nil}
	// cancel the ctx before the sig is sent to the exec pool
	cancel()

	// the main loop should stop after cancel()
	sv.WaitForStop()

	// release the tasks
	close(holdTasks)

	wg.Wait()
	require.ErrorIs(t, result.Err, execpool.ErrShuttingDownError)
}

// TestStreamToBatchCtxCancelPoolQueue tests the termination when the ctx is canceled
// To make sure that the batchingLoop is still working on a batch when the
// ctx is cancled, this test first saturates the exec pool buffer, then
// sends a txn and cancels the ctx after multiple waitForNextTxnDuration
// so that the batch is sent to the pool. Since the pool is saturated,
// the task will be stuck waiting to be queued when the context is canceled
// everything should be gracefully terminated
func TestStreamToBatchCtxCancelPoolQueue(t *testing.T) { //nolint:paralleltest // Not parallel because it depends on the default logger
	partitiontest.PartitionTest(t)

	verificationPool, holdTasks := getSaturatedExecPool(t)

	// check the logged information
	var logBuffer bytes.Buffer
	log := logging.Base()
	log.SetOutput(&logBuffer)
	log.SetLevel(logging.Info)

	ctx, cancel := context.WithCancel(context.Background())
	cache := MakeVerifiedTransactionCache(50)
	inputChan := make(chan execpool.InputJob)
	resultChan := make(chan *VerificationResult, txBacklogSize)
	droppedChan := make(chan *UnverifiedTxnSigJob)
	ep, err := MakeSigVerifyJobProcessor(&DummyLedgerForSignature{}, cache, resultChan, droppedChan)
	require.NoError(t, err)
	sv := execpool.MakeStreamToBatch(inputChan, verificationPool, ep)
	sv.Start(ctx)

	var result *VerificationResult
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			result = <-resultChan
			// at least one ErrShuttingDownError is expected
			if result.Err != execpool.ErrShuttingDownError {
				continue
			}
			break
		}
	}()

	// send batchSizeBlockLimit after the exec pool buffer is full
	numOfTxns := 1
	txnGroups, _ := getSignedTransactions(numOfTxns, 1, 0, 0.5)

	wg.Add(1)
	// run in separate goroutine because the exec pool is blocked here, and this will not advance
	// until holdTasks are closed
	go func() {
		defer wg.Done()
		for {
			select {
			// Normally, a single txn is sufficient, but the goroutines could be scheduled is such a way that
			// the single transaction slips through and passes the batch verifier before the exec pool shuts down.
			// this happens when close(holdTasks) runs and frees the exec pool, and lets the txns get verified, before
			// verificationPool.Shutdown() executes.
			case inputChan <- &UnverifiedTxnSigJob{TxnGroup: txnGroups[0], BacklogMessage: nil}:
			case <-ctx.Done():
				return
			}
		}
	}()
	// cancel the ctx as the sig is not yet sent to the exec pool
	// the test might sporadically fail if between sending the txn above
	// and the cancelation, 2 x waitForNextTxnDuration elapses (10ms)
	time.Sleep(12 * time.Millisecond)
	go func() {
		// wait a bit before releasing the tasks, so that the verificationPool ctx first gets canceled
		time.Sleep(20 * time.Millisecond)
		close(holdTasks)
	}()
	verificationPool.Shutdown()

	// the main loop should stop before calling cancel() when the exec pool shuts down and returns an error
	sv.WaitForStop()
	cancel()

	wg.Wait()
	require.ErrorIs(t, result.Err, execpool.ErrShuttingDownError)
	require.Contains(t, logBuffer.String(), "addBatchToThePoolNow: EnqueueBacklog returned an error and StreamToBatch will stop: context canceled")
}

// TestStreamToBatchPostVBlocked tests the behavior when the return channel (result chan) of verified
// transactions is blocked, and checks droppedFromPool counter to confirm the drops
func TestStreamToBatchPostVBlocked(t *testing.T) {
	partitiontest.PartitionTest(t)

	// prepare the stream verifier
	verificationPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, t)
	defer verificationPool.Shutdown()
	errChan := make(chan error)
	var badSigResultCounter int
	var goodSigResultCounter int

	ctx := t.Context()
	cache := MakeVerifiedTransactionCache(50)

	txBacklogSizeMod := txBacklogSize / 20

	inputChan := make(chan execpool.InputJob)
	resultChan := make(chan *VerificationResult, txBacklogSizeMod)
	droppedChan := make(chan *UnverifiedTxnSigJob)
	ep, err := MakeSigVerifyJobProcessor(&DummyLedgerForSignature{}, cache, resultChan, droppedChan)
	require.NoError(t, err)
	sv := execpool.MakeStreamToBatch(inputChan, verificationPool, ep)

	defer close(droppedChan)
	go func() {
		for range droppedChan {
			droppedFromPool.Inc(nil)
		}
	}()

	// start the verifier
	sv.Start(ctx)
	overflow := 3
	// send txBacklogSizeMod + 3 transactions to overflow the result buffer
	numOfTxns := txBacklogSizeMod + overflow
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, 1, 0, 0.5)
	numOfTxnGroups := len(txnGroups)
	for _, tg := range txnGroups {
		inputChan <- &UnverifiedTxnSigJob{TxnGroup: tg, BacklogMessage: nil}
	}

	var droppedPool uint64
	// wait until overflow transactions are dropped
	for w := 0; w < 100; w++ {
		droppedPool = droppedFromPool.GetUint64Value()
		if droppedPool >= uint64(overflow) {
			break
		}
		time.Sleep(time.Millisecond * 20)
	}

	require.Equal(t, uint64(overflow), droppedPool)

	wg := sync.WaitGroup{}
	wg.Add(1)
	// make sure the other results are fine
	go processResults(ctx, errChan, resultChan, numOfTxnGroups-overflow, badTxnGroups, &badSigResultCounter, &goodSigResultCounter, &wg)

	for err := range errChan {
		require.ErrorIs(t, err, execpool.ErrShuttingDownError)
		fmt.Println(badTxnGroups)
	}

	// check if more transactions can be accepted
	errChan = make(chan error)

	wg.Add(1)
	// make sure the other results are fine
	txnGroups, badTxnGroups2 := getSignedTransactions(numOfTxns, 1, numOfTxns, 0.5)
	// need to combine these, since left overs from the previous one could still come out
	for b := range badTxnGroups2 {
		badTxnGroups[b] = struct{}{}
	}
	go processResults(ctx, errChan, resultChan, numOfTxnGroups, badTxnGroups, &badSigResultCounter, &goodSigResultCounter, &wg)

	for _, tg := range txnGroups {
		inputChan <- &UnverifiedTxnSigJob{TxnGroup: tg, BacklogMessage: nil}
	}

	for err := range errChan {
		require.ErrorIs(t, err, execpool.ErrShuttingDownError)
		fmt.Println(badTxnGroups)
	}

	wg.Wait()
}

func TestStreamToBatchMakeStreamToBatchErr(t *testing.T) {
	partitiontest.PartitionTest(t)
	_, err := MakeSigVerifier(&DummyLedgerForSignature{badHdr: true}, nil)
	require.Error(t, err)

	_, err = MakeSigVerifyJobProcessor(&DummyLedgerForSignature{badHdr: true}, nil, nil, nil)
	require.Error(t, err)
}

// TestStreamToBatchCancelWhenPooled tests the case where the ctx is cancled after the verification
// task is queued to the exec pool and before the task is executed in the pool
func TestStreamToBatchCancelWhenPooled(t *testing.T) {
	partitiontest.PartitionTest(t)
	numOfTxns := 1000
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, 1, 0, 0.5)

	// prepare the stream verifier
	numOfTxnGroups := len(txnGroups)
	execPool := execpool.MakePool(t)
	defer execPool.Shutdown()
	verificationPool := execpool.MakeBacklog(execPool, 64, execpool.LowPriority, t)
	defer verificationPool.Shutdown()

	cache := MakeVerifiedTransactionCache(50)

	inputChan := make(chan execpool.InputJob)
	resultChan := make(chan *VerificationResult, txBacklogSize)
	droppedChan := make(chan *UnverifiedTxnSigJob)
	ctx, cancel := context.WithCancel(context.Background())
	ep, err := MakeSigVerifyJobProcessor(&DummyLedgerForSignature{}, cache, resultChan, droppedChan)
	require.NoError(t, err)
	sv := execpool.MakeStreamToBatch(inputChan, verificationPool, ep)
	sv.Start(ctx)

	errChan := make(chan error)

	var badSigResultCounter int
	var goodSigResultCounter int

	ctx2, cancel2 := context.WithCancel(context.Background())

	wg := sync.WaitGroup{}
	wg.Add(1)
	go processResults(ctx2, errChan, resultChan, numOfTxnGroups, badTxnGroups, &badSigResultCounter, &goodSigResultCounter, &wg)

	wg.Add(1)
	// send txn groups to be verified
	go func() {
		defer wg.Done()
		for _, tg := range txnGroups {
			inputChan <- &UnverifiedTxnSigJob{TxnGroup: tg, BacklogMessage: nil}
		}
		// cancel the ctx, and expect at least one task queued to the pool but not yet executed
		cancel()
	}()
	for err := range errChan {
		require.ErrorIs(t, err, execpool.ErrShuttingDownError)
	}
	wg.Wait()
	sv.WaitForStop()
	cancel2() // not necessary, but the golint will want to see this

	verifyResults(txnGroups, badTxnGroups, cache, badSigResultCounter, goodSigResultCounter, t)
}

func TestGetErredUnprocessed(t *testing.T) {
	partitiontest.PartitionTest(t)

	droppedChan := make(chan *UnverifiedTxnSigJob, 1)
	svh := txnSigBatchProcessor{
		resultChan:  make(chan<- *VerificationResult),
		droppedChan: droppedChan,
	}

	svh.GetErredUnprocessed(&UnverifiedTxnSigJob{}, nil)
	dropped := <-droppedChan
	require.Equal(t, *dropped, UnverifiedTxnSigJob{})
}

func TestSigVerifier(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfTxns := 16
	txnGroups, badTxnGroups := getSignedTransactions(numOfTxns, numOfTxns, 0, 0)
	require.GreaterOrEqual(t, len(txnGroups), 1)
	require.Equal(t, len(badTxnGroups), 0)
	txnGroup := txnGroups[0]

	verificationPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, t)
	defer verificationPool.Shutdown()

	cache := MakeVerifiedTransactionCache(50000)

	verifier, err := MakeSigVerifier(&DummyLedgerForSignature{}, cache)
	require.NoError(t, err)

	err = verifier.Verify(txnGroup)
	require.NoError(t, err)

	txnGroups, badTxnGroups = getSignedTransactions(numOfTxns, numOfTxns, 0, 1)
	require.GreaterOrEqual(t, len(txnGroups), 1)
	require.Greater(t, len(badTxnGroups), 0)
	txnGroup = txnGroups[0]

	err = verifier.Verify(txnGroup)
	require.Error(t, err)
}

// TestProcessBatchRecoversPanic verifies the recover wrapping ProcessBatch, the live gossip
// signature-verification worker: a panic must fail the batch rather than crash the worker,
// reporting results only for jobs that did not already get one.
func TestProcessBatchRecoversPanic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// A panic before any result is delivered: every job must be reported as failed. A
	// NewBlockWatcher holding a nil header is a deterministic trigger: it makes group
	// preparation panic dereferencing contextHdr.CurrentProtocol.
	t.Run("PanicBeforeAnyResult", func(t *testing.T) {
		t.Parallel()
		nbw := &NewBlockWatcher{}
		nbw.blkHeader.Store((*bookkeeping.BlockHeader)(nil))

		resultChan := make(chan *VerificationResult, 1)
		tbp := &txnSigBatchProcessor{
			TxnGroupBatchSigVerifier: TxnGroupBatchSigVerifier{
				cache:  MakeVerifiedTransactionCache(50),
				nbw:    nbw,
				ledger: &DummyLedgerForSignature{},
			},
			resultChan:  resultChan,
			droppedChan: make(chan *UnverifiedTxnSigJob, 1),
		}

		group := []transactions.SignedTxn{{Txn: transactions.Transaction{Type: protocol.PaymentTx}}}
		job := &UnverifiedTxnSigJob{TxnGroup: group}

		// A leaked panic would fail the test; ProcessBatch must report the batch as failed instead.
		tbp.ProcessBatch([]execpool.InputJob{job})

		// The panicking batch was reported as failed rather than crashing the worker.
		select {
		case res := <-resultChan:
			require.ErrorContains(t, res.Err, "panic while verifying transaction batch")
			require.Equal(t, group, res.TxnGroup)
		default:
			t.Fatal("expected a failed verification result for the panicking batch")
		}
	})

	// A panic after results were already delivered: the recovery must not re-report those jobs.
	// Two unsigned txns fail prep and are reported immediately; the empty sig batch then panics
	// in cache.AddPayset (deliberately nil, standing in for any post-delivery panic).
	t.Run("PanicAfterResultsDelivered", func(t *testing.T) {
		t.Parallel()
		blkHdr := createDummyBlockHeader()
		resultChan := make(chan *VerificationResult, 4) // room to observe duplicates if the recovery were wrong
		droppedChan := make(chan *UnverifiedTxnSigJob, 4)
		tbp := &txnSigBatchProcessor{
			TxnGroupBatchSigVerifier: TxnGroupBatchSigVerifier{
				cache:  nil, // nil cache: AddPayset is the deterministic panic trigger
				nbw:    MakeNewBlockWatcher(blkHdr),
				ledger: &DummyLedgerForSignature{},
			},
			resultChan:  resultChan,
			droppedChan: droppedChan,
		}

		jobs := []execpool.InputJob{
			&UnverifiedTxnSigJob{TxnGroup: []transactions.SignedTxn{{Txn: transactions.Transaction{
				Type: protocol.PaymentTx, Header: transactions.Header{Sender: basics.Address{1}}}}}},
			&UnverifiedTxnSigJob{TxnGroup: []transactions.SignedTxn{{Txn: transactions.Transaction{
				Type: protocol.PaymentTx, Header: transactions.Header{Sender: basics.Address{2}}}}}},
		}

		// A leaked panic would fail the test; ProcessBatch must recover and report instead.
		tbp.ProcessBatch(jobs)

		// Exactly one result per job: the two preparation failures delivered before the
		// panic, and nothing re-reported by the recovery.
		require.Len(t, resultChan, len(jobs))
		for i := 0; i < len(jobs); i++ {
			res := <-resultChan
			require.Error(t, res.Err)
			require.NotContains(t, res.Err.Error(), "panic",
				"already-delivered results must not be re-reported by the panic recovery")
		}
		require.Empty(t, droppedChan)
	})
}

// TestProcessBatchSkippedGroupDoesNotMisattributeSigs checks that a group which fails signature prep
// partway (after one of its transactions already staged a signature) doesn't affect verification of
// the other groups in the batch. A bad group sits between two good ones; both good groups must verify.
// Two failure flavors are covered: an unsigned txn (rejected at the processor's contract level) and a
// malformed multisig, which passes both the stream's sig-presence pre-screen and the group-level
// WellFormed checks (neither inspects msig contents) and so is the shape that reaches ProcessBatch
// in production.
func TestProcessBatchSkippedGroupDoesNotMisattributeSigs(t *testing.T) {
	partitiontest.PartitionTest(t)

	cases := []struct {
		name string
		// makeBad builds the two bad-group members from txs[1]/txs[2]; group stamping happens after,
		// which invalidates any signature made here.
		makeBad  func(txs []transactions.Transaction, signed []transactions.SignedTxn) []transactions.SignedTxn
		checkErr func(t *testing.T, err error)
		// reachable: the group passes GetNumberOfBatchableItems, the stream's pre-screen, so it can
		// reach ProcessBatch in production rather than only via a direct call.
		reachable bool
	}{
		{
			name: "unsigned txn",
			makeBad: func(txs []transactions.Transaction, signed []transactions.SignedTxn) []transactions.SignedTxn {
				// txn[0]'s sig predates the group stamp, so it is present but invalid; txn[1] is
				// unsigned, so prep rejects the group after staging txn[0]'s sig.
				return []transactions.SignedTxn{signed[1], {Txn: txs[2]}}
			},
			checkErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errTxnSigHasNoSig)
			},
			reachable: false,
		},
		{
			name: "malformed msig",
			makeBad: func(txs []transactions.Transaction, signed []transactions.SignedTxn) []transactions.SignedTxn {
				// txn[1] swaps its ed25519 sig for a multisig with an unsupported version. The
				// group passes the sig-presence pre-screen and the group-level WellFormed checks
				// (neither inspects msig contents), then MultisigBatchPrep rejects it after
				// txn[0]'s sig was staged.
				bad := []transactions.SignedTxn{signed[1], signed[2]}
				bad[1].Msig = crypto.MultisigSig{
					Version:   2, // unsupported version
					Threshold: 1,
					Subsigs: []crypto.MultisigSubsig{
						{Key: crypto.PublicKey(bad[1].Txn.Sender), Sig: bad[1].Sig},
					},
				}
				bad[1].Sig = crypto.Signature{}
				return bad
			},
			checkErr: func(t *testing.T, err error) {
				var tge *TxGroupError
				require.ErrorAs(t, err, &tge)
				require.Equal(t, TxGroupErrorReasonMsigNotWellFormed, tge.Reason)
			},
			reachable: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// signed[0] and signed[3] are good single-txn groups; txs[1] and txs[2] form the bad group.
			txs, signed, _, _ := generateTestObjects(4, 4, 0, 0)
			goodFirst := []transactions.SignedTxn{signed[0]}
			goodLast := []transactions.SignedTxn{signed[3]}

			bad := tc.makeBad(txs, signed)
			var txGroup transactions.TxGroup
			for i := range bad {
				txGroup.TxGroupHashes = append(txGroup.TxGroupHashes, crypto.HashObj(bad[i].Txn))
			}
			groupHash := crypto.HashObj(txGroup)
			for i := range bad {
				bad[i].Txn.Group = groupHash
			}

			batchable, err := UnverifiedTxnSigJob{TxnGroup: bad}.GetNumberOfBatchableItems()
			if tc.reachable {
				require.NoError(t, err)
				require.EqualValues(t, 2, batchable)
			} else {
				require.ErrorIs(t, err, errTxnSigHasNoSig)
			}

			// The scenario depends on the bad group staging txn[0]'s sig before being rejected on
			// txn[1]; pin that ordering with a direct prep call so a future reordering of checks
			// cannot silently make this test vacuous.
			blkHdr := createDummyBlockHeader()
			pin := crypto.MakeBatchVerifier()
			_, prepErr := txnGroupBatchPrep(bad, &blkHdr, &DummyLedgerForSignature{}, pin, nil)
			tc.checkErr(t, prepErr)
			require.Equal(t, 1, pin.GetNumberOfEnqueuedSignatures(), "bad group must stage a sig before rejection")

			cache := MakeVerifiedTransactionCache(1000)
			resultChan := make(chan *VerificationResult, 3)
			droppedChan := make(chan *UnverifiedTxnSigJob, 3)
			tbp, err := MakeSigVerifyJobProcessor(&DummyLedgerForSignature{}, cache, resultChan, droppedChan)
			require.NoError(t, err)

			// A good group before and after the bad one, so both sides are checked.
			tbp.ProcessBatch([]execpool.InputJob{
				&UnverifiedTxnSigJob{TxnGroup: goodFirst, BacklogMessage: "good-first"},
				&UnverifiedTxnSigJob{TxnGroup: bad, BacklogMessage: "bad"},
				&UnverifiedTxnSigJob{TxnGroup: goodLast, BacklogMessage: "good-last"},
			})

			require.Empty(t, droppedChan, "every group should have produced a result on resultChan")
			results := make(map[string]error, 3)
			for i := 0; i < 3; i++ {
				select {
				case r := <-resultChan:
					results[r.BacklogMessage.(string)] = r.Err
				default:
					require.FailNow(t, "missing result", "got %d of 3 results", len(results))
				}
			}

			// The bad group is rejected; both good groups verify despite the bad group's invalid
			// signature having been staged in the same batch.
			tc.checkErr(t, results["bad"])
			require.NoError(t, results["good-first"], "good-first should verify")
			require.NoError(t, results["good-last"], "good-last should verify")
		})
	}
}
