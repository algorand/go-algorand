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

package data

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/pools"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-algorand/util/metrics"
	"github.com/algorand/go-deadlock"
)

func BenchmarkTxHandlerProcessing(b *testing.B) {
	const numUsers = 100
	log := logging.TestingLog(b)
	log.SetLevel(logging.Warn)
	secrets := make([]*crypto.SignatureSecrets, numUsers)
	addresses := make([]basics.Address, numUsers)

	genesis := make(map[basics.Address]basics.AccountData)
	for i := 0; i < numUsers; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
		genesis[addr] = basics.AccountData{
			Status:     basics.Online,
			MicroAlgos: basics.MicroAlgos{Raw: 10000000000000},
		}
	}

	genesis[poolAddr] = basics.AccountData{
		Status:     basics.NotParticipating,
		MicroAlgos: basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinBalance},
	}

	require.Equal(b, len(genesis), numUsers+1)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	ledgerName := fmt.Sprintf("%s-mem-%d", b.Name(), b.N)
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, nil, cfg)
	require.NoError(b, err)

	l := ledger

	cfg.TxPoolSize = 75000
	cfg.EnableProcessBlockStats = false
	txHandler := makeTestTxHandler(l, cfg)

	makeTxns := func(N int) [][]transactions.SignedTxn {
		ret := make([][]transactions.SignedTxn, 0, N)
		for u := 0; u < N; u++ {
			// generate transactions
			tx := transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender:     addresses[u%numUsers],
					Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
					FirstValid: 0,
					LastValid:  basics.Round(proto.MaxTxnLife),
					Note:       make([]byte, 2),
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: addresses[(u+1)%numUsers],
					Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance + (rand.Uint64() % 10000)},
				},
			}
			signedTx := tx.Sign(secrets[u%numUsers])
			ret = append(ret, []transactions.SignedTxn{signedTx})
		}
		return ret
	}

	b.Run("processDecoded", func(b *testing.B) {
		signedTransactionGroups := makeTxns(b.N)
		b.ResetTimer()
		for i := range signedTransactionGroups {
			txHandler.processDecoded(signedTransactionGroups[i])
		}
	})
	b.Run("verify.TxnGroup", func(b *testing.B) {
		signedTransactionGroups := makeTxns(b.N)
		b.ResetTimer()
		// make a header including only the fields needed by PrepareGroupContext
		hdr := bookkeeping.BlockHeader{}
		hdr.FeeSink = basics.Address{}
		hdr.RewardsPool = basics.Address{}
		hdr.CurrentProtocol = protocol.ConsensusCurrentVersion
		vtc := vtCache{}
		b.Logf("verifying %d signedTransactionGroups", len(signedTransactionGroups))
		b.ResetTimer()
		for i := range signedTransactionGroups {
			verify.TxnGroup(signedTransactionGroups[i], hdr, vtc, l)
		}
	})
}

// vtCache is a noop VerifiedTransactionCache
type vtCache struct{}

func (vtCache) Add(txgroup []transactions.SignedTxn, groupCtx *verify.GroupContext) {}
func (vtCache) AddPayset(txgroup [][]transactions.SignedTxn, groupCtxs []*verify.GroupContext) error {
	return nil
}
func (vtCache) GetUnverifiedTransactionGroups(payset [][]transactions.SignedTxn, CurrSpecAddrs transactions.SpecialAddresses, CurrProto protocol.ConsensusVersion) [][]transactions.SignedTxn {
	return nil
}
func (vtCache) UpdatePinned(pinnedTxns map[transactions.Txid]transactions.SignedTxn) error {
	return nil
}
func (vtCache) Pin(txgroup []transactions.SignedTxn) error { return nil }

func BenchmarkTimeAfter(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()
	deadline := time.Now().Add(5 * time.Second)
	after := 0
	before := 0
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if time.Now().After(deadline) {
			after++
		} else {
			before++
		}
	}
}

func makeRandomTransactions(num int) ([]transactions.SignedTxn, []byte) {
	stxns := make([]transactions.SignedTxn, num)
	result := make([]byte, 0, num*200)
	for i := 0; i < num; i++ {
		var sig crypto.Signature
		crypto.RandBytes(sig[:])
		var addr basics.Address
		crypto.RandBytes(addr[:])
		stxns[i] = transactions.SignedTxn{
			Sig:      sig,
			AuthAddr: addr,
			Txn: transactions.Transaction{
				Header: transactions.Header{
					Sender: addr,
					Fee:    basics.MicroAlgos{Raw: crypto.RandUint64()},
					Note:   sig[:],
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: addr,
					Amount:   basics.MicroAlgos{Raw: crypto.RandUint64()},
				},
			},
		}

		d2 := protocol.Encode(&stxns[i])
		result = append(result, d2...)
	}
	return stxns, result
}

func TestTxHandlerProcessIncomingTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const numTxns = 11
	handler := makeTestTxHandlerOrphaned(1)
	stxns, blob := makeRandomTransactions(numTxns)
	action := handler.processIncomingTxn(network.IncomingMessage{Data: blob})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)

	require.Equal(t, 1, len(handler.backlogQueue))
	msg := <-handler.backlogQueue
	require.Equal(t, numTxns, len(msg.unverifiedTxGroup))
	for i := 0; i < numTxns; i++ {
		require.Equal(t, stxns[i], msg.unverifiedTxGroup[i])
	}
}

// BenchmarkTxHandlerProcessIncomingTxn is single-threaded ProcessIncomingTxn benchmark
func BenchmarkTxHandlerProcessIncomingTxn(b *testing.B) {
	deadlockDisable := deadlock.Opts.Disable
	deadlock.Opts.Disable = true
	defer func() {
		deadlock.Opts.Disable = deadlockDisable
	}()

	const numTxnsPerGroup = 16
	handler := makeTestTxHandlerOrphaned(txBacklogSize)

	// prepare tx groups
	blobs := make([][]byte, b.N)
	stxns := make([][]transactions.SignedTxn, b.N)
	for i := 0; i < b.N; i++ {
		stxns[i], blobs[i] = makeRandomTransactions(numTxnsPerGroup)
	}

	ctx, cancelFun := context.WithCancel(context.Background())

	// start consumer
	var wg sync.WaitGroup
	wg.Add(1)
	go func(ctx context.Context, n int) {
		defer wg.Done()
	outer:
		for i := 0; i < n; i++ {
			select {
			case <-ctx.Done():
				break outer
			default:
			}
			msg := <-handler.backlogQueue
			require.Equal(b, numTxnsPerGroup, len(msg.unverifiedTxGroup))
		}
	}(ctx, b.N)

	// submit tx groups
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		action := handler.processIncomingTxn(network.IncomingMessage{Data: blobs[i]})
		require.Equal(b, network.OutgoingMessage{Action: network.Ignore}, action)
	}
	cancelFun()
	wg.Wait()
}

func ipow(x, n int) int {
	var res int = 1
	for n != 0 {
		if n&1 != 0 {
			res *= x
		}
		n >>= 1
		x *= x
	}
	return res
}

func TestPow(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Equal(t, 1, ipow(10, 0))
	require.Equal(t, 10, ipow(10, 1))
	require.Equal(t, 100, ipow(10, 2))
	require.Equal(t, 8, ipow(2, 3))
}

func numFromMetricString(str string) int {
	var val int
	// go backward and parse string
	// "algod_transaction_messages_dropped_backlog{} 270609\n"
	pos := 0
	for i := len(str) - 1; i >= 0; i-- {
		if str[i] == ' ' {
			break
		}
		if unicode.IsDigit(rune(str[i])) {
			val += ipow(10, pos) * int(str[i]-'0')
			pos++
		}
	}
	return val

}

func TestNumFromMetricString(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Equal(t, 1, numFromMetricString("1"))
	require.Equal(t, 1, numFromMetricString("1\n"))
	require.Equal(t, 1, numFromMetricString(" 1\n"))

	require.Equal(t, 123, numFromMetricString("123"))
	require.Equal(t, 123, numFromMetricString("123\n"))
	require.Equal(t, 123, numFromMetricString(" 123\n"))

	require.Equal(t, 270609, numFromMetricString("algod_transaction_messages_dropped_backlog{} 270609\n"))
}

func getNumBacklogDropped() int {
	var b strings.Builder
	transactionMessagesDroppedFromBacklog.WriteMetric(&b, "")
	return numFromMetricString(b.String())
}

func getNumRawMsgDup() int {
	var b strings.Builder
	transactionMessagesDupRawMsg.WriteMetric(&b, "")
	return numFromMetricString(b.String())
}

func TestGetNumBacklogDropped(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Equal(t, 0, getNumBacklogDropped())

	transactionMessagesDroppedFromBacklog.Inc(nil)
	require.Equal(t, 1, getNumBacklogDropped())

	for i := 1; i < 235; i++ {
		transactionMessagesDroppedFromBacklog.Inc(nil)
	}
	require.Equal(t, 235, getNumBacklogDropped())
}

type benchFinalize func()

func benchTxHandlerProcessIncomingTxnSubmit(b *testing.B, handler *TxHandler, blobs [][]byte, numThreads int) benchFinalize {
	// submit tx groups
	var wgp sync.WaitGroup
	wgp.Add(numThreads)

	hashesPerThread := b.N / numThreads
	if hashesPerThread == 0 {
		hashesPerThread = 1
	}

	finalize := func() {}

	if b.N == 100001 {
		profpath := b.Name() + "_cpuprof.pprof"
		profout, err := os.Create(profpath)
		if err != nil {
			b.Fatal(err)
			return finalize
		}
		b.Logf("%s: cpu profile for b.N=%d", profpath, b.N)
		pprof.StartCPUProfile(profout)

		finalize = func() {
			pprof.StopCPUProfile()
			profout.Close()
		}
	}

	for g := 0; g < numThreads; g++ {
		start := g * hashesPerThread
		end := (g + 1) * (hashesPerThread)
		// workaround for trivial runs with b.N = 1
		if start >= b.N {
			start = 0
		}
		if end >= b.N {
			end = b.N
		}
		// handle the remaining blobs
		if g == numThreads-1 {
			end = b.N
		}
		// b.Logf("%d: %d %d", b.N, start, end)
		go func(start int, end int) {
			defer wgp.Done()
			for i := start; i < end; i++ {
				action := handler.processIncomingTxn(network.IncomingMessage{Data: blobs[i]})
				require.Equal(b, network.OutgoingMessage{Action: network.Ignore}, action)
			}
		}(start, end)
	}
	wgp.Wait()

	return finalize
}

func benchTxHandlerProcessIncomingTxnConsume(b *testing.B, handler *TxHandler, numTxnsPerGroup int, avgDelay time.Duration, statsCh chan<- [3]int) benchFinalize {
	droppedStart := getNumBacklogDropped()
	dupStart := getNumRawMsgDup()
	// start consumer
	var wg sync.WaitGroup
	wg.Add(1)
	go func(statsCh chan<- [3]int) {
		defer wg.Done()
		received := 0
		dropped := getNumBacklogDropped() - droppedStart
		dups := getNumRawMsgDup() - dupStart
		for dups+dropped+received < b.N {
			select {
			case msg := <-handler.backlogQueue:
				require.Equal(b, numTxnsPerGroup, len(msg.unverifiedTxGroup))
				received++
			default:
				dropped = getNumBacklogDropped() - droppedStart
				dups = getNumRawMsgDup() - dupStart
			}
			if avgDelay > 0 {
				time.Sleep(avgDelay)
			}
		}
		statsCh <- [3]int{dropped, received, dups}
	}(statsCh)

	return func() {
		wg.Wait()
	}
}

// BenchmarkTxHandlerProcessIncomingTxn16 is the same BenchmarkTxHandlerProcessIncomingTxn with 16 goroutines
func BenchmarkTxHandlerProcessIncomingTxn16(b *testing.B) {
	deadlockDisable := deadlock.Opts.Disable
	deadlock.Opts.Disable = true
	defer func() {
		deadlock.Opts.Disable = deadlockDisable
	}()

	const nuThreads = 16
	const numTxnsPerGroup = 16
	handler := makeTestTxHandlerOrphaned(txBacklogSize)
	// uncomment to benchmark no-dedup version
	// handler.cacheConfig = txHandlerConfig{}

	// prepare tx groups
	blobs := make([][]byte, b.N)
	stxns := make([][]transactions.SignedTxn, b.N)
	for i := 0; i < b.N; i++ {
		stxns[i], blobs[i] = makeRandomTransactions(numTxnsPerGroup)
	}

	statsCh := make(chan [3]int, 1)
	defer close(statsCh)
	finConsume := benchTxHandlerProcessIncomingTxnConsume(b, handler, numTxnsPerGroup, 0, statsCh)

	// submit tx groups
	b.ResetTimer()
	finalizeSubmit := benchTxHandlerProcessIncomingTxnSubmit(b, handler, blobs, nuThreads)

	finalizeSubmit()
	finConsume()
}

// BenchmarkTxHandlerProcessIncomingTxnDup checks txn receiving with duplicates
// simulating processing delay
func BenchmarkTxHandlerProcessIncomingTxnDup(b *testing.B) {
	deadlockDisable := deadlock.Opts.Disable
	deadlock.Opts.Disable = true
	defer func() {
		deadlock.Opts.Disable = deadlockDisable
	}()

	// parameters
	const numTxnsPerGroup = 16
	const dupeFactor = 4
	const numThreads = 16
	const workerProcTime = 10 * time.Microsecond
	numPoolWorkers := runtime.NumCPU()
	avgDelay := workerProcTime / time.Duration(numPoolWorkers)

	handler := makeTestTxHandlerOrphaned(txBacklogSize)
	// uncomment to benchmark no-dedup version
	// handler.cacheConfig = txHandlerConfig{enableFilteringRawMsg: true, enableFilteringCanonical: false}
	// handler.cacheConfig = txHandlerConfig{}

	// prepare tx groups
	blobs := make([][]byte, b.N)
	stxns := make([][]transactions.SignedTxn, b.N)
	for i := 0; i < b.N; i += dupeFactor {
		stxns[i], blobs[i] = makeRandomTransactions(numTxnsPerGroup)
		if b.N >= dupeFactor { // skip trivial runs
			for j := 1; j < dupeFactor; j++ {
				if i+j < b.N {
					stxns[i+j], blobs[i+j] = stxns[i], blobs[i]
				}
			}
		}
	}

	statsCh := make(chan [3]int, 1)
	defer close(statsCh)

	finConsume := benchTxHandlerProcessIncomingTxnConsume(b, handler, numTxnsPerGroup, avgDelay, statsCh)

	// submit tx groups
	b.ResetTimer()
	finalizeSubmit := benchTxHandlerProcessIncomingTxnSubmit(b, handler, blobs, numThreads)

	finalizeSubmit()
	finConsume()

	stats := <-statsCh
	b.Logf("dropped %d, received %d, dups %d", stats[0], stats[1], stats[2])
}

func TestTxHandlerProcessIncomingGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type T struct {
		inputSize  int
		numDecoded int
	}
	var checks = []T{}
	for i := 1; i <= config.MaxTxGroupSize; i++ {
		checks = append(checks, T{i, i})
	}
	for i := 1; i < 10; i++ {
		checks = append(checks, T{config.MaxTxGroupSize + i, config.MaxTxGroupSize})
	}

	for _, check := range checks {
		t.Run(fmt.Sprintf("%d-%d", check.inputSize, check.numDecoded), func(t *testing.T) {
			handler := TxHandler{
				backlogQueue: make(chan *txBacklogMsg, 1),
			}
			stxns, blob := makeRandomTransactions(check.inputSize)
			action := handler.processIncomingTxn(network.IncomingMessage{Data: blob})
			require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
			msg := <-handler.backlogQueue
			require.Equal(t, check.numDecoded, len(msg.unverifiedTxGroup))
			for i := 0; i < check.numDecoded; i++ {
				require.Equal(t, stxns[i], msg.unverifiedTxGroup[i])
			}
		})
	}
}

func TestTxHandlerProcessIncomingCensoring(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	craftNonCanonical := func(t *testing.T, stxn *transactions.SignedTxn, blobStxn []byte) []byte {
		// make non-canonical encoding and ensure it is not accepted
		stxnNonCanTxn := transactions.SignedTxn{Txn: stxn.Txn}
		blobTxn := protocol.Encode(&stxnNonCanTxn)
		stxnNonCanAuthAddr := transactions.SignedTxn{AuthAddr: stxn.AuthAddr}
		blobAuthAddr := protocol.Encode(&stxnNonCanAuthAddr)
		stxnNonCanAuthSig := transactions.SignedTxn{Sig: stxn.Sig}
		blobSig := protocol.Encode(&stxnNonCanAuthSig)

		if blobStxn == nil {
			blobStxn = protocol.Encode(stxn)
		}

		// double check our skills for transactions.SignedTxn creation by creating a new canonical encoding and comparing to the original
		blobValidation := make([]byte, 0, len(blobTxn)+len(blobAuthAddr)+len(blobSig))
		blobValidation = append(blobValidation[:], blobAuthAddr...)
		blobValidation = append(blobValidation[:], blobSig[1:]...) // cut transactions.SignedTxn's field count
		blobValidation = append(blobValidation[:], blobTxn[1:]...) // cut transactions.SignedTxn's field count
		blobValidation[0] += 2                                     // increase field count
		require.Equal(t, blobStxn, blobValidation)

		// craft non-canonical
		blobNonCan := make([]byte, 0, len(blobTxn)+len(blobAuthAddr)+len(blobSig))
		blobNonCan = append(blobNonCan[:], blobTxn...)
		blobNonCan = append(blobNonCan[:], blobAuthAddr[1:]...) // cut transactions.SignedTxn's field count
		blobNonCan = append(blobNonCan[:], blobSig[1:]...)      // cut transactions.SignedTxn's field count
		blobNonCan[0] += 2                                      // increase field count
		require.Len(t, blobNonCan, len(blobStxn))
		require.NotEqual(t, blobStxn, blobNonCan)
		return blobNonCan
	}

	forgeSig := func(t *testing.T, stxn *transactions.SignedTxn, blobStxn []byte) (transactions.SignedTxn, []byte) {
		stxnForged := *stxn
		crypto.RandBytes(stxnForged.Sig[:])
		blobForged := protocol.Encode(&stxnForged)
		require.NotEqual(t, blobStxn, blobForged)
		return stxnForged, blobForged
	}

	encodeGroup := func(t *testing.T, g []transactions.SignedTxn, blobRef []byte) []byte {
		result := make([]byte, 0, len(blobRef))
		for i := 0; i < len(g); i++ {
			enc := protocol.Encode(&g[i])
			result = append(result, enc...)
		}
		require.NotEqual(t, blobRef, result)
		return result
	}

	t.Run("single", func(t *testing.T) {
		handler := makeTestTxHandlerOrphaned(txBacklogSize)
		stxns, blob := makeRandomTransactions(1)
		stxn := stxns[0]
		action := handler.processIncomingTxn(network.IncomingMessage{Data: blob})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		msg := <-handler.backlogQueue
		require.Equal(t, 1, len(msg.unverifiedTxGroup))
		require.Equal(t, stxn, msg.unverifiedTxGroup[0])

		// forge signature, ensure accepted
		stxnForged, blobForged := forgeSig(t, &stxn, blob)
		action = handler.processIncomingTxn(network.IncomingMessage{Data: blobForged})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		msg = <-handler.backlogQueue
		require.Equal(t, 1, len(msg.unverifiedTxGroup))
		require.Equal(t, stxnForged, msg.unverifiedTxGroup[0])

		// make non-canonical encoding and ensure it is not accepted
		blobNonCan := craftNonCanonical(t, &stxn, blob)
		action = handler.processIncomingTxn(network.IncomingMessage{Data: blobNonCan})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		require.Len(t, handler.backlogQueue, 0)
	})

	t.Run("group", func(t *testing.T) {
		handler := makeTestTxHandlerOrphaned(txBacklogSize)
		num := rand.Intn(config.MaxTxGroupSize-1) + 2 // 2..config.MaxTxGroupSize
		require.LessOrEqual(t, num, config.MaxTxGroupSize)
		stxns, blob := makeRandomTransactions(num)
		action := handler.processIncomingTxn(network.IncomingMessage{Data: blob})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		msg := <-handler.backlogQueue
		require.Equal(t, num, len(msg.unverifiedTxGroup))
		for i := 0; i < num; i++ {
			require.Equal(t, stxns[i], msg.unverifiedTxGroup[i])
		}

		// swap two txns
		i := rand.Intn(num / 2)
		j := rand.Intn(num-num/2) + num/2
		require.Less(t, i, j)
		swapped := make([]transactions.SignedTxn, num)
		copied := copy(swapped, stxns)
		require.Equal(t, num, copied)
		swapped[i], swapped[j] = swapped[j], swapped[i]
		blobSwapped := encodeGroup(t, swapped, blob)
		action = handler.processIncomingTxn(network.IncomingMessage{Data: blobSwapped})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		require.Len(t, handler.backlogQueue, 1)
		msg = <-handler.backlogQueue
		require.Equal(t, num, len(msg.unverifiedTxGroup))
		for i := 0; i < num; i++ {
			require.Equal(t, swapped[i], msg.unverifiedTxGroup[i])
		}

		// forge signature, ensure accepted
		i = rand.Intn(num)
		forged := make([]transactions.SignedTxn, num)
		copied = copy(forged, stxns)
		require.Equal(t, num, copied)
		crypto.RandBytes(forged[i].Sig[:])
		blobForged := encodeGroup(t, forged, blob)
		action = handler.processIncomingTxn(network.IncomingMessage{Data: blobForged})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		require.Len(t, handler.backlogQueue, 1)
		msg = <-handler.backlogQueue
		require.Equal(t, num, len(msg.unverifiedTxGroup))
		for i := 0; i < num; i++ {
			require.Equal(t, forged[i], msg.unverifiedTxGroup[i])
		}

		// make non-canonical encoding and ensure it is not accepted
		i = rand.Intn(num)
		nonCan := make([]transactions.SignedTxn, num)
		copied = copy(nonCan, stxns)
		require.Equal(t, num, copied)
		blobNonCan := make([]byte, 0, len(blob))
		for j := 0; j < num; j++ {
			enc := protocol.Encode(&nonCan[j])
			if j == i {
				enc = craftNonCanonical(t, &stxns[j], enc)
			}
			blobNonCan = append(blobNonCan, enc...)
		}
		require.Len(t, blobNonCan, len(blob))
		require.NotEqual(t, blob, blobNonCan)
		action = handler.processIncomingTxn(network.IncomingMessage{Data: blobNonCan})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		require.Len(t, handler.backlogQueue, 0)
	})
}

// makeTestTxHandlerOrphaned creates a tx handler without any backlog consumer.
// It is caller responsibility to run a consumer thread.
func makeTestTxHandlerOrphaned(backlogSize int) *TxHandler {
	return makeTestTxHandlerOrphanedWithContext(context.Background(), txBacklogSize, 0)
}

func makeTestTxHandlerOrphanedWithContext(ctx context.Context, backlogSize int, refreshInterval time.Duration) *TxHandler {
	if backlogSize <= 0 {
		backlogSize = txBacklogSize
	}
	return &TxHandler{
		backlogQueue:     make(chan *txBacklogMsg, backlogSize),
		msgCache:         makeSaltedCache(ctx, txBacklogSize, refreshInterval),
		txCanonicalCache: makeDigestCache(txBacklogSize),
		cacheConfig:      txHandlerConfig{true, true},
	}
}

func makeTestTxHandler(dl *Ledger, cfg config.Local) *TxHandler {
	tp := pools.MakeTransactionPool(dl.Ledger, cfg, logging.Base())
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	opts := TxHandlerOpts{
		tp, backlogPool, dl, &mocks.MockNetwork{}, "", crypto.Digest{}, cfg,
	}
	return MakeTxHandler(opts)
}

func TestTxHandlerProcessIncomingCache(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	handler := makeTestTxHandlerOrphaned(20)

	var action network.OutgoingMessage
	var msg *txBacklogMsg

	// double enqueue a single txn message, ensure it discarded
	stxns1, blob1 := makeRandomTransactions(1)
	require.Equal(t, 1, len(stxns1))

	action = handler.processIncomingTxn(network.IncomingMessage{Data: blob1})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 1, len(handler.backlogQueue))
	action = handler.processIncomingTxn(network.IncomingMessage{Data: blob1})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 1, len(handler.backlogQueue))
	msg = <-handler.backlogQueue
	require.Equal(t, 1, len(msg.unverifiedTxGroup))
	require.Equal(t, stxns1[0], msg.unverifiedTxGroup[0])

	// double enqueue a two txns message
	stxns2, blob2 := makeRandomTransactions(2)
	require.Equal(t, 2, len(stxns2))

	action = handler.processIncomingTxn(network.IncomingMessage{Data: blob2})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 1, len(handler.backlogQueue))
	action = handler.processIncomingTxn(network.IncomingMessage{Data: blob2})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 1, len(handler.backlogQueue))
	msg = <-handler.backlogQueue
	require.Equal(t, 2, len(msg.unverifiedTxGroup))
	require.Equal(t, stxns2[0], msg.unverifiedTxGroup[0])
	require.Equal(t, stxns2[1], msg.unverifiedTxGroup[1])

	// now combine seen and not seen txns, ensure the group is still enqueued
	stxns3, _ := makeRandomTransactions(2)
	require.Equal(t, 2, len(stxns3))
	stxns3[1] = stxns1[0]

	var blob3 []byte
	for i := range stxns3 {
		encoded := protocol.Encode(&stxns3[i])
		blob3 = append(blob3, encoded...)
	}
	require.Greater(t, len(blob3), 0)
	action = handler.processIncomingTxn(network.IncomingMessage{Data: blob3})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 1, len(handler.backlogQueue))
	msg = <-handler.backlogQueue
	require.Equal(t, 2, len(msg.unverifiedTxGroup))
	require.Equal(t, stxns3[0], msg.unverifiedTxGroup[0])
	require.Equal(t, stxns3[1], msg.unverifiedTxGroup[1])

	// check a combo from two different seen groups, ensure the group is still enqueued
	stxns4 := make([]transactions.SignedTxn, 2)
	stxns4[0] = stxns2[0]
	stxns4[1] = stxns3[0]
	var blob4 []byte
	for i := range stxns4 {
		encoded := protocol.Encode(&stxns4[i])
		blob4 = append(blob4, encoded...)
	}
	require.Greater(t, len(blob4), 0)
	action = handler.processIncomingTxn(network.IncomingMessage{Data: blob4})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 1, len(handler.backlogQueue))
	msg = <-handler.backlogQueue
	require.Equal(t, 2, len(msg.unverifiedTxGroup))
	require.Equal(t, stxns4[0], msg.unverifiedTxGroup[0])
	require.Equal(t, stxns4[1], msg.unverifiedTxGroup[1])
}

func TestTxHandlerProcessIncomingCacheRotation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	stxns1, blob1 := makeRandomTransactions(1)
	require.Equal(t, 1, len(stxns1))

	resetCanonical := func(handler *TxHandler) {
		handler.txCanonicalCache.swap()
		handler.txCanonicalCache.swap()
	}

	t.Run("scheduled", func(t *testing.T) {
		// double enqueue a single txn message, ensure it discarded
		ctx, cancelFunc := context.WithCancel(context.Background())
		handler := makeTestTxHandlerOrphanedWithContext(ctx, txBacklogSize, 10*time.Millisecond)

		var action network.OutgoingMessage
		var msg *txBacklogMsg

		action = handler.processIncomingTxn(network.IncomingMessage{Data: blob1})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		require.Equal(t, 1, len(handler.backlogQueue))
		resetCanonical(handler)
		action = handler.processIncomingTxn(network.IncomingMessage{Data: blob1})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		require.Equal(t, 1, len(handler.backlogQueue))
		msg = <-handler.backlogQueue
		require.Equal(t, 1, len(msg.unverifiedTxGroup))
		require.Equal(t, stxns1[0], msg.unverifiedTxGroup[0])
		cancelFunc()
	})

	t.Run("manual", func(t *testing.T) {
		// double enqueue a single txn message, ensure it discarded
		handler := makeTestTxHandlerOrphaned(txBacklogSize)
		var action network.OutgoingMessage
		var msg *txBacklogMsg

		action = handler.processIncomingTxn(network.IncomingMessage{Data: blob1})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		require.Equal(t, 1, len(handler.backlogQueue))
		resetCanonical(handler)
		action = handler.processIncomingTxn(network.IncomingMessage{Data: blob1})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		require.Equal(t, 1, len(handler.backlogQueue))
		msg = <-handler.backlogQueue
		require.Equal(t, 1, len(msg.unverifiedTxGroup))
		require.Equal(t, stxns1[0], msg.unverifiedTxGroup[0])

		// rotate once, ensure the txn still there
		handler.msgCache.remix()
		resetCanonical(handler)
		action = handler.processIncomingTxn(network.IncomingMessage{Data: blob1})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		require.Equal(t, 0, len(handler.backlogQueue))

		// rotate twice, ensure the txn done
		handler.msgCache.remix()
		resetCanonical(handler)
		action = handler.processIncomingTxn(network.IncomingMessage{Data: blob1})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		require.Equal(t, 1, len(handler.backlogQueue))
		resetCanonical(handler)
		action = handler.processIncomingTxn(network.IncomingMessage{Data: blob1})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		require.Equal(t, 1, len(handler.backlogQueue))
		msg = <-handler.backlogQueue
		require.Equal(t, 1, len(msg.unverifiedTxGroup))
		require.Equal(t, stxns1[0], msg.unverifiedTxGroup[0])
	})

}

const benchTxnNum = 25_000

func BenchmarkTxHandlerDecoder(b *testing.B) {
	_, blob := makeRandomTransactions(benchTxnNum)
	var err error
	stxns := make([]transactions.SignedTxn, benchTxnNum+1)
	for i := 0; i < b.N; i++ {
		dec := protocol.NewDecoderBytes(blob)
		var idx int
		for {
			err = dec.Decode(&stxns[idx])
			if err == io.EOF {
				break
			}
			require.NoError(b, err)
			idx++
		}
		require.Equal(b, benchTxnNum, idx)
	}
}

func BenchmarkTxHandlerDecoderMsgp(b *testing.B) {
	_, blob := makeRandomTransactions(benchTxnNum)
	var err error
	stxns := make([]transactions.SignedTxn, benchTxnNum+1)
	for i := 0; i < b.N; i++ {
		dec := protocol.NewMsgpDecoderBytes(blob)
		var idx int
		for {
			err = dec.Decode(&stxns[idx])
			if err == io.EOF {
				break
			}
			require.NoError(b, err)
			idx++
		}
		require.Equal(b, benchTxnNum, idx)
	}
}

func TestIncomingTxHandle(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	incomingTxHandlerProcessing(1, t)
}

func TestIncomingTxGroupHandle(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	incomingTxHandlerProcessing(proto.MaxTxGroupSize, t)
}

// incomingTxHandlerProcessing is a comprehensive transaction handling test
// It handles the singed transactions by passing them to the backlog for verification
func incomingTxHandlerProcessing(maxGroupSize int, t *testing.T) {
	const numUsers = 100
	numberOfTransactionGroups := 1000
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)
	addresses := make([]basics.Address, numUsers)
	secrets := make([]*crypto.SignatureSecrets, numUsers)

	// prepare the accounts
	genesis := make(map[basics.Address]basics.AccountData)
	for i := 0; i < numUsers; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
		genesis[addr] = basics.AccountData{
			Status:     basics.Online,
			MicroAlgos: basics.MicroAlgos{Raw: 10000000000000},
		}
	}
	genesis[poolAddr] = basics.AccountData{
		Status:     basics.NotParticipating,
		MicroAlgos: basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinBalance},
	}

	require.Equal(t, len(genesis), numUsers+1)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	ledgerName := fmt.Sprintf("%s-mem-%d", t.Name(), numberOfTransactionGroups)
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, nil, cfg)
	require.NoError(t, err)

	l := ledger
	handler := makeTestTxHandler(l, cfg)

	// since Start is not called, set the context here
	handler.ctx, handler.ctxCancel = context.WithCancel(context.Background())
	defer handler.ctxCancel()

	outChan := make(chan *txBacklogMsg, 10)
	wg := sync.WaitGroup{}
	wg.Add(1)
	// Make a test backlog worker, which is similar to backlogWorker, but sends the results
	// through the outChan instead of passing it to postProcessCheckedTxn
	go func() {
		defer wg.Done()
		defer close(outChan)
		for {
			// prioritize the postVerificationQueue
			select {
			case wi, ok := <-handler.postVerificationQueue:
				if !ok {
					return
				}
				outChan <- wi
				// restart the loop so that we could empty out the post verification queue.
				continue
			default:
			}

			// we have no more post verification items. wait for either backlog queue item or post verification item.
			select {
			case wi, ok := <-handler.backlogQueue:
				if !ok {
					// shut down to end the test
					handler.txVerificationPool.Shutdown()
					close(handler.postVerificationQueue)
					// wait until all the pending responses are obtained.
					// this is not in backlogWorker, maybe should be
					for wi := range handler.postVerificationQueue {
						outChan <- wi
					}
					return
				}
				if handler.checkAlreadyCommitted(wi) {
					// this is not expected during the test
					continue
				}

				// enqueue the task to the verification pool.
				handler.txVerificationPool.EnqueueBacklog(handler.ctx, handler.asyncVerifySignature, wi, nil)

			case wi, ok := <-handler.postVerificationQueue:
				if !ok {
					return
				}
				outChan <- wi

			case <-handler.ctx.Done():
				return
			}
		}
	}()

	// Prepare the transactions
	signedTransactionGroups, badTxnGroups :=
		makeSignedTxnGroups(numberOfTransactionGroups, numUsers, maxGroupSize, 0.5, addresses, secrets)
	encodedSignedTransactionGroups := make([]network.IncomingMessage, 0, numberOfTransactionGroups)
	for _, stxngrp := range signedTransactionGroups {
		data := make([]byte, 0)
		for _, stxn := range stxngrp {
			data = append(data, protocol.Encode(&stxn)...)
		}
		encodedSignedTransactionGroups =
			append(encodedSignedTransactionGroups, network.IncomingMessage{Data: data})
	}

	// Process the results and make sure they are correct
	wg.Add(1)
	go func() {
		defer wg.Done()
		groupCounter := 0
		txnCounter := 0
		invalidCounter := 0
		defer func() {
			t.Logf("processed %d txn groups (%d txns)\n", groupCounter, txnCounter)
		}()
		for wi := range outChan {
			txnCounter = txnCounter + len(wi.unverifiedTxGroup)
			groupCounter++
			u, _ := binary.Uvarint(wi.unverifiedTxGroup[0].Txn.Note)
			_, inBad := badTxnGroups[u]
			if wi.verificationErr == nil {
				require.False(t, inBad, "No error for invalid signature")
			} else {
				invalidCounter++
				require.True(t, inBad, "Error for good signature")
			}
		}
		t.Logf("Txn groups with invalid sigs: %d\n", invalidCounter)
	}()

	// Send the transactions to the verifier
	for _, tg := range encodedSignedTransactionGroups {
		handler.processIncomingTxn(tg)
		randduration := time.Duration(uint64(((1 + rand.Float32()) * 3)))
		time.Sleep(randduration * time.Microsecond)
	}
	close(handler.backlogQueue)
	wg.Wait()

	// Report the number of transactions dropped because the backlog was busy
	var buf strings.Builder
	metrics.DefaultRegistry().WriteMetrics(&buf, "")
	str := buf.String()
	x := strings.Index(str, "\nalgod_transaction_messages_dropped_backlog")
	str = str[x+44 : x+44+strings.Index(str[x+44:], "\n")]
	str = strings.TrimSpace(strings.ReplaceAll(str, "}", " "))
	t.Logf("dropped %s txn gropus\n", str)
}

// makeSignedTxnGroups prepares N transaction groups of random (maxGroupSize) sizes with random
// invalid signatures of a given probability (invalidProb)
func makeSignedTxnGroups(N, numUsers, maxGroupSize int, invalidProb float32, addresses []basics.Address,
	secrets []*crypto.SignatureSecrets) (ret [][]transactions.SignedTxn,
	badTxnGroups map[uint64]interface{}) {
	badTxnGroups = make(map[uint64]interface{})

	protoMaxGrpSize := proto.MaxTxGroupSize
	ret = make([][]transactions.SignedTxn, 0, N)
	for u := 0; u < N; u++ {
		grpSize := rand.Intn(protoMaxGrpSize-1) + 1
		if grpSize > maxGroupSize {
			grpSize = maxGroupSize
		}
		var txGroup transactions.TxGroup
		txns := make([]transactions.Transaction, 0, grpSize)
		for g := 0; g < grpSize; g++ {
			// generate transactions
			noteField := make([]byte, binary.MaxVarintLen64)
			binary.PutUvarint(noteField, uint64(u))
			tx := transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender:      addresses[(u+g)%numUsers],
					Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
					FirstValid:  0,
					LastValid:   basics.Round(proto.MaxTxnLife),
					GenesisHash: genesisHash,
					Note:        noteField,
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: addresses[(u+g+1)%numUsers],
					Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance + (rand.Uint64() % 10000)},
				},
			}
			txGroup.TxGroupHashes = append(txGroup.TxGroupHashes, crypto.Digest(tx.ID()))
			txns = append(txns, tx)
		}
		groupHash := crypto.HashObj(txGroup)
		signedTxGroup := make([]transactions.SignedTxn, 0, grpSize)
		for g, txn := range txns {
			txn.Group = groupHash
			signedTx := txn.Sign(secrets[(u+g)%numUsers])
			signedTx.Txn = txn
			signedTxGroup = append(signedTxGroup, signedTx)
		}
		// randomly make bad signatures
		if rand.Float32() < invalidProb {
			tinGrp := rand.Intn(grpSize)
			signedTxGroup[tinGrp].Sig[0] = signedTxGroup[tinGrp].Sig[0] + 1
			badTxnGroups[uint64(u)] = struct{}{}
		}
		ret = append(ret, signedTxGroup)
	}
	return
}

// BenchmarkHandler sends singed transactions the the verifier
func BenchmarkHandleTxns(b *testing.B) {
	b.N = b.N * proto.MaxTxGroupSize / 2
	runHandlerBenchmark(1, b)
}

// BenchmarkHandler sends signed transaction groups to the verifier
func BenchmarkHandleTxnGroups(b *testing.B) {
	runHandlerBenchmark(proto.MaxTxGroupSize, b)
}

// runHandlerBenchmark has a similar workflow to incomingTxHandlerProcessing,
// but bypasses the backlog, and sends the transactions directly to the verifier
func runHandlerBenchmark(maxGroupSize int, b *testing.B) {
	const numUsers = 100
	log := logging.TestingLog(b)
	log.SetLevel(logging.Warn)
	addresses := make([]basics.Address, numUsers)
	secrets := make([]*crypto.SignatureSecrets, numUsers)

	// prepare the accounts
	genesis := make(map[basics.Address]basics.AccountData)
	for i := 0; i < numUsers; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
		genesis[addr] = basics.AccountData{
			Status:     basics.Online,
			MicroAlgos: basics.MicroAlgos{Raw: 10000000000000},
		}
	}
	genesis[poolAddr] = basics.AccountData{
		Status:     basics.NotParticipating,
		MicroAlgos: basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinBalance},
	}

	require.Equal(b, len(genesis), numUsers+1)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	ledgerName := fmt.Sprintf("%s-mem-%d", b.Name(), b.N)
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, nil, cfg)
	require.NoError(b, err)

	l := ledger
	handler := makeTestTxHandler(l, cfg)
	// since Start is not called, set the context here
	handler.ctx, handler.ctxCancel = context.WithCancel(context.Background())
	defer handler.ctxCancel()

	// Prepare the transactions
	signedTransactionGroups, badTxnGroups := makeSignedTxnGroups(b.N, numUsers, maxGroupSize, 0.001, addresses, secrets)
	outChan := handler.postVerificationQueue
	wg := sync.WaitGroup{}

	var tt time.Time
	// Process the results and make sure they are correct
	wg.Add(1)
	go func() {
		defer wg.Done()
		groupCounter := 0
		var txnCounter uint64
		invalidCounter := 0
		for wi := range outChan {
			txnCounter = txnCounter + uint64(len(wi.unverifiedTxGroup))
			groupCounter++
			u, _ := binary.Uvarint(wi.unverifiedTxGroup[0].Txn.Note)
			_, inBad := badTxnGroups[u]
			if wi.verificationErr == nil {
				require.False(b, inBad, "No error for invalid signature")
			} else {
				invalidCounter++
				require.True(b, inBad, "Error for good signature")
			}
		}
		if txnCounter > 0 {
			b.Logf("TPS: %d\n", uint64(txnCounter)*1000000000/uint64(time.Since(tt)))
			b.Logf("Time/txn: %d(microsec)\n", uint64((time.Since(tt)/time.Microsecond))/txnCounter)
			b.Logf("processed total: [%d groups (%d invalid)] [%d txns]\n", groupCounter, invalidCounter, txnCounter)
		}
	}()

	b.ResetTimer()
	tt = time.Now()
	for _, stxngrp := range signedTransactionGroups {
		blm := txBacklogMsg{rawmsg: nil, unverifiedTxGroup: stxngrp}
		handler.txVerificationPool.EnqueueBacklog(handler.ctx, handler.asyncVerifySignature, &blm, nil)
	}
	// shut down to end the test
	handler.txVerificationPool.Shutdown()
	close(handler.postVerificationQueue)
	close(handler.backlogQueue)
	wg.Wait()
}

func TestTxHandlerPostProcessError(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	collect := func() map[string]float64 {
		// collect all specific error reason metrics except TxGroupErrorReasonNotWellFormed,
		// it is tested in TestPostProcessErrorWithVerify
		result := map[string]float64{}
		transactionMessagesTxnSigVerificationFailed.AddMetric(result)
		transactionMessagesAlreadyCommitted.AddMetric(result)
		transactionMessagesTxGroupInvalidFee.AddMetric(result)
		// transactionMessagesTxnNotWellFormed.AddMetric(result)
		transactionMessagesTxnSigNotWellFormed.AddMetric(result)
		transactionMessagesTxnMsigNotWellFormed.AddMetric(result)
		transactionMessagesTxnLogicSig.AddMetric(result)
		return result
	}
	var txh TxHandler

	errSome := errors.New("some error")
	txh.postProcessReportErrors(errSome)
	result := collect()
	require.Len(t, result, 0)
	transactionMessagesBacklogErr.AddMetric(result)
	require.Len(t, result, 1)

	counter := 0
	for i := verify.TxGroupErrorReasonGeneric; i <= verify.TxGroupErrorReasonLogicSigFailed; i++ {
		if i == verify.TxGroupErrorReasonNotWellFormed {
			// skip TxGroupErrorReasonNotWellFormed, tested in TestPostProcessErrorWithVerify.
			// the test uses global metric counters, skipping makes the test deterministic
			continue
		}

		errTxGroup := &verify.ErrTxGroupError{Reason: i}
		txh.postProcessReportErrors(errTxGroup)
		result = collect()
		if i == verify.TxGroupErrorReasonSigNotWellFormed {
			// TxGroupErrorReasonSigNotWellFormed and TxGroupErrorReasonHasNoSig increment the same metric
			counter--
			require.Equal(t, result[metrics.TransactionMessagesTxnSigNotWellFormed.Name], float64(2))
		}
		require.Len(t, result, counter)
		counter++
	}

	// there are one less metrics than number of tracked values,
	// plus one generic non-tracked value, plus skipped TxGroupErrorReasonNotWellFormed
	const expected = int(verify.TxGroupErrorReasonNumValues) - 3
	require.Len(t, result, expected)

	errVerify := crypto.ErrBatchVerificationFailed
	txh.postProcessReportErrors(errVerify)
	result = collect()
	require.Len(t, result, expected+1)
}

func TestTxHandlerPostProcessErrorWithVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	txn := transactions.Transaction{}
	stxn := transactions.SignedTxn{Txn: txn}

	hdr := bookkeeping.BlockHeader{
		UpgradeState: bookkeeping.UpgradeState{
			CurrentProtocol: protocol.ConsensusCurrentVersion,
		},
	}
	_, err := verify.TxnGroup([]transactions.SignedTxn{stxn}, hdr, nil, nil)
	var txGroupErr *verify.ErrTxGroupError
	require.ErrorAs(t, err, &txGroupErr)

	result := map[string]float64{}
	transactionMessagesTxnNotWellFormed.AddMetric(result)
	require.Len(t, result, 0)

	var txh TxHandler
	txh.postProcessReportErrors(err)
	transactionMessagesTxnNotWellFormed.AddMetric(result)
	require.Len(t, result, 1)
}
