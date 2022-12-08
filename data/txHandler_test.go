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

func makeTestGenesisAccounts(tb require.TestingT, numUsers int) ([]basics.Address, []*crypto.SignatureSecrets, map[basics.Address]basics.AccountData) {
	addresses := make([]basics.Address, numUsers)
	secrets := make([]*crypto.SignatureSecrets, numUsers)
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

	require.Equal(tb, len(genesis), numUsers+1)
	return addresses, secrets, genesis
}

func BenchmarkTxHandlerProcessing(b *testing.B) {
	const numUsers = 100
	log := logging.TestingLog(b)
	log.SetLevel(logging.Warn)

	addresses, secrets, genesis := makeTestGenesisAccounts(b, numUsers)
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
	//t.Parallel()

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
	//t.Parallel()

	require.Equal(t, 1, ipow(10, 0))
	require.Equal(t, 10, ipow(10, 1))
	require.Equal(t, 100, ipow(10, 2))
	require.Equal(t, 8, ipow(2, 3))
}

func getNumBacklogDropped() int {
	return int(transactionMessagesDroppedFromBacklog.GetUint64Value())
}

func getNumRawMsgDup() int {
	return int(transactionMessagesDupRawMsg.GetUint64Value())
}

func getNumCanonicalDup() int {
	return int(transactionMessagesDupCanonical.GetUint64Value())
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

func benchTxHandlerProcessIncomingTxnConsume(b *testing.B, handler *TxHandler, numTxnsPerGroup int, avgDelay time.Duration, statsCh chan<- [4]int) benchFinalize {
	droppedStart := getNumBacklogDropped()
	dupStart := getNumRawMsgDup()
	cdupStart := getNumCanonicalDup()
	// start consumer
	var wg sync.WaitGroup
	wg.Add(1)
	go func(statsCh chan<- [4]int) {
		defer wg.Done()
		received := 0
		dropped := getNumBacklogDropped() - droppedStart
		dups := getNumRawMsgDup() - dupStart
		cdups := getNumCanonicalDup() - cdupStart
		for dups+dropped+received+cdups < b.N {
			select {
			case msg := <-handler.backlogQueue:
				require.Equal(b, numTxnsPerGroup, len(msg.unverifiedTxGroup))
				received++
			default:
				dropped = getNumBacklogDropped() - droppedStart
				dups = getNumRawMsgDup() - dupStart
				cdups = getNumCanonicalDup() - cdupStart
			}
			if avgDelay > 0 {
				time.Sleep(avgDelay)
			}
		}
		statsCh <- [4]int{dropped, received, dups, cdups}
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

	const numSendThreads = 16
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

	statsCh := make(chan [4]int, 1)
	defer close(statsCh)
	finConsume := benchTxHandlerProcessIncomingTxnConsume(b, handler, numTxnsPerGroup, 0, statsCh)

	// submit tx groups
	b.ResetTimer()
	finalizeSubmit := benchTxHandlerProcessIncomingTxnSubmit(b, handler, blobs, numSendThreads)

	finalizeSubmit()
	finConsume()
}

// BenchmarkTxHandlerIncDeDup checks txn receiving with duplicates
// simulating processing delay
func BenchmarkTxHandlerIncDeDup(b *testing.B) {
	deadlockDisable := deadlock.Opts.Disable
	deadlock.Opts.Disable = true
	defer func() {
		deadlock.Opts.Disable = deadlockDisable
	}()

	// parameters
	const numSendThreads = 16
	const numTxnsPerGroup = 16

	var tests = []struct {
		dedup          bool
		dupFactor      int
		workerDelay    time.Duration
		firstLevelOnly bool
	}{
		{false, 4, 10 * time.Microsecond, false},
		{true, 4, 10 * time.Microsecond, false},
		{false, 8, 10 * time.Microsecond, false},
		{true, 8, 10 * time.Microsecond, false},
		{false, 4, 4 * time.Microsecond, false},
		{true, 4, 4 * time.Microsecond, false},
		{false, 4, 0, false},
		{true, 4, 0, false},
		{true, 4, 10 * time.Microsecond, true},
	}

	for _, test := range tests {
		var name string
		var enabled string = "Y"
		if !test.dedup {
			enabled = "N"
		}
		name = fmt.Sprintf("x%d/on=%s/delay=%v", test.dupFactor, enabled, test.workerDelay)
		if test.firstLevelOnly {
			name = fmt.Sprintf("%s/one-level", name)
		}
		b.Run(name, func(b *testing.B) {
			numPoolWorkers := runtime.NumCPU()
			dupFactor := test.dupFactor
			avgDelay := test.workerDelay / time.Duration(numPoolWorkers)

			handler := makeTestTxHandlerOrphaned(txBacklogSize)
			if test.firstLevelOnly {
				handler.cacheConfig = txHandlerConfig{enableFilteringRawMsg: true, enableFilteringCanonical: false}
			} else if !test.dedup {
				handler.cacheConfig = txHandlerConfig{}
			}

			// prepare tx groups
			blobs := make([][]byte, b.N)
			stxns := make([][]transactions.SignedTxn, b.N)
			for i := 0; i < b.N; i += dupFactor {
				stxns[i], blobs[i] = makeRandomTransactions(numTxnsPerGroup)
				if b.N >= dupFactor { // skip trivial runs
					for j := 1; j < dupFactor; j++ {
						if i+j < b.N {
							stxns[i+j], blobs[i+j] = stxns[i], blobs[i]
						}
					}
				}
			}

			statsCh := make(chan [4]int, 1)
			defer close(statsCh)

			finConsume := benchTxHandlerProcessIncomingTxnConsume(b, handler, numTxnsPerGroup, avgDelay, statsCh)

			// submit tx groups
			b.ResetTimer()
			finalizeSubmit := benchTxHandlerProcessIncomingTxnSubmit(b, handler, blobs, numSendThreads)

			finalizeSubmit()
			finConsume()

			stats := <-statsCh
			unique := b.N / dupFactor
			dropped := stats[0]
			received := stats[1]
			dups := stats[2]
			cdups := stats[3]
			b.ReportMetric(float64(received)/float64(unique)*100, "ack,%")
			b.ReportMetric(float64(dropped)/float64(b.N)*100, "drop,%")
			if test.dedup {
				b.ReportMetric(float64(dups)/float64(b.N)*100, "trap,%")
			}
			if b.N > 1 && os.Getenv("DEBUG") != "" {
				b.Logf("unique %d, dropped %d, received %d, dups %d", unique, dropped, received, dups)
				if cdups > 0 {
					b.Logf("canonical dups %d vs %d recv", cdups, received)
				}
			}
		})
	}
}

func TestTxHandlerProcessIncomingGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	//t.Parallel()

	type T struct {
		inputSize  int
		numDecoded int
		action     network.ForwardingPolicy
	}
	var checks = []T{}
	for i := 1; i <= config.MaxTxGroupSize; i++ {
		checks = append(checks, T{i, i, network.Ignore})
	}
	for i := 1; i < 10; i++ {
		checks = append(checks, T{config.MaxTxGroupSize + i, 0, network.Disconnect})
	}

	for _, check := range checks {
		t.Run(fmt.Sprintf("%d-%d", check.inputSize, check.numDecoded), func(t *testing.T) {
			handler := TxHandler{
				backlogQueue: make(chan *txBacklogMsg, 1),
			}
			stxns, blob := makeRandomTransactions(check.inputSize)
			action := handler.processIncomingTxn(network.IncomingMessage{Data: blob})
			require.Equal(t, network.OutgoingMessage{Action: check.action}, action)
			if check.numDecoded > 0 {
				msg := <-handler.backlogQueue
				require.Equal(t, check.numDecoded, len(msg.unverifiedTxGroup))
				for i := 0; i < check.numDecoded; i++ {
					require.Equal(t, stxns[i], msg.unverifiedTxGroup[i])
				}
			} else {
				require.Len(t, handler.backlogQueue, 0)
			}
		})
	}
}

func TestTxHandlerProcessIncomingCensoring(t *testing.T) {
	partitiontest.PartitionTest(t)
	//t.Parallel()

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
	return makeTestTxHandlerOrphanedWithContext(context.Background(), txBacklogSize, txBacklogSize, 0)
}

func makeTestTxHandlerOrphanedWithContext(ctx context.Context, backlogSize int, cacheSize int, refreshInterval time.Duration) *TxHandler {
	if backlogSize <= 0 {
		backlogSize = txBacklogSize
	}
	if cacheSize <= 0 {
		cacheSize = txBacklogSize
	}
	return &TxHandler{
		backlogQueue:     make(chan *txBacklogMsg, backlogSize),
		msgCache:         makeSaltedCache(ctx, cacheSize, refreshInterval),
		txCanonicalCache: makeDigestCache(cacheSize),
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
	//t.Parallel()

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
	//t.Parallel()

	stxns1, blob1 := makeRandomTransactions(1)
	require.Equal(t, 1, len(stxns1))

	resetCanonical := func(handler *TxHandler) {
		handler.txCanonicalCache.swap()
		handler.txCanonicalCache.swap()
	}

	t.Run("scheduled", func(t *testing.T) {
		// double enqueue a single txn message, ensure it discarded
		ctx, cancelFunc := context.WithCancel(context.Background())
		handler := makeTestTxHandlerOrphanedWithContext(ctx, txBacklogSize, txBacklogSize, 10*time.Millisecond)

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
		handler.msgCache.Remix()
		resetCanonical(handler)
		action = handler.processIncomingTxn(network.IncomingMessage{Data: blob1})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
		require.Equal(t, 0, len(handler.backlogQueue))

		// rotate twice, ensure the txn done
		handler.msgCache.Remix()
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

// TestTxHandlerProcessIncomingCacheBacklogDrop checks if dropped messages are also removed from caches
func TestTxHandlerProcessIncomingCacheBacklogDrop(t *testing.T) {
	partitiontest.PartitionTest(t)
	//t.Parallel()

	handler := makeTestTxHandlerOrphanedWithContext(context.Background(), 1, 20, 0)

	stxns1, blob1 := makeRandomTransactions(1)
	require.Equal(t, 1, len(stxns1))

	action := handler.processIncomingTxn(network.IncomingMessage{Data: blob1})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 1, len(handler.backlogQueue))
	require.Equal(t, 1, handler.msgCache.Len())
	require.Equal(t, 1, handler.txCanonicalCache.Len())

	stxns2, blob2 := makeRandomTransactions(1)
	require.Equal(t, 1, len(stxns2))

	initialValue := transactionMessagesDroppedFromBacklog.GetUint64Value()
	action = handler.processIncomingTxn(network.IncomingMessage{Data: blob2})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 1, len(handler.backlogQueue))
	require.Equal(t, 1, handler.msgCache.Len())
	require.Equal(t, 1, handler.txCanonicalCache.Len())
	currentValue := transactionMessagesDroppedFromBacklog.GetUint64Value()
	require.Equal(t, initialValue+1, currentValue)
}

func TestTxHandlerProcessIncomingCacheTxPoolDrop(t *testing.T) {
	partitiontest.PartitionTest(t)

	const numUsers = 100
	log := logging.TestingLog(t)

	// prepare the accounts
	addresses, secrets, genesis := makeTestGenesisAccounts(t, numUsers)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	ledgerName := fmt.Sprintf("%s-mem", t.Name())
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, nil, cfg)
	require.NoError(t, err)

	l := ledger
	handler := makeTestTxHandler(l, cfg)
	handler.postVerificationQueue = make(chan *txBacklogMsg)

	makeTxns := func(sendIdx, recvIdx int) ([]transactions.SignedTxn, []byte) {
		tx := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:     addresses[sendIdx],
				Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
				FirstValid: 0,
				LastValid:  basics.Round(proto.MaxTxnLife),
				Note:       make([]byte, 2),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: addresses[recvIdx],
				Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance + (rand.Uint64() % 10000)},
			},
		}
		signedTx := tx.Sign(secrets[sendIdx])
		blob := protocol.Encode(&signedTx)
		return []transactions.SignedTxn{signedTx}, blob
	}

	stxns, blob := makeTxns(1, 2)

	action := handler.processIncomingTxn(network.IncomingMessage{Data: blob})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 1, len(handler.backlogQueue))
	require.Equal(t, 1, handler.msgCache.Len())
	require.Equal(t, 1, handler.txCanonicalCache.Len())

	msg := <-handler.backlogQueue
	require.Equal(t, 1, len(msg.unverifiedTxGroup))
	require.Equal(t, stxns, msg.unverifiedTxGroup)

	initialCount := transactionMessagesDroppedFromPool.GetUint64Value()
	handler.asyncVerifySignature(msg)
	currentCount := transactionMessagesDroppedFromPool.GetUint64Value()
	require.Equal(t, initialCount+1, currentCount)
	require.Equal(t, 0, handler.msgCache.Len())
	require.Equal(t, 0, handler.txCanonicalCache.Len())
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

// TestTxHandlerIncomingTxHandle checks the correctness with single txns
func TestTxHandlerIncomingTxHandle(t *testing.T) {
	partitiontest.PartitionTest(t)

	numberOfTransactionGroups := 1000
	incomingTxHandlerProcessing(1, numberOfTransactionGroups, t)
}

// TestTxHandlerIncomingTxGroupHandle checks the correctness with txn groups
func TestTxHandlerIncomingTxGroupHandle(t *testing.T) {
	partitiontest.PartitionTest(t)

	numberOfTransactionGroups := 1000 / proto.MaxTxGroupSize
	incomingTxHandlerProcessing(proto.MaxTxGroupSize, numberOfTransactionGroups, t)
}

// TestTxHandlerIncomingTxHandleDrops accounts for the dropped txns when the verifier/exec pool is saturated
func TestTxHandlerIncomingTxHandleDrops(t *testing.T) {
	partitiontest.PartitionTest(t)

	// use smaller backlog size to test the message drops
	origValue := txBacklogSize
	defer func() {
		txBacklogSize = origValue
	}()
	txBacklogSize = 10

	numberOfTransactionGroups := 1000
	incomingTxHandlerProcessing(1, numberOfTransactionGroups, t)
}

// incomingTxHandlerProcessing is a comprehensive transaction handling test
// It handles the singed transactions by passing them to the backlog for verification
func incomingTxHandlerProcessing(maxGroupSize, numberOfTransactionGroups int, t *testing.T) {
	defer func() {
		// reset the counters
		transactionMessagesDroppedFromBacklog = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromBacklog)
		transactionMessagesDroppedFromPool = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromPool)
	}()

	const numUsers = 100
	log := logging.TestingLog(t)

	// prepare the accounts
	addresses, secrets, genesis := makeTestGenesisAccounts(t, numUsers)
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
	initDroppedBacklog, initDroppedPool := getDropped()
	wg.Add(1)
	go func() {
		defer wg.Done()
		var groupCounter uint64
		txnCounter := 0
		invalidCounter := 0
		var droppedBacklog, droppedPool uint64
		defer func() {
			t.Logf("Txn groups with invalid sigs: %d\n", invalidCounter)
			t.Logf("dropped: [%d backlog] [%d pool]\n", droppedBacklog, droppedPool)
			// release the backlog worker
			t.Logf("processed %d txn groups (%d txns)\n", groupCounter, txnCounter)
			handler.Stop() // cancel the handler ctx
		}()
		timer := time.NewTicker(250 * time.Millisecond)
		for {
			select {
			case wi := <-outChan:
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
			case <-timer.C:
				droppedBacklog, droppedPool = getDropped()
				if int(groupCounter+(droppedBacklog-initDroppedBacklog)+(droppedPool-initDroppedPool)) == len(signedTransactionGroups) {
					// all the benchmark txns processed
					return
				}
				time.Sleep(250 * time.Millisecond)
				timer.Reset(250 * time.Millisecond)
			}
		}
	}()

	// Send the transactions to the verifier
	for _, tg := range encodedSignedTransactionGroups {
		handler.processIncomingTxn(tg)
	}
	wg.Wait()
}

func getDropped() (droppedBacklog, droppedPool uint64) {
	droppedBacklog = transactionMessagesDroppedFromBacklog.GetUint64Value()
	droppedPool = transactionMessagesDroppedFromPool.GetUint64Value()
	return
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
			if grpSize > 1 {
				txGroup.TxGroupHashes = append(txGroup.TxGroupHashes, crypto.Digest(tx.ID()))
			}
			txns = append(txns, tx)
		}
		groupHash := crypto.HashObj(txGroup)
		signedTxGroup := make([]transactions.SignedTxn, 0, grpSize)
		for g, txn := range txns {
			if grpSize > 1 {
				txn.Group = groupHash
			}
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

// BenchmarkHandleTxns sends signed transactions directly to the verifier
func BenchmarkHandleTxns(b *testing.B) {
	maxGroupSize := 1
	tpss := []int{6000000, 600000, 60000, 6000}
	invalidRates := []float32{0.5, 0.001}
	for _, tps := range tpss {
		for _, ivr := range invalidRates {
			b.Run(fmt.Sprintf("tps_%d_inv_%.3f", tps, ivr), func(b *testing.B) {
				runHandlerBenchmarkWithBacklog(maxGroupSize, tps, ivr, b, false)
			})
		}
	}
}

// BenchmarkHandleTxnGroups sends signed transaction groups directly to the verifier
func BenchmarkHandleTxnGroups(b *testing.B) {
	maxGroupSize := proto.MaxTxGroupSize / 2
	tpss := []int{6000000, 600000, 60000, 6000}
	invalidRates := []float32{0.5, 0.001}
	for _, tps := range tpss {
		for _, ivr := range invalidRates {
			b.Run(fmt.Sprintf("tps_%d_inv_%.3f", tps, ivr), func(b *testing.B) {
				runHandlerBenchmarkWithBacklog(maxGroupSize, tps, ivr, b, false)
			})
		}
	}
}

// BenchmarkBacklogWorkerHandleTxns sends signed transactions to the verifier
// using a backlog worker replica
func BenchmarkHandleBLWTxns(b *testing.B) {
	maxGroupSize := 1
	tpss := []int{6000000, 600000, 60000, 6000}
	invalidRates := []float32{0.5, 0.001}
	for _, tps := range tpss {
		for _, ivr := range invalidRates {
			b.Run(fmt.Sprintf("tps_%d_inv_%.3f", tps, ivr), func(b *testing.B) {
				runHandlerBenchmarkWithBacklog(maxGroupSize, tps, ivr, b, true)
			})
		}
	}
}

// BenchmarkBacklogWorkerHandleTxnGroups sends signed transaction groups to the verifier
// using a backlog worker replica
func BenchmarkHandleBLWTxnGroups(b *testing.B) {
	maxGroupSize := proto.MaxTxGroupSize / 2
	tpss := []int{6000000, 600000, 60000, 6000}
	invalidRates := []float32{0.5, 0.001}
	for _, tps := range tpss {
		for _, ivr := range invalidRates {
			b.Run(fmt.Sprintf("tps_%d_inv_%.3f", tps, ivr), func(b *testing.B) {
				runHandlerBenchmarkWithBacklog(maxGroupSize, tps, ivr, b, true)
			})
		}
	}
}

// runHandlerBenchmarkWithBacklog benchmarks the number of transactions verfied or dropped
func runHandlerBenchmarkWithBacklog(maxGroupSize, tps int, invalidRate float32, b *testing.B, useBacklogWorker bool) {
	defer func() {
		// reset the counters
		transactionMessagesDroppedFromBacklog = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromBacklog)
		transactionMessagesDroppedFromPool = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromPool)
	}()

	const numUsers = 100
	log := logging.TestingLog(b)
	log.SetLevel(logging.Warn)

	addresses, secrets, genesis := makeTestGenesisAccounts(b, numUsers)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	ivrString := strings.IndexAny(fmt.Sprintf("%f", invalidRate), "1")
	ledgerName := fmt.Sprintf("%s-mem-%d-%d", b.Name(), b.N, ivrString)
	ledgerName = strings.Replace(ledgerName, "#", "-", 1)
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

	testResultChan := handler.postVerificationQueue
	wg := sync.WaitGroup{}

	if useBacklogWorker {
		wg.Add(1)
		testResultChan = make(chan *txBacklogMsg, 10)
		// Make a test backlog worker, which is similar to backlogWorker, but sends the results
		// through the testResultChan instead of passing it to postProcessCheckedTxn
		go func() {
			defer wg.Done()
			for {
				// prioritize the postVerificationQueue
				select {
				case wi, ok := <-handler.postVerificationQueue:
					if !ok {
						return
					}
					testResultChan <- wi

					// restart the loop so that we could empty out the post verification queue.
					continue
				default:
				}

				// we have no more post verification items. wait for either backlog queue item or post verification item.
				select {
				case wi, ok := <-handler.backlogQueue:
					if !ok {
						return
					}
					if handler.checkAlreadyCommitted(wi) {
						// this is not expected during the test
						continue
					}
					handler.txVerificationPool.EnqueueBacklog(handler.ctx, handler.asyncVerifySignature, wi, nil)

				case wi, ok := <-handler.postVerificationQueue:
					if !ok {
						return
					}
					testResultChan <- wi

				case <-handler.ctx.Done():
					return
				}
			}
		}()
	}

	// Prepare the transactions
	signedTransactionGroups, badTxnGroups := makeSignedTxnGroups(b.N, numUsers, maxGroupSize, invalidRate, addresses, secrets)
	var encodedSignedTransactionGroups []network.IncomingMessage
	if useBacklogWorker {
		encodedSignedTransactionGroups = make([]network.IncomingMessage, 0, b.N)
		for _, stxngrp := range signedTransactionGroups {
			data := make([]byte, 0)
			for _, stxn := range stxngrp {
				data = append(data, protocol.Encode(&stxn)...)
			}
			encodedSignedTransactionGroups =
				append(encodedSignedTransactionGroups, network.IncomingMessage{Data: data})
		}
	}

	var tt time.Time
	// Process the results and make sure they are correct
	rateAdjuster := time.Second / time.Duration(tps)
	wg.Add(1)
	go func() {
		defer wg.Done()
		groupCounter := uint64(0)
		var txnCounter uint64
		invalidCounter := 0
		defer func() {
			if groupCounter > 1 {
				droppedBacklog, droppedPool := getDropped()
				b.Logf("Input T(grp)PS: %d (delay %f microsec)", tps, float64(rateAdjuster)/float64(time.Microsecond))
				b.Logf("Verified TPS: %d", uint64(txnCounter)*uint64(time.Second)/uint64(time.Since(tt)))
				b.Logf("Time/txn: %d(microsec)", uint64((time.Since(tt)/time.Microsecond))/txnCounter)
				b.Logf("processed total: [%d groups (%d invalid)] [%d txns]", groupCounter, invalidCounter, txnCounter)
				b.Logf("dropped: [%d backlog] [%d pool]\n", droppedBacklog, droppedPool)
			}
			handler.Stop() // cancel the handler ctx
		}()
		stopChan := make(chan interface{})
		go func() {
			for {
				time.Sleep(200 * time.Millisecond)
				droppedBacklog, droppedPool := getDropped()
				if int(groupCounter+droppedBacklog+droppedPool) == len(signedTransactionGroups) {
					// all the benchmark txns processed
					close(stopChan)
					return
				}
			}
		}()

		for {
			select {
			case wi := <-testResultChan:
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
				if groupCounter == uint64(len(signedTransactionGroups)) {
					// all the benchmark txns processed
					return
				}
			case <-stopChan:
				return
			}
		}
	}()

	b.ResetTimer()
	tt = time.Now()
	if useBacklogWorker {
		for _, tg := range encodedSignedTransactionGroups {
			handler.processIncomingTxn(tg)
			time.Sleep(rateAdjuster)
		}
	} else {
		for _, stxngrp := range signedTransactionGroups {
			blm := txBacklogMsg{rawmsg: nil, unverifiedTxGroup: stxngrp}
			handler.txVerificationPool.EnqueueBacklog(handler.ctx, handler.asyncVerifySignature, &blm, nil)
			time.Sleep(rateAdjuster)
		}
	}
	wg.Wait()
	handler.Stop() // cancel the handler ctx
}

func TestTxHandlerPostProcessError(t *testing.T) {
	partitiontest.PartitionTest(t)
	//t.Parallel()

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
	//t.Parallel()

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
