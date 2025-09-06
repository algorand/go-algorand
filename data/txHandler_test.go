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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/config/bounds"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/pools"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-algorand/util/metrics"
)

// txHandler uses config values to determine backlog size. Tests should use a static value
var txBacklogSize = config.GetDefaultLocal().TxBacklogSize

// mock sender is used to implement OnClose, since TXHandlers expect to use Senders and ERL Clients
type mockSender struct{}

func (m mockSender) OnClose(func())                 {}
func (m mockSender) GetNetwork() network.GossipNode { panic("not implemented") }

func (m mockSender) IPAddr() []byte      { return nil }
func (m mockSender) RoutingAddr() []byte { return nil }

// txHandlerConfig is a subset of tx handler related options from config.Local
type txHandlerConfig struct {
	enableFilteringRawMsg    bool
	enableFilteringCanonical bool
}

func makeTestGenesisAccounts(tb testing.TB, numUsers int) ([]basics.Address, []*crypto.SignatureSecrets, map[basics.Address]basics.AccountData) {
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
	cfg.TxBacklogReservedCapacityPerPeer = 1
	cfg.IncomingConnectionsLimit = 10
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, cfg)
	require.NoError(b, err)
	defer ledger.Close()

	l := ledger

	cfg.TxPoolSize = 75000
	cfg.EnableProcessBlockStats = false
	txHandler, err := makeTestTxHandler(l, cfg)
	require.NoError(b, err)
	defer txHandler.txVerificationPool.Shutdown()
	defer close(txHandler.streamVerifierDropped)

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
			verify.TxnGroup(signedTransactionGroups[i], &hdr, vtc, l)
		}
	})
}

// vtCache is a noop VerifiedTransactionCache
type vtCache struct{}

func (vtCache) Add(txgroup []transactions.SignedTxn, groupCtx *verify.GroupContext) {}
func (vtCache) AddPayset(txgroup [][]transactions.SignedTxn, groupCtxs []*verify.GroupContext) {
	return
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
	action := handler.processIncomingTxn(network.IncomingMessage{Data: blob, Sender: mockSender{}})
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

// BenchmarkTxHandlerProcessIncomingLogicTxn16 is similar to BenchmarkTxHandlerProcessIncomingTxn16
// but with logicsig groups of 4 txns
func BenchmarkTxHandlerProcessIncomingLogicTxn16(b *testing.B) {
	deadlockDisable := deadlock.Opts.Disable
	deadlock.Opts.Disable = true
	defer func() {
		deadlock.Opts.Disable = deadlockDisable
	}()

	const numSendThreads = 16
	handler := makeTestTxHandlerOrphaned(txBacklogSize)

	// prepare tx groups
	blobs := make([][]byte, b.N)
	stxns := make([][]transactions.SignedTxn, b.N)
	for i := 0; i < b.N; i++ {
		txns := txntest.CreateTinyManTxGroup(b, true)
		stxns[i], _ = txntest.CreateTinyManSignedTxGroup(b, txns)
		var blob []byte
		for j := range stxns[i] {
			encoded := protocol.Encode(&stxns[i][j])
			blob = append(blob, encoded...)
		}
		blobs[i] = blob
	}
	numTxnsPerGroup := len(stxns[0])

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
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var handler *TxHandler
			if test.firstLevelOnly {
				handler = makeTestTxHandlerOrphanedWithContext(
					ctx, txBacklogSize, txBacklogSize,
					txHandlerConfig{enableFilteringRawMsg: true, enableFilteringCanonical: false}, 0,
				)
			} else if !test.dedup {
				handler = makeTestTxHandlerOrphanedWithContext(
					ctx, txBacklogSize, 0,
					txHandlerConfig{}, 0,
				)
			} else {
				handler = makeTestTxHandlerOrphanedWithContext(
					ctx, txBacklogSize, txBacklogSize,
					txHandlerConfig{enableFilteringRawMsg: true, enableFilteringCanonical: true}, 0,
				)
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
	t.Parallel()

	type T struct {
		inputSize  int
		numDecoded int
		action     network.ForwardingPolicy
	}
	var checks = []T{}
	for i := 1; i <= bounds.MaxTxGroupSize; i++ {
		checks = append(checks, T{i, i, network.Ignore})
	}
	for i := 1; i < 10; i++ {
		checks = append(checks, T{bounds.MaxTxGroupSize + i, 0, network.Disconnect})
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

func craftNonCanonical(t *testing.T, stxn *transactions.SignedTxn, blobStxn []byte) []byte {
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

func TestTxHandlerProcessIncomingCensoring(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
		handler := makeTestTxHandlerOrphanedWithContext(context.Background(), txBacklogSize, txBacklogSize, txHandlerConfig{true, true}, 0)
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
		handler := makeTestTxHandlerOrphanedWithContext(context.Background(), txBacklogSize, txBacklogSize, txHandlerConfig{true, true}, 0)
		num := rand.Intn(bounds.MaxTxGroupSize-1) + 2 // 2..bounds.MaxTxGroupSize
		require.LessOrEqual(t, num, bounds.MaxTxGroupSize)
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
	return makeTestTxHandlerOrphanedWithContext(context.Background(), backlogSize, backlogSize, txHandlerConfig{true, false}, 0)
}

func makeTestTxHandlerOrphanedWithContext(ctx context.Context, backlogSize int, cacheSize int, txHandlerConfig txHandlerConfig, refreshInterval time.Duration) *TxHandler {
	if backlogSize <= 0 {
		backlogSize = txBacklogSize
	}
	if cacheSize <= 0 {
		cacheSize = txBacklogSize
	}
	handler := &TxHandler{
		backlogQueue: make(chan *txBacklogMsg, backlogSize),
	}

	if txHandlerConfig.enableFilteringRawMsg {
		handler.msgCache = makeSaltedCache(cacheSize)
		handler.msgCache.Start(ctx, refreshInterval)
	}
	if txHandlerConfig.enableFilteringCanonical {
		handler.txCanonicalCache = makeDigestCache(cacheSize)
	}

	return handler
}

func makeTestTxHandler(dl *Ledger, cfg config.Local) (*TxHandler, error) {
	tp := pools.MakeTransactionPool(dl.Ledger, cfg, logging.Base(), nil)
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	opts := TxHandlerOpts{
		tp, backlogPool, dl, &mocks.MockNetwork{}, cfg,
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
		defer cancelFunc()

		handler := makeTestTxHandlerOrphanedWithContext(ctx, txBacklogSize, txBacklogSize, txHandlerConfig{true, true}, 10*time.Millisecond)

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
	})

	t.Run("manual", func(t *testing.T) {
		// double enqueue a single txn message, ensure it discarded
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		handler := makeTestTxHandlerOrphanedWithContext(ctx, txBacklogSize, txBacklogSize, txHandlerConfig{true, true}, 10*time.Millisecond)

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

	handler := makeTestTxHandlerOrphanedWithContext(context.Background(), 1, 20, txHandlerConfig{true, true}, 0)

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

func makeTxns(addresses []basics.Address, secrets []*crypto.SignatureSecrets, sendIdx, recvIdx int, gh crypto.Digest) ([]transactions.SignedTxn, []byte) {
	note := make([]byte, 2)
	crypto.RandBytes(note)
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[sendIdx],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        note,
			GenesisHash: gh,
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

func TestTxHandlerProcessIncomingCacheTxPoolDrop(t *testing.T) {
	partitiontest.PartitionTest(t)

	const numUsers = 100
	log := logging.TestingLog(t)
	log.SetLevel(logging.Panic)

	// prepare the accounts
	addresses, secrets, genesis := makeTestGenesisAccounts(t, numUsers)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	ledgerName := fmt.Sprintf("%s-mem", t.Name())
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	cfg.EnableTxBacklogRateLimiting = false
	cfg.TxIncomingFilteringFlags = 3 // txFilterRawMsg + txFilterCanonical
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, cfg)
	require.NoError(t, err)
	defer ledger.Close()

	l := ledger
	handler, err := makeTestTxHandler(l, cfg)
	require.NoError(t, err)
	defer handler.txVerificationPool.Shutdown()
	defer close(handler.streamVerifierDropped)

	// saturate the postVerificationQueue
loop:
	for {
		select {
		case handler.postVerificationQueue <- &verify.VerificationResult{}:
		default:
			break loop
		}
	}

	stxns, blob := makeTxns(addresses, secrets, 1, 2, genesisHash)

	action := handler.processIncomingTxn(network.IncomingMessage{Data: blob})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 1, len(handler.backlogQueue))
	require.Equal(t, 1, handler.msgCache.Len())
	require.Equal(t, 1, handler.txCanonicalCache.Len())

	msg := <-handler.backlogQueue
	require.Equal(t, 1, len(msg.unverifiedTxGroup))
	require.Equal(t, stxns, msg.unverifiedTxGroup)

	initialCount := transactionMessagesDroppedFromPool.GetUint64Value()

	// emulate handler.Start() without the backlog
	handler.ctx, handler.ctxCancel = context.WithCancel(context.Background())
	handler.streamVerifier.Start(handler.ctx)
	defer handler.streamVerifier.WaitForStop()
	defer handler.ctxCancel()
	handler.streamVerifierChan <- &verify.UnverifiedTxnSigJob{
		TxnGroup: msg.unverifiedTxGroup, BacklogMessage: msg}
	var currentCount uint64
	for x := 0; x < 1000; x++ {
		currentCount = transactionMessagesDroppedFromPool.GetUint64Value()
		if currentCount > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
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
func TestTxHandlerIncomingTxHandle(t *testing.T) { //nolint:paralleltest // Not parallel because incomingTxHandlerProcessing mutates global metrics
	partitiontest.PartitionTest(t)

	numberOfTransactionGroups := 1000
	incomingTxHandlerProcessing(1, numberOfTransactionGroups, t)
}

// TestTxHandlerIncomingTxGroupHandle checks the correctness with txn groups
func TestTxHandlerIncomingTxGroupHandle(t *testing.T) { //nolint:paralleltest // Not parallel because incomingTxHandlerProcessing mutates global metrics
	partitiontest.PartitionTest(t)

	numberOfTransactionGroups := 1000 / proto.MaxTxGroupSize
	incomingTxHandlerProcessing(proto.MaxTxGroupSize, numberOfTransactionGroups, t)
}

// TestTxHandlerIncomingTxHandleDrops accounts for the dropped txns when the verifier/exec pool is saturated
func TestTxHandlerIncomingTxHandleDrops(t *testing.T) { //nolint:paralleltest // Not parallel because it changes the backlog size
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
	// reset the counters
	transactionMessagesDroppedFromBacklog = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromBacklog)
	transactionMessagesDroppedFromPool = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromPool)

	const numUsers = 100
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)

	// prepare the accounts
	addresses, secrets, genesis := makeTestGenesisAccounts(t, numUsers)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	ledgerName := fmt.Sprintf("%s-mem-%d", t.Name(), numberOfTransactionGroups)
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	cfg.EnableTxBacklogRateLimiting = false
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, cfg)
	require.NoError(t, err)
	defer ledger.Close()

	handler, err := makeTestTxHandler(ledger, cfg)
	require.NoError(t, err)
	defer handler.txVerificationPool.Shutdown()
	defer close(handler.streamVerifierDropped)

	// since Start is not called, set the context here
	handler.ctx, handler.ctxCancel = context.WithCancel(context.Background())
	defer handler.ctxCancel()

	// emulate handler.Start() without the backlog
	handler.ctx, handler.ctxCancel = context.WithCancel(context.Background())
	handler.streamVerifier.Start(handler.ctx)

	testResultChan := make(chan *txBacklogMsg, 10)
	wg := sync.WaitGroup{}
	wg.Add(1)
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
				txBLMsg := wi.BacklogMessage.(*txBacklogMsg)
				txBLMsg.verificationErr = wi.Err
				testResultChan <- txBLMsg

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
				handler.streamVerifierChan <- &verify.UnverifiedTxnSigJob{TxnGroup: wi.unverifiedTxGroup, BacklogMessage: wi}
			case wi, ok := <-handler.postVerificationQueue:
				if !ok {
					return
				}
				txBLMsg := wi.BacklogMessage.(*txBacklogMsg)
				txBLMsg.verificationErr = wi.Err
				testResultChan <- txBLMsg

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
			append(encodedSignedTransactionGroups, network.IncomingMessage{Data: data, Sender: mockSender{}})
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
			case wi := <-testResultChan:
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

func getTransaction(sender, receiver basics.Address, u int) transactions.Transaction {
	noteField := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(noteField, uint64(u))

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			GenesisHash: genesisHash,
			Note:        noteField,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance + (rand.Uint64() % 10000)},
		},
	}
	return tx
}

func getTransactionGroups(N, numUsers, maxGroupSize int, addresses []basics.Address) [][]transactions.Transaction {
	txnGrps := make([][]transactions.Transaction, N)
	protoMaxGrpSize := proto.MaxTxGroupSize
	for u := 0; u < N; u++ {
		grpSize := min(rand.Intn(protoMaxGrpSize-1)+1, maxGroupSize)
		var txGroup transactions.TxGroup
		txns := make([]transactions.Transaction, 0, grpSize)
		for g := 0; g < grpSize; g++ {
			// generate transactions
			tx := getTransaction(addresses[(u+g)%numUsers], addresses[(u+g+1)%numUsers], u)
			if grpSize > 1 {
				txGroup.TxGroupHashes = append(txGroup.TxGroupHashes, crypto.Digest(tx.ID()))
			}
			txns = append(txns, tx)
		}
		if grpSize > 1 {
			groupHash := crypto.HashObj(txGroup)
			for t := range txns {
				txns[t].Group = groupHash
			}
		}
		txnGrps[u] = txns
	}
	return txnGrps
}

func signTransactionGroups(txnGroups [][]transactions.Transaction, secrets []*crypto.SignatureSecrets, invalidProb float32) (
	ret [][]transactions.SignedTxn, badTxnGroups map[uint64]interface{}) {
	numUsers := len(secrets)
	badTxnGroups = make(map[uint64]interface{})
	for tg := range txnGroups {
		grpSize := len(txnGroups[tg])
		signedTxGroup := make([]transactions.SignedTxn, 0, grpSize)
		for t := range txnGroups[tg] {
			signedTx := txnGroups[tg][t].Sign(secrets[(tg+t)%numUsers])
			signedTx.Txn = txnGroups[tg][t]
			signedTxGroup = append(signedTxGroup, signedTx)
		}
		// randomly make bad signatures
		if rand.Float32() < invalidProb {
			tinGrp := rand.Intn(grpSize)
			signedTxGroup[tinGrp].Sig[0] = signedTxGroup[tinGrp].Sig[0] + 1
			badTxnGroups[uint64(tg)] = struct{}{}
		}
		ret = append(ret, signedTxGroup)
	}
	return
}

func signMSigTransactionGroups(txnGroups [][]transactions.Transaction, secrets []*crypto.SignatureSecrets,
	invalidProb float32, msigSize int) (ret [][]transactions.SignedTxn, badTxnGroups map[uint64]interface{}, err error) {
	ret = make([][]transactions.SignedTxn, len(txnGroups))
	numUsers := len(secrets)
	badTxnGroups = make(map[uint64]interface{})
	badTxnGroupsMU := deadlock.Mutex{}
	// process them using multiple threads
	workers := make(chan interface{}, runtime.NumCPU()-1)
	wg := sync.WaitGroup{}
	errChan := make(chan error, 1)
	for tg := range txnGroups {
		wg.Add(1)
		workers <- struct{}{}
		go func(i int) {
			defer func() {
				wg.Done()
				<-workers
			}()
			msigVer := uint8(1)
			msigTHld := uint8(msigSize)
			pks := make([]crypto.PublicKey, msigSize)
			for x := 0; x < msigSize; x++ {
				pks[x] = secrets[(i+x)%numUsers].SignatureVerifier
			}
			multiSigAddr, err := crypto.MultisigAddrGen(msigVer, msigTHld, pks)
			if err != nil {
				select {
				case errChan <- err:
					return
				default:
					return
				}
			}
			grpSize := len(txnGroups[i])
			signedTxGroup := make([]transactions.SignedTxn, grpSize)
			sigsForTxn := make([]crypto.MultisigSig, msigTHld)

			for t := range txnGroups[i] {
				txnGroups[i][t].Sender = basics.Address(multiSigAddr)
				for s := range sigsForTxn {
					sig, err := crypto.MultisigSign(txnGroups[i][t], crypto.Digest(multiSigAddr), msigVer, msigTHld, pks, *secrets[(i+s)%numUsers])
					if err != nil {
						select {
						case errChan <- err:
							return
						default:
							return
						}
					}
					sigsForTxn[s] = sig
				}
				msig, err := crypto.MultisigAssemble(sigsForTxn)
				if err != nil {
					select {
					case errChan <- err:
						return
					default:
						return
					}
				}
				signedTxGroup[t].Txn = txnGroups[i][t]
				signedTxGroup[t].Msig = msig
			}
			// randomly make bad signatures
			if rand.Float32() < invalidProb {
				tinGrp := rand.Intn(grpSize)
				tinMsig := rand.Intn(len(signedTxGroup[tinGrp].Msig.Subsigs))
				signedTxGroup[tinGrp].Msig.Subsigs[tinMsig].Sig[0] = signedTxGroup[tinGrp].Msig.Subsigs[tinMsig].Sig[0] + 1
				badTxnGroupsMU.Lock()
				badTxnGroups[uint64(i)] = struct{}{}
				badTxnGroupsMU.Unlock()
			}
			ret[i] = signedTxGroup
		}(tg)
	}
	wg.Wait()
	close(errChan)
	err = <-errChan
	return
}

// makeSignedTxnGroups prepares N transaction groups of random (maxGroupSize) sizes with random
// invalid signatures of a given probability (invalidProb)
func makeSignedTxnGroups(N, numUsers, maxGroupSize int, invalidProb float32, addresses []basics.Address,
	secrets []*crypto.SignatureSecrets) (ret [][]transactions.SignedTxn,
	badTxnGroups map[uint64]interface{}) {

	txnGroups := getTransactionGroups(N, numUsers, maxGroupSize, addresses)
	ret, badTxnGroups = signTransactionGroups(txnGroups, secrets, invalidProb)
	return
}

const numBenchUsers = 512

// BenchmarkHandleTxns sends signed transactions directly to the verifier
func BenchmarkHandleTxns(b *testing.B) {
	maxGroupSize := 1
	invalidRates := []float32{0.5, 0.001}
	for _, ivr := range invalidRates {
		b.Run(fmt.Sprintf("inv_%.3f", ivr), func(b *testing.B) {
			txGen := makeSigGenerator(b, numBenchUsers, maxGroupSize, ivr)
			runHandlerBenchmarkWithBacklog(b, txGen, 0, false)
		})
	}
}

// BenchmarkHandleTxnGroups sends signed transaction groups directly to the verifier
func BenchmarkHandleTxnGroups(b *testing.B) {
	maxGroupSize := proto.MaxTxGroupSize / 2
	invalidRates := []float32{0.5, 0.001}
	for _, ivr := range invalidRates {
		b.Run(fmt.Sprintf("inv_%.3f", ivr), func(b *testing.B) {
			txGen := makeSigGenerator(b, numBenchUsers, maxGroupSize, ivr)
			runHandlerBenchmarkWithBacklog(b, txGen, 0, false)
		})
	}
}

// BenchmarkHandleMsigTxns sends signed transactions directly to the verifier
func BenchmarkHandleMsigTxns(b *testing.B) {
	maxGroupSize := 1
	msigSizes := []int{64, 16, 8, 4}
	invalidRates := []float32{0.5, 0.001}
	for _, msigSize := range msigSizes {
		for _, ivr := range invalidRates {
			b.Run(fmt.Sprintf("msigSize_%d_inv_%.3f", msigSize, ivr), func(b *testing.B) {
				txGen := makeMsigGenerator(b, numBenchUsers, maxGroupSize, ivr, msigSize)
				runHandlerBenchmarkWithBacklog(b, txGen, 0, false)
			})
		}
	}
}

// BenchmarkHandleTxnGroups sends signed transaction groups directly to the verifier
func BenchmarkHandleMsigTxnGroups(b *testing.B) {
	maxGroupSize := proto.MaxTxGroupSize / 2
	msigSizes := []int{64, 16, 8, 4}
	invalidRates := []float32{0.5, 0.001}
	for _, msigSize := range msigSizes {
		for _, ivr := range invalidRates {
			b.Run(fmt.Sprintf("msigSize_%d_inv_%.3f", msigSize, ivr), func(b *testing.B) {
				txGen := makeMsigGenerator(b, numBenchUsers, maxGroupSize, ivr, msigSize)
				runHandlerBenchmarkWithBacklog(b, txGen, 0, false)
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
				txGen := makeSigGenerator(b, numBenchUsers, maxGroupSize, ivr)
				runHandlerBenchmarkWithBacklog(b, txGen, tps, true)
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
				txGen := makeSigGenerator(b, numBenchUsers, maxGroupSize, ivr)
				runHandlerBenchmarkWithBacklog(b, txGen, tps, true)
			})
		}
	}
}

// BenchmarkHandleTxnGroups sends signed transaction groups directly to the verifier
func BenchmarkHandleLsigTxnGroups(b *testing.B) {
	maxGroupSize := proto.MaxTxGroupSize / 2
	invalidRates := []float32{0.5, 0.001}
	for _, ivr := range invalidRates {
		b.Run(fmt.Sprintf("lsig-inv_%.3f", ivr), func(b *testing.B) {
			txGen := makeLsigGenerator(b, numBenchUsers, maxGroupSize, ivr)
			runHandlerBenchmarkWithBacklog(b, txGen, 0, false)
		})
	}
}

type txGenIf interface {
	makeLedger(tb testing.TB, cfg config.Local, log logging.Logger, namePrefix string) *Ledger
	createSignedTxGroups(tb testing.TB, txgCount int) ([][]transactions.SignedTxn, map[uint64]interface{})
}

type txGenerator struct {
	numUsers     int
	maxGroupSize int
	invalidRate  float32

	addresses []basics.Address
	secrets   []*crypto.SignatureSecrets
	genesis   map[basics.Address]basics.AccountData
}

type sigGenerator struct {
	txGenerator
}

type msigGenerator struct {
	txGenerator
	msigSize int
}

type lsigGenerator struct {
	txGenerator
}

func makeTxGenerator(tb testing.TB, numUsers, maxGroupSize int, invalidRate float32) *txGenerator {
	addresses, secrets, genesis := makeTestGenesisAccounts(tb, numUsers)
	return &txGenerator{
		numUsers:     numUsers,
		maxGroupSize: maxGroupSize,
		invalidRate:  invalidRate,
		addresses:    addresses,
		secrets:      secrets,
		genesis:      genesis,
	}
}

func (g *txGenerator) makeLedger(tb testing.TB, cfg config.Local, log logging.Logger, namePrefix string) *Ledger {
	genBal := bookkeeping.MakeGenesisBalances(g.genesis, sinkAddr, poolAddr)
	ivrString := strings.IndexAny(fmt.Sprintf("%f", g.invalidRate), "1")
	ledgerName := fmt.Sprintf("%s-in_mem-w_inv=%d", namePrefix, ivrString)
	ledgerName = strings.Replace(ledgerName, "#", "-", 1)
	const inMem = true
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, cfg)
	require.NoError(tb, err)
	return ledger
}

func makeSigGenerator(tb testing.TB, numUsers, maxGroupSize int, invalidRate float32) *sigGenerator {
	return &sigGenerator{
		txGenerator: *makeTxGenerator(tb, numUsers, maxGroupSize, invalidRate),
	}
}

func (g *sigGenerator) createSignedTxGroups(tb testing.TB, txgCount int) ([][]transactions.SignedTxn, map[uint64]interface{}) {
	return makeSignedTxnGroups(txgCount, g.numUsers, g.maxGroupSize, g.invalidRate, g.addresses, g.secrets)
}

func makeMsigGenerator(tb testing.TB, numUsers, maxGroupSize int, invalidRate float32, msigSize int) *msigGenerator {
	return &msigGenerator{
		txGenerator: *makeTxGenerator(tb, numUsers, maxGroupSize, invalidRate),
		msigSize:    msigSize,
	}
}

func (g *msigGenerator) createSignedTxGroups(tb testing.TB, txgCount int) ([][]transactions.SignedTxn, map[uint64]interface{}) {
	txnGroups := getTransactionGroups(txgCount, g.numUsers, g.maxGroupSize, g.addresses)
	signedTransactionGroups, badTxnGroups, err := signMSigTransactionGroups(txnGroups, g.secrets, g.invalidRate, g.msigSize)
	require.NoError(tb, err)
	return signedTransactionGroups, badTxnGroups
}

func makeLsigGenerator(tb testing.TB, numUsers, maxGroupSize int, invalidRate float32) *lsigGenerator {
	return &lsigGenerator{
		txGenerator: *makeTxGenerator(tb, numUsers, maxGroupSize, invalidRate),
	}
}

func (g *lsigGenerator) createSignedTxGroups(tb testing.TB, txgCount int) ([][]transactions.SignedTxn, map[uint64]interface{}) {
	stxns := make([][]transactions.SignedTxn, txgCount)
	badTxnGroups := make(map[uint64]interface{})
	for i := 0; i < txgCount; i++ {
		txns := txntest.CreateTinyManTxGroup(tb, true)
		stxns[i], _ = txntest.CreateTinyManSignedTxGroup(tb, txns)

		// randomly make bad signatures
		if rand.Float32() < g.invalidRate {
			tinGrp := rand.Intn(len(txns))
			if stxns[i][tinGrp].Sig != (crypto.Signature{}) {
				stxns[i][tinGrp].Sig[0] = stxns[i][tinGrp].Sig[0] + 1
			} else {
				stxns[i][tinGrp].Lsig.Logic[0] = 255
			}
			badTxnGroups[uint64(i)] = struct{}{}
		}
	}
	return stxns, badTxnGroups
}

// runHandlerBenchmarkWithBacklog benchmarks the number of transactions verified or dropped
func runHandlerBenchmarkWithBacklog(b *testing.B, txGen txGenIf, tps int, useBacklogWorker bool) {
	defer func() {
		// reset the counters
		transactionMessagesDroppedFromBacklog = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromBacklog)
		transactionMessagesDroppedFromPool = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromPool)
	}()
	// reset the counters
	transactionMessagesDroppedFromBacklog = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromBacklog)
	transactionMessagesDroppedFromPool = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromPool)

	log := logging.TestingLog(b)
	log.SetLevel(logging.Warn)

	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	cfg.TxBacklogReservedCapacityPerPeer = 1
	cfg.IncomingConnectionsLimit = 10
	ledger := txGen.makeLedger(b, cfg, log, fmt.Sprintf("%s-%d", b.Name(), b.N))
	defer ledger.Close()

	// The benchmark generates only 1000 txns, and reuses them. This is done for faster benchmark time and the
	// ability to have long runs without being limited to the memory. The dedup will block the txns once the same
	// ones are rotated again. If the purpose is to test dedup, then this can be changed by setting
	// genTCount = b.N
	cfg.TxIncomingFilteringFlags = 0
	handler, err := makeTestTxHandler(ledger, cfg)
	require.NoError(b, err)
	defer handler.txVerificationPool.Shutdown()
	defer close(handler.streamVerifierDropped)

	// since Start is not called, set the context here
	handler.ctx, handler.ctxCancel = context.WithCancel(context.Background())
	defer handler.ctxCancel()

	// emulate handler.Start() without the backlog
	handler.ctx, handler.ctxCancel = context.WithCancel(context.Background())
	handler.streamVerifier.Start(handler.ctx)

	testResultChan := make(chan *txBacklogMsg, 10)
	wg := sync.WaitGroup{}

	if useBacklogWorker {
		wg.Add(1)
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
					txBLMsg := wi.BacklogMessage.(*txBacklogMsg)
					txBLMsg.verificationErr = wi.Err
					testResultChan <- txBLMsg

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
					handler.streamVerifierChan <- &verify.UnverifiedTxnSigJob{TxnGroup: wi.unverifiedTxGroup, BacklogMessage: wi}
				case wi, ok := <-handler.postVerificationQueue:
					if !ok {
						return
					}
					txBLMsg := wi.BacklogMessage.(*txBacklogMsg)
					txBLMsg.verificationErr = wi.Err
					testResultChan <- txBLMsg

				case <-handler.ctx.Done():
					return
				}
			}
		}()
	}

	// Prepare 1000 transactions
	genTCount := min(b.N, 1000)
	signedTransactionGroups, badTxnGroups := txGen.createSignedTxGroups(b, genTCount)
	var encStxns []network.IncomingMessage
	if useBacklogWorker {
		encStxns = make([]network.IncomingMessage, 0, genTCount)
		for _, stxngrp := range signedTransactionGroups {
			data := make([]byte, 0)
			for _, stxn := range stxngrp {
				data = append(data, protocol.Encode(&stxn)...)
			}
			encStxns = append(encStxns, network.IncomingMessage{Data: data})
		}
	}

	var tt time.Time
	// Process the results and make sure they are correct
	var rateAdjuster time.Duration
	if tps > 0 {
		rateAdjuster = time.Second / time.Duration(tps)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		groupCounter := uint64(0)
		var txnCounter uint64
		invalidCounter := 0
		// report the results
		defer func() {
			if groupCounter > 1 {
				timeSinceStart := time.Since(tt)
				droppedBacklog, droppedPool := getDropped()
				if tps > 0 {
					b.Logf("Input T(grp)PS: %d (delay %f microsec)", tps, float64(rateAdjuster)/float64(time.Microsecond))
				}
				b.Logf("Verified TPS: %d T(grp)PS: %d", uint64(txnCounter)*uint64(time.Second)/uint64(timeSinceStart),
					uint64(groupCounter)*uint64(time.Second)/uint64(timeSinceStart))
				b.Logf("Time/txn: %d(microsec)", uint64(timeSinceStart/time.Microsecond)/txnCounter)
				b.Logf("processed total: [%d groups (%d invalid)] [%d txns]", groupCounter, invalidCounter, txnCounter)
				b.Logf("dropped: [%d backlog] [%d pool]\n", droppedBacklog, droppedPool)
			}
			handler.Stop() // cancel the handler ctx
		}()
		counterMutex := deadlock.Mutex{}
		stopChan := make(chan interface{})
		// monitor the counters to tell when everything is processed and the checker should stop
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				time.Sleep(200 * time.Millisecond)
				droppedBacklog, droppedPool := getDropped()
				counterMutex.Lock()
				counters := groupCounter + droppedBacklog + droppedPool
				counterMutex.Unlock()
				if int(counters) == b.N {
					// all the benchmark txns processed
					close(stopChan)
					return
				}
			}
		}()
		// pick up each output from the verifier and check it is was correctly decided
		// since the data paths differ, distinguish between useBacklogWorker or not
		if useBacklogWorker {
			for {
				select {
				case wi := <-testResultChan:
					txnCounter = txnCounter + uint64(len(wi.unverifiedTxGroup))
					counterMutex.Lock()
					groupCounter++
					counterMutex.Unlock()
					u, _ := binary.Uvarint(wi.unverifiedTxGroup[0].Txn.Note)
					_, inBad := badTxnGroups[u]
					if wi.verificationErr == nil {
						require.False(b, inBad, "No error for invalid signature")
					} else {
						invalidCounter++
						require.True(b, inBad, "Error for good signature")
					}
					if groupCounter == uint64(b.N) {
						// all the benchmark txns processed
						return
					}
				case <-stopChan:
					return
				}
			}
		} else {
			for {
				select {
				case wi := <-handler.postVerificationQueue:
					txnCounter = txnCounter + uint64(len(wi.TxnGroup))
					counterMutex.Lock()
					groupCounter++
					counterMutex.Unlock()
					u, _ := binary.Uvarint(wi.TxnGroup[0].Txn.Note)
					_, inBad := badTxnGroups[u]
					if wi.Err == nil {
						require.False(b, inBad, "No error for invalid signature")
					} else {
						invalidCounter++
						require.True(b, inBad, "Error for good signature")
					}
					if groupCounter == uint64(b.N) {
						// all the benchmark txns processed
						return
					}
				case <-stopChan:
					return
				}
			}
		}
	}()

	completed := false
	c := 0
	ticker := &time.Ticker{}
	if rateAdjuster > 0 {
		ticker = time.NewTicker(rateAdjuster)
	}
	defer ticker.Stop()
	b.ResetTimer()
	tt = time.Now()
	for !completed {
		for i := range signedTransactionGroups {
			if useBacklogWorker {
				handler.processIncomingTxn(encStxns[i])
				<-ticker.C
			} else {
				stxngrp := signedTransactionGroups[i]
				blm := txBacklogMsg{rawmsg: nil, unverifiedTxGroup: stxngrp}
				handler.streamVerifierChan <- &verify.UnverifiedTxnSigJob{TxnGroup: stxngrp, BacklogMessage: &blm}
			}
			c++
			if c == b.N {
				completed = true
				break
			}
		}
	}
	wg.Wait()
	handler.Stop() // cancel the handler ctx
}

func TestTxHandlerPostProcessError(t *testing.T) { //nolint:paralleltest // Not parallel because it mutates global metrics
	partitiontest.PartitionTest(t)

	defer func() {
		transactionMessagesTxnSigVerificationFailed = metrics.MakeCounter(metrics.TransactionMessagesTxnSigVerificationFailed)
		transactionMessagesAlreadyCommitted = metrics.MakeCounter(metrics.TransactionMessagesAlreadyCommitted)
		transactionMessagesTxGroupInvalidFee = metrics.MakeCounter(metrics.TransactionMessagesTxGroupInvalidFee)
		transactionMessagesTxnSigNotWellFormed = metrics.MakeCounter(metrics.TransactionMessagesTxnSigNotWellFormed)
		transactionMessagesTxnMsigNotWellFormed = metrics.MakeCounter(metrics.TransactionMessagesTxnMsigNotWellFormed)
		transactionMessagesTxnLogicSig = metrics.MakeCounter(metrics.TransactionMessagesTxnLogicSig)
	}()

	transactionMessagesTxnSigVerificationFailed = metrics.MakeCounter(metrics.TransactionMessagesTxnSigVerificationFailed)
	transactionMessagesAlreadyCommitted = metrics.MakeCounter(metrics.TransactionMessagesAlreadyCommitted)
	transactionMessagesTxGroupInvalidFee = metrics.MakeCounter(metrics.TransactionMessagesTxGroupInvalidFee)
	transactionMessagesTxnSigNotWellFormed = metrics.MakeCounter(metrics.TransactionMessagesTxnSigNotWellFormed)
	transactionMessagesTxnMsigNotWellFormed = metrics.MakeCounter(metrics.TransactionMessagesTxnMsigNotWellFormed)
	transactionMessagesTxnLogicSig = metrics.MakeCounter(metrics.TransactionMessagesTxnLogicSig)

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

		errTxGroup := &verify.TxGroupError{Reason: i}
		txh.postProcessReportErrors(errTxGroup)
		result = collect()
		if i == verify.TxGroupErrorReasonSigNotWellFormed {
			// TxGroupErrorReasonSigNotWellFormed and TxGroupErrorReasonHasNoSig increment the same metric
			counter--
			require.Equal(t, float64(2), result[metrics.TransactionMessagesTxnSigNotWellFormed.Name])
		}
		require.Len(t, result, counter)
		counter++
	}

	// there are one less metrics than number of tracked values,
	// plus one generic non-tracked value, plus skipped TxGroupErrorReasonNotWellFormed
	const expected = int(verify.TxGroupErrorReasonNumValues) - 3
	require.Len(t, result, expected)

	errVerify := crypto.ErrBatchHasFailedSigs
	txh.postProcessReportErrors(errVerify)
	result = collect()
	require.Len(t, result, expected+1)
}

func TestTxHandlerPostProcessErrorWithVerify(t *testing.T) { //nolint:paralleltest // Not parallel because it mutates global metrics
	partitiontest.PartitionTest(t)

	defer func() {
		transactionMessagesTxnNotWellFormed = metrics.MakeCounter(metrics.TransactionMessagesTxnNotWellFormed)
	}()
	transactionMessagesTxnNotWellFormed = metrics.MakeCounter(metrics.TransactionMessagesTxnNotWellFormed)

	txn := transactions.Transaction{}
	stxn := transactions.SignedTxn{Txn: txn}

	hdr := bookkeeping.BlockHeader{
		UpgradeState: bookkeeping.UpgradeState{
			CurrentProtocol: protocol.ConsensusCurrentVersion,
		},
	}
	_, err := verify.TxnGroup([]transactions.SignedTxn{stxn}, &hdr, nil, nil)
	var txGroupErr *verify.TxGroupError
	require.ErrorAs(t, err, &txGroupErr)

	result := map[string]float64{}
	transactionMessagesTxnNotWellFormed.AddMetric(result)
	require.Len(t, result, 0)

	var txh TxHandler
	txh.postProcessReportErrors(err)
	transactionMessagesTxnNotWellFormed.AddMetric(result)
	require.Len(t, result, 1)
}

// TestTxHandlerRememberReportErrors checks Is and As statements work as expected
func TestTxHandlerRememberReportErrors(t *testing.T) { //nolint:paralleltest // Not parallel because incomingTxHandlerProcessing mutates global metrics
	partitiontest.PartitionTest(t)

	defer func() {
		transactionMessageTxPoolRememberCounter = metrics.NewTagCounter(
			"algod_transaction_messages_txpool_remember_err_{TAG}", "Number of transaction messages not remembered by txpool b/c of {TAG}",
			txPoolRememberTagCap, txPoolRememberPendingEval, txPoolRememberTagNoSpace, txPoolRememberTagFee, txPoolRememberTagTxnDead, txPoolRememberTagTxnEarly, txPoolRememberTagTooLarge, txPoolRememberTagGroupID,
			txPoolRememberTagTxID, txPoolRememberTagLease, txPoolRememberTagTxIDEval, txPoolRememberTagLeaseEval, txPoolRememberTagEvalGeneric,
		)
	}()
	transactionMessageTxPoolRememberCounter = metrics.NewTagCounter(
		"algod_transaction_messages_txpool_remember_err_{TAG}", "Number of transaction messages not remembered by txpool b/c of {TAG}",
		txPoolRememberTagCap, txPoolRememberPendingEval, txPoolRememberTagNoSpace, txPoolRememberTagFee, txPoolRememberTagTxnDead, txPoolRememberTagTxnEarly, txPoolRememberTagTooLarge, txPoolRememberTagGroupID,
		txPoolRememberTagTxID, txPoolRememberTagLease, txPoolRememberTagTxIDEval, txPoolRememberTagLeaseEval, txPoolRememberTagEvalGeneric,
	)

	var txh TxHandler
	result := map[string]float64{}

	getMetricName := func(tag string) string {
		return strings.ReplaceAll(transactionMessageTxPoolRememberCounter.Name, "{TAG}", tag)
	}
	getMetricCounter := func(tag string) int {
		transactionMessageTxPoolRememberCounter.AddMetric(result)
		return int(result[getMetricName(tag)])
	}

	noSpaceErr := ledgercore.ErrNoSpace
	txh.rememberReportErrors(noSpaceErr)
	transactionMessageTxPoolRememberCounter.AddMetric(result)
	require.Equal(t, 1, getMetricCounter(txPoolRememberTagNoSpace))

	wrapped := fmt.Errorf("wrap: %w", noSpaceErr) // simulate wrapping
	txh.rememberReportErrors(wrapped)

	transactionMessageTxPoolRememberCounter.AddMetric(result)
	require.Equal(t, 2, getMetricCounter(txPoolRememberTagNoSpace))

	feeErr := pools.ErrTxPoolFeeError{}
	wrapped = fmt.Errorf("wrap: %w", &feeErr) // simulate wrapping
	txh.rememberReportErrors(wrapped)

	transactionMessageTxPoolRememberCounter.AddMetric(result)
	require.Equal(t, 1, getMetricCounter(txPoolRememberTagFee))
}

func makeBlockTicker() *blockTicker {
	return &blockTicker{
		waiter: make(chan struct{}, 10),
	}
}

type blockTicker struct {
	waiter chan struct{}
}

func (t *blockTicker) OnNewBlock(block bookkeeping.Block, delta ledgercore.StateDelta) {
	t.waiter <- struct{}{}
}

func (t *blockTicker) Wait() {
	timer := time.NewTimer(1 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-t.waiter:
			return
		case <-timer.C:
			return
		}
	}
}

func TestTxHandlerRememberReportErrorsWithTxPool(t *testing.T) { //nolint:paralleltest // Not parallel because it mutates global metrics
	partitiontest.PartitionTest(t)
	defer func() {
		transactionMessageTxPoolRememberCounter = metrics.NewTagCounter(
			"algod_transaction_messages_txpool_remember_err_{TAG}", "Number of transaction messages not remembered by txpool b/c of {TAG}",
			txPoolRememberTagCap, txPoolRememberPendingEval, txPoolRememberTagNoSpace, txPoolRememberTagFee, txPoolRememberTagTxnDead, txPoolRememberTagTxnEarly, txPoolRememberTagTooLarge, txPoolRememberTagGroupID,
			txPoolRememberTagTxID, txPoolRememberTagLease, txPoolRememberTagTxIDEval, txPoolRememberTagLeaseEval, txPoolRememberTagEvalGeneric,
		)
		transactionMessageTxPoolCheckCounter = metrics.NewTagCounter(
			"algod_transaction_messages_txpool_check_err_{TAG}", "Number of transaction messages that didn't pass check by txpool b/c of {TAG}",
			txPoolRememberTagTxnNotWellFormed, txPoolRememberTagTxnDead, txPoolRememberTagTxnEarly, txPoolRememberTagTooLarge, txPoolRememberTagGroupID,
			txPoolRememberTagTxID, txPoolRememberTagLease, txPoolRememberTagTxIDEval, txPoolRememberTagLeaseEval, txPoolRememberTagEvalGeneric,
		)
	}()
	transactionMessageTxPoolRememberCounter = metrics.NewTagCounter(
		"algod_transaction_messages_txpool_remember_err_{TAG}", "Number of transaction messages not remembered by txpool b/c of {TAG}",
		txPoolRememberTagCap, txPoolRememberPendingEval, txPoolRememberTagNoSpace, txPoolRememberTagFee, txPoolRememberTagTxnDead, txPoolRememberTagTxnEarly, txPoolRememberTagTooLarge, txPoolRememberTagGroupID,
		txPoolRememberTagTxID, txPoolRememberTagLease, txPoolRememberTagTxIDEval, txPoolRememberTagLeaseEval, txPoolRememberTagEvalGeneric,
	)
	transactionMessageTxPoolCheckCounter = metrics.NewTagCounter(
		"algod_transaction_messages_txpool_check_err_{TAG}", "Number of transaction messages that didn't pass check by txpool b/c of {TAG}",
		txPoolRememberTagTxnNotWellFormed, txPoolRememberTagTxnDead, txPoolRememberTagTxnEarly, txPoolRememberTagTooLarge, txPoolRememberTagGroupID,
		txPoolRememberTagTxID, txPoolRememberTagLease, txPoolRememberTagTxIDEval, txPoolRememberTagLeaseEval, txPoolRememberTagEvalGeneric,
	)

	result := map[string]float64{}
	checkResult := map[string]float64{}
	getMetricName := func(tag string) string {
		return strings.ReplaceAll(transactionMessageTxPoolRememberCounter.Name, "{TAG}", tag)
	}
	getCheckMetricName := func(tag string) string {
		return strings.ReplaceAll(transactionMessageTxPoolCheckCounter.Name, "{TAG}", tag)
	}
	getMetricCounter := func(tag string) int {
		transactionMessageTxPoolRememberCounter.AddMetric(result)
		return int(result[getMetricName(tag)])
	}
	getCheckMetricCounter := func(tag string) int {
		transactionMessageTxPoolCheckCounter.AddMetric(checkResult)
		return int(checkResult[getCheckMetricName(tag)])
	}

	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)

	const numAccts = 2
	genesis := make(map[basics.Address]basics.AccountData, numAccts+1)
	addresses := make([]basics.Address, numAccts)
	secrets := make([]*crypto.SignatureSecrets, numAccts)

	for i := 0; i < numAccts; i++ {
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

	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)

	ledgerName := fmt.Sprintf("%s-mem-%d", t.Name(), rand.Int())
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	cfg.TxPoolSize = bounds.MaxTxGroupSize + 1
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, cfg)
	require.NoError(t, err)
	defer ledger.Close()

	handler, err := makeTestTxHandler(ledger, cfg)
	require.NoError(t, err)
	defer handler.txVerificationPool.Shutdown()
	defer close(handler.streamVerifierDropped)
	// since Start is not called, set the context here
	handler.ctx, handler.ctxCancel = context.WithCancel(context.Background())
	defer handler.ctxCancel()

	var wi txBacklogMsg
	wi.unverifiedTxGroup = []transactions.SignedTxn{{}}
	handler.postProcessCheckedTxn(&wi)
	require.Equal(t, 1, getMetricCounter(txPoolRememberTagTxnDead))

	txn1 := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			GenesisHash: genesisHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: poolAddr,
			Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance + (rand.Uint64() % 10000)},
		},
	}

	wi.unverifiedTxGroup = []transactions.SignedTxn{txn1.Sign(secrets[0])}
	for i := 0; i <= cfg.TxPoolSize; i++ {
		txn := txn1
		crypto.RandBytes(txn.Note[:])
		wi.unverifiedTxGroup = append(wi.unverifiedTxGroup, txn.Sign(secrets[0]))
	}
	handler.postProcessCheckedTxn(&wi)
	require.Equal(t, 1, getMetricCounter(txPoolRememberTagCap))

	// trigger not well-formed error
	txn2 := txn1
	txn2.Sender = basics.Address{}
	wi.unverifiedTxGroup = []transactions.SignedTxn{txn2.Sign(secrets[0])}
	handler.checkAlreadyCommitted(&wi)
	require.Equal(t, 1, getCheckMetricCounter(txPoolRememberTagTxnNotWellFormed))

	// trigger group id error
	txn2 = txn1
	crypto.RandBytes(txn2.Group[:])
	wi.unverifiedTxGroup = []transactions.SignedTxn{txn1.Sign(secrets[0]), txn2.Sign(secrets[0])}
	handler.checkAlreadyCommitted(&wi)
	require.Equal(t, 1, getCheckMetricCounter(txPoolRememberTagGroupID))
	handler.postProcessCheckedTxn(&wi)
	require.Equal(t, 1, getMetricCounter(txPoolRememberTagGroupID))

	// trigger group too large error
	wi.unverifiedTxGroup = []transactions.SignedTxn{txn1.Sign(secrets[0])}
	for i := 0; i < bounds.MaxTxGroupSize; i++ {
		txn := txn1
		crypto.RandBytes(txn.Note[:])
		wi.unverifiedTxGroup = append(wi.unverifiedTxGroup, txn.Sign(secrets[0]))
	}
	handler.postProcessCheckedTxn(&wi)
	require.Equal(t, 1, getMetricCounter(txPoolRememberTagTooLarge))
	handler.checkAlreadyCommitted(&wi)
	require.Equal(t, 1, getCheckMetricCounter(txPoolRememberTagTooLarge))

	// trigger eval error
	secret := keypair()
	addr := basics.Address(secret.SignatureVerifier)
	txn2 = txn1
	txn2.Sender = addr
	wi.unverifiedTxGroup = []transactions.SignedTxn{txn2.Sign(secret)}
	handler.postProcessCheckedTxn(&wi)
	require.Equal(t, 1, getMetricCounter(txPoolRememberTagEvalGeneric))

	// trigger TxnDeadErr from the evaluator for "early" case
	txn2 = txn1
	txn2.FirstValid = ledger.LastRound() + 10
	prevTxnEarly := getMetricCounter(txPoolRememberTagTxnEarly)
	wi.unverifiedTxGroup = []transactions.SignedTxn{txn2.Sign(secrets[0])}
	handler.postProcessCheckedTxn(&wi)
	require.Equal(t, prevTxnEarly+1, getMetricCounter(txPoolRememberTagTxnEarly))
	handler.checkAlreadyCommitted(&wi)
	require.Equal(t, 1, getCheckMetricCounter(txPoolRememberTagTxnEarly))

	// trigger TxnDeadErr from the evaluator for "late" case
	txn2 = txn1
	txn2.LastValid = 0
	prevTxnDead := getMetricCounter(txPoolRememberTagTxnDead)
	wi.unverifiedTxGroup = []transactions.SignedTxn{txn2.Sign(secrets[0])}
	handler.postProcessCheckedTxn(&wi)
	require.Equal(t, prevTxnDead+1, getMetricCounter(txPoolRememberTagTxnDead))
	handler.checkAlreadyCommitted(&wi)
	require.Equal(t, 1, getCheckMetricCounter(txPoolRememberTagTxnDead))

	// trigger TransactionInLedgerError (txid) error
	wi.unverifiedTxGroup = []transactions.SignedTxn{txn1.Sign(secrets[0])}
	wi.rawmsg = &network.IncomingMessage{}
	handler.postProcessCheckedTxn(&wi)
	handler.postProcessCheckedTxn(&wi)
	require.Equal(t, 1, getMetricCounter(txPoolRememberTagTxIDEval))
	handler.checkAlreadyCommitted(&wi)
	require.Equal(t, 1, getCheckMetricCounter(txPoolRememberTagTxIDEval))

	// trigger LeaseInLedgerError (lease) error
	txn2 = txn1
	crypto.RandBytes(txn2.Lease[:])
	txn3 := txn2
	txn3.Receiver = addr
	wi.unverifiedTxGroup = []transactions.SignedTxn{txn2.Sign(secrets[0])}
	handler.postProcessCheckedTxn(&wi)
	wi.unverifiedTxGroup = []transactions.SignedTxn{txn3.Sign(secrets[0])}
	handler.postProcessCheckedTxn(&wi)
	require.Equal(t, 1, getMetricCounter(txPoolRememberTagLeaseEval))
	handler.checkAlreadyCommitted(&wi)
	require.Equal(t, 1, getCheckMetricCounter(txPoolRememberTagLeaseEval))

	// TODO: not sure how to trigger fee error - need to return ErrNoSpace from ledger
	// trigger pool fee error
	// txn1.Fee = basics.MicroAlgos{Raw: proto.MinTxnFee / 2}
	// wi.unverifiedTxGroup = []transactions.SignedTxn{txn1.Sign(secrets[0])}
	// handler.postProcessCheckedTxn(&wi)
	// require.Equal(t, 1, getMetricCounter(txPoolRememberFee))

	// make an invalid block to fail recompute pool and expose transactionMessageTxGroupRememberNoPendingEval metric
	blockTicker := makeBlockTicker()
	blockListeners := []ledgercore.BlockListener{
		handler.txPool,
		blockTicker,
	}
	ledger.RegisterBlockListeners(blockListeners)

	// add few blocks: on ci sometimes blockTicker is not fired in time in case of a single block
	for i := basics.Round(1); i <= 3; i++ {
		hdr := bookkeeping.BlockHeader{
			Round: i,
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: "test",
			},
		}

		blk := bookkeeping.Block{
			BlockHeader: hdr,
			Payset:      []transactions.SignedTxnInBlock{{}},
		}
		vb := ledgercore.MakeValidatedBlock(blk, ledgercore.StateDelta{})
		err = ledger.AddValidatedBlock(vb, agreement.Certificate{})
		require.NoError(t, err)
	}
	blockTicker.Wait()

	wi.unverifiedTxGroup = []transactions.SignedTxn{}
	handler.postProcessCheckedTxn(&wi)
	require.Equal(t, 1, getMetricCounter(txPoolRememberPendingEval))
}

func TestMakeTxHandlerErrors(t *testing.T) {
	partitiontest.PartitionTest(t)
	opts := TxHandlerOpts{
		nil, nil, nil, &mocks.MockNetwork{}, config.Local{},
	}
	_, err := MakeTxHandler(opts)
	require.Error(t, err, ErrInvalidTxPool)

	opts = TxHandlerOpts{
		&pools.TransactionPool{}, nil, nil, &mocks.MockNetwork{}, config.Local{},
	}
	_, err = MakeTxHandler(opts)
	require.Error(t, err, ErrInvalidLedger)

	// it is not possible to test MakeStreamVerifier returning an error, because it is not possible to
	// get the ledger to return an error for returining the header of its latest round
}

// TestTxHandlerRestartWithBacklogAndTxPool starts txHandler, sends transactions,
// stops, starts in a loop, sends more transactions, and makes sure all the transactions
// are accounted for. It uses the production backlog worker
func TestTxHandlerRestartWithBacklogAndTxPool(t *testing.T) { //nolint:paralleltest // Not parallel because it mutates global metrics
	partitiontest.PartitionTest(t)
	transactionMessagesDroppedFromBacklog = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromBacklog)
	transactionMessagesDroppedFromPool = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromPool)
	transactionMessagesTxnSigVerificationFailed = metrics.MakeCounter(metrics.TransactionMessagesTxnSigVerificationFailed)
	transactionMessagesBacklogErr = metrics.MakeCounter(metrics.TransactionMessagesBacklogErr)
	transactionMessagesAlreadyCommitted = metrics.MakeCounter(metrics.TransactionMessagesAlreadyCommitted)
	transactionMessagesRemember = metrics.MakeCounter(metrics.TransactionMessagesRemember)
	transactionMessagesHandled = metrics.MakeCounter(metrics.TransactionMessagesHandled)

	defer func() {
		// reset the counters
		transactionMessagesDroppedFromBacklog = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromBacklog)
		transactionMessagesDroppedFromPool = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromPool)
		transactionMessagesTxnSigVerificationFailed = metrics.MakeCounter(metrics.TransactionMessagesTxnSigVerificationFailed)
		transactionMessagesBacklogErr = metrics.MakeCounter(metrics.TransactionMessagesBacklogErr)
		transactionMessagesAlreadyCommitted = metrics.MakeCounter(metrics.TransactionMessagesAlreadyCommitted)
		transactionMessagesRemember = metrics.MakeCounter(metrics.TransactionMessagesRemember)
		transactionMessagesHandled = metrics.MakeCounter(metrics.TransactionMessagesHandled)
	}()

	const numUsers = 100
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)
	addresses := make([]basics.Address, numUsers)
	secrets := make([]*crypto.SignatureSecrets, numUsers)

	// avoid printing the warning messages
	origLevel := logging.Base().GetLevel()
	defer func() { logging.Base().SetLevel(origLevel) }()
	logging.Base().SetLevel(logging.Error)

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

	// setup the ledger
	require.Equal(t, len(genesis), numUsers+1)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	ledgerName := fmt.Sprintf("%s-mem", t.Name())
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, cfg)
	require.NoError(t, err)
	defer ledger.Ledger.Close()

	handler, err := makeTestTxHandler(ledger, cfg)
	require.NoError(t, err)
	defer handler.txVerificationPool.Shutdown()
	defer close(handler.streamVerifierDropped)
	// prepare the transactions
	numTxns := 3000
	maxGroupSize := 1
	tps := 40000
	invalidRate := float32(0.5)
	rateAdjuster := time.Second / time.Duration(tps)
	signedTransactionGroups, badTxnGroups := makeSignedTxnGroups(numTxns, numUsers, maxGroupSize, invalidRate, addresses, secrets)
	var encodedSignedTransactionGroups []network.IncomingMessage

	encodedSignedTransactionGroups = make([]network.IncomingMessage, 0, numTxns)
	for _, stxngrp := range signedTransactionGroups {
		data := make([]byte, 0)
		for _, stxn := range stxngrp {
			data = append(data, protocol.Encode(&stxn)...)
		}
		encodedSignedTransactionGroups =
			append(encodedSignedTransactionGroups, network.IncomingMessage{Data: data, Sender: mockSender{}})
	}

	// start the handler
	handler.Start()

	// send the transactions to the backlog worker
	for _, tg := range encodedSignedTransactionGroups[0 : numTxns/2] {
		handler.processIncomingTxn(tg)
		time.Sleep(rateAdjuster)
	}
	// stop in a loop to test for possible race conditions
	for x := 0; x < 1000; x++ {
		handler.Stop()
		handler.Start()
	}
	handler.Stop()

	// send the second half after stopping the txHandler
	for _, tg := range encodedSignedTransactionGroups[numTxns/2:] {
		handler.processIncomingTxn(tg)
		time.Sleep(rateAdjuster)
	}

	// check that all the incomming transactions are accounted for
	droppeda, droppedb := getDropped()
	dropped := droppeda + droppedb
	stuckInBLQueue := uint64(len(handler.backlogQueue))
	resultBadTxnCount := transactionMessagesTxnSigVerificationFailed.GetUint64Value()
	resultGoodTxnCount := transactionMessagesHandled.GetUint64Value()
	shutdownDropCount := transactionMessagesBacklogErr.GetUint64Value()
	require.Equal(t, numTxns, int(dropped+resultGoodTxnCount+resultBadTxnCount+stuckInBLQueue+shutdownDropCount))

	// start the handler again
	handler.Start()
	defer handler.Stop()

	// no dpulicates are sent at this point
	require.Equal(t, 0, int(transactionMessagesAlreadyCommitted.GetUint64Value()))

	// send the same set of transactions again
	for _, tg := range encodedSignedTransactionGroups {
		handler.processIncomingTxn(tg)
		time.Sleep(rateAdjuster)
	}

	inputGoodTxnCount := len(signedTransactionGroups) - len(badTxnGroups)
	tp := handler.txPool
	// Wait untill all the expected transactions are in the pool
	for x := 0; x < 100; x++ {
		if len(tp.PendingTxGroups()) == inputGoodTxnCount {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}

	// check the couters and the accepted transactions
	require.Equal(t, inputGoodTxnCount, len(tp.PendingTxGroups()))
	for _, txg := range tp.PendingTxGroups() {
		u, _ := binary.Uvarint(txg[0].Txn.Note)
		_, inBad := badTxnGroups[u]
		require.False(t, inBad, "invalid transaction accepted")
	}
}

// check ERL and AppRateLimiter enablement with separate config values,
// and the app limiter kicks in after congestion.
func TestTxHandlerAppRateLimiterERLEnabled(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// technically we don't need any users for this test
	// but we need to create the genesis accounts to prevent this warning:
	// "cannot start evaluator: overflowed subtracting rewards for block 1"
	_, _, genesis := makeTestGenesisAccounts(t, 0)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	ledgerName := fmt.Sprintf("%s-mem", t.Name())
	const inMem = true

	log := logging.TestingLog(t)
	log.SetLevel(logging.Panic)

	cfg := config.GetDefaultLocal()
	cfg.TxBacklogAppTxRateLimiterMaxSize = 100
	cfg.TxBacklogServiceRateWindowSeconds = 1
	cfg.TxBacklogAppTxPerSecondRate = 3
	cfg.TxBacklogSize = 3
	l, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, cfg)
	require.NoError(t, err)
	defer l.Close()

	func() {
		cfg.EnableTxBacklogRateLimiting = false
		cfg.EnableTxBacklogAppRateLimiting = false
		handler, err := makeTestTxHandler(l, cfg)
		require.NoError(t, err)
		defer handler.txVerificationPool.Shutdown()
		defer close(handler.streamVerifierDropped)

		require.Nil(t, handler.erl)
		require.Nil(t, handler.appLimiter)
	}()

	func() {
		cfg.EnableTxBacklogRateLimiting = true
		cfg.EnableTxBacklogAppRateLimiting = false
		handler, err := makeTestTxHandler(l, cfg)
		require.NoError(t, err)
		defer handler.txVerificationPool.Shutdown()
		defer close(handler.streamVerifierDropped)

		require.NotNil(t, handler.erl)
		require.Nil(t, handler.appLimiter)
	}()

	cfg.EnableTxBacklogRateLimiting = true
	cfg.EnableTxBacklogAppRateLimiting = true
	handler, err := makeTestTxHandler(l, cfg)
	require.NoError(t, err)
	defer handler.txVerificationPool.Shutdown()
	defer close(handler.streamVerifierDropped)
	require.NotNil(t, handler.erl)
	require.NotNil(t, handler.appLimiter)

	var addr basics.Address
	crypto.RandBytes(addr[:])

	tx := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:     addr,
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 2),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: 1,
		},
	}
	signedTx := tx.Sign(keypair()) // some random key
	blob := protocol.Encode(&signedTx)
	sender := mockSender{}

	// submit and ensure it is accepted
	pct := float64(cfg.TxBacklogRateLimitingCongestionPct) / 100
	limit := int(float64(cfg.TxBacklogSize) * pct)
	congested := len(handler.backlogQueue) > limit
	require.False(t, congested)

	action := handler.processIncomingTxn(network.IncomingMessage{Data: blob, Sender: sender})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 1, len(handler.backlogQueue))

	// repeat the same txn, we are still not congested
	congested = len(handler.backlogQueue) > limit
	require.False(t, congested)

	signedTx = tx.Sign(keypair())
	blob = protocol.Encode(&signedTx)
	action = handler.processIncomingTxn(network.IncomingMessage{Data: blob, Sender: sender})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 2, len(handler.backlogQueue))
	require.Equal(t, 0, handler.appLimiter.len()) // no rate limiting yet

	congested = len(handler.backlogQueue) > limit
	require.True(t, congested)

	// submit it again and the app rate limiter should kick in
	signedTx = tx.Sign(keypair())
	blob = protocol.Encode(&signedTx)
	action = handler.processIncomingTxn(network.IncomingMessage{Data: blob, Sender: sender})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 3, len(handler.backlogQueue))

	require.Equal(t, 1, handler.appLimiter.len())
}

// TestTxHandlerAppRateLimiter submits few app txns to make the app rate limit to filter one the last txn
// to ensure it is propely integrated with the txHandler
func TestTxHandlerAppRateLimiter(t *testing.T) {
	partitiontest.PartitionTest(t)

	const numUsers = 10
	log := logging.TestingLog(t)
	log.SetLevel(logging.Panic)

	// prepare the accounts
	addresses, secrets, genesis := makeTestGenesisAccounts(t, numUsers)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	ledgerName := fmt.Sprintf("%s-mem", t.Name())
	const inMem = true

	cfg := config.GetDefaultLocal()
	cfg.EnableTxBacklogRateLimiting = true
	cfg.TxBacklogAppTxRateLimiterMaxSize = 100
	cfg.TxBacklogServiceRateWindowSeconds = 1
	cfg.TxBacklogAppTxPerSecondRate = 3
	l, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, cfg)
	require.NoError(t, err)
	defer l.Close()

	handler, err := makeTestTxHandler(l, cfg)
	require.NoError(t, err)
	defer handler.txVerificationPool.Shutdown()
	defer close(handler.streamVerifierDropped)

	handler.appLimiterBacklogThreshold = -1 // force the rate limiter to start checking transactions
	tx := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:     addresses[0],
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 2),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: 1,
		},
	}
	signedTx := tx.Sign(secrets[1])
	blob := protocol.Encode(&signedTx)

	action := handler.processIncomingTxn(network.IncomingMessage{Data: blob, Sender: mockSender{}})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 1, len(handler.backlogQueue))

	counterBefore := transactionMessagesAppLimiterDrop.GetUint64Value()
	// trigger the rate limiter and ensure the txn is ignored
	numTxnToTriggerARL := cfg.TxBacklogAppTxPerSecondRate * cfg.TxBacklogServiceRateWindowSeconds
	for i := 0; i < numTxnToTriggerARL; i++ {
		tx2 := tx
		tx2.Header.Sender = addresses[i+1]
		signedTx2 := tx2.Sign(secrets[i+1])
		blob2 := protocol.Encode(&signedTx2)

		action = handler.processIncomingTxn(network.IncomingMessage{Data: blob2, Sender: mockSender{}})
		require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	}
	// last txn should be dropped
	require.Equal(t, 1+numTxnToTriggerARL-1, len(handler.backlogQueue))
	require.Equal(t, counterBefore+1, transactionMessagesAppLimiterDrop.GetUint64Value())
}

// TestTxHandlerCapGuard checks there is no cap guard leak in case of invalid input.
func TestTxHandlerCapGuard(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const numUsers = 10
	addresses, secrets, genesis := makeTestGenesisAccounts(t, numUsers)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	ledgerName := fmt.Sprintf("%s-mem", t.Name())
	const inMem = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Error)

	cfg := config.GetDefaultLocal()
	cfg.EnableTxBacklogRateLimiting = true
	cfg.EnableTxBacklogAppRateLimiting = false
	cfg.TxIncomingFilteringFlags = 0
	cfg.TxBacklogServiceRateWindowSeconds = 1
	cfg.TxBacklogReservedCapacityPerPeer = 1
	cfg.IncomingConnectionsLimit = 1
	cfg.TxBacklogSize = 3

	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, cfg)
	require.NoError(t, err)
	defer ledger.Close()

	handler, err := makeTestTxHandler(ledger, cfg)
	require.NoError(t, err)
	defer handler.txVerificationPool.Shutdown()
	defer close(handler.streamVerifierDropped)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     addresses[0],
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: 1000},
		},
	}

	signedTx := tx.Sign(secrets[0])
	blob := protocol.Encode(&signedTx)
	blob[0]++ // make it invalid

	var completed atomic.Bool
	go func() {
		for i := 0; i < 10; i++ {
			outgoing := handler.processIncomingTxn(network.IncomingMessage{Data: blob, Sender: mockSender{}})
			require.Equal(t, network.OutgoingMessage{Action: network.Disconnect}, outgoing)
			require.Equal(t, 0, len(handler.backlogQueue))
		}
		completed.Store(true)
	}()

	require.Eventually(t, func() bool { return completed.Load() }, 1*time.Second, 10*time.Millisecond)
}

func TestTxHandlerValidateIncomingTxMessage(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const numUsers = 10
	addresses, secrets, genesis := makeTestGenesisAccounts(t, numUsers)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)

	ledgerName := fmt.Sprintf("%s-mem", t.Name())
	const inMem = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Panic)

	cfg := config.GetDefaultLocal()
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, cfg)
	require.NoError(t, err)
	defer ledger.Close()

	handler, err := makeTestTxHandler(ledger, cfg)
	require.NoError(t, err)
	handler.Start()
	defer handler.Stop()

	// valid message
	_, blob := makeTxns(addresses, secrets, 1, 2, genesisHash)
	outmsg := handler.validateIncomingTxMessage(network.IncomingMessage{Data: blob})
	require.Equal(t, outmsg.Action, network.Accept)

	// non-canonical message
	// for some reason craftNonCanonical cannot handle makeTxns output so make a simpler random txn
	stxns, blob := makeRandomTransactions(1)
	stxn := stxns[0]
	blobNonCan := craftNonCanonical(t, &stxn, blob)
	outmsg = handler.validateIncomingTxMessage(network.IncomingMessage{Data: blobNonCan})
	require.Equal(t, outmsg.Action, network.Disconnect)

	// invalid signature
	stxns, _ = makeTxns(addresses, secrets, 1, 2, genesisHash)
	stxns[0].Sig[0] = stxns[0].Sig[0] + 1
	blob2 := protocol.Encode(&stxns[0])
	outmsg = handler.validateIncomingTxMessage(network.IncomingMessage{Data: blob2})
	require.Equal(t, outmsg.Action, network.Disconnect)

	// invalid message
	_, blob = makeTxns(addresses, secrets, 1, 2, genesisHash)
	blob[0] = blob[0] + 1
	outmsg = handler.validateIncomingTxMessage(network.IncomingMessage{Data: blob})
	require.Equal(t, outmsg.Action, network.Disconnect)

	t.Run("with-canonical", func(t *testing.T) {
		// make sure the reencoding from the canonical dedup checker's reencoding buf is correctly reused
		cfg.TxIncomingFilteringFlags = 2
		require.True(t, cfg.TxFilterCanonicalEnabled())
		handler, err := makeTestTxHandler(ledger, cfg)
		require.NoError(t, err)
		handler.Start()
		defer handler.Stop()

		// valid message
		_, blob := makeTxns(addresses, secrets, 1, 2, genesisHash)
		outmsg := handler.validateIncomingTxMessage(network.IncomingMessage{Data: blob})
		require.Equal(t, outmsg.Action, network.Accept)

		// non-canonical message
		// for some reason craftNonCanonical cannot handle makeTxns output so make a simpler random txn
		stxns, blob := makeRandomTransactions(1)
		stxn := stxns[0]
		blobNonCan := craftNonCanonical(t, &stxn, blob)
		outmsg = handler.validateIncomingTxMessage(network.IncomingMessage{Data: blobNonCan})
		require.Equal(t, outmsg.Action, network.Disconnect)
	})
}

// Create mock types to satisfy interfaces
type erlMockPeer struct {
	network.DisconnectableAddressablePeer
	util.ErlClient
	addr   string
	closer func()
}

func newErlMockPeer(addr string) *erlMockPeer {
	return &erlMockPeer{
		addr: addr,
	}
}

// Implement required interface methods
func (m *erlMockPeer) RoutingAddr() []byte { return []byte(m.addr) }
func (m *erlMockPeer) OnClose(f func())    { m.closer = f }

func TestTxHandlerErlClientMapper(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("Same routing address clients share erlIPClient", func(t *testing.T) {
		mapper := erlClientMapper{
			mapping:    make(map[string]*erlIPClient),
			maxClients: 4,
		}

		peer1 := newErlMockPeer("192.168.1.1")
		peer2 := newErlMockPeer("192.168.1.1")

		client1 := mapper.getClient(peer1)
		client2 := mapper.getClient(peer2)

		// Verify both peers got same erlIPClient
		require.Equal(t, client1, client2, "Expected same erlIPClient for same routing address")
		require.Equal(t, 1, len(mapper.mapping))

		ipClient := mapper.mapping["192.168.1.1"]
		require.Equal(t, 2, len(ipClient.clients))
	})

	t.Run("Different routing addresses get different erlIPClients", func(t *testing.T) {
		mapper := erlClientMapper{
			mapping:    make(map[string]*erlIPClient),
			maxClients: 4,
		}

		peer1 := newErlMockPeer("192.168.1.1")
		peer2 := newErlMockPeer("192.168.1.2")

		client1 := mapper.getClient(peer1)
		client2 := mapper.getClient(peer2)

		// Verify peers got different erlIPClients
		require.NotEqual(t, client1, client2, "Expected different erlIPClients for different routing addresses")
		require.Equal(t, 2, len(mapper.mapping))
	})

	t.Run("Client cleanup on connection close", func(t *testing.T) {
		mapper := erlClientMapper{
			mapping:    make(map[string]*erlIPClient),
			maxClients: 4,
		}

		peer1 := newErlMockPeer("192.168.1.1")
		peer2 := newErlMockPeer("192.168.1.1")

		// Register clients for both peers
		mapper.getClient(peer1)
		mapper.getClient(peer2)

		ipClient := mapper.mapping["192.168.1.1"]
		closerCalled := false
		ipClient.OnClose(func() {
			closerCalled = true
		})

		require.Equal(t, 2, len(ipClient.clients))

		// Simulate connection close for peer1
		peer1.closer()
		require.Equal(t, 1, len(ipClient.clients))
		require.False(t, closerCalled)

		// Simulate connection close for peer2
		peer2.closer()
		require.Equal(t, 0, len(ipClient.clients))
		require.True(t, closerCalled)
	})
}

// TestTxHandlerERLIPClient checks that ERL properly handles sender with the same and different addresses:
// Configure ERL in following way:
// 1. Small maxCapacity=10 fully shared by two IP senders (TxBacklogReservedCapacityPerPeer=5, IncomingConnectionsLimit=0)
// 2. Submit one from both IP senders to initalize per peer-queues and exhaust shared capacity
// 3. Make sure the third peer does not come through
// 4. Make sure extra messages from the first peer and second peer are accepted
func TestTxHandlerERLIPClient(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// technically we don't need any users for this test
	// but we need to create the genesis accounts to prevent this warning:
	// "cannot start evaluator: overflowed subtracting rewards for block 1"
	_, _, genesis := makeTestGenesisAccounts(t, 0)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	ledgerName := fmt.Sprintf("%s-mem", t.Name())
	const inMem = true

	log := logging.TestingLog(t)
	log.SetLevel(logging.Panic)

	const backlogSize = 10 // to have targetRateRefreshTicks: bsize / 10  != 0 in NewREDCongestionManager
	cfg := config.GetDefaultLocal()
	cfg.TxIncomingFilteringFlags = 0 // disable duplicate filtering to simplify the test
	cfg.IncomingConnectionsLimit = 0 // disable incoming connections limit to have TxBacklogSize controlled
	cfg.EnableTxBacklogRateLimiting = true
	cfg.EnableTxBacklogAppRateLimiting = false
	cfg.TxBacklogServiceRateWindowSeconds = 100 // large window
	cfg.TxBacklogRateLimitingCongestionPct = 0  // always congested
	cfg.TxBacklogReservedCapacityPerPeer = 5    // 5 messages per peer (IP address in our case)
	cfg.TxBacklogSize = backlogSize
	l, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, cfg)
	require.NoError(t, err)
	defer l.Close()

	handler, err := makeTestTxHandler(l, cfg)
	require.NoError(t, err)
	defer handler.txVerificationPool.Shutdown()
	defer close(handler.streamVerifierDropped)
	require.NotNil(t, handler.erl)
	require.Nil(t, handler.appLimiter)
	handler.erl.Start()
	defer handler.erl.Stop()

	var addr1, addr2 basics.Address
	crypto.RandBytes(addr1[:])
	crypto.RandBytes(addr2[:])

	tx := getTransaction(addr1, addr2, 1)

	signedTx := tx.Sign(keypair()) // some random key
	blob := protocol.Encode(&signedTx)
	sender1 := newErlMockPeer("1")
	sender2 := newErlMockPeer("2")
	sender3 := newErlMockPeer("3")

	// initialize peer queues
	action := handler.processIncomingTxn(network.IncomingMessage{Data: blob, Sender: sender1})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 1, len(handler.backlogQueue))

	action = handler.processIncomingTxn(network.IncomingMessage{Data: blob, Sender: sender2})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 2, len(handler.backlogQueue))

	// make sure the third peer does not come through
	action = handler.processIncomingTxn(network.IncomingMessage{Data: blob, Sender: sender3})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 2, len(handler.backlogQueue))

	// make sure messages from other sender objects with the same IP are accepted
	sender11 := newErlMockPeer("1")
	sender21 := newErlMockPeer("2")

	action = handler.processIncomingTxn(network.IncomingMessage{Data: blob, Sender: sender11})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 3, len(handler.backlogQueue))

	action = handler.processIncomingTxn(network.IncomingMessage{Data: blob, Sender: sender21})
	require.Equal(t, network.OutgoingMessage{Action: network.Ignore}, action)
	require.Equal(t, 4, len(handler.backlogQueue))
}
