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
	tp := pools.MakeTransactionPool(l.Ledger, cfg, logging.Base())
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	txHandler, err := MakeTxHandler(tp, l, &mocks.MockNetwork{}, "", crypto.Digest{}, backlogPool)
	require.NoError(b, err)

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

	const numTxns = 11
	handler := TxHandler{
		backlogQueue: make(chan *txBacklogMsg, 1),
	}
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

// TestIncomingTxHandle checks the correctness with single txns
func TestIncomingTxHandle(t *testing.T) {
	partitiontest.PartitionTest(t)

	numberOfTransactionGroups := 1000
	incomingTxHandlerProcessing(1, numberOfTransactionGroups, t)
}

// TestIncomingTxGroupHandle checks the correctness with txn groups
func TestIncomingTxGroupHandle(t *testing.T) {
	partitiontest.PartitionTest(t)

	numberOfTransactionGroups := 1000 / proto.MaxTxGroupSize
	incomingTxHandlerProcessing(proto.MaxTxGroupSize, numberOfTransactionGroups, t)
}

// TestIncomingTxHandleDrops accounts for the dropped txns when the verifier/exec pool is saturated
func TestIncomingTxHandleDrops(t *testing.T) {
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
	tp := pools.MakeTransactionPool(l.Ledger, cfg, logging.Base())
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	handler, err := MakeTxHandler(tp, l, &mocks.MockNetwork{}, "", crypto.Digest{}, backlogPool)
	require.NoError(t, err)
	// since Start is not called, set the context here
	handler.ctx, handler.ctxCancel = context.WithCancel(context.Background())
	defer handler.ctxCancel()

	// emulate handler.Start() without the backlog
	handler.ctx, handler.ctxCancel = context.WithCancel(context.Background())
	handler.streamVerifier.Start(handler.ctx)

	testResultChan := make(chan *txBacklogMsg, 10)
	wg := sync.WaitGroup{}
	wg.Add(1)
	// Make a test backlog worker, which is simiar to backlogWorker, but sends the results
	// through the testResultChan instead of passing it to postprocessCheckedTxn
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
				handler.streamVerifierChan <- &verify.UnverifiedElement{TxnGroup: wi.unverifiedTxGroup, BacklogMessage: wi}
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
			append(encodedSignedTransactionGroups, network.IncomingMessage{Data: data})
	}

	// Process the results and make sure they are correct
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
				if int(groupCounter+droppedBacklog+droppedPool) == len(signedTransactionGroups) {
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
	ivrString := strings.IndexAny(fmt.Sprintf("%f", invalidRate), "1")
	ledgerName := fmt.Sprintf("%s-mem-%d-%d", b.Name(), b.N, ivrString)
	ledgerName = strings.Replace(ledgerName, "#", "-", 1)
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, nil, cfg)
	require.NoError(b, err)

	l := ledger
	tp := pools.MakeTransactionPool(l.Ledger, cfg, logging.Base())
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	handler, err := MakeTxHandler(tp, l, &mocks.MockNetwork{}, "", crypto.Digest{}, backlogPool)
	require.NoError(b, err)
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
		// Make a test backlog worker, which is simiar to backlogWorker, but sends the results
		// through the testResultChan instead of passing it to postprocessCheckedTxn
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
					handler.streamVerifierChan <- &verify.UnverifiedElement{TxnGroup: wi.unverifiedTxGroup, BacklogMessage: wi}
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

		if useBacklogWorker {
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
		} else {
			for {
				select {
				case wi := <-handler.postVerificationQueue:
					txnCounter = txnCounter + uint64(len(wi.TxnGroup))
					groupCounter++
					u, _ := binary.Uvarint(wi.TxnGroup[0].Txn.Note)
					_, inBad := badTxnGroups[u]
					if wi.Err == nil {
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
			handler.streamVerifierChan <- &verify.UnverifiedElement{TxnGroup: stxngrp, BacklogMessage: &blm}
			time.Sleep(rateAdjuster)
		}
	}
	wg.Wait()
	handler.Stop() // cancel the handler ctx
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

	errVerify := crypto.ErrBatchHasFailedSigs
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
	_, err := verify.TxnGroup([]transactions.SignedTxn{stxn}, &hdr, nil, nil)
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

func TestMakeTxHandlerErrors(t *testing.T) {
	_, err := MakeTxHandler(nil, nil, &mocks.MockNetwork{}, "", crypto.Digest{}, nil)
	require.Error(t, err, ErrInvalidTxPool)

	_, err = MakeTxHandler(&pools.TransactionPool{}, nil, &mocks.MockNetwork{}, "", crypto.Digest{}, nil)
	require.Error(t, err, ErrInvalidLedger)

	// it is not possible to test MakeStreamVerifier returning an error, because it is not possible to
	// get the leger return an error for returining the header of its latest round
}

func TestTxHandlerRestartWithBacklogAndTxPool(t *testing.T) {
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
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, nil, cfg)
	require.NoError(t, err)
	defer ledger.Ledger.Close()

	tp := pools.MakeTransactionPool(ledger.Ledger, cfg, logging.Base())
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()
	handler, err := MakeTxHandler(tp, ledger, &mocks.MockNetwork{}, "", crypto.Digest{}, backlogPool)
	require.NoError(t, err)

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
			append(encodedSignedTransactionGroups, network.IncomingMessage{Data: data})
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
