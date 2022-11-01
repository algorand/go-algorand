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
	"encoding/binary"
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
	txHandler := MakeTxHandler(tp, l, &mocks.MockNetwork{}, "", crypto.Digest{}, backlogPool)

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

func TestIncomingTxHandle(t *testing.T) {
	incomingTxHandlerProcessing(1, t)
}

func TestIncomingTxGroupHandle(t *testing.T) {
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
	tp := pools.MakeTransactionPool(l.Ledger, cfg, logging.Base())
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	handler := MakeTxHandler(tp, l, &mocks.MockNetwork{}, "", crypto.Digest{}, backlogPool)
	defer handler.ctxCancel()

	outChan := make(chan *txBacklogMsg, 10)
	wg := sync.WaitGroup{}
	wg.Add(1)
	// Make a test backlog worker, which is simiar to backlogWorker, but sends the results
	// through the outChan instead of passing it to postprocessCheckedTxn
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

// BenchmarkHandler sends singed transaction groups to the verifier
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
	tp := pools.MakeTransactionPool(l.Ledger, cfg, logging.Base())
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	handler := MakeTxHandler(tp, l, &mocks.MockNetwork{}, "", crypto.Digest{}, backlogPool)
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
