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

package transactions

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

// TestTxnSync sends payments by two nodes, and verifies that
// each transaction is received by the other node and the relay
//
// The test sets up a network with 2 nodes and 2 relays.
// The two nodes send payment transactions.
//
// For each transaction, the test checks if the relays and the nodes
// (including the node that originated the transaction) have the
// transaction in the pool (i.e. the transactionInfo.ConfirmedRound ==
// 0).
//
// The tests needs a delicate balance to pass.
//
// The transactions need to be checked in the pool fast enough before
// they are moved out to the block.
//
// In order to quickly test them while maintaining a high transaction
// throughput, the checks need to be performed in parallel.
//
// The parallel checks require open files for the rest
// connections. Too many of them and the system will complain about
// too many open files.
//
// The test keeps the number of simultaneous open connections via
// maxParallelChecks.
func TestTxnSync(t *testing.T) {
	t.Parallel()

	// maxParallelChecks is the number of goroutines will simultaniously check if the
	// transaction is received by the node.
	// If this is too large, the system will report too many open files.
	// If too small, the txns will be moved to the block.
	maxParallelChecks := 1
	numberOfSends := 1
	targetRate := 300 // txn/sec
	if testing.Short() {
		numberOfSends = 100
	}
	templatePath := filepath.Join("nettemplates", "TwoNodes50EachWithTwoRelays.json")

	var fixture fixtures.RestClientFixture

	roundTime := time.Duration(20)

	proto, ok := config.Consensus[protocol.ConsensusCurrentVersion]
	require.True(t, ok)
	proto.AgreementFilterTimeoutPeriod0 = roundTime * time.Second
	proto.AgreementFilterTimeout = roundTime * time.Second
	fixture.SetConsensus(config.ConsensusProtocols{protocol.ConsensusCurrentVersion: proto})

	fixture.Setup(t, templatePath)
	defer fixture.Shutdown()

	node1 := fixture.GetLibGoalClientForNamedNode("Node1")
	node2 := fixture.GetLibGoalClientForNamedNode("Node2")
	relay1 := fixture.GetLibGoalClientForNamedNode("Relay1")
	relay2 := fixture.GetLibGoalClientForNamedNode("Relay2")

	n1chan := make(chan string, numberOfSends*2)
	n2chan := make(chan string, numberOfSends*2)
	r1chan := make(chan string, numberOfSends*2)
	r2chan := make(chan string, numberOfSends*2)

	parallelCheckChannel := make(chan bool, maxParallelChecks)

	ctx, cancel := context.WithCancel(context.Background())

	account1List, err := fixture.GetNodeWalletsSortedByBalance(node1.DataDir())
	require.NoError(t, err)
	account1 := account1List[0].Address

	account2List, err := fixture.GetNodeWalletsSortedByBalance(node2.DataDir())
	require.NoError(t, err)
	account2 := account2List[0].Address

	ttn1 := transactionTracker{
		t:                    t,
		ctx:                  ctx,
		client:               &node1,
		othersToVerify:       []chan string{n2chan, r1chan, r2chan, n1chan},
		selfToVerify:         n1chan,
		pendingVerification:  make(map[string]bool),
		parallelCheckChannel: parallelCheckChannel,
		cancelFunc:           cancel,
		account1:             account1,
		account2:             account2,
	}

	ttn2 := transactionTracker{
		t:                    t,
		ctx:                  ctx,
		client:               &node2,
		othersToVerify:       []chan string{n1chan, r1chan, r2chan, n2chan},
		selfToVerify:         n2chan,
		pendingVerification:  make(map[string]bool),
		parallelCheckChannel: parallelCheckChannel,
		cancelFunc:           cancel,
		account1:             account1,
		account2:             account2,
	}

	ttr1 := transactionTracker{
		t:                    t,
		ctx:                  ctx,
		client:               &relay1,
		othersToVerify:       []chan string{n1chan, n2chan, r2chan, r1chan},
		selfToVerify:         r1chan,
		pendingVerification:  make(map[string]bool),
		parallelCheckChannel: parallelCheckChannel,
		cancelFunc:           cancel,
		account1:             account1,
		account2:             account2,
	}

	ttr2 := transactionTracker{
		t:                    t,
		ctx:                  ctx,
		client:               &relay2,
		othersToVerify:       []chan string{n1chan, n2chan, r1chan, r2chan},
		selfToVerify:         r2chan,
		pendingVerification:  make(map[string]bool),
		parallelCheckChannel: parallelCheckChannel,
		cancelFunc:           cancel,
		account1:             account1,
		account2:             account2,
	}

	minTxnFee, minAcctBalance, err := fixture.CurrentMinFeeAndBalance()
	require.NoError(t, err)

	transactionFee := minTxnFee * 1000
	amount1 := minAcctBalance / uint64(numberOfSends)
	amount2 := minAcctBalance / uint64(numberOfSends)

	defer ttn1.terminate()
	defer ttn2.terminate()
	defer ttr1.terminate()
	defer ttr2.terminate()
	defer cancel()

	st := time.Now()
	for i := 0; i < numberOfSends; i++ {
		select {
		case <-ctx.Done():
			require.True(t, false, "Context canceled due to an error at iteration %d", i)
			return
		default:
		}
		throttleRate(st, targetRate, i*2)
		tx1, err := node1.SendPaymentFromUnencryptedWallet(account1, account2, transactionFee, amount1, GenerateRandomBytes(8))
		require.NoError(t, err, "Failed to send transaction on iteration %d", i)
		ttn1.addTransactionToVerify(tx1.ID().String())

		tx2, err := node2.SendPaymentFromUnencryptedWallet(account2, account1, transactionFee, amount2, GenerateRandomBytes(8))
		require.NoError(t, err, "Failed to send transaction on iteration %d", i)
		ttn2.addTransactionToVerify(tx2.ID().String())
		if i%100 == 0 {
			fmt.Printf("txn sent  %d / %d\n", i, numberOfSends)
		}
	}

	go ttn1.checkAll()
	go ttn2.checkAll()
	go ttr1.checkAll()
	go ttr2.checkAll()

	// wait until all channels are empty for max 50 seconds
	for x := 0; x < 250; x++ {
		select {
		case <-ctx.Done():
			require.True(t, false, "Context canceled due to an error")
		default:
		}

		if ttn1.channelsAreEmpty() {
			break
		}
		time.Sleep(200 * time.Millisecond)
		if x%10 == 0 {
			fmt.Printf("waiting for channel flushing [%d %d %d %d]  %d / %d\n", len(n1chan), len(n2chan), len(r1chan), len(r2chan), x, 250)
		}
	}
	require.True(t, ttn1.channelsAreEmpty())

	unprocessed := 0
	maxWait := 1000
	for x := 0; x < maxWait; x++ {
		select {
		case <-ctx.Done():
			require.True(t, false, "Context canceled due to an error")
		default:
		}
		ttn1.mu.Lock()
		unprocessed = len(ttn1.pendingVerification)
		ttn1.mu.Unlock()

		ttn2.mu.Lock()
		unprocessed += len(ttn2.pendingVerification)
		ttn2.mu.Unlock()

		ttr1.mu.Lock()
		unprocessed += len(ttr1.pendingVerification)
		ttr1.mu.Unlock()

		ttr2.mu.Lock()
		unprocessed += len(ttr2.pendingVerification)
		ttr2.mu.Unlock()

		if unprocessed == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
		if x%10 == 0 {
			fmt.Printf("waiting for pending verificaitons [%d] %d / %d\n", unprocessed, x, maxWait)
		}
	}
	require.Equal(t, 0, unprocessed)
}

type transactionTracker struct {
	t                    *testing.T
	ctx                  context.Context
	mu                   sync.Mutex
	wg                   sync.WaitGroup
	client               *libgoal.Client
	othersToVerify       []chan string
	selfToVerify         chan string
	pendingVerification  map[string]bool
	parallelCheckChannel chan bool
	cancelFunc           context.CancelFunc
	account1             string
	account2             string
}

// Adds the transaction to the channels of the nodes intended to receive the transaction
// This should not block to maintain the transaction rate. Hence, the channel is large enough.
func (tt *transactionTracker) addTransactionToVerify(transactionID string) {
	for _, c := range tt.othersToVerify {
		select {
		case <-tt.ctx.Done():
			return
		case c <- transactionID:
		}
	}
}

func (tt *transactionTracker) checkAll() {
	for len(tt.selfToVerify) > 0 {
		select {
		case <-tt.ctx.Done():
			return
		case tid := <-tt.selfToVerify:
			tt.mu.Lock()
			tt.pendingVerification[tid] = true
			tt.mu.Unlock()
		}
	}

	for len(tt.pendingVerification) != 0 {
		select {
		case <-tt.ctx.Done():
			return
		default:
		}
		transactions, err := tt.client.GetPendingTransactionsByAddress(tt.account1, 1000000)
		require.NoError(tt.t, err)

		for _, transactionInfo := range transactions.TruncatedTxns.Transactions {
			tt.mu.Lock()
			delete(tt.pendingVerification, transactionInfo.TxID)
			tt.mu.Unlock()
		}

		transactions, err = tt.client.GetPendingTransactionsByAddress(tt.account2, 1000000)
		require.NoError(tt.t, err)

		for _, transactionInfo := range transactions.TruncatedTxns.Transactions {
			tt.mu.Lock()
			delete(tt.pendingVerification, transactionInfo.TxID)
			tt.mu.Unlock()
		}
		time.Sleep(50*time.Millisecond)
	}
}

func (tt *transactionTracker) terminate() {
	tt.wg.Wait()
	tt.mu.Lock()
	defer tt.mu.Unlock()
	require.Equal(tt.t, 0, len(tt.pendingVerification))
}

// Retruns true if all the associated channels are empty
func (tt *transactionTracker) channelsAreEmpty() bool {
	for _, c := range tt.othersToVerify {
		if len(c) > 0 {
			return false
		}
	}
	return true
}

// throttle transaction rate
func throttleRate(startTime time.Time, targetRate int, total int) {
	localTimeDelta := time.Now().Sub(startTime)
	currentTps := float64(total) / localTimeDelta.Seconds()
	if currentTps > float64(targetRate) {
		sleepSec := float64(total)/float64(targetRate) - localTimeDelta.Seconds()
		sleepTime := time.Duration(int64(math.Round(sleepSec*1000))) * time.Millisecond
		time.Sleep(sleepTime)
	}
}
