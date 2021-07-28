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
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

// TestTxnSync sends payments between two nodes, and verifies that
// each transaction is received by the other node and the relay
func TestTxnSync(t *testing.T) {
	t.Parallel()

	numberOfSends := 2500
	targetRate := 30 // txn/sec
	if testing.Short() {
		numberOfSends = 3
	}
	templatePath := filepath.Join("nettemplates", "TwoNodes50EachWithRelay.json")

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, templatePath)

	node1 := fixture.GetLibGoalClientForNamedNode("Node1")
	node2 := fixture.GetLibGoalClientForNamedNode("Node2")
	relay := fixture.GetLibGoalClientForNamedNode("Relay")

	n1chan := make(chan string)
	n2chan := make(chan string)
	rchan := make(chan string)

	ctx, cancel := context.WithCancel(context.Background())

	ttn1 := transactionTracker{
		t:                   t,
		ctx:                 ctx,
		client:              &node1,
		othersToVerify:      []chan string{n2chan, rchan},
		selfToVerify:        n1chan,
		pendingVerification: make(map[string]bool),
	}

	ttn2 := transactionTracker{
		t:                   t,
		ctx:                 ctx,
		client:              &node2,
		othersToVerify:      []chan string{n1chan, rchan},
		selfToVerify:        n2chan,
		pendingVerification: make(map[string]bool),
	}

	ttr := transactionTracker{
		t:                   t,
		ctx:                 ctx,
		client:              &relay,
		othersToVerify:      []chan string{n1chan, n2chan},
		selfToVerify:        rchan,
		pendingVerification: make(map[string]bool),
	}

	defer fixture.Shutdown()

	account1List, err := fixture.GetNodeWalletsSortedByBalance(node1.DataDir())
	require.NoError(t, err)
	account1 := account1List[0].Address

	account2List, err := fixture.GetNodeWalletsSortedByBalance(node2.DataDir())
	require.NoError(t, err)
	account2 := account2List[0].Address

	minTxnFee, minAcctBalance, err := fixture.CurrentMinFeeAndBalance()
	require.NoError(t, err)

	transactionFee := minTxnFee + 5
	amount1 := minAcctBalance / uint64(numberOfSends)
	amount2 := minAcctBalance / uint64(numberOfSends)

	go ttn1.verifyTransactions()
	go ttn2.verifyTransactions()
	go ttr.verifyTransactions()

	st := time.Now()

	for i := 0; i < numberOfSends; i++ {
		tx1, err := node1.SendPaymentFromUnencryptedWallet(account1, account2, transactionFee, amount1, GenerateRandomBytes(8))
		require.NoError(t, err, "Failed to send transaction on iteration %d", i)
		ttn1.addTransactionToVerify(tx1.ID().String())
		tx2, err := node2.SendPaymentFromUnencryptedWallet(account2, account1, transactionFee, amount2, GenerateRandomBytes(8))
		require.NoError(t, err, "Failed to send transaction on iteration %d", i)
		// Post "http://127.0.0.1:57255/v1/transactions": dial tcp 127.0.0.1:57255: connect: can't assign requested address
		ttn2.addTransactionToVerify(tx2.ID().String())

		throttleTransactionRate(st, targetRate, i)
	}

	// wait until all channels are empty for max 1 second
	for x := 0; x < 100; x++ {
		if ttn1.channelsAreEmpty() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.True(t, ttn1.channelsAreEmpty())

	for x := 0; x < 100; x++ {
		unprocessed := len(ttn1.pendingVerification) +
			len(ttn2.pendingVerification) +
			len(ttr.pendingVerification)
		if unprocessed == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	ttn1.wg.Wait()
	ttn2.wg.Wait()
	ttr.wg.Wait()

	require.Empty(t, ttn1.pendingVerification)
	require.Empty(t, ttn2.pendingVerification)
	require.Empty(t, ttr.pendingVerification)
}

type transactionTracker struct {
	t                   *testing.T
	ctx                 context.Context
	mu                  sync.Mutex
	wg                  sync.WaitGroup
	client              *libgoal.Client
	othersToVerify      []chan string
	selfToVerify        chan string
	pendingVerification map[string]bool
}

// Adds the transaction to the channels of the nodes intended to receive the transaction
func (tt *transactionTracker) addTransactionToVerify(transactionID string) {
	for _, c := range tt.othersToVerify {
		c <- transactionID
	}
}

// Pulls transactions from the channel and async checks if recived by the node  
func (tt *transactionTracker) verifyTransactions() {
	for {
		select {
		case <-tt.ctx.Done():
			return
		case tid := <-tt.selfToVerify:
			tt.mu.Lock()
			tt.pendingVerification[tid] = true
			tt.mu.Unlock()
			go tt.checkIfReceivedTransaction(tid)
		default:
		}
	}
}

// Waits until gets a confirmation that the transaction is recieved by the node
func (tt *transactionTracker) checkIfReceivedTransaction(transactionID string) {
	tt.wg.Add(1)
	defer tt.wg.Done()
	for {
		select {
		case <-tt.ctx.Done():
			return
		default:
			transactionInfo, err := tt.client.PendingTransactionInformation(transactionID)
			if err != nil {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			require.NotNil(tt.t, transactionInfo)
		}
		break
	}
	// if received
	tt.mu.Lock()
	defer tt.mu.Unlock()
	delete(tt.pendingVerification, transactionID)
}

// Retruns true if all the associated channels are empty
func (tt *transactionTracker) channelsAreEmpty() bool {
	if len(tt.selfToVerify) > 0 {
		return false
	}
	for _, c := range tt.othersToVerify {
		if len(c) > 0 {
			return false
		}
	}
	return true
}

// throttle transaction rate
func throttleTransactionRate(startTime time.Time, targetRate int, totalSent int) {
	localTimeDelta := time.Now().Sub(startTime)
	currentTps := float64(totalSent) / localTimeDelta.Seconds()
	if currentTps > float64(targetRate) {
		sleepSec := float64(totalSent)/float64(targetRate) - localTimeDelta.Seconds()
		sleepTime := time.Duration(int64(math.Round(sleepSec*1000))) * time.Millisecond
		time.Sleep(sleepTime)
	}
}
