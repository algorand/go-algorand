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

	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

// TestTxnSync sends payments between two nodes, and verifies that
// each transaction is received by the other node and the relay
func TestTxnSync(t *testing.T) {
	t.Parallel()

	// maxParallelChecks is the number of goroutines will simultaniously check if the
	// transaction is received by the node.
	// If this is too large, the system will report too many open files.
	// If too small, the txns will be moved to the block.
	maxParallelChecks := 100
	numberOfSends := 2500
	targetRate := 300 // txn/sec
	if testing.Short() {
		numberOfSends = 100
	}
	templatePath := filepath.Join("nettemplates", "TwoNodes50EachWithTwoRelays.json")

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, templatePath)

	node1 := fixture.GetLibGoalClientForNamedNode("Node1")
	node2 := fixture.GetLibGoalClientForNamedNode("Node2")
	relay1 := fixture.GetLibGoalClientForNamedNode("Relay1")
	relay2 := fixture.GetLibGoalClientForNamedNode("Relay2")

	n1chan := make(chan string, numberOfSends)
	n2chan := make(chan string, numberOfSends)
	r1chan := make(chan string, numberOfSends*2)
	r2chan := make(chan string, numberOfSends*2)

	parallelCheckChannel := make(chan bool, maxParallelChecks)

	ctx, cancel := context.WithCancel(context.Background())

	ttn1 := transactionTracker{
		t:                    t,
		ctx:                  ctx,
		client:               &node1,
		othersToVerify:       []chan string{n2chan, r1chan, r2chan},
		selfToVerify:         n1chan,
		pendingVerification:  make(map[string]bool),
		parallelCheckChannel: parallelCheckChannel,
		cancelFunc:           cancel,
	}

	ttn2 := transactionTracker{
		t:                    t,
		ctx:                  ctx,
		client:               &node2,
		othersToVerify:       []chan string{n1chan, r1chan, r2chan},
		selfToVerify:         n2chan,
		pendingVerification:  make(map[string]bool),
		parallelCheckChannel: parallelCheckChannel,
		cancelFunc:           cancel,
	}

	ttr1 := transactionTracker{
		t:                    t,
		ctx:                  ctx,
		client:               &relay1,
		othersToVerify:       []chan string{n1chan, n2chan, r2chan},
		selfToVerify:         r1chan,
		pendingVerification:  make(map[string]bool),
		parallelCheckChannel: parallelCheckChannel,
		cancelFunc:           cancel,
	}

	ttr2 := transactionTracker{
		t:                    t,
		ctx:                  ctx,
		client:               &relay2,
		othersToVerify:       []chan string{n1chan, n2chan, r1chan},
		selfToVerify:         r2chan,
		pendingVerification:  make(map[string]bool),
		parallelCheckChannel: parallelCheckChannel,
		cancelFunc:           cancel,
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

	transactionFee := minTxnFee * 5
	amount1 := minAcctBalance / uint64(numberOfSends)
	amount2 := minAcctBalance / uint64(numberOfSends)

	go ttn1.verifyTransactions()
	go ttn2.verifyTransactions()
	go ttr1.verifyTransactions()
	go ttr2.verifyTransactions()

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
			fmt.Printf("txn iteration %d\n", i)
		}
	}

	// wait until all channels are empty for max 50 seconds
	for x := 0; x < 250; x++ {
		select {
		case <-ctx.Done():
			require.True(t, false, "Context canceled due to an error")
			return
		default:
		}

		if ttn1.channelsAreEmpty() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	require.True(t, ttn1.channelsAreEmpty())

	unprocessed := 0
	for x := 0; x < numberOfSends/10; x++ {
		fmt.Printf("unprocessed items: %d\n", unprocessed)
		select {
		case <-ctx.Done():
			require.True(t, false, "Context canceled due to an error")
			return
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
}

func (tt *transactionTracker) terminate() {
	tt.wg.Wait()
	tt.mu.Lock()
	defer tt.mu.Unlock()
	require.Equal(tt.t, 0, len(tt.pendingVerification))
}

// Adds the transaction to the channels of the nodes intended to receive the transaction
// This should not block to maintain the transaction rate. Hence, the channel is large enough.
func (tt *transactionTracker) addTransactionToVerify(transactionID string) {
	for _, c := range tt.othersToVerify {
		c <- transactionID
	}
}

// Pulls transactions from the channel and pushes them to another limited bandwith channel
// Then, the check if the node received is performed async
func (tt *transactionTracker) verifyTransactions() {
	for {
		select {
		case <-tt.ctx.Done():
			return
		case tid := <-tt.selfToVerify:
			tt.mu.Lock()
			tt.pendingVerification[tid] = true
			tt.mu.Unlock()
			// This may be blocked untill there is room in parallelCheckChannel
			tt.parallelCheckChannel <- true
			tt.wg.Add(1)
			go tt.checkIfReceivedTransaction(tid)
		}
	}
}

// Waits until gets a confirmation that the transaction is recieved by the node
func (tt *transactionTracker) checkIfReceivedTransaction(transactionID string) {
	defer tt.wg.Done()
	startTime := time.Now()
	tries := 0
	for {
		select {
		case <-tt.ctx.Done():
			return
		default:
			transactionInfo, err := tt.client.PendingTransactionInformation(transactionID)
			tries++
			if err != nil {
				if err.Error() != "HTTP 404 Not Found: couldn't find the required transaction in the required range" {
					require.NoError(tt.t, err)
					tt.cancelFunc()
					fmt.Println(err)
				}
				throttleRate(startTime, 3, tries)
				continue
			}
			if transactionInfo.ConfirmedRound > 0 {
				fmt.Printf("Out of pool %d try %d\n", int(transactionInfo.ConfirmedRound), tries)
				tt.cancelFunc()
			}
			require.Equal(tt.t, 0, int(transactionInfo.ConfirmedRound))
		}
		break
	}
	if tries > 10 {
		fmt.Print("Tries ")
		fmt.Println(tries)
	}
	<-tt.parallelCheckChannel
	// if received
	tt.mu.Lock()
	defer tt.mu.Unlock()
	delete(tt.pendingVerification, transactionID)
}

// Retruns true if all the associated channels are empty
func (tt *transactionTracker) channelsAreEmpty() bool {
	if len(tt.selfToVerify) > 0 {
		fmt.Printf("channelsAreEmpty0 %d\n", len(tt.selfToVerify))
		return false
	}
	for _, c := range tt.othersToVerify {
		if len(c) > 0 {
			fmt.Printf("channelsAreEmpty %d\n", len(c))
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
