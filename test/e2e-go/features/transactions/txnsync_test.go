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
	"testing"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

// This test sets up a network with 2 nodes and 2 relays.
// The two nodes send payment transactions.

// For each transaction, the test checks if the relays and the nodes
// (including the node that originated the transaction) have the
// transaction in the pool (i.e. the transactionInfo.ConfirmedRound ==
// 0).

// The tests needs to check for the transactions in the pool fast
// enough before they get evicted from the pool to the block.

// To achieve this, it sends transactions during the first half of the
// round period, to give the test enough time to check for the
// transactions.
func TestTxnSync(t *testing.T) {
	t.Parallel()

	maxNumberOfSends := 1200
	maxRate := 1000 // txn/sec
	if testing.Short() {
		maxNumberOfSends = 300
	}
	templatePath := filepath.Join("nettemplates", "TwoNodes50EachWithTwoRelays.json")

	var fixture fixtures.RestClientFixture

	roundTime := time.Duration(8 * 1000 * time.Millisecond)

	proto, ok := config.Consensus[protocol.ConsensusCurrentVersion]
	require.True(t, ok)
	proto.AgreementFilterTimeoutPeriod0 = roundTime
	proto.AgreementFilterTimeout = roundTime
	fixture.SetConsensus(config.ConsensusProtocols{protocol.ConsensusCurrentVersion: proto})

	fixture.Setup(t, templatePath)
	defer fixture.Shutdown()

	node1 := fixture.GetLibGoalClientForNamedNode("Node1")
	node2 := fixture.GetLibGoalClientForNamedNode("Node2")
	relay1 := fixture.GetLibGoalClientForNamedNode("Relay1")
	relay2 := fixture.GetLibGoalClientForNamedNode("Relay2")

	n1chan := make(chan string, maxNumberOfSends*2)
	n2chan := make(chan string, maxNumberOfSends*2)
	r1chan := make(chan string, maxNumberOfSends*2)
	r2chan := make(chan string, maxNumberOfSends*2)

	ctx, cancel := context.WithCancel(context.Background())

	account1List, err := fixture.GetNodeWalletsSortedByBalance(node1.DataDir())
	require.NoError(t, err)
	account1 := account1List[0].Address

	account2List, err := fixture.GetNodeWalletsSortedByBalance(node2.DataDir())
	require.NoError(t, err)
	account2 := account2List[0].Address

	ttn1 := transactionTracker{
		t:                   t,
		ctx:                 ctx,
		client:              &node1,
		othersToVerify:      []chan string{n2chan, r1chan, r2chan, n1chan},
		selfToVerify:        n1chan,
		pendingVerification: make(map[string]bool),
		account1:            account1,
		account2:            account2,
		name:                "node1",
		cancelFunc:          cancel,
	}

	ttn2 := transactionTracker{
		t:                   t,
		ctx:                 ctx,
		client:              &node2,
		othersToVerify:      []chan string{n1chan, r1chan, r2chan, n2chan},
		selfToVerify:        n2chan,
		pendingVerification: make(map[string]bool),
		account1:            account1,
		account2:            account2,
		name:                "node2",
		cancelFunc:          cancel,
	}

	ttr1 := transactionTracker{
		t:                   t,
		ctx:                 ctx,
		client:              &relay1,
		othersToVerify:      []chan string{n1chan, n2chan, r2chan, r1chan},
		selfToVerify:        r1chan,
		pendingVerification: make(map[string]bool),
		account1:            account1,
		account2:            account2,
		name:                "relay1",
		cancelFunc:          cancel,
	}

	ttr2 := transactionTracker{
		t:                   t,
		ctx:                 ctx,
		client:              &relay2,
		othersToVerify:      []chan string{n1chan, n2chan, r1chan, r2chan},
		selfToVerify:        r2chan,
		pendingVerification: make(map[string]bool),
		account1:            account1,
		account2:            account2,
		name:                "relay2",
		cancelFunc:          cancel,
	}

	minTxnFee, minAcctBalance, err := fixture.CurrentMinFeeAndBalance()
	require.NoError(t, err)

	transactionFee := minTxnFee * 1000
	amount1 := minAcctBalance / uint64(maxNumberOfSends)
	amount2 := minAcctBalance / uint64(maxNumberOfSends)

	defer ttn1.terminate()
	defer ttn2.terminate()
	defer ttr1.terminate()
	defer ttr2.terminate()

	defer cancel()

	go ttn1.passTxnsToVeirfy()
	go ttn2.passTxnsToVeirfy()
	go ttr1.passTxnsToVeirfy()
	go ttr2.passTxnsToVeirfy()

	go ttn1.checkAll()
	go ttn2.checkAll()
	go ttr1.checkAll()
	go ttr2.checkAll()

	// wait for the 1st round
	nextRound := uint64(1)
	err = fixture.ClientWaitForRound(fixture.AlgodClient, nextRound, 20*roundTime)
	require.NoError(t, err)
	nextRound++

	st := time.Now()
	timeout := time.NewTimer(roundTime / 2)

	for i := 0; i < maxNumberOfSends; i++ {

		select {
		case <-ctx.Done():
			require.True(t, false, "Context canceled due to an error at iteration %d", i)
			return
		case <-timeout.C:
			// Send the transactions only during the first half of the round
			// Wait for the next round, and stop sending transactions after the first half
			err = fixture.ClientWaitForRound(fixture.AlgodClient, nextRound, 2*roundTime)
			require.NoError(t, err)
			fmt.Printf("Round %d\n", int(nextRound))
			nextRound++
			timeout = time.NewTimer(roundTime / 2)
		default:
		}
		throttleRate(st, maxRate, i*2)
		tx1, err := node1.SendPaymentFromUnencryptedWallet(account1, account2, transactionFee, amount1, GenerateRandomBytes(8))
		require.NoError(t, err, "Failed to send transaction on iteration %d", i)
		ttn1.addTransactionToVerify(tx1.ID().String())

		tx2, err := node2.SendPaymentFromUnencryptedWallet(account2, account1, transactionFee, amount2, GenerateRandomBytes(8))
		require.NoError(t, err, "Failed to send transaction on iteration %d", i)
		ttn2.addTransactionToVerify(tx2.ID().String())
		if i%100 == 0 {
			fmt.Printf("txn sent  %d / %d\n", i, maxNumberOfSends)
		}
	}
	close(ttn1.selfToVerify)
	close(ttn2.selfToVerify)
	close(ttr1.selfToVerify)
	close(ttr2.selfToVerify)

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
	maxWait := 100
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
		time.Sleep(200 * time.Millisecond)
		if x%10 == 0 {
			fmt.Printf("waiting for pending verificaitons [%d] %d / %d\n", unprocessed, x, maxWait)
		}
	}
	require.Equal(t, 0, unprocessed, "missing %d transactions", unprocessed)
}

type transactionTracker struct {
	t                   *testing.T
	ctx                 context.Context
	mu                  deadlock.Mutex
	client              *libgoal.Client
	othersToVerify      []chan string
	selfToVerify        chan string
	pendingVerification map[string]bool
	account1            string
	account2            string
	name                string
	cancelFunc          context.CancelFunc
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

func (tt *transactionTracker) passTxnsToVeirfy() {
	for tid := range tt.selfToVerify {
		select {
		case <-tt.ctx.Done():
			return
		default:
		}

		tt.mu.Lock()
		tt.pendingVerification[tid] = true
		tt.mu.Unlock()
	}
}

func (tt *transactionTracker) checkAll() {
	for {
		select {
		case <-tt.ctx.Done():
			return
		case _, more := <-tt.selfToVerify:
			tt.mu.Lock()
			if !more && len(tt.pendingVerification) == 0 {
				tt.mu.Unlock()
				return
			}
			tt.mu.Unlock()
		default:
		}
		transactions, err := tt.client.GetPendingTransactionsByAddress(tt.account1, 1000000)
		if err != nil {
			tt.cancelFunc()
			require.NoError(tt.t, err)
		}

		for _, transactionInfo := range transactions.TruncatedTxns.Transactions {
			tt.mu.Lock()
			if _, ok := tt.pendingVerification[transactionInfo.TxID]; ok {
				delete(tt.pendingVerification, transactionInfo.TxID)
			}
			tt.mu.Unlock()
		}

		transactions, err = tt.client.GetPendingTransactionsByAddress(tt.account2, 1000000)
		if err != nil {
			tt.cancelFunc()
			require.NoError(tt.t, err)
		}

		for _, transactionInfo := range transactions.TruncatedTxns.Transactions {
			tt.mu.Lock()
			if _, ok := tt.pendingVerification[transactionInfo.TxID]; ok {
				delete(tt.pendingVerification, transactionInfo.TxID)
			}
			tt.mu.Unlock()
		}
		time.Sleep(time.Second)
	}
}

func (tt *transactionTracker) terminate() {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	require.Equal(tt.t, 0, len(tt.pendingVerification), "%s is missing %d transactions", tt.name, len(tt.pendingVerification))
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
