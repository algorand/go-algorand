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
	"math/rand"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/testpartitioning"
)

func TestTransactionPoolOrderingAndClearing(t *testing.T) {
	testpartitioning.PartitionTest(t)

	t.Skip("test is flaky as of 2019-06-18")
	t.Parallel()
	r := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachOneOnline.json"))
	defer fixture.Shutdown()
	c := fixture.LibGoalClient

	// stop the other node in this network so that no new blocks are produced
	otherNode, err := fixture.GetNodeController("Node")
	r.NoError(err, "should be able to get other node's controller")
	err = otherNode.StopAlgod()
	r.NoError(err, "should be able to stop other node")
	// get the round that the network was stopped on, it will be used when the network restarts
	curStatus, _ := c.Status()
	stoppedRound := curStatus.LastRound

	minTxnFee, minAcctBalance, err := fixture.MinFeeAndBalance(curStatus.LastRound)
	r.NoError(err)

	// put transactions in the pool - they cannot be removed from the pool while the node is stopped
	numTransactions := 25
	sourceAccount, err := fixture.GetRichestAccount()
	r.NoError(err, "should be able to get richest account")
	wh, err := c.GetUnencryptedWalletHandle()
	r.NoError(err, "should be able to get unencrypted wallet handle")
	fixedRandSeed := int64(0)
	rand.Seed(fixedRandSeed)
	var pendingTxids []string
	txidsAndAddressesForConfirmationChecking := make(map[string]string)
	for i := 0; i < numTransactions; i++ {
		newAccount, err := c.GenerateAddress(wh)
		r.NoError(err, "should be able to generate new address")
		txnFee := uint64(rand.Int()%10000) + minTxnFee
		tx, err := c.SendPaymentFromUnencryptedWallet(sourceAccount.Address, newAccount, txnFee, minAcctBalance, nil)
		r.NoError(err)
		fixture.AssertValidTxid(tx.ID().String())
		pendingTxids = append(pendingTxids, tx.ID().String())
		txidsAndAddressesForConfirmationChecking[tx.ID().String()] = sourceAccount.Address
	}
	// examine the pending pool
	pendingTxnsResponse, err := c.GetPendingTransactions(uint64(0)) // "0" == "give everything you know of"
	r.NoError(err, "should be able to get pending transactions")
	// verify len(pending) is correct
	r.Equal(uint64(numTransactions), pendingTxnsResponse.TotalTxns)
	// verify pending is sorted by priority
	// (which, since each txn is of equal length, is equivalent to fee)
	pendingTxns := pendingTxnsResponse.TruncatedTxns.Transactions
	r.Equal(uint64(len(pendingTxnsResponse.TruncatedTxns.Transactions)), pendingTxnsResponse.TotalTxns)
	last := pendingTxns[0].Fee
	for i := 0; i < numTransactions; i++ {
		r.False(last < pendingTxns[i].Fee)
		last = pendingTxns[i].Fee
	}
	// start the other node again
	_, err = fixture.StartNode(otherNode.GetDataDir())
	r.NoError(err)
	// wait for the pending transactions to be confirmed,
	// then demonstrate they ended up in the confirmed blocks
	timeoutRound := stoppedRound + uint64(5)
	fixture.WaitForAllTxnsToConfirm(timeoutRound, txidsAndAddressesForConfirmationChecking)
	latestStatus, err := c.Status()
	r.NoError(err)
	latestRound := latestStatus.LastRound
	var confirmedTransactions []string
	for i := stoppedRound; i < latestRound; i++ {
		block, err := c.Block(i)
		r.NoError(err)
		for _, tx := range block.Transactions.Transactions {
			confirmedTransactions = append(confirmedTransactions, tx.TxID)
		}
	}
	for _, confirmedTransaction := range confirmedTransactions {
		r.Contains(pendingTxids, confirmedTransaction)
	}
	// check the pending pool now and confirm it's empty
	pendingTxnsResponse, err = c.GetPendingTransactions(uint64(0))
	r.NoError(err, "should be able to get pending transactions")
	// verify len(pending) is correct
	r.Equal(uint64(0), pendingTxnsResponse.TotalTxns)

}

func TestTransactionPoolExponentialFees(t *testing.T) {
	testpartitioning.PartitionTest(t)

	t.Skip("new FIFO pool does not have exponential fee txn replacement")

	t.Parallel()
	r := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer fixture.Shutdown()
	c := fixture.LibGoalClient

	// stop the other node in this network so that no new blocks are produced
	otherNode, err := fixture.GetNodeController("Node")
	r.NoError(err, "should be able to get other node's controller")
	err = otherNode.StopAlgod()
	r.NoError(err, "should be able to stop other node")
	// put transactions in the pool - they cannot be removed from the pool while the node is stopped
	transactionPoolSize := 50000
	sourceAccount, err := fixture.GetRichestAccount()
	r.NoError(err, "should be able to get richest account")
	wh, err := c.GetUnencryptedWalletHandle()
	r.NoError(err, "should be able to get unencrypted wallet handle")

	minTxnFee, minAcctBalance, err := fixture.CurrentMinFeeAndBalance()
	r.NoError(err)

	txnFee := minTxnFee
	for i := 0; i < transactionPoolSize; i++ {
		newAccount, err := c.GenerateAddress(wh)
		r.NoError(err, "should be able to generate new address")
		tx, err := c.SendPaymentFromUnencryptedWallet(sourceAccount.Address, newAccount, txnFee, minAcctBalance, nil)
		r.NoError(err, "got an error on number %d", i)
		fixture.AssertValidTxid(tx.ID().String())
	}
	// the transaction pool is now full.
	// it will take an exponentially-increasing fee to add more transactions.
	// try to add another one without increasing the fee to see an error.
	newAccount, err := c.GenerateAddress(wh)
	r.NoError(err, "should be able to generate new address")
	_, err = c.SendPaymentFromUnencryptedWallet(sourceAccount.Address, newAccount, txnFee, minAcctBalance, nil)
	r.Error(err, "should not be able to add a 50001th txn")
	// replace as many transactions as we can and see no error.
	// (will have to abort early, of course, because we cannot go all the way up to 2^50000 algos fee.)
	for i := 0; i < transactionPoolSize; i++ {
		txnFee = txnFee * 2
		// if the txnFee is "enormous", we're done checking
		if txnFee > (sourceAccount.Amount / 2) {
			break
		}
		newAccount, err := c.GenerateAddress(wh)
		r.NoError(err, "should be able to generate new address")
		tx, err := c.SendPaymentFromUnencryptedWallet(sourceAccount.Address, newAccount, txnFee, minAcctBalance, nil)
		r.NoError(err, "should be able to add exponentially-more-fee-paying transaction to pool")
		fixture.AssertValidTxid(tx.ID().String())
	}
}
