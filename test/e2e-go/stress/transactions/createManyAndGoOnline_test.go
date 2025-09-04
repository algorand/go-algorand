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

package transactions

import (
	"maps"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func cascadeCreateAndFundAccounts(amountToSend, transactionFee uint64, fundingAccount string, client libgoal.Client, a *require.Assertions) map[string]string {
	outputTxidsToAccounts := make(map[string]string)
	const txnPoolLimit = 5 // wait for 5 txns to confirm at a time, as transaction pool rejects more than 5 txns from the same acct at a time
	i := 0                 // for assert debug messages
	for j := 0; j < txnPoolLimit; j++ {
		wh, err := client.GetUnencryptedWalletHandle()
		a.NoError(err, "should be able to get unencrypted wallet handle")
		newAddress, err := client.GenerateAddress(wh)
		a.NoError(err, "should be able to generate new address")
		tx, err := client.SendPaymentFromWallet(wh, nil, fundingAccount, newAddress, transactionFee, amountToSend, nil, "", 0, 0)
		a.NoError(err, "should be no errors when funding new accounts, send number %v", i)
		i++
		outputTxidsToAccounts[tx.ID().String()] = newAddress
	}

	return outputTxidsToAccounts
}

// this test creates many accounts
// sends them all money, and sends them online
func TestManyAccountsCanGoOnline(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer fixture.Shutdown()

	client := fixture.LibGoalClient
	fixtureWallets, _ := fixture.GetWalletsSortedByBalance()
	fundingAccount := fixtureWallets[0].Address

	txidsToAccountsWaveOne := make(map[string]string)
	const transactionFee = uint64(1)
	const fundingTimeoutRound basics.Round = 400
	// cascade-create and fund 1000 accounts
	amountToSend := uint64(560000) // ends up leaving each acct with ~4300 algos, which is more than absolutely necessary to go online
	txidsToAccountsWaveOnePartOne := cascadeCreateAndFundAccounts(amountToSend, transactionFee, fundingAccount, client, a)
	allConfirmed := fixture.WaitForAllTxnsToConfirm(fundingTimeoutRound, txidsToAccountsWaveOnePartOne)
	a.True(allConfirmed, "Not all transactions confirmed. Failing test and aborting early.")
	txidsToAccountsWaveOnePartTwo := cascadeCreateAndFundAccounts(amountToSend, transactionFee, fundingAccount, client, a)
	allConfirmed = fixture.WaitForAllTxnsToConfirm(fundingTimeoutRound, txidsToAccountsWaveOnePartTwo)
	a.True(allConfirmed, "Not all transactions confirmed. Failing test and aborting early.")

	// now have 10 accounts
	// use those to create and fund 100
	eachBalance := amountToSend
	amountToSend = (eachBalance / 10) - 10*transactionFee
	txidsToAccountsWaveTwo := make(map[string]string)
	for _, account := range txidsToAccountsWaveOne {
		txidsToChildAccounts := cascadeCreateAndFundAccounts(amountToSend, transactionFee, account, client, a)
		maps.Copy(txidsToAccountsWaveTwo, txidsToChildAccounts)
	}
	allConfirmed = fixture.WaitForAllTxnsToConfirm(fundingTimeoutRound, txidsToAccountsWaveTwo)
	a.True(allConfirmed, "Not all transactions confirmed. Failing test and aborting early.")
	for _, account := range txidsToAccountsWaveOne {
		txidsToChildAccounts := cascadeCreateAndFundAccounts(amountToSend, transactionFee, account, client, a)
		maps.Copy(txidsToAccountsWaveTwo, txidsToChildAccounts)
	}
	allConfirmed = fixture.WaitForAllTxnsToConfirm(fundingTimeoutRound, txidsToAccountsWaveTwo)
	a.True(allConfirmed, "Not all transactions confirmed. Failing test and aborting early.")
	// now have 100 accounts
	// use those to create and fund 1000
	eachBalance = amountToSend
	amountToSend = (eachBalance / 10) - 10*transactionFee
	txidsToAccountsWaveThree := make(map[string]string)
	for _, account := range txidsToAccountsWaveTwo {
		txidsToChildAccounts := cascadeCreateAndFundAccounts(amountToSend, transactionFee, account, client, a)
		maps.Copy(txidsToAccountsWaveThree, txidsToChildAccounts)
	}
	allConfirmed = fixture.WaitForAllTxnsToConfirm(fundingTimeoutRound, txidsToAccountsWaveThree)
	a.True(allConfirmed, "Not all transactions confirmed. Failing test and aborting early.")

	for _, account := range txidsToAccountsWaveTwo {
		txidsToChildAccounts := cascadeCreateAndFundAccounts(amountToSend, transactionFee, account, client, a)
		maps.Copy(txidsToAccountsWaveThree, txidsToChildAccounts)
	}
	allConfirmed = fixture.WaitForAllTxnsToConfirm(fundingTimeoutRound, txidsToAccountsWaveThree)
	a.True(allConfirmed, "Not all transactions confirmed. Failing test and aborting early.")

	// make funded accounts go online
	const transactionValidityPeriod = 100 // rounds
	_, curRound := fixture.GetBalanceAndRound(fundingAccount)
	i := 0 // for assert debug messages
	txidsToAccountsGoOnline := make(map[string]string)
	for _, account := range txidsToAccountsWaveThree {
		partkeyResponse, _, err := client.GenParticipationKeys(account, curRound-10, curRound+1000, 0)
		a.NoError(err, "should be no errors when creating many partkeys, creation number %v", i)
		a.Equal(account, partkeyResponse.Address, "successful partkey creation should echo account")
		goOnlineUTx, err := client.MakeUnsignedGoOnlineTx(account, curRound, curRound+transactionValidityPeriod, transactionFee, [32]byte{})
		a.NoError(err, "should be able to make go online tx %v", i)
		wh, err := client.GetUnencryptedWalletHandle()
		a.NoError(err, "should be able to get unencrypted wallet handle")
		onlineTxID, err := client.SignAndBroadcastTransaction(wh, nil, goOnlineUTx)
		a.NoError(err, "should be no errors when using partkey to go online, attempt number %v", i)
		i++
		txidsToAccountsGoOnline[onlineTxID] = account
	}
	// wait for txns to clear
	goOnlineTimeoutRound := fundingTimeoutRound + 100
	allConfirmed = fixture.WaitForAllTxnsToConfirm(goOnlineTimeoutRound, txidsToAccountsGoOnline)
	a.True(allConfirmed, "Not all transactions confirmed. Failing test and aborting early.")

	_, curRound = fixture.GetBalanceAndRound(fundingAccount)
	i = 0 // for assert debug messages
	for _, account := range txidsToAccountsWaveThree {
		partkeyResponse, _, err := client.GenParticipationKeys(account, curRound-10, curRound+1000, 0)
		a.NoError(err, "should be no errors when creating many partkeys, creation number %v", i)
		a.Equal(account, partkeyResponse.Address, "successful partkey creation should echo account")

		goOnlineUTx, err := client.MakeUnsignedGoOnlineTx(account, curRound, curRound+transactionValidityPeriod, transactionFee, [32]byte{})
		a.NoError(err, "should be able to make go online tx %v", i)
		wh, err := client.GetUnencryptedWalletHandle()
		a.NoError(err, "should be able to get unencrypted wallet handle")
		onlineTxID, err := client.SignAndBroadcastTransaction(wh, nil, goOnlineUTx)
		a.NoError(err, "should be no errors when using partkey to go online, attempt number %v", i)
		i++
		txidsToAccountsGoOnline[onlineTxID] = account

		// use debug counter to wait for batches of transactions to clear before adding more to the pool
		if i%20 == 0 {
			goOnlineTimeoutRound = fundingTimeoutRound + 100
			allConfirmed = fixture.WaitForAllTxnsToConfirm(goOnlineTimeoutRound, txidsToAccountsGoOnline)
			a.True(allConfirmed, "Not all transactions confirmed. Failing test and aborting early.")
		}
	}

	// wait for the next round after confirmation
	_, curRound = fixture.GetBalanceAndRound(fundingAccount)
	deadline := curRound + 1
	fixture.WaitForRoundWithTimeout(deadline)

	i = 0 // for assert debug messages
	for txid, account := range txidsToAccountsGoOnline {
		accountStatus, err := client.AccountInformation(account, false)
		a.NoError(err)
		_, round := fixture.GetBalanceAndRound(account)
		curTxStatus, err := client.PendingTransactionInformation(txid)
		a.NotNil(curTxStatus.ConfirmedRound)
		a.True(*curTxStatus.ConfirmedRound <= round, "go online transaction confirmed on round %d, current round is %d\n", curTxStatus.ConfirmedRound, round)
		a.NoError(err, "should be no error when querying account information (query number %v regarding account %v)", i, account)
		a.Equal(byte(basics.Online), accountStatus.Status, "account %v should be online by now", account)
		i++
	}
}
