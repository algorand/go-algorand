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

package fixtures

import (
	"fmt"
	"sort"
	"time"
	"unicode"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/test/e2e-go/globals"
	"github.com/algorand/go-algorand/util/tokens"
)

// RestClientFixture is a test fixture for tests requiring a running node with a REST client
type RestClientFixture struct {
	LibGoalFixture
	AlgodClient client.RestClient
}

// Setup is called to initialize the test fixture for the test(s)
func (f *RestClientFixture) Setup(t TestingTB, templateFile string) {
	f.LibGoalFixture.Setup(t, templateFile)
	f.AlgodClient = f.GetAlgodClientForController(f.NC)
}

// SetupNoStart is called to initialize the test fixture for the test(s)
// but does not start the network before returning.  Call NC.Start() to start later.
func (f *RestClientFixture) SetupNoStart(t TestingTB, templateFile string) {
	f.LibGoalFixture.SetupNoStart(t, templateFile)
}

// SetupShared is called to initialize the test fixture that will be used for multiple tests
func (f *RestClientFixture) SetupShared(testName string, templateFile string) {
	f.LibGoalFixture.SetupShared(testName, templateFile)
	f.AlgodClient = f.GetAlgodClientForController(f.NC)
}

// GetAlgodClientForController returns a RestClient for the specified NodeController
func (f *RestClientFixture) GetAlgodClientForController(nc nodecontrol.NodeController) client.RestClient {
	url, err := nc.ServerURL()
	f.failOnError(err, fmt.Sprintf("get ServerURL failed for %s: %%v", nc.GetDataDir()))
	adminAPIToken, err := tokens.GetAndValidateAPIToken(nc.GetDataDir(), tokens.AlgodAdminTokenFilename)
	f.failOnError(err, "error validating AdminAPIToken for node: %v")
	return client.MakeRestClient(url, adminAPIToken)
}

// WaitForRound waits up to the specified amount of time for
// the network to reach or pass the specified round
func (f *RestClientFixture) WaitForRound(round uint64, waitTime time.Duration) error {
	return f.ClientWaitForRound(f.AlgodClient, round, waitTime)
}

// ClientWaitForRound waits up to the specified amount of time for
// the network to reach or pass the specified round, on the specific client/node
func (f *RestClientFixture) ClientWaitForRound(client client.RestClient, round uint64, waitTime time.Duration) error {
	timeout := time.NewTimer(waitTime)
	for {
		status, err := client.Status()
		if err != nil {
			return err
		}

		if status.LastRound >= round {
			return nil
		}
		select {
		case <-timeout.C:
			return fmt.Errorf("timeout waiting for round %v", round)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// WaitForRoundWithTimeout waits for a given round to reach. The implementation also ensures to limit the wait time for each round to the
// globals.MaxTimePerRound so we can alert when we're getting "hung" before waiting for all the expected rounds to reach.
func (f *RestClientFixture) WaitForRoundWithTimeout(roundToWaitFor uint64) error {
	return f.ClientWaitForRoundWithTimeout(f.AlgodClient, roundToWaitFor)
}

const singleRoundMaxTime = globals.MaxTimePerRound * 40

// ClientWaitForRoundWithTimeout waits for a given round to be reached by the specific client/node. The implementation
// also ensures to limit the wait time for each round to the globals.MaxTimePerRound so we can alert when we're
// getting "hung" before waiting for all the expected rounds to reach.
func (f *RestClientFixture) ClientWaitForRoundWithTimeout(client client.RestClient, roundToWaitFor uint64) error {
	status, err := client.Status()
	require.NoError(f.t, err)
	lastRound := status.LastRound

	// If node is already at or past target round, we're done
	if lastRound >= roundToWaitFor {
		return nil
	}

	roundTime := globals.MaxTimePerRound * 10 // For first block, we wait much longer
	roundComplete := make(chan error, 2)

	for nextRound := lastRound + 1; lastRound < roundToWaitFor; {
		roundStarted := time.Now()

		go func(done chan error) {
			err := f.ClientWaitForRound(client, nextRound, roundTime)
			done <- err
		}(roundComplete)

		select {
		case lastError := <-roundComplete:
			if lastError != nil {
				close(roundComplete)
				return lastError
			}
		case <-time.After(roundTime):
			// we've timed out.
			time := time.Now().Sub(roundStarted)
			return fmt.Errorf("fixture.WaitForRound took %3.2f seconds between round %d and %d", time.Seconds(), lastRound, nextRound)
		}

		roundTime = singleRoundMaxTime
		lastRound++
		nextRound++
	}
	return nil
}

// GetFirstAccount returns the first account from listing local accounts
func (f *RestClientFixture) GetFirstAccount() (account string, err error) {
	client := f.LibGoalClient
	wh, err := client.GetUnencryptedWalletHandle()
	if err != nil {
		return
	}
	accounts, err := client.ListAddresses(wh)
	if err != nil {
		return
	}
	account = accounts[0]
	return
}

// GetRichestAccount returns the first account when calling GetWalletsSortedByBalance, which should be the richest account
func (f *RestClientFixture) GetRichestAccount() (richest v1.Account, err error) {
	list, err := f.GetWalletsSortedByBalance()
	if len(list) > 0 {
		richest = list[0]
	}
	return
}

// GetBalanceAndRound returns the current balance of an account and the current round for that balance
func (f *RestClientFixture) GetBalanceAndRound(account string) (balance uint64, round uint64) {
	client := f.LibGoalClient
	status, err := client.Status()
	require.NoError(f.t, err, "client should be able to get status")
	round = status.LastRound

	balance, err = client.GetBalance(account)
	require.NoError(f.t, err, "client should be able to get balance")
	if err != nil {
		return
	}
	return
}

// GetWalletsSortedByBalance returns the Primary node's accounts sorted DESC by balance
// the richest account will be at accounts[0]
func (f *RestClientFixture) GetWalletsSortedByBalance() (accounts []v1.Account, err error) {
	return f.getNodeWalletsSortedByBalance(f.LibGoalClient)
}

// GetNodeWalletsSortedByBalance returns the specified node's accounts sorted DESC by balance
// the richest account will be at accounts[0]
func (f *RestClientFixture) GetNodeWalletsSortedByBalance(nodeDataDir string) (accounts []v1.Account, err error) {
	return f.getNodeWalletsSortedByBalance(f.GetLibGoalClientFromDataDir(nodeDataDir))
}

func (f *RestClientFixture) getNodeWalletsSortedByBalance(client libgoal.Client) (accounts []v1.Account, err error) {
	wh, err := client.GetUnencryptedWalletHandle()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve wallet handle : %v", err)
	}
	addresses, err := client.ListAddresses(wh)
	if err != nil {
		return nil, fmt.Errorf("unable to list wallet addresses : %v", err)
	}
	for _, addr := range addresses {
		info, err := client.AccountInformation(addr)
		f.failOnError(err, "failed to get account info: %v")
		accounts = append(accounts, info)
	}
	sort.SliceStable(accounts, func(i, j int) bool {
		return accounts[i].Amount > accounts[j].Amount
	})
	return accounts, nil
}

// WaitForTxnConfirmation waits until either the passed txid is confirmed
// or until the passed roundTimeout passes
// or until waiting for a round to pass times out
func (f *RestClientFixture) WaitForTxnConfirmation(roundTimeout uint64, accountAddress, txid string) bool {
	_, err := f.WaitForConfirmedTxn(roundTimeout, accountAddress, txid)
	return err == nil
}

// WaitForConfirmedTxn waits until either the passed txid is confirmed
// or until the passed roundTimeout passes
// or until waiting for a round to pass times out
func (f *RestClientFixture) WaitForConfirmedTxn(roundTimeout uint64, accountAddress, txid string) (txn v1.Transaction, err error) {
	client := f.AlgodClient
	for {
		// Get current round information
		curStatus, statusErr := client.Status()
		require.NoError(f.t, statusErr, "fixture should be able to get node status")
		curRound := curStatus.LastRound

		// Check if we know about the transaction yet
		txn, err = client.TransactionInformation(accountAddress, txid)
		if err == nil {
			return
		}

		// Check if we should wait a round
		if curRound > roundTimeout {
			err = fmt.Errorf("failed to see confirmed transaction by round %v", roundTimeout)
			return
		}
		// Wait a round
		err = f.WaitForRoundWithTimeout(curRound + 1)
		require.NoError(f.t, err, "fixture should be able to wait for one round to pass")
	}
}

// WaitForAllTxnsToConfirm is as WaitForTxnConfirmation,
// but accepting a whole map of txids to their issuing address
func (f *RestClientFixture) WaitForAllTxnsToConfirm(roundTimeout uint64, txidsAndAddresses map[string]string) bool {
	if len(txidsAndAddresses) == 0 {
		return true
	}
	for txid, addr := range txidsAndAddresses {
		_, err := f.WaitForConfirmedTxn(roundTimeout, addr, txid)
		if err != nil {
			return false
		}
	}
	return true
}

// SendMoneyAndWait uses the rest client to send money and WaitForTxnConfirmation to wait for the send to confirm
// it adds some extra error checking as well
func (f *RestClientFixture) SendMoneyAndWait(curRound, amountToSend, transactionFee uint64, fromAccount, toAccount string, closeToAccount string) (txn v1.Transaction) {
	client := f.LibGoalClient
	wh, err := client.GetUnencryptedWalletHandle()
	require.NoError(f.t, err, "client should be able to get unencrypted wallet handle")
	txn = f.SendMoneyAndWaitFromWallet(wh, nil, curRound, amountToSend, transactionFee, fromAccount, toAccount, closeToAccount)
	return
}

// SendMoneyAndWaitFromWallet is as above, but for a specific wallet
func (f *RestClientFixture) SendMoneyAndWaitFromWallet(walletHandle, walletPassword []byte, curRound, amountToSend, transactionFee uint64, fromAccount, toAccount string, closeToAccount string) (txn v1.Transaction) {
	client := f.LibGoalClient
	fundingTx, err := client.SendPaymentFromWallet(walletHandle, walletPassword, fromAccount, toAccount, transactionFee, amountToSend, nil, closeToAccount, 0, 0)
	require.NoError(f.t, err, "client should be able to send money from rich to poor account")
	require.NotEmpty(f.t, fundingTx.ID().String(), "transaction ID should not be empty")
	waitingDeadline := curRound + uint64(5)
	txn, err = f.WaitForConfirmedTxn(waitingDeadline, fromAccount, fundingTx.ID().String())
	require.NoError(f.t, err)
	return
}

// VerifyBlockProposed checks the rounds starting at fromRounds and moving backwards checking countDownNumRounds rounds if any
// blocks were proposed by address
func (f *RestClientFixture) VerifyBlockProposedRange(account string, fromRound, countDownNumRounds int) (blockWasProposed bool) {
	c := f.LibGoalClient
	for i := 0; i < countDownNumRounds; i++ {
		block, err := c.Block(uint64(fromRound - i))
		require.NoError(f.t, err, "client failed to get block %d", fromRound - i)
		if block.Proposer == account {
			blockWasProposed = true
			break
		}
	}
	return
}

// VerifyBlockProposed checks the last searchRange blocks to see if any blocks were proposed by address
func (f *RestClientFixture) VerifyBlockProposed(account string, searchRange int) (blockWasProposed bool) {
	c := f.LibGoalClient
	currentRound, err := c.CurrentRound()
	if err != nil {
		require.NoError(f.t, err, "client failed to get the last round")
	}
	return f.VerifyBlockProposedRange(account, int(currentRound), int(searchRange))
}

// GetBalancesOnSameRound gets the balances for the passed addresses, and keeps trying until the balances are all the same round
// if it can't get the balances for the same round within maxRetries retries, it will return the last balance seen for each acct
// it also returns whether it got balances all for the same round, and what the last queried round was
func (f *RestClientFixture) GetBalancesOnSameRound(maxRetries int, accounts ...string) (balances map[string]uint64, allSameRound bool, lastRound uint64) {
	retries := 0
	balances = make(map[string]uint64)
	for {
		lastRound = uint64(0)
		allSameRound = true
		for _, account := range accounts {
			balance, thisRound := f.GetBalanceAndRound(account)
			balances[account] = balance
			if lastRound == 0 {
				lastRound = thisRound
			}
			if thisRound != lastRound {
				allSameRound = false
			}
			lastRound = thisRound
		}
		if allSameRound {
			return
		}
		retries++
		if retries > maxRetries {
			return
		}
	}
}

// AssertValidTxid takes a string txid and checks whether it is well-formed and valid
func (f *RestClientFixture) AssertValidTxid(txid string) {
	require.Equal(f.t, 52, len(txid), "txid should be 52 chars long")
	allLettersOrNumbers := true
	for _, r := range txid {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) {
			allLettersOrNumbers = false
			break
		}
	}
	require.True(f.t, allLettersOrNumbers, "txid should be all letters")
}

// AccountListContainsAddress searches the passed account list for the passed account address
func (f *RestClientFixture) AccountListContainsAddress(searchList []v1.Account, address string) bool {
	for _, item := range searchList {
		if item.Address == address {
			return true
		}
	}
	return false
}
