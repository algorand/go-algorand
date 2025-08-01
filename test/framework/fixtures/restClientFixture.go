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

package fixtures

import (
	"fmt"
	"sort"
	"time"
	"unicode"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/netdeploy"

	"github.com/algorand/go-algorand/daemon/algod/api/client"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"

	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/util/tokens"
)

// RestClientFixture is a test fixture for tests requiring a running node with a REST client
type RestClientFixture struct {
	LibGoalFixture
	AlgodClient client.RestClient
}

// Setup is called to initialize the test fixture for the test(s)
func (f *RestClientFixture) Setup(t TestingTB, templateFile string, overrides ...netdeploy.TemplateOverride) {
	f.LibGoalFixture.Setup(t, templateFile, overrides...)
	f.AlgodClient = f.GetAlgodClientForController(f.NC)
}

// SetupNoStart is called to initialize the test fixture for the test(s)
// but does not start the network before returning.  Call NC.Start() to start later.
func (f *RestClientFixture) SetupNoStart(t TestingTB, templateFile string, overrides ...netdeploy.TemplateOverride) {
	f.LibGoalFixture.SetupNoStart(t, templateFile, overrides...)
}

// SetupShared is called to initialize the test fixture that will be used for multiple tests
func (f *RestClientFixture) SetupShared(testName string, templateFile string, overrides ...netdeploy.TemplateOverride) {
	f.LibGoalFixture.SetupShared(testName, templateFile, overrides...)
	f.AlgodClient = f.GetAlgodClientForController(f.NC)
}

// Start can be called to start the fixture's network if SetupNoStart() was used.
func (f *RestClientFixture) Start() {
	f.LibGoalFixture.Start()
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
func (f *RestClientFixture) WaitForRound(round basics.Round, waitTime time.Duration) error {
	_, err := f.AlgodClient.WaitForRound(round, waitTime)
	return err
}

// WithEveryBlock calls the provided function for every block from first to last.
func (f *RestClientFixture) WithEveryBlock(first, last basics.Round, visit func(bookkeeping.Block)) {
	for round := first; round <= last; round++ {
		err := f.WaitForRoundWithTimeout(round)
		require.NoError(f.t, err)
		block, err := f.AlgodClient.Block(round)
		require.NoError(f.t, err)
		visit(block.Block)
	}
}

// WaitForRoundWithTimeout waits for a given round to reach. The implementation also ensures to limit the wait time for each round to the
// globals.MaxTimePerRound so we can alert when we're getting "hung" before waiting for all the expected rounds to reach.
func (f *RestClientFixture) WaitForRoundWithTimeout(roundToWaitFor basics.Round) error {
	return f.AlgodClient.WaitForRoundWithTimeout(roundToWaitFor)
}

// WaitForBlockWithTimeout waits for a given round and returns its block.
func (f *RestClientFixture) WaitForBlockWithTimeout(roundToWaitFor basics.Round) (bookkeeping.Block, error) {
	if err := f.AlgodClient.WaitForRoundWithTimeout(roundToWaitFor); err != nil {
		return bookkeeping.Block{}, err
	}
	both, err := f.AlgodClient.EncodedBlockCert(roundToWaitFor)
	if err != nil {
		return bookkeeping.Block{}, err
	}
	return both.Block, nil
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
func (f *RestClientFixture) GetRichestAccount() (richest model.Account, err error) {
	list, err := f.GetWalletsSortedByBalance()
	if len(list) > 0 {
		richest = list[0]
	}
	return
}

// GetBalanceAndRound returns the current balance of an account and the current round for that balance
func (f *RestClientFixture) GetBalanceAndRound(account string) (balance uint64, round basics.Round) {
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
func (f *RestClientFixture) GetWalletsSortedByBalance() (accounts []model.Account, err error) {
	return f.GetNodeWalletsSortedByBalance(f.LibGoalClient)
}

// GetNodeWalletsSortedByBalance returns the specified node's accounts sorted DESC by balance
// the richest account will be at accounts[0]
func (f *RestClientFixture) GetNodeWalletsSortedByBalance(client libgoal.Client) (accounts []model.Account, err error) {
	wh, err := client.GetUnencryptedWalletHandle()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve wallet handle : %v", err)
	}
	addresses, err := client.ListAddresses(wh)
	if err != nil {
		return nil, fmt.Errorf("unable to list wallet addresses : %v", err)
	}
	for _, addr := range addresses {
		info, err := client.AccountInformation(addr, true)
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
func (f *RestClientFixture) WaitForTxnConfirmation(roundTimeout basics.Round, txid string) bool {
	_, err := f.WaitForConfirmedTxn(roundTimeout, txid)
	return err == nil
}

// WaitForConfirmedTxn waits until either the passed txid is confirmed
// or until the passed roundTimeout passes
// or until waiting for a round to pass times out
func (f *RestClientFixture) WaitForConfirmedTxn(roundTimeout basics.Round, txid string) (txn v2.PreEncodedTxInfo, err error) {
	return f.AlgodClient.WaitForConfirmedTxn(roundTimeout, txid)
}

// WaitForAllTxnsToConfirm is as WaitForTxnConfirmation,
// but accepting a whole map of txids to their issuing address
func (f *RestClientFixture) WaitForAllTxnsToConfirm(roundTimeout basics.Round, txidsAndAddresses map[string]string) bool {
	if len(txidsAndAddresses) == 0 {
		return true
	}
	for txid, addr := range txidsAndAddresses {
		_, err := f.WaitForConfirmedTxn(roundTimeout, txid)
		if err != nil {
			f.t.Logf("txn failed to confirm: addr=%s, txid=%s", addr, txid)
			pendingTxns, err := f.LibGoalClient.GetParsedPendingTransactions(0)
			if err == nil {
				pendingTxids := make([]string, 0, pendingTxns.TotalTransactions)
				for _, txn := range pendingTxns.TopTransactions {
					pendingTxids = append(pendingTxids, txn.Txn.ID().String())
				}
				f.t.Logf("pending txids: %v", pendingTxids)
			} else {
				f.t.Logf("unable to log pending txns: %v", err)
			}
			allTxids := make([]string, 0, len(txidsAndAddresses))
			for txID := range txidsAndAddresses {
				allTxids = append(allTxids, txID)
			}
			f.t.Logf("all txids: %s", allTxids)

			dataDirs := f.network.NodeDataDirs()
			for _, nodedir := range dataDirs {
				client, err := libgoal.MakeClientWithBinDir(f.binDir, nodedir, nodedir, libgoal.FullClient)
				if err != nil {
					f.t.Logf("failed to make a node client for %s: %v", nodedir, err)
					continue
				}
				pendingTxns, err := client.GetParsedPendingTransactions(0)
				if err != nil {
					f.t.Logf("failed to get pending txns for %s: %v", nodedir, err)
					continue
				}
				pendingTxids := make([]string, 0, pendingTxns.TotalTransactions)
				for _, txn := range pendingTxns.TopTransactions {
					pendingTxids = append(pendingTxids, txn.Txn.ID().String())
				}
				f.t.Logf("pending txids at node %s: %v", nodedir, pendingTxids)
			}
			return false
		}
	}
	return true
}

// WaitForAccountFunded waits until either the passed account gets non-empty balance
// or until the passed roundTimeout passes
// or until waiting for a round to pass times out
func (f *RestClientFixture) WaitForAccountFunded(roundTimeout basics.Round, accountAddress string) (err error) {
	client := f.AlgodClient
	for {
		// Get current round information
		curStatus, statusErr := client.Status()
		require.NoError(f.t, statusErr, "fixture should be able to get node status")
		curRound := curStatus.LastRound

		// Check if we know about the transaction yet
		acct, acctErr := client.AccountInformation(accountAddress, false)
		require.NoError(f.t, acctErr, "fixture should be able to get account info")
		if acct.Amount > 0 {
			return nil
		}

		// Check if we should wait a round
		if curRound > roundTimeout {
			return fmt.Errorf("failed to see confirmed transaction by round %v", roundTimeout)
		}
		// Wait a round
		err = client.WaitForRoundWithTimeout(curRound + 1)
		require.NoError(f.t, err, "fixture should be able to wait for one round to pass")
	}
}

// SendMoneyAndWait uses the rest client to send money and WaitForTxnConfirmation to wait for the send to confirm
// it adds some extra error checking as well
func (f *RestClientFixture) SendMoneyAndWait(curRound basics.Round, amountToSend, transactionFee uint64, fromAccount, toAccount string, closeToAccount string) (txn v2.PreEncodedTxInfo) {
	client := f.LibGoalClient
	wh, err := client.GetUnencryptedWalletHandle()
	require.NoError(f.t, err, "client should be able to get unencrypted wallet handle")
	txn = f.SendMoneyAndWaitFromWallet(wh, nil, curRound, amountToSend, transactionFee, fromAccount, toAccount, closeToAccount)
	return
}

// SendMoneyAndWaitFromWallet is as above, but for a specific wallet
func (f *RestClientFixture) SendMoneyAndWaitFromWallet(walletHandle, walletPassword []byte, curRound basics.Round, amountToSend, transactionFee uint64, fromAccount, toAccount string, closeToAccount string) (txn v2.PreEncodedTxInfo) {
	client := f.LibGoalClient
	// use one curRound - 1 in case other nodes are behind
	fundingTx, err := client.SendPaymentFromWallet(walletHandle, walletPassword, fromAccount, toAccount, transactionFee, amountToSend, nil, closeToAccount, basics.Round(curRound).SubSaturate(1), 0)
	require.NoError(f.t, err, "client should be able to send money from rich to poor account")
	require.NotEmpty(f.t, fundingTx.ID().String(), "transaction ID should not be empty")
	waitingDeadline := curRound + 5
	txn, err = client.WaitForConfirmedTxn(waitingDeadline, fundingTx.ID().String())
	require.NoError(f.t, err)
	return
}

// VerifyBlockProposedRange checks the rounds starting at fromRounds and moving backwards checking countDownNumRounds rounds if any
// blocks were proposed by address
func (f *RestClientFixture) VerifyBlockProposedRange(account string, fromRound, countDownNumRounds basics.Round) bool {
	for i := range countDownNumRounds {
		cert, err := f.AlgodClient.EncodedBlockCert(fromRound - i)
		require.NoError(f.t, err, "client failed to get block %d", fromRound-i)
		if cert.Certificate.Proposal.OriginalProposer.GetUserAddress() == account {
			return true
		}
	}
	return false
}

// VerifyBlockProposed checks the last searchRange blocks to see if any blocks were proposed by address
func (f *RestClientFixture) VerifyBlockProposed(account string, searchRange basics.Round) (blockWasProposed bool) {
	c := f.LibGoalClient
	currentRound, err := c.CurrentRound()
	if err != nil {
		require.NoError(f.t, err, "client failed to get the last round")
	}
	return f.VerifyBlockProposedRange(account, currentRound, searchRange)
}

// GetBalancesOnSameRound gets the balances for the passed addresses, and keeps trying until the balances are all the same round
// if it can't get the balances for the same round within maxRetries retries, it will return the last balance seen for each acct
// it also returns whether it got balances all for the same round, and what the last queried round was
func (f *RestClientFixture) GetBalancesOnSameRound(maxRetries int, accounts ...string) (balances map[string]uint64, allSameRound bool, lastRound basics.Round) {
	retries := 0
	balances = make(map[string]uint64)
	for {
		lastRound = 0
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
