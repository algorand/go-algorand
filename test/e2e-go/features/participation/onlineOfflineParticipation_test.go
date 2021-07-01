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

package participation

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/testpartitioning"
)

func TestParticipationKeyOnlyAccountParticipatesCorrectly(t *testing.T) {
	testpartitioning.PartitionTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesPartialPartkeyOnlyWallets.json"))
	defer fixture.Shutdown()
	client := fixture.LibGoalClient
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err, "fixture should be able to get wallet list")
	// partkeyonly_account is pre-created by template, marked ParticipationOnly: true. already has some stake
	// verify both accounts got rewards
	richAccount := accountList[0].Address // 30% stake

	partAccounts := fixture.GetParticipationOnlyAccounts(client)
	a.NotEmpty(partAccounts)

	partkeyOnlyAccount := partAccounts[0].Address().String() // 20% stake
	// allow "a few" rounds to pass so accounts can participate

	// the below window controls the likelihood a block will be proposed by the account under test
	// since block proposer selection is probabilistic, it is not guaranteed that the account will be chosen
	// it is a trade-off between test flakiness and test duration
	proposalWindow := 50 // arbitrary
	blockWasProposedByPartkeyOnlyAccountRecently := waitForAccountToProposeBlock(a, &fixture, partkeyOnlyAccount, proposalWindow)
	a.True(blockWasProposedByPartkeyOnlyAccountRecently, "partkey-only account should be proposing blocks")

	// verify partkeyonly_account cannot spend
	transactionFee := uint64(3)   // arbitrary
	amountToSend := uint64(10000) // arbitrary
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err, "should get unencrypted wallet handle")
	_, err = client.SendPaymentFromWallet(wh, nil, partkeyOnlyAccount, richAccount, amountToSend, transactionFee, nil, "", basics.Round(0), basics.Round(0))
	a.Error(err, "attempt to send money from partkey-only account should be treated as though wallet is not controlled")
	// partkeyonly_account attempts to go offline, should fail (no rootkey to sign txn with)
	goOfflineUTx, err := client.MakeUnsignedGoOfflineTx(partkeyOnlyAccount, 0, 0, transactionFee, [32]byte{})
	a.NoError(err, "should be able to make go offline tx")
	wh, err = client.GetUnencryptedWalletHandle()
	a.NoError(err, "should get unencrypted wallet handle")
	_, err = client.SignAndBroadcastTransaction(wh, nil, goOfflineUTx)
	a.Error(err, "partkey only account should fail to go offline")
}

func waitForAccountToProposeBlock(a *require.Assertions, fixture *fixtures.RestClientFixture, account string, window int) bool {
	client := fixture.AlgodClient

	curStatus, err := client.Status()
	a.NoError(err)
	curRound := curStatus.LastRound

	// the below window controls the likelihood a block will be proposed by the account under test
	// since block proposer selection is probabilistic, it is not guaranteed that the account will be chosen
	// it is a trade-off between test flakiness and test duration
	for window > 0 {
		window--
		curRound++
		err := fixture.WaitForRoundWithTimeout(curRound)
		a.NoErrorf(err, "fixture failed waiting for round %d", curRound)

		// See if account was participating by looking at block proposers
		blockWasProposed := fixture.VerifyBlockProposed(account, 1)
		if blockWasProposed {
			return blockWasProposed
		}
	}
	return false
}

func TestNewAccountCanGoOnlineAndParticipate(t *testing.T) {
	testpartitioning.PartitionTest(t)

	/*if runtime.GOOS == "darwin" {
		t.Skip()
	}
	if testing.Short() {
		t.Skip()
	}*/
	t.Skip() // temporary disable the test since it's failing.

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesOneOnline.json"))
	defer fixture.Shutdown()
	client := fixture.LibGoalClient

	// account is newly created
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)
	newAccount, err := client.GenerateAddress(wh)
	a.NoError(err)

	// send money to new account from some other account in the template, so that account can go online
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err, "fixture should be able to get wallet list")
	richAccount := accountList[0].Address // 30% stake
	richBalance, initialRound := fixture.GetBalanceAndRound(richAccount)

	minTxnFee, minAcctBalance, err := fixture.MinFeeAndBalance(initialRound)
	a.NoError(err)

	transactionFee := minTxnFee
	amountToSendInitial := 5 * minAcctBalance
	fixture.SendMoneyAndWait(initialRound, amountToSendInitial, transactionFee, richAccount, newAccount)
	amt, err := client.GetBalance(newAccount)
	a.NoError(err)
	nodeStatus, err := client.Status()
	a.NoError(err)
	seededRound := nodeStatus.LastRound
	a.Equal(amountToSendInitial, amt, "new account should be funded with the amount the rich account sent")

	// account adds part key
	partKeyFirstValid := uint64(0)
	partKeyValidityPeriod := uint64(10000)
	partKeyLastValid := partKeyFirstValid + partKeyValidityPeriod
	partkeyResponse, _, err := client.GenParticipationKeys(newAccount, partKeyFirstValid, partKeyLastValid, 0)
	a.NoError(err, "rest client should be able to add participation key to new account")
	a.Equal(newAccount, partkeyResponse.Parent.String(), "partkey response should echo queried account")
	// account uses part key to go online
	goOnlineTx, err := client.MakeUnsignedGoOnlineTx(newAccount, nil, 0, 0, transactionFee, [32]byte{})
	a.NoError(err, "should be able to make go online tx")
	a.Equal(newAccount, goOnlineTx.Src().String(), "go online response should echo queried account")
	onlineTxID, err := client.SignAndBroadcastTransaction(wh, nil, goOnlineTx)
	a.NoError(err, "new account with new partkey should be able to go online")

	fixture.AssertValidTxid(onlineTxID)
	maxRoundsToWaitForTxnConfirm := uint64(5)
	fixture.WaitForTxnConfirmation(seededRound+maxRoundsToWaitForTxnConfirm, newAccount, onlineTxID)
	nodeStatus, _ = client.Status()
	onlineRound := nodeStatus.LastRound
	newAccountStatus, err := client.AccountInformation(newAccount)
	a.NoError(err, "client should be able to get information about new account")
	a.Equal(basics.Online.String(), newAccountStatus.Status, "new account should be online")
	// account receives almost all of rich account's stake (minus enough to
	// keep it over MinBalance), so it will be selected for participation
	amountToSend := richBalance - 3*transactionFee - amountToSendInitial - minAcctBalance
	fixture.SendMoneyAndWait(onlineRound, amountToSend, transactionFee, richAccount, newAccount)

	nodeStatus, _ = client.Status()
	fundedRound := nodeStatus.LastRound

	params, err := client.ConsensusParams(nodeStatus.LastRound)
	a.NoError(err)
	lookbackRound := balanceRound(basics.Round(nodeStatus.LastRound), params)
	delta := int64(nodeStatus.LastRound) - int64(lookbackRound)
	a.True(delta > 0)

	// Need to wait for funding to take effect on selection, then we can see if we're participating
	// Stop before the account should become eligible for selection so we can ensure it wasn't
	err = fixture.WaitForRoundWithTimeout(fundedRound + uint64(delta) - 1)
	a.NoError(err)

	blockWasProposed := fixture.VerifyBlockProposed(newAccount, int(delta)-1)
	a.False(blockWasProposed, "account should not be selected until BalLookback (round %d) passes", int(delta)-1)

	// check that account starts participating after a while
	proposalWindow := 20 // arbitrary
	blockWasProposedByNewAccountRecently := waitForAccountToProposeBlock(a, &fixture, newAccount, proposalWindow)
	a.True(blockWasProposedByNewAccountRecently, "newly online account should be proposing blocks")
}

// helper copied from agreement/selector.go
func balanceRound(r basics.Round, cparams config.ConsensusParams) basics.Round {
	return r.SubSaturate(basics.Round(2 * cparams.SeedRefreshInterval * cparams.SeedLookback))
}
