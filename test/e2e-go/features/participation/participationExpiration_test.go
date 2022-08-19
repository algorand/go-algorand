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

package participation

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func testExpirationAccounts(t *testing.T, fixture *fixtures.RestClientFixture, finalStatus basics.Status, protocolCheck string, includeStateProofs bool) {

	a := require.New(fixtures.SynchronizedTest(t))
	pClient := fixture.GetLibGoalClientForNamedNode("Primary")

	sClient := fixture.GetLibGoalClientForNamedNode("Secondary")
	sWH, err := sClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	sAccount, err := sClient.GenerateAddress(sWH)
	a.NoError(err)

	// send money to new account from some other account in the template, so that account can go online
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)
	richAccount := accountList[0].Address
	latestRound := fetchLatestRound(fixture, a)

	minTxnFee, minAcctBalance, err := fixture.MinFeeAndBalance(latestRound)
	a.NoError(err)

	transactionFee := minTxnFee
	amountToSendInitial := 5 * minAcctBalance

	initialAmt, err := sClient.GetBalance(sAccount)
	a.NoError(err)

	fixture.SendMoneyAndWait(latestRound, amountToSendInitial, transactionFee, richAccount, sAccount, "")

	newAmt, err := sClient.GetBalance(sAccount)
	a.NoError(err)

	a.GreaterOrEqual(newAmt, initialAmt)

	newAccountStatus, err := pClient.AccountInformation(sAccount)
	a.NoError(err)
	a.Equal(basics.Offline.String(), newAccountStatus.Status)

	var onlineTxID string
	var partKeyLastValid uint64

	startTime := time.Now()
	for time.Since(startTime) < 2*time.Minute {
		currentRound := fetchLatestRound(fixture, a)

		// account adds part key
		partKeyFirstValid := uint64(0)
		partKeyValidityPeriod := uint64(10)
		partKeyLastValid = currentRound + partKeyValidityPeriod
		partkeyResponse, _, err := sClient.GenParticipationKeys(sAccount, partKeyFirstValid, partKeyLastValid, 0)
		a.NoError(err)
		a.Equal(sAccount, partkeyResponse.Parent.String())

		// account uses part key to go online
		goOnlineTx, err := sClient.MakeRegistrationTransactionWithGenesisID(partkeyResponse, transactionFee, 0, 0, [32]byte{}, includeStateProofs)
		a.NoError(err)

		a.Equal(sAccount, goOnlineTx.Src().String())
		onlineTxID, err = sClient.SignAndBroadcastTransaction(sWH, nil, goOnlineTx)

		if err == nil {
			break
		}

		if strings.Contains(err.Error(), "transaction tries to mark an account as online with last voting round in the past") {
			continue
		}

		// Error occurred
		logging.TestingLog(t).Errorf("signAndBroadcastTransaction error: %s", err.Error())
		logging.TestingLog(t).Errorf("first valid: %d, last valid: %d, current round: %d", partKeyFirstValid, partKeyLastValid, currentRound)
		a.NoError(err)
	}

	fixture.AssertValidTxid(onlineTxID)
	maxRoundsToWaitForTxnConfirm := uint64(3)

	sNodeStatus, err := sClient.Status()
	a.NoError(err)
	seededRound := sNodeStatus.LastRound

	txnConfirmed := fixture.WaitForTxnConfirmation(seededRound+maxRoundsToWaitForTxnConfirm, sAccount, onlineTxID)
	a.True(txnConfirmed)

	newAccountStatus, err = pClient.AccountInformation(sAccount)
	a.NoError(err)
	a.Equal(basics.Online.String(), newAccountStatus.Status)

	// get the round number of the primary node
	pNodeStatus, err := pClient.Status()
	a.NoError(err)

	// ensure the secondary node reaches that number
	_, err = sClient.WaitForRound(pNodeStatus.LastRound)
	a.NoError(err)

	// get the account data ( which now is syncronized across the network )
	sAccountData, err := sClient.AccountData(sAccount)
	a.NoError(err)
	lastValidRound := sAccountData.VoteLastValid

	a.Equal(basics.Round(partKeyLastValid), lastValidRound)

	// We want to wait until we get to one round past the last valid round
	err = fixture.WaitForRoundWithTimeout(uint64(lastValidRound) + 1)
	newAccountStatus, err = pClient.AccountInformation(sAccount)
	a.NoError(err)

	// The account should be online still...
	a.Equal(basics.Online.String(), newAccountStatus.Status)

	// Now we want to send a transaction to the account and test that
	// it was taken offline after we sent it something

	latestRound = fetchLatestRound(fixture, a)

	// making certain sClient has the same blocks as pClient.
	_, err = sClient.WaitForRound(uint64(lastValidRound + 1))
	a.NoError(err)

	blk, err := sClient.Block(latestRound)
	a.NoError(err)
	a.Equal(blk.CurrentProtocol, protocolCheck)

	sendMoneyTxn := fixture.SendMoneyAndWait(latestRound, amountToSendInitial, transactionFee, richAccount, sAccount, "")

	txnConfirmed = fixture.WaitForTxnConfirmation(latestRound+maxRoundsToWaitForTxnConfirm, sAccount, sendMoneyTxn.TxID)
	a.True(txnConfirmed)

	newAccountStatus, err = pClient.AccountInformation(sAccount)
	a.NoError(err)

	// The account should be equal to the target status now
	a.Equal(finalStatus.String(), newAccountStatus.Status)
}

func fetchLatestRound(fixture *fixtures.RestClientFixture, a *require.Assertions) uint64 {
	status, err := fixture.LibGoalClient.Status()
	a.NoError(err)
	return status.LastRound
}

// TestParticipationAccountsExpirationFuture tests that sending a transaction to an account with
// its last valid round being less than the current round will turn it offline.  This test will only
// work when the consensus protocol enables it (in this case the future protocol)
func TestParticipationAccountsExpirationFuture(t *testing.T) {
	partitiontest.PartitionTest(t)

	if testing.Short() {
		t.Skip()
	}

	t.Parallel()

	var fixture fixtures.RestClientFixture

	fixture.SetupNoStart(t, filepath.Join("nettemplates", "TwoNodesExpiredOfflineVFuture.json"))

	fixture.Start()
	defer fixture.Shutdown()

	testExpirationAccounts(t, &fixture, basics.Offline, "future", true)
}

// TestParticipationAccountsExpirationNonFuture tests that sending a transaction to an account with
// its last valid round being less than the current round will NOT turn it offline.  This tests that
// when the consensus protocol is less than the required version, it will not turn nodes offline
func TestParticipationAccountsExpirationNonFuture(t *testing.T) {
	partitiontest.PartitionTest(t)

	if testing.Short() {
		t.Skip()
	}

	t.Parallel()

	var fixture fixtures.RestClientFixture

	// V29 is the version before participation key expiration checking was enabled
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "TwoNodesExpiredOfflineV29.json"))

	fixture.Start()
	defer fixture.Shutdown()

	testExpirationAccounts(t, &fixture, basics.Online, string(protocol.ConsensusV29), false)
}
