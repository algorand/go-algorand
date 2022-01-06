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

package transactions

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func GenerateRandomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil
	}

	return b
}

// this test checks that two accounts' balances stay up to date
// as they send each other money many times
func TestAccountsCanSendMoney(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	numberOfSends := 25
	if testing.Short() {
		numberOfSends = 3
	}
	testAccountsCanSendMoney(t, filepath.Join("nettemplates", "TwoNodes50Each.json"), numberOfSends)
}

// this test checks that two accounts' balances stay up to date
// as they send each other money many times
func TestDevModeAccountsCanSendMoney(t *testing.T) {
	defer fixtures.ShutdownSynchronizedTest(t)

	numberOfSends := 25
	if testing.Short() {
		numberOfSends = 3
	}
	testAccountsCanSendMoney(t, filepath.Join("nettemplates", "DevModeNetwork.json"), numberOfSends)
}

func testAccountsCanSendMoney(t *testing.T, templatePath string, numberOfSends int) {
	t.Parallel()

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, templatePath)
	defer fixture.Shutdown()
	testAccountsCanSendMoneyFixture(t, &fixture, numberOfSends)
}

func testAccountsCanSendMoneyFixture(t *testing.T, fixture *fixtures.RestClientFixture, numberOfSends int) {
	a := require.New(fixtures.SynchronizedTest(t))

	c := fixture.LibGoalClient

	pingClient := fixture.LibGoalClient
	pingAccountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err, "fixture should be able to get wallets sorted by balance")
	pingAccount := pingAccountList[0].Address

	pongClient := fixture.GetLibGoalClientForNamedNode("Node")
	pongAccounts, err := fixture.GetNodeWalletsSortedByBalance(pongClient.DataDir())
	a.NoError(err)
	var pongAccount string
	for _, acct := range pongAccounts {
		if acct.Address == pingAccount {
			continue
		}
		// we found an account.
		pongAccount = acct.Address
		break
	}

	pingBalance, err := c.GetBalance(pingAccount)
	pongBalance, err := c.GetBalance(pongAccount)

	a.Equal(pingBalance, pongBalance, "both accounts should start with same balance")
	a.NotEqual(pingAccount, pongAccount, "accounts under study should be different")

	expectedPingBalance := pingBalance
	expectedPongBalance := pongBalance

	minTxnFee, minAcctBalance, err := fixture.CurrentMinFeeAndBalance()
	a.NoError(err)

	transactionFee := minTxnFee + 5
	amountPongSendsPing := minAcctBalance
	amountPingSendsPong := minAcctBalance * 3 / 2

	pongTxidsToAddresses := make(map[string]string)
	pingTxidsToAddresses := make(map[string]string)

	waitForTransaction := false

	for i := 0; i < numberOfSends; i++ {
		pongTx, err := pongClient.SendPaymentFromUnencryptedWallet(pongAccount, pingAccount, transactionFee, amountPongSendsPing, GenerateRandomBytes(8))
		pongTxidsToAddresses[pongTx.ID().String()] = pongAccount
		a.NoError(err, "fixture should be able to send money (pong -> ping), error on send number %v", i)
		pingTx, err := pingClient.SendPaymentFromUnencryptedWallet(pingAccount, pongAccount, transactionFee, amountPingSendsPong, GenerateRandomBytes(8))
		pingTxidsToAddresses[pingTx.ID().String()] = pingAccount
		a.NoError(err, "fixture should be able to send money (ping -> pong), error on send number %v", i)
		expectedPingBalance = expectedPingBalance - transactionFee - amountPingSendsPong + amountPongSendsPing
		expectedPongBalance = expectedPongBalance - transactionFee - amountPongSendsPing + amountPingSendsPong

		var pongTxInfo, pingTxInfo v1.Transaction
		pongTxInfo, err = pingClient.PendingTransactionInformation(pongTx.ID().String())
		if err == nil {
			pingTxInfo, err = pingClient.PendingTransactionInformation(pingTx.ID().String())
		}
		waitForTransaction = err != nil || pongTxInfo.ConfirmedRound == 0 || pingTxInfo.ConfirmedRound == 0

		if waitForTransaction {
			curStatus, _ := pongClient.Status()
			curRound := curStatus.LastRound
			err = fixture.WaitForRoundWithTimeout(curRound + uint64(1))
			a.NoError(err)
		}
	}
	curStatus, _ := pongClient.Status()
	curRound := curStatus.LastRound

	if waitForTransaction {
		fixture.AlgodClient = fixture.GetAlgodClientForController(fixture.GetNodeControllerForDataDir(pongClient.DataDir()))
		fixture.WaitForAllTxnsToConfirm(curRound+uint64(5), pingTxidsToAddresses)
	}

	pingBalance, _ = fixture.GetBalanceAndRound(pingAccount)
	pongBalance, _ = fixture.GetBalanceAndRound(pongAccount)
	a.True(expectedPingBalance <= pingBalance, "ping balance is different than expected.")
	a.True(expectedPongBalance <= pongBalance, "pong balance is different than expected.")

	if waitForTransaction {
		fixture.AlgodClient = fixture.GetAlgodClientForController(fixture.GetNodeControllerForDataDir(pingClient.DataDir()))
		fixture.WaitForAllTxnsToConfirm(curRound+uint64(5), pongTxidsToAddresses)
	}

	pingBalance, _ = fixture.GetBalanceAndRound(pingAccount)
	pongBalance, _ = fixture.GetBalanceAndRound(pongAccount)
	a.True(expectedPingBalance <= pingBalance, "ping balance is different than expected.")
	a.True(expectedPongBalance <= pongBalance, "pong balance is different than expected.")
}

// this test checks that two accounts' balances stay up to date
// as they send each other money many times
func TestAccountsCanSendMoneyAcrossTxSync(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	numberOfSends := 3
	a := require.New(fixtures.SynchronizedTest(t))

	networkProtocolVersions := []string{"3.0", "2.1"}

	testMoneySending := func(t *testing.T, primaryNodeVersionIdx, nodeVersionIdx int) {
		t.Run(fmt.Sprintf("%s->%s", networkProtocolVersions[primaryNodeVersionIdx], networkProtocolVersions[nodeVersionIdx]),
			func(t *testing.T) {
				t.Parallel()
				var fixture fixtures.RestClientFixture
				fixture.SetupNoStart(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
				defer fixture.Shutdown()

				cfg, err := config.LoadConfigFromDisk(fixture.PrimaryDataDir())
				a.NoError(err)
				cfg.NetworkProtocolVersion = networkProtocolVersions[primaryNodeVersionIdx]
				cfg.SaveToDisk(fixture.PrimaryDataDir())

				cfg, err = config.LoadConfigFromDisk(fixture.NodeDataDirs()[0])
				a.NoError(err)
				cfg.NetworkProtocolVersion = networkProtocolVersions[primaryNodeVersionIdx]
				cfg.SaveToDisk(fixture.NodeDataDirs()[0])

				fixture.Start()
				testAccountsCanSendMoneyFixture(t, &fixture, numberOfSends)
			})
	}

	// test to see that we can communicate correctly regardless of the network protocol version.
	for primaryNodeVersionIdx := 0; primaryNodeVersionIdx < 2; primaryNodeVersionIdx++ {
		for nodeVersionIdx := 0; nodeVersionIdx < 2; nodeVersionIdx++ {
			testMoneySending(t, primaryNodeVersionIdx, nodeVersionIdx)
		}
	}
}

// this test checks that a relay would relay a transaction
// received via the txnsync onto a node that doesn't support
// transaction sync.
func TestTransactionSyncRelayBridge(t *testing.T) {

	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "ThreeNodesOneOnline.json"))
	defer fixture.Shutdown()

	onlineNodeController, err := fixture.GetNodeController("OnlineNode")
	a.NoError(err)

	cfg, err := config.LoadConfigFromDisk(onlineNodeController.GetDataDir())
	a.NoError(err)
	cfg.NetworkProtocolVersion = "2.1"
	cfg.SaveToDisk(onlineNodeController.GetDataDir())

	offlineNodeController, err := fixture.GetNodeController("OfflineNode")
	a.NoError(err)

	cfg, err = config.LoadConfigFromDisk(offlineNodeController.GetDataDir())
	a.NoError(err)
	cfg.NetworkProtocolVersion = "3.0"
	cfg.SaveToDisk(offlineNodeController.GetDataDir())

	fixture.Start()

	client := fixture.GetLibGoalClientFromNodeController(offlineNodeController)
	accounts, err := fixture.GetNodeWalletsSortedByBalance(client.DataDir())
	a.NoError(err)

	a.Equal(1, len(accounts))

	sendingAccount := accounts[0].Address

	_, err = client.SendPaymentFromUnencryptedWallet(sendingAccount, sendingAccount, 1024*1024, 1024, nil)
	a.NoError(err)

	startRoundStatus, err := client.Status()
	a.NoError(err)
	for {
		pendingTxns, err := client.GetPendingTransactions(2)
		a.NoError(err)
		if pendingTxns.TotalTxns == 0 {
			break
		}
		status, err := client.Status()
		a.NoError(err)
		_, err = client.WaitForRound(status.LastRound)
		a.NoError(err)
		a.Less(uint64(status.LastRound), uint64(startRoundStatus.LastRound+5), "transaction is still pending after 5 rounds, whereas it should have been confirmed within 2 rounds.")
	}
}
