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
	numberOfSends := 25
	if testing.Short() {
		numberOfSends = 3
	}
	testAccountsCanSendMoney(t, filepath.Join("nettemplates", "TwoNodes50Each.json"), numberOfSends)
}

func testAccountsCanSendMoney(t *testing.T, templatePath string, numberOfSends int) {
	t.Parallel()
	a := require.New(t)

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, templatePath)
	defer fixture.Shutdown()
	c := fixture.LibGoalClient

	pingClient := fixture.LibGoalClient
	pingAccountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err, "fixture should be able to get wallets sorted by balance")
	pingAccount := pingAccountList[0].Address

	pongClient := fixture.GetLibGoalClientForNamedNode("Node")
	wh, err := pongClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	pongAccountList, err := pongClient.ListAddresses(wh)
	a.NoError(err)
	pongAccount := pongAccountList[0]

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

	for i := 0; i < numberOfSends; i++ {
		pongTx, err := pongClient.SendPaymentFromUnencryptedWallet(pongAccount, pingAccount, transactionFee, amountPongSendsPing, GenerateRandomBytes(8))
		pongTxidsToAddresses[pongTx.ID().String()] = pongAccount
		a.NoError(err, "fixture should be able to send money (pong -> ping), error on send number %v", i)
		pingTx, err := pingClient.SendPaymentFromUnencryptedWallet(pingAccount, pongAccount, transactionFee, amountPingSendsPong, GenerateRandomBytes(8))
		pingTxidsToAddresses[pingTx.ID().String()] = pingAccount
		a.NoError(err, "fixture should be able to send money (ping -> pong), error on send number %v", i)
		expectedPingBalance = expectedPingBalance - transactionFee - amountPingSendsPong + amountPongSendsPing
		expectedPongBalance = expectedPongBalance - transactionFee - amountPongSendsPing + amountPingSendsPong
		curStatus, _ := pongClient.Status()
		curRound := curStatus.LastRound
		err = fixture.WaitForRoundWithTimeout(curRound + uint64(1))
		a.NoError(err)
	}
	curStatus, _ := pongClient.Status()
	curRound := curStatus.LastRound

	fixture.AlgodClient = fixture.GetAlgodClientForController(fixture.GetNodeControllerForDataDir(pongClient.DataDir()))
	fixture.WaitForAllTxnsToConfirm(curRound+uint64(1), pingTxidsToAddresses)

	pingBalance, _ = fixture.GetBalanceAndRound(pingAccount)
	pongBalance, _ = fixture.GetBalanceAndRound(pongAccount)
	a.True(expectedPingBalance <= pingBalance, "ping balance is different than expected.")
	a.True(expectedPongBalance <= pongBalance, "pong balance is different than expected.")

	fixture.AlgodClient = fixture.GetAlgodClientForController(fixture.GetNodeControllerForDataDir(pingClient.DataDir()))
	fixture.WaitForAllTxnsToConfirm(curRound+uint64(1), pongTxidsToAddresses)

	pingBalance, _ = fixture.GetBalanceAndRound(pingAccount)
	pongBalance, _ = fixture.GetBalanceAndRound(pongAccount)
	a.True(expectedPingBalance <= pingBalance, "ping balance is different than expected.")
	a.True(expectedPongBalance <= pongBalance, "pong balance is different than expected.")
}
