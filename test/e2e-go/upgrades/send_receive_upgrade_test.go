// Copyright (C) 2019 Algorand, Inc.
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
	"time"

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

// this test checks that two accounts can send money to one another
// across a protocol upgrade.
func TestAccountsCanSendMoneyAcrossUpgradeV7toV8(t *testing.T) {
	testAccountsCanSendMoneyAcrossUpgrade(t, filepath.Join("nettemplates", "TwoNodes50EachV7Upgrade.json"))
}

func TestAccountsCanSendMoneyAcrossUpgradeV8toV9(t *testing.T) {
	testAccountsCanSendMoneyAcrossUpgrade(t, filepath.Join("nettemplates", "TwoNodes50EachV8Upgrade.json"))
}

func TestAccountsCanSendMoneyAcrossUpgradeV9toV10(t *testing.T) {
	testAccountsCanSendMoneyAcrossUpgrade(t, filepath.Join("nettemplates", "TwoNodes50EachV9Upgrade.json"))
}

func TestAccountsCanSendMoneyAcrossUpgradeV10toV11(t *testing.T) {
	testAccountsCanSendMoneyAcrossUpgrade(t, filepath.Join("nettemplates", "TwoNodes50EachV10Upgrade.json"))
}

func TestAccountsCanSendMoneyAcrossUpgradeV11toV12(t *testing.T) {
	testAccountsCanSendMoneyAcrossUpgrade(t, filepath.Join("nettemplates", "TwoNodes50EachV11Upgrade.json"))
}

func TestAccountsCanSendMoneyAcrossUpgradeV12toV13(t *testing.T) {
	testAccountsCanSendMoneyAcrossUpgrade(t, filepath.Join("nettemplates", "TwoNodes50EachV12Upgrade.json"))
}

func TestAccountsCanSendMoneyAcrossUpgradeV13toV14(t *testing.T) {
	testAccountsCanSendMoneyAcrossUpgrade(t, filepath.Join("nettemplates", "TwoNodes50EachV13Upgrade.json"))
}

func TestAccountsCanSendMoneyAcrossUpgradeV14toV15(t *testing.T) {
	testAccountsCanSendMoneyAcrossUpgrade(t, filepath.Join("nettemplates", "TwoNodes50EachV14Upgrade.json"))
}

func TestAccountsCanSendMoneyAcrossUpgradeV15toV16(t *testing.T) {
	testAccountsCanSendMoneyAcrossUpgrade(t, filepath.Join("nettemplates", "TwoNodes50EachV15Upgrade.json"))
}

func testAccountsCanSendMoneyAcrossUpgrade(t *testing.T, templatePath string) {
	t.Parallel()
	a := require.New(t)

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, templatePath)
	defer fixture.Shutdown()
	c := fixture.LibGoalClient

	initialStatus, err := c.Status()
	a.NoError(err, "getting status")

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

	const transactionFee = uint64(9000)
	const amountPongSendsPing = uint64(10000)
	const amountPingSendsPong = uint64(11000)

	curStatus, err := c.Status()
	a.NoError(err, "getting status")
	var pingTxids []string
	var pongTxids []string

	startTime := time.Now()
	for curStatus.LastVersion == initialStatus.LastVersion {
		pongTx, err := pongClient.SendPaymentFromUnencryptedWallet(pongAccount, pingAccount, transactionFee, amountPongSendsPing, GenerateRandomBytes(8))
		a.NoError(err, "fixture should be able to send money (pong -> ping)")
		pongTxids = append(pongTxids, pongTx.ID().String())

		pingTx, err := pingClient.SendPaymentFromUnencryptedWallet(pingAccount, pongAccount, transactionFee, amountPingSendsPong, GenerateRandomBytes(8))
		a.NoError(err, "fixture should be able to send money (ping -> pong)")
		pingTxids = append(pingTxids, pingTx.ID().String())

		expectedPingBalance = expectedPingBalance - transactionFee - amountPingSendsPong + amountPongSendsPing
		expectedPongBalance = expectedPongBalance - transactionFee - amountPongSendsPing + amountPingSendsPong

		curStatus, err = pongClient.Status()
		a.NoError(err)

		time.Sleep(time.Second)

		if time.Now().After(startTime.Add(2 * time.Minute)) {
			a.Fail("upgrade taking too long")
		}
	}

	// submit a few more transactions to make sure payments work in new protocol
	for i := 0; i < 20; i++ {
		pongTx, err := pongClient.SendPaymentFromUnencryptedWallet(pongAccount, pingAccount, transactionFee, amountPongSendsPing, GenerateRandomBytes(8))
		a.NoError(err, "fixture should be able to send money (pong -> ping)")
		pongTxids = append(pongTxids, pongTx.ID().String())

		pingTx, err := pingClient.SendPaymentFromUnencryptedWallet(pingAccount, pongAccount, transactionFee, amountPingSendsPong, GenerateRandomBytes(8))
		a.NoError(err, "fixture should be able to send money (ping -> pong)")
		pingTxids = append(pingTxids, pingTx.ID().String())

		expectedPingBalance = expectedPingBalance - transactionFee - amountPingSendsPong + amountPongSendsPing
		expectedPongBalance = expectedPongBalance - transactionFee - amountPongSendsPing + amountPingSendsPong

		time.Sleep(time.Second)
	}

	curStatus, err = pongClient.Status()
	a.NoError(err)

	// wait for all transactions to confirm
	for _, txid := range pingTxids {
		_, err = fixture.WaitForConfirmedTxn(curStatus.LastRound+5, pingAccount, txid)
		a.NoError(err, "waiting for txn")
	}

	for _, txid := range pongTxids {
		_, err = fixture.WaitForConfirmedTxn(curStatus.LastRound+5, pongAccount, txid)
		a.NoError(err, "waiting for txn")
	}

	// check balances
	pingBalance, err = c.GetBalance(pingAccount)
	a.NoError(err)
	pongBalance, err = c.GetBalance(pongAccount)
	a.NoError(err)

	a.True(expectedPingBalance <= pingBalance, "ping balance is different than expected")
	a.True(expectedPongBalance <= pongBalance, "pong balance is different than expected")
}
