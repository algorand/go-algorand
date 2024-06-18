// Copyright (C) 2019-2024 Algorand, Inc.
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

package other

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/tokens"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDisabledAPIConfig(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "DisableAPIAuth.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	statusResponse, err := testClient.Status()
	a.NoError(err)
	a.NotEmpty(statusResponse)
	statusResponse2, err := testClient.Status()
	a.NoError(err)
	a.NotEmpty(statusResponse2)
	a.True(statusResponse2.LastRound >= statusResponse.LastRound)

	// Check the public token isn't created when the API authentication is disabled
	nc, err := localFixture.GetNodeController("Primary")
	assert.NoError(t, err)
	_, err = os.Stat(path.Join(nc.GetDataDir(), tokens.AlgodAdminTokenFilename))
	assert.NoError(t, err)
	_, err = os.Stat(path.Join(nc.GetDataDir(), tokens.AlgodTokenFilename))
	assert.True(t, os.IsNotExist(err))

	// check public api works without a token
	testClient.WaitForRound(1)
	_, err = testClient.Block(1)
	assert.NoError(t, err)
	// check admin api works with the generated token
	_, err = testClient.GetParticipationKeys()
	assert.NoError(t, err)
	// check admin api doesn't work with an invalid token
	algodURL, err := nc.ServerURL()
	assert.NoError(t, err)
	client := client.MakeRestClient(algodURL, "")
	_, err = client.GetParticipationKeys()
	assert.Contains(t, err.Error(), "Invalid API Token")
}

func TestSendingNotClosingAccountFails(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	// use a local fixture because we might really mess with the balances
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer localFixture.Shutdown()
	testClient := localFixture.LibGoalClient
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	var emptyAddress string
	for _, addr := range addresses {
		bal, err := testClient.GetBalance(addr)
		a.NoError(err)
		if bal == 0 {
			emptyAddress = addr
			break
		}
	}
	if emptyAddress == "" {
		emptyAddress, err = testClient.GenerateAddress(wh)
		a.NoError(err)
	}
	var someAddress string
	someBal := uint64(0)
	for _, addr := range addresses {
		if addr != emptyAddress {
			bal, err := testClient.GetBalance(addr)
			a.NoError(err)
			if bal > someBal {
				someAddress = addr
				someBal = bal
			}
		}
	}
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	amt := someBal - 10000 - 1
	_, err = testClient.SendPaymentFromWallet(wh, nil, someAddress, emptyAddress, 10000, amt, nil, "", 0, 0)
	a.Error(err)
}

func TestClientCanGetPendingTransactions(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient
	wh, _ := testClient.GetUnencryptedWalletHandle()
	addresses, _ := testClient.ListAddresses(wh)
	fromAddress := addresses[0]
	toAddress, _ := testClient.GenerateAddress(wh)
	// We may not need to kill the other node, but do it anyways to ensure the txn never gets committed
	nc, _ := localFixture.GetNodeController("Node")
	err := nc.FullStop()
	a.NoError(err)

	minTxnFee, minAcctBalance, err := localFixture.CurrentMinFeeAndBalance()
	a.NoError(err)

	// Check that a single pending txn is corectly displayed
	tx, err := testClient.SendPaymentFromUnencryptedWallet(fromAddress, toAddress, minTxnFee, minAcctBalance, nil)
	a.NoError(err)
	statusResponse, err := testClient.GetParsedPendingTransactions(0)
	a.NoError(err)
	a.NotEmpty(statusResponse)
	a.True(statusResponse.TotalTransactions == 1)
	a.True(len(statusResponse.TopTransactions) == 1)

	// Parse response into SignedTxn
	pendingTxn := statusResponse.TopTransactions[0]
	a.True(pendingTxn.Txn.ID().String() == tx.ID().String())
}

func TestClientTruncatesPendingTransactions(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient
	wh, _ := testClient.GetUnencryptedWalletHandle()
	nc, _ := localFixture.GetNodeController("Node")
	err := nc.FullStop()
	a.NoError(err)

	minTxnFee, minAcctBalance, err := localFixture.CurrentMinFeeAndBalance()
	a.NoError(err)

	NumTxns := 10
	MaxTxns := 7
	addresses, _ := testClient.ListAddresses(wh)
	fromAddress := addresses[0]
	txIDsSeen := make(map[string]bool)
	for i := 0; i < NumTxns; i++ {
		toAddress, _ := testClient.GenerateAddress(wh)
		tx2, err := testClient.SendPaymentFromUnencryptedWallet(fromAddress, toAddress, minTxnFee, minAcctBalance, nil)
		a.NoError(err)
		txIDsSeen[tx2.ID().String()] = true
	}
	statusResponse, err := testClient.GetParsedPendingTransactions(uint64(MaxTxns))
	a.NoError(err)
	a.True(int(statusResponse.TotalTransactions) == NumTxns)
	a.True(len(statusResponse.TopTransactions) == MaxTxns)
	for _, tx := range statusResponse.TopTransactions {
		a.True(txIDsSeen[tx.Txn.ID().String()])
		delete(txIDsSeen, tx.Txn.ID().String())
	}
	a.True(len(txIDsSeen) == NumTxns-MaxTxns)
}

func TestClientPrioritizesPendingTransactions(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Skip("new FIFO pool does not have prioritization")
	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient
	wh, _ := testClient.GetUnencryptedWalletHandle()
	addresses, _ := testClient.ListAddresses(wh)
	fromAddress := addresses[0]
	toAddress, _ := testClient.GenerateAddress(wh)
	nc, _ := localFixture.GetNodeController("Node")
	err := nc.FullStop()
	a.NoError(err)

	minTxnFee, minAcctBalance, err := localFixture.CurrentMinFeeAndBalance()
	a.NoError(err)

	NumTxns := 5
	MaxTxns := 3
	for i := 0; i < NumTxns; i++ {
		toAddress2, _ := testClient.GenerateAddress(wh)
		_, err := testClient.SendPaymentFromUnencryptedWallet(fromAddress, toAddress2, minTxnFee, minAcctBalance, nil)
		a.NoError(err)
	}

	// Add a very high fee transaction. This should have first priority
	// (even if we don't know the encoding length of the underlying signed txn)
	txHigh, err := testClient.SendPaymentFromUnencryptedWallet(fromAddress, toAddress, minTxnFee*10, minAcctBalance, nil)
	a.NoError(err)

	statusResponse, err := testClient.GetParsedPendingTransactions(uint64(MaxTxns))
	a.NoError(err)
	a.NotEmpty(statusResponse)
	a.True(int(statusResponse.TotalTransactions) == NumTxns+1)
	a.True(len(statusResponse.TopTransactions) == MaxTxns)

	pendingTxn := statusResponse.TopTransactions[0]
	a.True(pendingTxn.Txn.ID().String() == txHigh.ID().String())
}
