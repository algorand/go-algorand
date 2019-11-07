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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func TestLeaseTransactionsSameSender(t *testing.T) {
	t.Parallel()
	a := require.New(t)

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer fixture.Shutdown()

	client := fixture.LibGoalClient
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)
	account0 := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	account1, err := client.GenerateAddress(wh)
	a.NoError(err)

	account2, err := client.GenerateAddress(wh)
	a.NoError(err)

	lease := [32]byte{1, 2, 3, 4}

	// construct transactions for sending money to account1 and account2
	// from same sender with identical lease
	tx1, err := client.ConstructPayment(account0, account1, 0, 1000000, nil, "", lease, 0, 0)
	a.NoError(err)

	tx2, err := client.ConstructPayment(account0, account2, 0, 2000000, nil, "", lease, 0, 0)
	a.NoError(err)

	stx1, err := client.SignTransactionWithWallet(wh, nil, tx1)
	a.NoError(err)

	stx2, err := client.SignTransactionWithWallet(wh, nil, tx2)
	a.NoError(err)

	// submitting the first transaction should succeed
	_, err = client.BroadcastTransaction(stx1)
	a.NoError(err)

	// submitting the second transaction should fail
	_, err = client.BroadcastTransaction(stx2)
	a.Error(err)

	// wait for the txids and check balance
	txids := make(map[string]string)
	txids[stx1.Txn.ID().String()] = account0

	_, curRound := fixture.GetBalanceAndRound(account0)
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+5, txids)
	a.True(confirmed, "lease txn confirmed")

	bal1, _ := fixture.GetBalanceAndRound(account1)
	bal2, _ := fixture.GetBalanceAndRound(account2)
	a.Equal(bal1, uint64(1000000))
	a.Equal(bal2, uint64(0))
}

func TestLeaseTransactionsDifferentSender(t *testing.T) {
	t.Parallel()
	a := require.New(t)

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer fixture.Shutdown()

	client := fixture.LibGoalClient
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)
	account0 := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	account1, err := client.GenerateAddress(wh)
	a.NoError(err)

	account2, err := client.GenerateAddress(wh)
	a.NoError(err)

	account3, err := client.GenerateAddress(wh)
	a.NoError(err)

	// Fund account1
	tx, err := client.SendPaymentFromWallet(wh, nil, account0, account1, 0, 100000000, nil, "", 0, 0)
	a.NoError(err)

	// Wait to confirm
	txids := make(map[string]string)
	txids[tx.ID().String()] = account0
	_, curRound := fixture.GetBalanceAndRound(account0)
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+5, txids)
	a.True(confirmed, "funding txn confirmed")

	lease := [32]byte{1, 2, 3, 4}

	// construct transactions for sending money to account1 and account2
	// from different senders with identical lease
	tx1, err := client.ConstructPayment(account0, account2, 0, 1000000, nil, "", lease, 0, 0)
	a.NoError(err)

	tx2, err := client.ConstructPayment(account1, account3, 0, 2000000, nil, "", lease, 0, 0)
	a.NoError(err)

	stx1, err := client.SignTransactionWithWallet(wh, nil, tx1)
	a.NoError(err)

	stx2, err := client.SignTransactionWithWallet(wh, nil, tx2)
	a.NoError(err)

	// submitting the first transaction should succeed
	_, err = client.BroadcastTransaction(stx1)
	a.NoError(err)

	// submitting the second transaction should succeed
	_, err = client.BroadcastTransaction(stx2)
	a.NoError(err)

	// wait for the txids and check balance
	txids = make(map[string]string)
	txids[stx1.Txn.ID().String()] = account0
	txids[stx2.Txn.ID().String()] = account1

	_, curRound = fixture.GetBalanceAndRound(account0)
	confirmed = fixture.WaitForAllTxnsToConfirm(curRound+5, txids)
	a.True(confirmed, "lease txns confirmed")

	bal1, _ := fixture.GetBalanceAndRound(account2)
	bal2, _ := fixture.GetBalanceAndRound(account3)
	a.Equal(bal1, uint64(1000000))
	a.Equal(bal2, uint64(2000000))
}
