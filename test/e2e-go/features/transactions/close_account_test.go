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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/testPartitioning"
)

func TestAccountsCanClose(t *testing.T) {
	testPartitioning.PartitionTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachV15.json"))
	defer fixture.Shutdown()
	client := fixture.LibGoalClient

	// We will create three new accounts, transfer some amount of money into
	// the first account, and then transfer a smaller amount to the second
	// account while closing out the rest into the third.

	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)
	baseAcct := accountList[0].Address

	walletHandle, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	acct0, err := client.GenerateAddress(walletHandle)
	a.NoError(err)

	acct1, err := client.GenerateAddress(walletHandle)
	a.NoError(err)

	acct2, err := client.GenerateAddress(walletHandle)
	a.NoError(err)

	status, err := client.Status()
	a.NoError(err)

	// Transfer some money to acct0 and wait.
	tx, err := client.SendPaymentFromUnencryptedWallet(baseAcct, acct0, 1000, 10000000, nil)
	a.NoError(err)
	fixture.WaitForConfirmedTxn(status.LastRound+10, baseAcct, tx.ID().String())

	tx, err = client.SendPaymentFromWallet(walletHandle, nil, acct0, acct1, 1000, 1000000, nil, acct2, 0, 0)
	a.NoError(err)
	fixture.WaitForConfirmedTxn(status.LastRound+10, acct0, tx.ID().String())

	bal0, err := client.GetBalance(acct0)
	a.NoError(err)

	bal1, err := client.GetBalance(acct1)
	a.NoError(err)

	bal2, err := client.GetBalance(acct2)
	a.NoError(err)

	a.True(bal0 == 0)
	a.True(bal1 >= 1000000)
	a.True(bal2 >= 8999000)
}
