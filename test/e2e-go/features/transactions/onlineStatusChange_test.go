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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

const transactionValidityPeriod = uint64(100) // rounds
const transactionFee = uint64(0)

func TestAccountsCanChangeOnlineState(t *testing.T) {
	testAccountsCanChangeOnlineState(t, filepath.Join("nettemplates", "TwoNodesPartlyOffline.json"))
}

func TestAccountsCanChangeOnlineStateV7(t *testing.T) {
	testAccountsCanChangeOnlineState(t, filepath.Join("nettemplates", "TwoNodesPartlyOfflineV7.json"))
}

func TestAccountsCanChangeOnlineStateInTheFuture(t *testing.T) {
	testAccountsCanChangeOnlineState(t, filepath.Join("nettemplates", "TwoNodesPartlyOfflineVFuture.json"))
}

func testAccountsCanChangeOnlineState(t *testing.T, templatePath string) {

	t.Parallel()
	a := require.New(t)

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, templatePath)
	defer fixture.Shutdown()
	client := fixture.LibGoalClient

	// Capture the account we're tracking
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)

	initiallyOnline := accountList[0].Address         // 35% stake
	initiallyOffline := accountList[1].Address        // 20% stake
	becomesNonparticipating := accountList[2].Address // 10% stake

	// assert that initiallyOfflineAccount is offline
	initiallyOfflineAccountStatus, err := client.AccountInformation(initiallyOffline)
	a.NoError(err)
	a.Equal(initiallyOfflineAccountStatus.Status, basics.Offline.String())

	// assert that initiallyOnlineAccount is online
	initiallyOnlineAccountStatus, err := client.AccountInformation(initiallyOnline)
	a.NoError(err)
	a.Equal(initiallyOnlineAccountStatus.Status, basics.Online.String())

	// assert that the account that will become nonparticipating hasn't yet been marked as such
	unmarkedAccountStatus, err := client.AccountInformation(becomesNonparticipating)
	a.NoError(err)
	a.NotEqual(unmarkedAccountStatus.Status, basics.NotParticipating.String())

	// get the current round for partkey creation
	_, curRound := fixture.GetBalanceAndRound(initiallyOnline)

	// make a participation key for initiallyOffline
	partkeyResponse, _, err := client.GenParticipationKeys(initiallyOffline, 0, curRound+1000, 0)
	a.NoError(err, "should be no errors when creating partkeys")
	a.Equal(initiallyOffline, partkeyResponse.Address().String(), "successful partkey creation should echo account")

	goOnlineUTx, err := client.MakeUnsignedGoOnlineTx(initiallyOffline, nil, curRound, curRound+transactionValidityPeriod, transactionFee, [32]byte{})
	a.NoError(err, "should be able to make go online tx")
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err, "should be able to get unencrypted wallet handle")
	onlineTxID, err := client.SignAndBroadcastTransaction(wh, nil, goOnlineUTx)
	a.NoError(err, "should be no errors when using partkey to go online")

	// make a participation key for initiallyOnline
	partkeyResponse, _, err = client.GenParticipationKeys(initiallyOnline, 0, curRound+1000, 0)
	a.NoError(err, "should be no errors when creating partkeys")
	a.Equal(initiallyOnline, partkeyResponse.Address().String(), "successful partkey creation should echo account")

	goOfflineUTx, err := client.MakeUnsignedGoOfflineTx(initiallyOnline, curRound, curRound+transactionValidityPeriod, transactionFee, [32]byte{})
	a.NoError(err, "should be able to make go offline tx")
	wh, err = client.GetUnencryptedWalletHandle()
	offlineTxID, err := client.SignAndBroadcastTransaction(wh, nil, goOfflineUTx)
	a.NoError(err, "should be no errors when going offline")

	consensusParams, err := client.ConsensusParams(curRound)
	a.NoError(err)
	doNonparticipationTest := consensusParams.SupportBecomeNonParticipatingTransactions
	nonparticipatingTxID := ""
	if doNonparticipationTest {
		becomeNonparticpatingUTx, err := client.MakeUnsignedBecomeNonparticipatingTx(becomesNonparticipating, curRound, curRound+transactionValidityPeriod, transactionFee)
		a.NoError(err, "should be able to make become-nonparticipating tx")
		wh, err = client.GetUnencryptedWalletHandle()
		nonparticipatingTxID, err = client.SignAndBroadcastTransaction(wh, nil, becomeNonparticpatingUTx)
		a.NoError(err, "should be  no errors when marking nonparticipating")
	}

	txidsForStatusChange := make(map[string]string)
	txidsForStatusChange[onlineTxID] = initiallyOffline
	txidsForStatusChange[offlineTxID] = initiallyOnline
	if doNonparticipationTest {
		txidsForStatusChange[nonparticipatingTxID] = becomesNonparticipating
	}
	txnConfirmationDeadline := curRound + uint64(5)
	confirmed := fixture.WaitForAllTxnsToConfirm(txnConfirmationDeadline, txidsForStatusChange)
	a.True(confirmed, "Transactions failed to confirm.")

	_, curRound = fixture.GetBalanceAndRound(initiallyOnline)
	fixture.WaitForRoundWithTimeout(curRound + uint64(1))

	// assert that initiallyOffline is now online
	initiallyOfflineAccountStatus, err = client.AccountInformation(initiallyOffline)
	a.NoError(err)
	a.Equal(initiallyOfflineAccountStatus.Status, basics.Online.String())

	// assert that initiallyOnline is now offline
	initiallyOnlineAccountStatus, err = client.AccountInformation(initiallyOnline)
	a.NoError(err)
	a.Equal(initiallyOnlineAccountStatus.Status, basics.Offline.String())

	if doNonparticipationTest {
		// assert that becomesNonparticipating is no longer participating
		unmarkedAccountStatus, err = client.AccountInformation(becomesNonparticipating)
		a.NoError(err)
		a.Equal(unmarkedAccountStatus.Status, basics.NotParticipating.String())
	}
}
