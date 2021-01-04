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

package upgrades

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

// TestRekeyUpgrade tests that we rekey does not work before the upgrade and works well after
func TestRekeyUpgrade(t *testing.T) {
	a := require.New(t)

	smallLambdaMs := 500
	consensus := makeApplicationUpgradeConsensus(t)

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes100SecondTestUnupgradedProtocol.json"))
	defer fixture.Shutdown()

	client := fixture.GetLibGoalClientForNamedNode("Node")
	accountList, err := fixture.GetNodeWalletsSortedByBalance(client.DataDir())
	a.NoError(err)

	accountA := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	accountB, err := client.GenerateAddress(wh)
	a.NoError(err)

	round, err := client.CurrentRound()
	a.NoError(err)

	// Ensure no rekeying happened
	ad, err := client.AccountData(accountA)
	a.NoError(err)
	a.Equal(basics.Address{}, ad.AuthAddr)

	// rekey A -> B (RekeyTo check)
	fee := uint64(1000)
	amount := uint64(1000000)
	lease := [32]byte{}
	tx, err := client.ConstructPayment(accountA, accountB, fee, amount, nil, "", lease, basics.Round(round), basics.Round(round+1000))
	a.NoError(err)

	addrB, err := basics.UnmarshalChecksumAddress(accountB)
	a.NoError(err)
	tx.RekeyTo = addrB

	rekey, err := client.SignTransactionWithWalletAndSigner(wh, nil, "", tx)
	a.NoError(err)
	_, err = client.BroadcastTransaction(rekey)
	a.Error(err)
	require.Contains(t, err.Error(), "transaction has RekeyTo set but rekeying not yet enable")

	// use rekeyed key to authorize (AuthAddr check)
	tx.RekeyTo = basics.Address{}
	rekeyed, err := client.SignTransactionWithWalletAndSigner(wh, nil, accountB, tx)
	a.NoError(err)
	_, err = client.BroadcastTransaction(rekeyed)
	a.Error(err)
	require.Contains(t, err.Error(), "nonempty AuthAddr but rekeying not supported")
	// go to upgrade
	curStatus, err := client.Status()
	require.NoError(t, err)
	initialStatus := curStatus

	startLoopTime := time.Now()

	// wait until the network upgrade : this can take a while.
	for curStatus.LastVersion == initialStatus.LastVersion {
		curStatus, err = client.Status()
		require.NoError(t, err)

		require.Less(t, int64(time.Now().Sub(startLoopTime)), int64(3*time.Minute))
		time.Sleep(time.Duration(smallLambdaMs) * time.Millisecond)
		round = curStatus.LastRound
	}

	// now, that we have upgraded to the new protocol which supports rekey, try again.
	_, err = client.BroadcastTransaction(rekey)
	require.NoError(t, err)

	round, err = client.CurrentRound()
	a.NoError(err)
	client.WaitForRound(round + 1)

	_, err = client.BroadcastTransaction(rekeyed)
	require.NoError(t, err)
}
