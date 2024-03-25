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

package upgrades

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestRekeyUpgrade tests that the rekey does not work before the upgrade and works well after
func TestRekeyUpgrade(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))

	smallLambdaMs := 500
	consensus := makeApplicationUpgradeConsensus(t)

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes100SecondTestUnupgradedProtocol.json"))
	defer fixture.Shutdown()

	client := fixture.GetLibGoalClientForNamedNode("Node")
	accountList, err := fixture.GetNodeWalletsSortedByBalance(client)
	a.NoError(err)

	accountA := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	accountB, err := client.GenerateAddress(wh)
	a.NoError(err)

	addrB, err := basics.UnmarshalChecksumAddress(accountB)
	a.NoError(err)

	accountC, err := client.GenerateAddress(wh)
	a.NoError(err)

	accountD, err := client.GenerateAddress(wh)
	a.NoError(err)

	addrD, err := basics.UnmarshalChecksumAddress(accountD)
	a.NoError(err)

	fee := uint64(1000)
	amount := uint64(1000000)
	lease := [32]byte{}

	// move some money from accountA -> accountC
	tx, err := client.ConstructPayment(accountA, accountC, fee, amount*10, nil, "", lease, basics.Round(0), basics.Round(0))
	a.NoError(err)

	fundAccountC, err := client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)

	_, err = client.BroadcastTransaction(fundAccountC)
	a.NoError(err)

	curStatus, err := client.Status()
	a.NoError(err)
	initialStatus := curStatus
	round := curStatus.LastRound

	// no consensus upgrade took place (yet)
	// in fact on slow environment it might happen faster than the test advances.
	// that's why errors from BroadcastTransaction are checked for exact specific errors
	// rather than simply "rekeying not yet enable" or "nonempty AuthAddr"

	// Ensure no rekeying happened
	ad, err := client.AccountData(accountA)
	a.NoError(err)
	a.Equal(basics.Address{}, ad.AuthAddr)

	// rekey A -> B (RekeyTo check)
	tx, err = client.ConstructPayment(accountA, accountB, fee, amount, nil, "", lease, basics.Round(round), basics.Round(initialStatus.NextVersionRound).SubSaturate(1))
	a.NoError(err)

	tx.RekeyTo = addrB
	rekey, err := client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)

	_, err = client.BroadcastTransaction(rekey)
	// non empty err means the upgrade have not happened yet (as expected), ensure the error
	if err != nil {
		// should be either "transaction has RekeyTo set but rekeying not yet enable" or "txn dead"
		if !strings.Contains(err.Error(), "transaction has RekeyTo set but rekeying not yet enable") &&
			!strings.Contains(err.Error(), "txn dead") {
			a.NoErrorf(err, "error message should be one of :\n%s\n%s", "transaction has RekeyTo set but rekeying not yet enable", "txn dead")
		}
	} else {
		// if we had no error it must mean that we've upgraded already. Verify that.
		curStatus, err := client.Status()
		a.NoError(err)
		a.NotEqual(consensusTestUnupgradedProtocol, protocol.ConsensusVersion(curStatus.LastVersion))
	}

	// use rekeyed key to authorize (AuthAddr check)
	tx.RekeyTo = basics.Address{}
	rekeyed, err := client.SignTransactionWithWalletAndSigner(wh, nil, accountB, tx)
	a.NoError(err)

	_, err = client.BroadcastTransaction(rekeyed)
	// non empty err means the upgrade have not happened yet (as expected), ensure the error
	if err != nil {
		// should be either "nonempty AuthAddr but rekeying is not supported" or "txn dead"
		if !strings.Contains(err.Error(), "nonempty AuthAddr but rekeying is not supported") &&
			!strings.Contains(err.Error(), "txn dead") {
			a.NoErrorf(err, "error message should be one of :\n%s\n%s", "nonempty AuthAddr but rekeying is not supported", "txn dead")
		}
	} else {
		// if we had no error it must mean that we've upgraded already. Verify that.
		curStatus, err := client.Status()
		a.NoError(err)
		a.NotEqual(consensusTestUnupgradedProtocol, protocol.ConsensusVersion(curStatus.LastVersion))
	}

	// go to upgrade
	curStatus, err = client.Status()
	a.NoError(err)

	startLoopTime := time.Now()
	// wait until the network upgrade : this can take a while.
	for protocol.ConsensusVersion(curStatus.LastVersion) != consensusTestFastUpgrade(firstProtocolWithApplicationSupport) {
		curStatus, err = client.Status()
		a.NoError(err)

		a.Less(int64(time.Now().Sub(startLoopTime)), int64(3*time.Minute))
		time.Sleep(time.Duration(smallLambdaMs) * time.Millisecond)
		round = curStatus.LastRound
	}

	// now that the network already upgraded:
	tx, err = client.ConstructPayment(accountC, accountD, fee, amount, nil, "", lease, basics.Round(round), basics.Round(round+1000))
	a.NoError(err)
	tx.RekeyTo = addrD

	rekey, err = client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)

	// now, that we have upgraded to the new protocol which supports rekey, try again.
	_, err = client.BroadcastTransaction(rekey)
	a.NoError(err)

	round, err = client.CurrentRound()
	a.NoError(err)
	client.WaitForRound(round + 1)

	// use rekeyed key to authorize (AuthAddr check)
	tx.RekeyTo = basics.Address{}
	rekeyed, err = client.SignTransactionWithWalletAndSigner(wh, nil, accountD, tx)
	a.NoError(err)

	_, err = client.BroadcastTransaction(rekeyed)
	a.NoError(err)
}
