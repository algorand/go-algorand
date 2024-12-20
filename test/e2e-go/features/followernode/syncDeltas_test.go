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

package followernode

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestBasicSyncMode(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Overview of this test:
	// Start a two-node network--one in follower mode (follower has 0%, secondary has 100%)
	// Let it run for a few blocks.
	// Retrieve deltas for some rounds using sync round calls on the follower node.

	var fixture fixtures.RestClientFixture
	// Give the second node (which starts up last) all the stake so that its proposal always has better credentials,
	// and so that its proposal isn't dropped. Otherwise, the test burns 17s to recover. We don't care about stake
	// distribution so this is fine.
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesFollower100Second.json"))
	defer fixture.Shutdown()

	// Get controller for Primary node to see the state of the chain
	nc, err := fixture.GetNodeController("Primary")
	a.NoError(err)

	sender, err := fixture.GetRichestAccount()
	require.NoError(t, err)

	status, err := fixture.AlgodClient.Status()
	require.NoError(t, err)
	curRound := status.LastRound

	wh, err := fixture.LibGoalClient.GetUnencryptedWalletHandle()
	require.NoError(t, err)

	fundingTx, err := fixture.LibGoalClient.SendPaymentFromWalletWithLease(wh, nil, sender.Address, sender.Address, 0, 0, nil, "", [32]byte{1, 2, 3}, basics.Round(curRound).SubSaturate(1), 0)
	require.NoError(t, err)
	txn, err := fixture.WaitForConfirmedTxn(5, fundingTx.ID().String())
	require.NoError(t, err)

	require.LessOrEqual(t, *txn.ConfirmedRound, uint64(5), "Transaction should be confirmed in the first 5 rounds")

	// Let the network make some progress
	waitForRound := uint64(5)
	err = fixture.GetAlgodClientForController(nc).WaitForRoundWithTimeout(waitForRound)
	a.NoError(err)

	// Get the follower client, and exercise the sync/ledger functionality
	followControl, err := fixture.GetNodeController("Follower")
	a.NoError(err)
	followClient := fixture.GetAlgodClientForController(followControl)
	// Now, catch up round by round, retrieving state deltas for each
	for round := uint64(1); round <= waitForRound; round++ {
		// assert sync round set
		rResp, err := followClient.GetSyncRound()
		a.NoError(err)
		a.Equal(round, rResp.Round)
		// make some progress to round
		err = followClient.WaitForRoundWithTimeout(round)
		a.NoError(err)
		// retrieve state delta
		gResp, err := followClient.GetLedgerStateDelta(round)
		a.NoError(err)
		a.NotZero(gResp)

		if round == *txn.ConfirmedRound {
			// Txleases should always be nil for JSON responses
			require.Nil(t, gResp.Txleases)

			// Verify that the transaction is in the state delta
			expectedTxids := map[transactions.Txid]ledgercore.IncludedTransactions{
				txn.Txn.ID(): {
					LastValid: txn.Txn.Txn.LastValid,
					Intra:     0,
				},
			}
			require.Equal(t, expectedTxids, gResp.Txids)
		}

		// set sync round next
		err = followClient.SetSyncRound(round + 1)
		a.NoError(err)
	}
	err = fixture.WaitForRoundWithTimeout(waitForRound)
	a.NoError(err)
}
