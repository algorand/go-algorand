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

package suspension

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const roundTime = 2 * time.Second // with speedup below, what's a good value?

// TestBasicSuspension confirms that accounts that don't propose get suspended
// (when a tx naming them occurs)
func TestBasicSuspension(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Overview of this test:
	// Start a three-node network (84,15,1)
	// Wait for 15% node to propose (we never suspend accounts with lastProposed=lastHeartbeat=0)
	// Stop it
	// Let it run for less than 10*100/15 = 66.6
	// check not suspended, send a tx, still not suspended
	// Let it run two more, during which the node can't propose, so it is ready for suspension
	// check not suspended, send a tx, NOW suspended

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "Suspension.json"))
	defer fixture.Shutdown()

	richAccount, err := fixture.GetRichestAccount()
	a.NoError(err)

	// get Node15's address
	n15c := fixture.GetLibGoalClientForNamedNode("Node15")
	accounts, err := fixture.GetNodeWalletsSortedByBalance(n15c)
	a.NoError(err)
	a.Len(accounts, 1)
	a.Equal(accounts[0].Status, basics.Online.String())
	address := accounts[0].Address

	// wait for n15 to have LastProposed != 0
	account, err := fixture.LibGoalClient.AccountData(address)
	for account.LastProposed == 0 {
		a.NoError(err)
		a.Equal(basics.Online, account.Status)
		account, err = fixture.LibGoalClient.AccountData(address)
		time.Sleep(roundTime)
	}
	a.NoError(err)

	// turn off Node15
	n15, err := fixture.GetNodeController("Node15")
	a.NoError(err)
	a.NoError(n15.FullStop())

	afterStop, err := fixture.AlgodClient.Status()
	a.NoError(err)

	// Advance 60 rounds
	err = fixture.WaitForRound(afterStop.LastRound+60, 60*roundTime)
	a.NoError(err)

	// n15account is still online (the node is off, but the account is marked online)
	account, err = fixture.LibGoalClient.AccountData(address)
	a.NoError(err)
	a.Equal(basics.Online, account.Status)
	voteID := account.VoteID
	a.NotZero(voteID)

	// Advance 10 more, n15 has been "absent" for 70 rounds now
	err = fixture.WaitForRound(afterStop.LastRound+70, 15*roundTime)
	a.NoError(err)

	// n15's account is still online, but only because it has gone "unnoticed"
	account, err = fixture.LibGoalClient.AccountData(address)
	a.NoError(err)
	a.Equal(basics.Online, account.Status)

	// pay n15, so it gets noticed
	fixture.SendMoneyAndWait(afterStop.LastRound+70, 5, 1000, richAccount.Address, address, "")

	// n15's account is now offline, but has voting key material (suspended)
	account, err = fixture.LibGoalClient.AccountData(address)
	a.NoError(err)
	a.Equal(basics.Offline, account.Status)
	a.NotZero(account.VoteID)
	a.False(account.IncentiveEligible)

	// Use the fixture to start the node again. Since we're only a bit past the
	// suspension round, it will still be voting.  It should get a chance to
	// propose soon (15/100 of blocks) which will put it back online.
	lg, err := fixture.StartNode(n15.GetDataDir())
	a.NoError(err)

	// Wait for newly restarted node to start. Presumably it'll catchup in
	// seconds, and propose by round 90
	stat, err := lg.Status()
	a.NoError(err)

	// Proceed until a round is proposed by n15. (Stop at 50 rounds, that's more likely a bug than luck)
	for r := stat.LastRound; r < stat.LastRound+50; r++ {
		err = fixture.WaitForRound(r, roundTime)
		a.NoError(err)

		// Once n15 proposes, break out early
		if fixture.VerifyBlockProposed(address, 1) {
			// wait one extra round, because changes are processed in block n+1.
			err = fixture.WaitForRound(r+1, roundTime)
			a.NoError(err)
			break
		}
	}
	// n15's account is back online, with same voting material
	account, err = fixture.LibGoalClient.AccountData(address)
	a.NoError(err)
	a.Equal(basics.Online, account.Status)
	a.Equal(voteID, account.VoteID)
	// coming back online by proposal does not make you incentive eligible (you
	// didn't "pay the fine")
	a.False(account.IncentiveEligible)

	// but n15 wants incentives, so it keyregs again, paying the extra fee.
	// We're going to re-reg the exact same key material, so that the running
	// node can keep voting.

	// we make an _offline_ tx here, because we want to populate the key
	// material ourself, by copying the account's existing state. That makes it
	// an _online_ keyreg. That allows the running node to chug along without
	// new part keys.
	reReg, err := n15c.MakeUnsignedGoOfflineTx(address, 0, 0, 5_000_000, [32]byte{})
	require.NoError(t, err, "should be able to make tx")

	reReg.KeyregTxnFields = transactions.KeyregTxnFields{
		VotePK:          account.VoteID,
		SelectionPK:     account.SelectionID,
		StateProofPK:    account.StateProofID,
		VoteFirst:       account.VoteFirstValid,
		VoteLast:        account.VoteLastValid,
		VoteKeyDilution: account.VoteKeyDilution,
	}

	wh, err := n15c.GetUnencryptedWalletHandle()
	require.NoError(t, err, "should be able to get unencrypted wallet handle")
	onlineTxID, err := n15c.SignAndBroadcastTransaction(wh, nil, reReg)
	require.NoError(t, err, "should be no errors when going online")

	fixture.WaitForConfirmedTxn(uint64(reReg.LastValid), onlineTxID)
	account, err = fixture.LibGoalClient.AccountData(address)

	a.NoError(err)
	a.Equal(basics.Online, account.Status)
	a.True(account.IncentiveEligible) // eligible!

}
