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
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestBasicSuspension confirms that accounts that don't propose get suspended
// (when a tx naming them occurs)
func TestBasicSuspension(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Overview of this test:
	// Start a three-node network (70,20,10), all online
	// Wait for 10 and 20% nodes to propose (we never suspend accounts with lastProposed=lastHeartbeat=0)
	// Stop them both
	// Run for 55 rounds, which is enough for 20% node to be suspended, but not 10%
	// check neither suspended, send a tx from 20% to 10%, only 20% gets suspended
	// TODO once we have heartbeats: bring them back up, make sure 20% gets back online
	const suspend20 = 55

	var fixture fixtures.RestClientFixture
	// Speed up rounds, but keep long lookback, so 20% node has a chance to get
	// back online after being suspended.
	fixture.FasterConsensus(protocol.ConsensusFuture, time.Second, 320)
	fixture.Setup(t, filepath.Join("nettemplates", "Suspension.json"))
	defer fixture.Shutdown()

	clientAndAccount := func(name string) (libgoal.Client, model.Account) {
		c := fixture.GetLibGoalClientForNamedNode(name)
		accounts, err := fixture.GetNodeWalletsSortedByBalance(c)
		a.NoError(err)
		a.Len(accounts, 1)
		fmt.Printf("Client %s is %v\n", name, accounts[0].Address)
		return c, accounts[0]
	}

	c10, account10 := clientAndAccount("Node10")
	c20, account20 := clientAndAccount("Node20")

	rekeyreg(&fixture, a, c10, account10.Address)
	rekeyreg(&fixture, a, c20, account20.Address)

	// Wait until each have proposed, so they are suspendable
	proposed10 := false
	proposed20 := false
	for !proposed10 || !proposed20 {
		status, err := c10.Status()
		a.NoError(err)
		block, err := c10.BookkeepingBlock(status.LastRound)
		a.NoError(err)

		fmt.Printf(" block %d proposed by %v\n", status.LastRound, block.Proposer())

		fixture.WaitForRoundWithTimeout(status.LastRound + 1)

		switch block.Proposer().String() {
		case account10.Address:
			proposed10 = true
		case account20.Address:
			proposed20 = true
		}
	}

	a.NoError(c20.FullStop())

	afterStop, err := c10.Status()
	a.NoError(err)

	// Advance 55 rounds
	err = fixture.WaitForRoundWithTimeout(afterStop.LastRound + suspend20)
	a.NoError(err)

	// n20 is still online after 55 rounds of absence (the node is off, but the
	// account is marked online) because it has not been "noticed".
	account, err := fixture.LibGoalClient.AccountData(account20.Address)
	a.NoError(err)
	a.Equal(basics.Online, account.Status)
	voteID := account.VoteID
	a.NotZero(voteID)

	// pay n10 & n20, so both could be noticed
	richAccount, err := fixture.GetRichestAccount()
	a.NoError(err)
	fixture.SendMoneyAndWait(afterStop.LastRound+suspend20, 5, 1000, richAccount.Address, account10.Address, "")
	fixture.SendMoneyAndWait(afterStop.LastRound+suspend20, 5, 1000, richAccount.Address, account20.Address, "")

	// make sure c10 node is in-sync with the network
	status, err := fixture.LibGoalClient.Status()
	a.NoError(err)
	_, err = c10.WaitForRound(status.LastRound)
	a.NoError(err)

	// n20's account is now offline, but has voting key material (suspended)
	account, err = c10.AccountData(account20.Address)
	a.NoError(err)
	a.Equal(basics.Offline, account.Status)
	a.NotZero(account.VoteID)
	a.False(account.IncentiveEligible) // suspension turns off flag

	// n10's account is still online, because it's got less stake, has not been absent 10 x interval.
	account, err = c10.AccountData(account10.Address)
	a.NoError(err)
	a.Equal(basics.Online, account.Status)
	a.NotZero(account.VoteID)
	a.True(account.IncentiveEligible)

	// Use the fixture to start the node again. Since we're only a bit past the
	// suspension round, it will still be voting.  It should get a chance to
	// propose soon (20/100 of blocks) which will put it back online.
	lg, err := fixture.StartNode(c20.DataDir())
	a.NoError(err)

	// Wait for newly restarted node to start.
	stat, err := lg.Status()
	a.NoError(err)

	// Get the current round, and wait for the restarted node to get there.
	stat, err = fixture.AlgodClient.Status()
	a.NoError(err)

	// Wait for latest round to show n20 has started and caught up.
	restartRound := stat.LastRound
	stat, err = lg.WaitForRound(restartRound)
	a.NoError(err)

	// Proceed until a round is proposed by n20.
	attempts := 0
	for !fixture.VerifyBlockProposed(account20.Address, 1) {
		stat, err = lg.WaitForRound(stat.LastRound + 1)
		a.NoError(err)
		attempts++
		a.Less(attempts, 2*suspend20, "n20 didn't propose\n")
	}
	// paranoia. see payouts_test.go for more details.
	r := require.New(t)
	for i, c := range []libgoal.Client{c10, c20} {
		_, err := c.WaitForRound(stat.LastRound)
		r.NoError(err)
		account, err = c.AccountData(account20.Address)
		a.NoError(err)
		r.Equal(basics.Online, account.Status, i)
		r.Greater(account.LastProposed, restartRound, i)

		r.Equal(voteID, account.VoteID, i)
		r.False(account.IncentiveEligible, i)
	}
}
