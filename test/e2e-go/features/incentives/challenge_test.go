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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util"
)

// TestChallenges ensures that accounts are knocked off if they don't respond to
// a challenge, and that algod responds for accounts it knows (keepign them online)
func TestChallenges(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Overview of this test:
	// Use a consensus protocol with challenge interval=50, grace period=10, bits=2.
	// Start a three-node network. One relay, two nodes with 4 accounts each
	// At round 50, ~2 nodes will be challenged.

	const lookback = 32
	const interval = 50
	const grace = 10
	const mask = 0x80

	var fixture fixtures.RestClientFixture
	// Speed up rounds, keep lookback > 2 * grace period
	fixture.FasterConsensus(protocol.ConsensusFuture, time.Second, lookback)
	fixture.AlterConsensus(protocol.ConsensusFuture,
		func(cp config.ConsensusParams) config.ConsensusParams {
			cp.Payouts.ChallengeInterval = 50
			cp.Payouts.ChallengeGracePeriod = 10
			cp.Payouts.ChallengeBits = 1 // half of nodes should get challenged
			return cp
		})
	fixture.Setup(t, filepath.Join("nettemplates", "Challenges.json"))
	defer fixture.Shutdown()

	clientAndAccounts := func(name string) (libgoal.Client, []model.Account) {
		c := fixture.GetLibGoalClientForNamedNode(name)
		accounts, err := fixture.GetNodeWalletsSortedByBalance(c)
		a.NoError(err)
		a.Len(accounts, 8)
		fmt.Printf("Client %s has %v\n", name, accounts)
		return c, accounts
	}

	c1, accounts1 := clientAndAccounts("Node1")
	c2, accounts2 := clientAndAccounts("Node2")

	// By re-regging, we become eligible for suspension (normal + challenges)
	// TODO: Confirm that rereg is required for challenge suspensions

	err := fixture.WaitForRoundWithTimeout(interval - lookback) // Make all LastHeartbeats > interval, < 2*interval
	a.NoError(err)

	for _, account := range accounts1 {
		rekeyreg(&fixture, a, c1, account.Address)
	}
	for _, account := range accounts2 {
		rekeyreg(&fixture, a, c2, account.Address)
	}

	// turn off node 1, so it can't heartbeat
	a.NoError(c1.FullStop())

	current, err := c2.CurrentRound()
	a.NoError(err)
	// Get them all done so that their inflated LastHeartbeat comes before the
	// next challenge.
	a.Less(current+lookback, 2*uint64(interval))

	// We need to wait for the first challenge that happens after the keyreg
	// LastHeartbeat has passed.  Example: current is 40, so the lastPossible
	// LastHeartbeat is 72. Interval is 50, so challengeRound is 100.

	// 100 = 40 + 32 + (50-22) = 72 + 28
	lastPossible := current + lookback
	challengeRound := lastPossible + (interval - lastPossible%interval)

	// Advance to challenge round, check the blockseed
	err = fixture.WaitForRoundWithTimeout(challengeRound)
	a.NoError(err)
	blk, err := c2.BookkeepingBlock(challengeRound)
	a.NoError(err)
	challenge := blk.BlockHeader.Seed[0] & mask // high bit

	challenged1 := util.MakeSet[basics.Address]()
	for _, account := range accounts1 {
		address, err := basics.UnmarshalChecksumAddress(account.Address)
		a.NoError(err)
		if address[0]&mask == challenge {
			fmt.Printf("%v of node 1 was challenged %v by %v\n", address, address[0], challenge)
			challenged1.Add(address)
		}
	}
	require.NotEmpty(t, challenged1, "rerun the test") // TODO: remove.

	challenged2 := util.MakeSet[basics.Address]()
	for _, account := range accounts2 {
		address, err := basics.UnmarshalChecksumAddress(account.Address)
		a.NoError(err)
		if address[0]&mask == challenge {
			fmt.Printf("%v of node 2 was challenged %v by %v\n", address, address[0], challenge)
			challenged2.Add(address)
		}
	}
	require.NotEmpty(t, challenged2, "rerun the test") // TODO: remove.

	allChallenged := util.Union(challenged1, challenged2)

	// All challenged nodes are still online
	for address := range allChallenged {
		data, err := c2.AccountData(address.String())
		a.NoError(err)
		a.Equal(basics.Online, data.Status, "%v %d", address.String(), data.LastHeartbeat)
		a.NotZero(data.VoteID)
		a.True(data.IncentiveEligible)
	}

	// In the second half of the grace period, Node 2 should heartbeat for its accounts
	beated := util.MakeSet[basics.Address]()
	fixture.WithEveryBlock(challengeRound+grace/2, challengeRound+grace, func(block bookkeeping.Block) {
		for _, txn := range block.Payset {
			hb := txn.Txn.HeartbeatTxnFields
			fmt.Printf("Heartbeat txn %v\n", hb)
			a.True(challenged2.Contains(hb.HbAddress)) // only Node 2 is alive
			a.False(beated.Contains(hb.HbAddress))     // beat only once
			beated.Add(hb.HbAddress)
		}
		a.Empty(block.AbsentParticipationAccounts) // nobody suspended during grace
	})
	a.Equal(challenged2, beated)

	blk, err = fixture.WaitForBlockWithTimeout(challengeRound + grace + 1)
	a.NoError(err)
	a.Equal(challenged1, util.MakeSet(blk.AbsentParticipationAccounts...))

	// node 1 challenged accounts are suspended because node 1 is off
	for address := range challenged1 {
		data, err := c2.AccountData(address.String())
		a.NoError(err)
		a.Equal(basics.Offline, data.Status, address)
		a.NotZero(data.VoteID, address)
		a.False(data.IncentiveEligible, address) // suspension turns off flag
	}

	// node 2 challenged accounts are not suspended (saved by heartbeat)
	for address := range challenged2 {
		data, err := c2.AccountData(address.String())
		a.NoError(err)
		a.Equal(basics.Online, data.Status, address)
		a.NotZero(data.VoteID, address)
		a.True(data.IncentiveEligible, address)
	}

}
