// Copyright (C) 2019-2025 Algorand, Inc.
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

// eligible is just a dumb 50/50 choice of whether to mark an address
// incentiveELigible or not, so we get a diversity of testing. Ineligible
// accounts should not be challenged or try to heartbeat.
func eligible(address string) bool {
	return address[0]&0x01 == 0
}

// TestChallenges ensures that accounts are knocked off if they don't respond to
// a challenge, and that algod responds for accounts it knows (keepign them online)
func TestChallenges(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)
	a := require.New(fixtures.SynchronizedTest(t))

	retry := true
	for retry {
		retry = testChallengesOnce(t, a)
	}
}

// testChallengesOnce is the core of TestChallenges, but is allowed to bail out
// if the random accounts aren't suitable. TestChallenges will try again.
func testChallengesOnce(t *testing.T, a *require.Assertions) (retry bool) {
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
		t.Logf("Client %s has %v\n", name, accounts)
		return c, accounts
	}

	c1, accounts1 := clientAndAccounts("Node1")
	c2, accounts2 := clientAndAccounts("Node2")

	err := fixture.WaitForRoundWithTimeout(interval - lookback) // Make all LastHeartbeats > interval, < 2*interval
	a.NoError(err)

	// eligible accounts1 will get challenged with node offline, and suspended
	for _, account := range accounts1 {
		rekeyreg(a, c1, account.Address, eligible(account.Address))
	}
	// eligible accounts2 will get challenged, but node2 will heartbeat for them
	for _, account := range accounts2 {
		rekeyreg(a, c2, account.Address, eligible(account.Address))
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
	t.Logf("current %d lastPossible %d challengeRound %d", current, lastPossible, challengeRound)

	// Advance to challenge round, check the blockseed
	err = fixture.WaitForRoundWithTimeout(challengeRound)
	a.NoError(err)
	blk, err := c2.BookkeepingBlock(challengeRound)
	a.NoError(err)
	challenge := blk.BlockHeader.Seed[0] & mask // high bit

	// match1 are the accounts from node1 that match the challenge, but only
	// eligible ones are truly challenged and could be suspended.
	match1 := util.MakeSet[basics.Address]()
	eligible1 := util.MakeSet[basics.Address]() // matched AND eligible
	for _, account := range accounts1 {
		address, err := basics.UnmarshalChecksumAddress(account.Address)
		a.NoError(err)
		if address[0]&mask == challenge {
			t.Logf("%v of node 1 was challenged %v by %v\n", address, address[0], challenge)
			match1.Add(address)
			if eligible(address.String()) {
				eligible1.Add(address)
			}
		}
	}
	if match1.Empty() {
		return true
	}

	match2 := util.MakeSet[basics.Address]()
	eligible2 := util.MakeSet[basics.Address]() // matched AND eligible
	for _, account := range accounts2 {
		address, err := basics.UnmarshalChecksumAddress(account.Address)
		a.NoError(err)
		if address[0]&mask == challenge {
			t.Logf("%v of node 2 was challenged %v by %v\n", address, address[0], challenge)
			match2.Add(address)
			if eligible(address.String()) {
				eligible2.Add(address)
			}
		}
	}
	if match2.Empty() {
		return true
	}

	allMatches := util.Union(match1, match2)

	// All nodes are online to start
	for address := range allMatches {
		data, err := c2.AccountData(address.String())
		a.NoError(err)
		a.Equal(basics.Online, data.Status, "%v %d", address.String(), data.LastHeartbeat)
		a.NotZero(data.VoteID)
		a.Equal(eligible(address.String()), data.IncentiveEligible)
	}

	// Watch the first half grace period for proposals from challenged nodes, since they won't have to heartbeat.
	lucky := util.MakeSet[basics.Address]()
	fixture.WithEveryBlock(challengeRound, challengeRound+grace/2, func(block bookkeeping.Block) {
		if eligible2.Contains(block.Proposer()) {
			lucky.Add(block.Proposer())
		}
		a.Empty(block.AbsentParticipationAccounts) // nobody suspended during grace
	})

	// In the second half of the grace period, Node 2 should heartbeat for its eligible accounts
	beated := util.MakeSet[basics.Address]()
	fixture.WithEveryBlock(challengeRound+grace/2+1, challengeRound+grace, func(block bookkeeping.Block) {
		t.Logf("2nd half Block %d\n", block.Round())
		if eligible2.Contains(block.Proposer()) {
			lucky.Add(block.Proposer())
		}
		for i, txn := range block.Payset {
			hb := txn.Txn.HeartbeatTxnFields
			t.Logf("Heartbeat txn %v in position %d round %d\n", hb, i, block.Round())
			a.Contains(match2, hb.HbAddress, hb.HbAddress)                 // only Node 2 is alive
			a.Contains(eligible2, hb.HbAddress, hb.HbAddress)              // only eligible accounts get heartbeat
			a.NotContains(beated, hb.HbAddress, "rebeat %s", hb.HbAddress) // beat only once
			beated.Add(hb.HbAddress)
			a.NotContains(lucky, hb.HbAddress, "unneeded %s", hb.HbAddress) // we should not see a heartbeat from an account that proposed
		}
		a.Empty(block.AbsentParticipationAccounts) // nobody suspended during grace
	})
	a.Equal(eligible2, util.Union(beated, lucky))

	blk, err = fixture.WaitForBlockWithTimeout(challengeRound + grace + 1)
	a.NoError(err)
	a.Equal(eligible1, util.MakeSet(blk.AbsentParticipationAccounts...))

	// node 1 challenged (eligible) accounts are suspended because node 1 is off
	for address := range match1 {
		data, err := c2.AccountData(address.String())
		a.NoError(err)
		if eligible1.Contains(address) {
			a.Equal(basics.Offline, data.Status, "%v was not offline in round %d. (%d and %d)",
				address, challengeRound+grace+1, data.LastHeartbeat, data.LastProposed)
		} else {
			a.Equal(basics.Online, data.Status, address) // not eligible, so not suspended
		}
		a.NotZero(data.VoteID, address)
		a.False(data.IncentiveEligible, address) // suspension turns off flag
	}

	// node 2 challenged accounts are not suspended (saved by heartbeat or weren't eligible)
	for address := range match2 {
		data, err := c2.AccountData(address.String())
		a.NoError(err)
		a.Equal(basics.Online, data.Status, address)
		a.NotZero(data.VoteID, address)
		a.Equal(data.IncentiveEligible, eligible(address.String()))
	}

	return false // no need to retry
}
