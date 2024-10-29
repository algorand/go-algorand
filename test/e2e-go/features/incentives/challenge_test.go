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

	const interval = 50
	const grace = 10

	var fixture fixtures.RestClientFixture
	// Speed up rounds, keep lookback > 2 * grace period
	fixture.FasterConsensus(protocol.ConsensusFuture, time.Second, 32)
	fixture.AlterConsensus(protocol.ConsensusFuture,
		func(cp config.ConsensusParams) config.ConsensusParams {
			cp.Payouts.ChallengeInterval = 50
			cp.Payouts.ChallengeGracePeriod = 10
			cp.Payouts.ChallengeBits = 2
			return cp
		})
	fixture.Setup(t, filepath.Join("nettemplates", "Challenges.json"))
	defer fixture.Shutdown()

	clientAndAccounts := func(name string) (libgoal.Client, []model.Account) {
		c := fixture.GetLibGoalClientForNamedNode(name)
		accounts, err := fixture.GetNodeWalletsSortedByBalance(c)
		a.NoError(err)
		a.Len(accounts, 4)
		fmt.Printf("Client %s has %v\n", name, accounts)
		return c, accounts
	}

	c1, accounts1 := clientAndAccounts("Node1")
	c2, accounts2 := clientAndAccounts("Node2")

	// By re-regging, we become eligible for suspension (normal + challenges)
	// TODO: Confirm that rereg is required for challenge suspensions
	for _, account := range accounts1 {
		rekeyreg(&fixture, a, c1, account.Address)
	}
	for _, account := range accounts2 {
		rekeyreg(&fixture, a, c2, account.Address)
	}

	// turn off node 1, so it can't heartbeat
	a.NoError(c1.FullStop())

	// Advance to first challenge round, check the blockseed
	err := fixture.WaitForRoundWithTimeout(interval)
	a.NoError(err)

	blk, err := c2.BookkeepingBlock(interval)
	a.NoError(err)
	challenge := blk.BlockHeader.Seed[0] & 0xA0 // high two bits

	challenged1 := util.MakeSet[model.Account]()
	for _, account := range accounts1 {
		abytes, err := basics.UnmarshalChecksumAddress(account.Address)
		a.NoError(err)
		if abytes[0]&0xA0 == challenge {
			fmt.Printf("%v of node 1 was challenged %v by %v\n", account.Address, abytes[0], challenge)
			challenged1.Add(account)
		}
	}

	challenged2 := util.MakeSet[model.Account]()
	for _, account := range accounts2 {
		abytes, err := basics.UnmarshalChecksumAddress(account.Address)
		a.NoError(err)
		if abytes[0]&0xA0 == challenge {
			fmt.Printf("%v of node 2 was challenged %v by %v\n", account.Address, abytes[0], challenge)
			challenged2.Add(account)
		}
	}

	allChallenged := util.Union(challenged1, challenged2)

	// TODO: unroll this loop and notice the heartbeat transactions from node 2
	err = fixture.WaitForRoundWithTimeout(interval + grace)
	a.NoError(err)

	// challenged accounts are still online
	for account := range allChallenged {
		data, err := c2.AccountData(account.Address)
		a.NoError(err)
		a.Equal(basics.Online, data.Status)
		a.NotZero(data.VoteID)
		a.True(data.IncentiveEligible)
	}

	err = fixture.WaitForRoundWithTimeout(interval + grace + 1)
	a.NoError(err)

	// The challenged nodes need be "noticed" to be suspended. TODO: Remove this
	// section when we have prompt suspensions.
	source := accounts2[0] // always pay from operational account on node 2
	for account := range allChallenged {
		fmt.Printf("pay %v\n", account.Address)
		txn, err := c2.SendPaymentFromUnencryptedWallet(source.Address, account.Address, 1000, 0, nil)
		a.NoError(err)
		info, err := fixture.WaitForConfirmedTxn(uint64(txn.LastValid), txn.ID().String())
		a.NoError(err)

		blk, err := c2.BookkeepingBlock(*info.ConfirmedRound)
		a.NoError(err)
		a.Len(blk.AbsentParticipationAccounts, 1)
		a.Equal(blk.AbsentParticipationAccounts[0].String(), account.Address)
	}

	// node 1 challenged accounts are suspended because node 1 is off
	for account := range challenged1 {
		fmt.Printf("check1 %v\n", account.Address)
		data, err := c2.AccountData(account.Address)
		a.NoError(err)
		a.Equal(basics.Offline, data.Status, account.Address)
		a.NotZero(data.VoteID, account.Address)
		a.False(data.IncentiveEligible, account.Address) // suspension turns off flag
	}

	// node 2 challenged accounts are not suspended (saved by heartbeat)
	for account := range challenged2 {
		fmt.Printf("check2 %v\n", account.Address)
		data, err := c2.AccountData(account.Address)
		a.NoError(err)
		a.Equal(basics.Online, data.Status, account.Address)
		a.NotZero(data.VoteID, account.Address)
		a.True(data.IncentiveEligible, account.Address)
	}

}
