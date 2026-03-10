// Copyright (C) 2019-2026 Algorand, Inc.
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
)

// TestBasicSuspension confirms that accounts that don't propose get suspended
func TestBasicSuspension(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	consensusVersion := protocol.ConsensusFuture
	// Overview of this test:
	// Start a three-node network (70,20,10), all online
	// Wait for 10 and 20% nodes to propose (we never suspend accounts with lastProposed=lastHeartbeat=0)
	// Stop them both
	// Run for 105 rounds, which is enough for 20% node to be suspended, but not 10%
	// check neither suspended, send a tx from 20% to 10%, only 20% gets suspended
	// bring n20 back up, make sure it gets back online by proposing during the lookback
	const suspend20 = 105 // 1.00/0.20 * absentFactor

	var fixture fixtures.RestClientFixture
	// Speed up rounds.  Long enough lookback, so 20% node has a chance to
	// get back online after being suspended. (0.8^32 is very small)

	const lookback = 32
	fixture.FasterConsensus(consensusVersion, time.Second, lookback)
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

	proto := config.Consensus[consensusVersion]
	rekeyreg(a, c10, proto, account10.Address, true)
	rekeyreg(a, c20, proto, account20.Address, true)

	// Accounts are now suspendable whether they have proposed yet or not
	// because keyreg sets LastHeartbeat. Stop c20 which means account20 will be
	// absent about 50 rounds after keyreg goes into effect (lookback)
	a.NoError(c20.FullStop())

	afterStop, err := c10.Status()
	a.NoError(err)

	// Advance lookback+55 rounds
	err = fixture.WaitForRoundWithTimeout(afterStop.LastRound + lookback + suspend20)
	a.NoError(err)

	// make sure c10 node is in-sync with the network
	status, err := fixture.LibGoalClient.Status()
	a.NoError(err)
	fmt.Printf("status.LastRound %d\n", status.LastRound)
	_, err = c10.WaitForRound(status.LastRound)
	a.NoError(err)

	// n20's account has been suspended (offline, but has voting key material)
	account, err := c10.AccountData(account20.Address)
	a.NoError(err)
	fmt.Printf("account20 %d %d\n", account.LastProposed, account.LastHeartbeat)
	a.Equal(basics.Offline, account.Status)
	a.NotZero(account.VoteID)
	a.False(account.IncentiveEligible) // suspension turns off flag

	account, err = c10.AccountData(account10.Address)
	a.NoError(err)
	a.Equal(basics.Online, account.Status)
	a.NotZero(account.VoteID)
	a.True(account.IncentiveEligible)

	// Use the fixture to start node20  again. Since we're only a bit past the
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
		r.False(account.IncentiveEligible, i)
	}
}
