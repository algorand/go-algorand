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
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const roundTime = 4 * time.Second

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
	// Stop the 15% node
	// Let it run for less than 10*100/15
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

	// turn off Node15
	n15, err := fixture.GetNodeController("Node15")
	a.NoError(err)
	a.NoError(n15.FullStop())

	// Proceed 60 rounds
	err = fixture.WaitForRound(60, 60*roundTime)
	a.NoError(err)

	// n15account is still online (the node is off, but the account is marked online)
	account, err := fixture.LibGoalClient.AccountData(address)
	a.NoError(err)
	a.Equal(basics.Online, account.Status)

	// Proceed to round 70
	err = fixture.WaitForRound(70, 10*roundTime)
	a.NoError(err)

	// n15's account is still online, but only because it has gone "unnoticed"
	account, err = fixture.LibGoalClient.AccountData(address)
	a.NoError(err)
	a.Equal(basics.Online, account.Status)

	fixture.SendMoneyAndWait(70, 1000, 1000, richAccount.Address, address, "")

	// n15's account is now offline, but has voting key material (suspended)
	account, err = fixture.LibGoalClient.AccountData(address)
	a.NoError(err)
	a.Equal(basics.Offline, account.Status)
	a.NotZero(account.VoteID)

	// Use the fixture to start the node again. Since we're only a bit past the
	// suspension round, it will still be voting.  It should get a chance to
	// propose soon (15/100 of blocks) which will put it back online.
	lg, err := fixture.StartNode(n15.GetDataDir())
	a.NoError(err)

	// Wait for newly restarted node to start. Presumably it'll catchup in
	// seconds, and propose by round 90
	_, err = lg.Status()
	a.NoError(err)

	// Proceed to round 90
	err = fixture.WaitForRound(90, 20*roundTime)
	a.NoError(err)
	// n15's account is back online, but has voting key material (suspended)
	account, err = fixture.LibGoalClient.AccountData(address)
	a.NoError(err)
	a.Equal(basics.Online, account.Status)
	a.NotZero(account.VoteID)
}
