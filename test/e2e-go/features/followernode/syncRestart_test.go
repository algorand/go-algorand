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

package followernode

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// Overview of this test:
// Start a two-node network--one in follower mode (follower has 0%, secondary has 100%)
// with the nodes having a max account lookback of 2.
// Advance the primary node to particular rounds, set the follower's sync round
// and then advance the follower node as much as possible.
// Restart the network and verify that the sync round hasn't advanced.
//
// NOTE: with a max account lookback of MAL, and the follower's sync round at SR:
// the follower cannot advance past round SR - 1 + MAL
func TestSyncRestart(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesFollower100SecondMaxAccountLookback2.json"))

	defer fixture.Shutdown()

	// sanity check that the follower has the expected max account lookback of 2:
	followerCtrl, err := fixture.GetNodeController("Follower")
	a.NoError(err)
	cfg, err := config.LoadConfigFromDisk(followerCtrl.GetDataDir())
	a.NoError(err)
	a.Equal(uint64(2), cfg.MaxAcctLookback)

	waitTill := func(node string, round basics.Round) {
		controller, err := fixture.GetNodeController(node)
		a.NoError(err)
		err = fixture.GetAlgodClientForController(controller).WaitForRoundWithTimeout(round)
		a.NoError(err)
	}

	getAlgod := func(node string) client.RestClient {
		controller, err := fixture.GetNodeController(node)
		a.NoError(err)
		algod := fixture.GetAlgodClientForController(controller)
		return algod
	}

	getRound := func(node string) basics.Round {
		algod := getAlgod(node)
		status, err := algod.Status()
		a.NoError(err)
		return status.LastRound
	}

	getSyncRound := func() basics.Round {
		followClient := getAlgod("Follower")
		rResp, err := followClient.GetSyncRound()
		a.NoError(err)
		return rResp.Round
	}

	a.EqualValues(1, getSyncRound())

	waitTill("Primary", 3)
	// with a max account lookback of 2, and the sync round at 1,
	// the follower cannot advance past round 2 = 1 - 1 + 2
	waitTill("Follower", 2)
	a.LessOrEqual(uint64(3), getRound("Primary"))
	a.EqualValues(2, getRound("Follower"))
	a.EqualValues(1, getSyncRound())

	/** restart the network **/
	fixture.ShutdownImpl(true)
	fixture.Start()

	a.LessOrEqual(uint64(3), getRound("Primary"))
	a.EqualValues(1, getSyncRound())
	a.EqualValues(2, getRound("Follower"))

	waitTill("Primary", 6)
	followerClient := getAlgod("Follower")
	err = followerClient.SetSyncRound(3)
	a.NoError(err)
	a.EqualValues(3, getSyncRound())
	// with a max account lookback of 2, and the sync round at 3,
	// the follower cannot advance past round 4 = 3 - 1 + 2
	waitTill("Follower", 4)
	a.LessOrEqual(basics.Round(6), getRound("Primary"))
	a.EqualValues(4, getRound("Follower"))
	a.EqualValues(3, getSyncRound())

	fixture.ShutdownImpl(true)
	fixture.Start()

	a.LessOrEqual(basics.Round(6), getRound("Primary"))
	a.EqualValues(4, getRound("Follower"))
	a.EqualValues(3, getSyncRound())
}
