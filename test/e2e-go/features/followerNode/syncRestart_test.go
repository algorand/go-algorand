// Copyright (C) 2019-2023 Algorand, Inc.
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

package followerNode

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestSyncRestart(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Overview of this test:
	// Start a two-node network--one in follower mode (follower has 0%, secondary has 100%)
	// with follower having a max account lookback of 2.
	// Advance the primary node to particular rounds and the follower node as far as possible.
	// Restart the follower node and verify that the sync round hasn't advanced.

	// NOTE: with a max account lookback of MAL, when the follower's sync round is SR:
	// 		 the follower cannot advance past round SR + MAL - 1

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesFollower100SecondMaxAccountLookback2.json"))

	defer fixture.Shutdown()

	// sanity check that the follower has the expected max account lookback:
	maxAccountLookback := uint64(2)
	followerCtrl, err := fixture.GetNodeController("Follower")
	a.NoError(err)
	cfg, err := config.LoadConfigFromDisk(followerCtrl.GetDataDir())
	a.NoError(err)
	a.Equal(maxAccountLookback, cfg.MaxAcctLookback)

	advanceTo := func(node string, round uint64) {
		controller, err := fixture.GetNodeController(node)
		a.NoError(err)
		err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(controller), round)
		a.NoError(err)
	}

	getAlgod := func(node string) client.RestClient {
		controller, err := fixture.GetNodeController(node)
		a.NoError(err)
		algod := fixture.GetAlgodClientForController(controller)
		return algod
	}

	getRound := func(node string) uint64 {
		algod := getAlgod(node)
		status, err := algod.Status()
		a.NoError(err)
		return status.LastRound
	}

	getSyncRound := func() uint64 {
		followClient := getAlgod("Follower")
		rResp, err := followClient.GetSyncRound()
		a.NoError(err)
		return rResp.Round
	}

	a.Equal(uint64(1), getSyncRound())

	advanceTo("Primary", 3)

	// with a max account lookback of 2, and the sync round at 1,
	// the follower cannot advance past round 2 = 1 + 2 - 1
	advanceTo("Follower", 2)
	a.LessOrEqual(uint64(3), getRound("Primary"))
	a.Equal(uint64(2), getRound("Follower"))
	a.Equal(uint64(1), getSyncRound())

	/** restart the network **/
	fixture.ShutdownImpl(true)
	fixture.Start()

	a.LessOrEqual(uint64(3), getRound("Primary"))
	a.Equal(uint64(2), getRound("Follower"))
	a.Equal(uint64(1), getSyncRound())

	advanceTo("Primary", 6)
	followerClient := getAlgod("Follower")
	err = followerClient.SetSyncRound(uint64(3))
	a.NoError(err)
	a.Equal(uint64(3), getSyncRound())
	// with a max account lookback of 2, and the sync round at 3,
	// the follower cannot advance past round 4 = 3 + 2 - 10
	advanceTo("Follower", 4)
	a.LessOrEqual(uint64(6), getRound("Primary"))
	a.Equal(uint64(4), getRound("Follower"))
	a.Equal(uint64(3), getSyncRound())

	fixture.ShutdownImpl(true)
	fixture.Start()

	a.LessOrEqual(uint64(6), getRound("Primary"))
	a.Equal(uint64(4), getRound("Follower"))
	a.Equal(uint64(3), getSyncRound())
}

func TestPrelim2(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Overview of this test:
	// Start a two-node network--one in follower mode (follower has 0%, secondary has 100%)
	// with follower having a max account lookback of 2.
	// Advance the primary node to round 3 and the follower node to round 2.
	// Restart the network.
	// Check that the sync round hasn't advanced.

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesFollower100SecondMaxAccountLookback2.json"))

	defer fixture.Shutdown()

	// sanity check that the follower has the expected max account lookback:
	maxAccountLookback := uint64(2)
	followerCtrl, err := fixture.GetNodeController("Follower")
	a.NoError(err)
	cfg, err := config.LoadConfigFromDisk(followerCtrl.GetDataDir())
	a.NoError(err)
	a.Equal(maxAccountLookback, cfg.MaxAcctLookback)

	advanceTo := func(node string, round uint64) {
		controller, err := fixture.GetNodeController(node)
		a.NoError(err)
		err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(controller), round)
		a.NoError(err)
	}

	getAlgod := func(node string) client.RestClient {
		controller, err := fixture.GetNodeController(node)
		a.NoError(err)
		algod := fixture.GetAlgodClientForController(controller)
		return algod
	}

	getRound := func(node string) uint64 {
		algod := getAlgod(node)
		status, err := algod.Status()
		a.NoError(err)
		return status.LastRound
	}

	getSyncRound := func() uint64 {
		followClient := getAlgod("Follower")
		rResp, err := followClient.GetSyncRound()
		a.NoError(err)
		return rResp.Round
	}

	a.Equal(uint64(1), getSyncRound())

	stats := map[string]uint64{}

	stats["p000"] = getRound("Primary")
	stats["f000"] = getRound("Follower")
	stats["s000"] = getSyncRound()
	advanceTo("Primary", 3)
	advanceTo("Follower", 2)

	stats["p321"] = getRound("Primary")
	stats["f321"] = getRound("Follower")
	stats["s321"] = getSyncRound()
	// a.LessOrEqual(uint64(3), getRound("Primary"))

	// advanceTo("Follower", 2)
	// a.LessOrEqual(uint64(2), getRound("Follower"))

	/** restart the network **/
	fixture.ShutdownImpl(true)
	fixture.Start()

	stats["p321r"] = getRound("Primary")
	stats["f321r"] = getRound("Follower")
	stats["s321r"] = getSyncRound()

	advanceTo("Primary", 6)
	followerClient := getAlgod("Follower")

	// with a max account lookback of 2,
	// the follower cannot advance past round 4
	// when the sync round is 3
	err = followerClient.SetSyncRound(uint64(3))
	advanceTo("Follower", 4)
	a.NoError(err)
	stats["p643"] = getRound("Primary")
	stats["f643"] = getRound("Follower")
	stats["s643"] = getSyncRound()

	fixture.ShutdownImpl(true)
	fixture.Start()

	stats["p643r"] = getRound("Primary")
	stats["f643r"] = getRound("Follower")
	stats["s643r"] = getSyncRound()

	fmt.Printf("stats: %+v\n", stats)
	// stats: map[f000:0 f321:2 f321r:2 f643:4 f643r:4 p000:0 p321:5 p321r:5 p643:6 p643r:6 s000:1 s321:1 s321r:1 s643:3 s643r:3]
	// stats: map[f000:0 f321:2 f321r:2 f643:4 f643r:4 p000:0 p321:6 p321r:6 p643:6 p643r:6 s000:1 s321:1 s321r:1 s643:3 s643r:3]
	a.Equal(uint64(1), getSyncRound())
}

func TestPrelim1(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Overview of this test:
	// Start a two-node network--one in follower mode (follower has 0%, secondary has 100%)
	// with follower having a max account lookback of 2.
	// Repeatedly advance the primary sometimes re-syncing the follower, sometimes not.
	// In between the advances, stop and restart the network.

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesFollower100SecondMaxAccountLookback2.json"))

	defer fixture.Shutdown()

	// sanity check that the follower has the expected max account lookback:
	maxAccountLookback := uint64(2)
	followerC, err := fixture.GetNodeController("Follower")
	a.NoError(err)
	cfg, err := config.LoadConfigFromDisk(followerC.GetDataDir())
	a.NoError(err)
	a.Equal(maxAccountLookback, cfg.MaxAcctLookback)

	// waits to advance the primary node by the given number of rounds
	advanceTo := func(node string, round uint64) {
		controller, err := fixture.GetNodeController(node)
		a.NoError(err)
		err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(controller), round)
		a.NoError(err)
	}

	// gets the follower client
	getAlgod := func(node string) client.RestClient {
		controller, err := fixture.GetNodeController(node)
		a.NoError(err)
		algod := fixture.GetAlgodClientForController(controller)
		return algod
	}

	getRound := func(node string) uint64 {
		algod := getAlgod(node)
		status, err := algod.Status()
		a.NoError(err)
		return status.LastRound
	}

	getSyncRound := func() uint64 {
		followClient := getAlgod("Follower")
		rResp, err := followClient.GetSyncRound()
		a.NoError(err)
		return rResp.Round
	}

	a.Equal(uint64(1), getSyncRound())

	stats := map[string]uint64{}

	stats["p0"] = getRound("Primary")
	stats["f0"] = getRound("Follower")
	stats["s0"] = getSyncRound()
	advanceTo("Primary", 3)
	stats["p3"] = getRound("Primary")
	stats["f3"] = getRound("Follower")
	stats["s3"] = getSyncRound()
	// a.LessOrEqual(uint64(3), getRound("Primary"))

	// advanceTo("Follower", 2)
	// a.LessOrEqual(uint64(2), getRound("Follower"))

	/** restart the network **/
	fixture.ShutdownImpl(true)
	fixture.Start()

	stats["p3r"] = getRound("Primary")
	stats["f3r"] = getRound("Follower")
	stats["s3r"] = getSyncRound()
	advanceTo("Primary", 7)
	stats["p7"] = getRound("Primary")
	stats["f7"] = getRound("Follower")
	stats["s7"] = getSyncRound()

	fixture.ShutdownImpl(true)
	fixture.Start()

	stats["p7r"] = getRound("Primary")
	stats["f7r"] = getRound("Follower")
	stats["s7r"] = getSyncRound()

	fmt.Printf("stats: %+v\n", stats)

	// a.LessOrEqual(uint64(3), getRound("Primary"))
	// a.LessOrEqual(uint64(2), getRound("Follower"))

	/** STILL: Primary >= 1 AND Follower @ 1 **/
	a.Equal(uint64(1), getSyncRound())

	// with sync == LatestCommitted() + 1 :
	// all the way through:
	// stats: map[f0:0 f3:1 f3r:3 f7:3 f7r:5 p0:0 p3:3 p3r:3 p7:7 p7r:7 s0:1 s3:1 s3r:2 s7:2 s7r:4]
	// stats: map[f0:0 f3:1 f3r:3 f7:3 f7r:5 p0:0 p3:3 p3r:3 p7:7 p7r:7 s0:1 s3:1 s3r:2 s7:2 s7r:4]
	// longish 10 sec pauses before L102 and L118:
	// stats: map[f0:0 f3:1 f3r:3 f7:3 f7r:5 p0:0 p3:5 p3r:5 p7:9 p7r:9 s0:1 s3:1 s3r:2 s7:2 s7r:4]

	// with sync == NextRound():
	// all the way through:
	// stats: map[f0:0 f3:1 f3r:3 f7:3 f7r:5 p0:0 p3:3 p3r:3 p7:7 p7r:7 s0:1 s3:1 s3r:2 s7:2 s7r:4]
	// longish 10 sec pauses before L102 and L118:
	// stats: map[f0:0 f3:1 f3r:3 f7:3 f7r:5 p0:0 p3:5 p3r:5 p7:9 p7r:9 s0:1 s3:1 s3r:2 s7:2 s7r:4]

	// with sync == DBRound():
	// all the way through:
	// stats: map[f0:0 f3:1 f3r:2 f7:2 f7r:2 p0:0 p3:3 p3r:3 p7:7 p7r:7 s0:1 s3:1 s3r:1 s7:1 s7r:1]

	// OUT OF DATE:
	// Next version of PR:
	// stats: map[f0:0 f3:1 f3r:2 p0:0 p3:3 p3r:3 s0:1 s3:1 s3r:1]
	//                                                      ^^^^^
	// Original version of code:
	// stats: map[f0:0 f3:1 f3r:3 p0:0 p3:3 p3r:3 s0:1 s3:1 s3r:2]
	//                                                      ^^^^^
	// stats: map[f0:0 f3:1 f3r:4 p0:0 p3:3 p3r:7 s0:1 s3:1 s3r:3]
	//                                                      ^^^^^

	// /** Primary >= 3 AND Follower @ 1 **/
	// primaryRound = advanceTo(2)
	// a.Equal(uint64(3), primaryRound)

	// a.Equal(uint64(1), getSyncRound())

	// /** restart the network **/
	// fixture.ShutdownImpl(true)
	// fixture.Start()

	// /** Primary >= 3 AND Follower >= 1 because something got saved to DB **/
	// syncRound := getSyncRound() // >= 2
	// a.LessOrEqual(uint64(1), syncRound)

	// // err = followClient.SetSyncRound(expectedSyncRound)
	// // rResp, err = followClient.GetSyncRound()
	// // a.NoError(err)
	// // a.Equal(expectedSyncRound, rResp.Round)

	// /** Primary >= 3 AND Follower @ 1 **/
	// err := getAlgod().SetSyncRound(1)
	// a.NoError(err)
	// a.Equal(uint64(1), getSyncRound())

	// /** Primary >= 5 AND Follower @ 1 **/
	// primaryRound = advanceTo(2)
	// a.Equal(uint64(5), primaryRound)
	// a.Equal(uint64(1), getSyncRound())

	// /** Primary >= 5 AND Follower @ 2 **/
	// err = getAlgod().SetSyncRound(2)
	// a.NoError(err)
	// a.Equal(uint64(2), getSyncRound())

	// /** restart the network **/
	// fixture.ShutdownImpl(true)
	// fixture.Start()

	// /** Primary >= 5 AND Follower @ 5 **/
	// a.Equal(uint64(5), getSyncRound())
}
