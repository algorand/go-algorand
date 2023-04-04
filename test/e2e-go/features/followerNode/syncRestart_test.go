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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// I think the test would be starting a 2 node network with one follower and then restarting the follower a couple times.
// Should be able to reproduce the issue after 1 block is created since the sync round would currently change from 0 to 1

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
	// Repeatedly advance the primary sometimes advancing the follower, sometimes not.
	// In between the advances, stop and restart the network.

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesFollower100Second.json"))
	defer fixture.Shutdown()

	primaryRound := uint64(1)

	// Get controller for Primary node to see the state of the chain
	primaryAdvance := func(advance uint64) uint64 {
		primaryController, err := fixture.GetNodeController("Primary")
		a.NoError(err)
		waitForRound := uint64(primaryRound + advance)
		err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(primaryController), waitForRound)
		a.NoError(err)
		return waitForRound
	}

	// Get the follower client
	getFollowClient := func() client.RestClient {
		followControl, err := fixture.GetNodeController("Follower")
		a.NoError(err)
		followClient := fixture.GetAlgodClientForController(followControl)
		return followClient
	}

	/** Primary >= 1 AND Follower @ 1 **/
	expectedSyncRound := uint64(1)
	followClient := getFollowClient()
	rResp, err := followClient.GetSyncRound()
	a.NoError(err)
	a.Equal(expectedSyncRound, rResp.Round)

	/** restart the network **/
	fixture.ShutdownImpl(true)
	fixture.Start()

	/** STILL: Primary >= 1 AND Follower @ 1 **/
	expectedSyncRound = uint64(1)

	followClient = getFollowClient()
	rResp, err = followClient.GetSyncRound() // before bugfix was >= 2
	a.NoError(err)
	a.Equal(expectedSyncRound, rResp.Round)

	/** Primary >= 3 AND Follower @ 1 **/
	expectedSyncRound = uint64(1)

	primaryRound = primaryAdvance(2)
	a.Equal(uint64(3), primaryRound)
	followClient = getFollowClient()
	rResp, err = followClient.GetSyncRound()
	a.NoError(err)
	a.Equal(expectedSyncRound, rResp.Round)

	/** restart the network **/
	fixture.ShutdownImpl(true)
	fixture.Start()

	/** Primary >= 3 AND Follower >= 1 because something got saved to DB **/
	expectedSyncRound = uint64(1)

	followClient = getFollowClient()
	rResp, err = followClient.GetSyncRound() // >= 2
	a.NoError(err)
	a.LessOrEqual(expectedSyncRound, rResp.Round)

	/** Primary >= 3 AND Follower @ 1 **/
	expectedSyncRound = uint64(1)
	err = followClient.SetSyncRound(expectedSyncRound)
	a.NoError(err)

	followClient = getFollowClient()
	rResp, err = followClient.GetSyncRound() // 1
	a.NoError(err)
	a.Equal(expectedSyncRound, rResp.Round)

	/** Primary >= 5 AND Follower @ 1 **/
	expectedSyncRound = uint64(1)

	primaryRound = primaryAdvance(2)
	a.Equal(uint64(5), primaryRound)
	followClient = getFollowClient()
	rResp, err = followClient.GetSyncRound() // 1
	a.NoError(err)
	a.Equal(expectedSyncRound, rResp.Round)

	/** Primary >= 5 AND Follower @ 2 **/
	expectedSyncRound = uint64(2)
	err = followClient.SetSyncRound(expectedSyncRound)
	a.NoError(err)

	followClient = getFollowClient()
	rResp, err = followClient.GetSyncRound() // 2
	a.NoError(err)
	a.Equal(expectedSyncRound, rResp.Round)

	/** restart the network **/
	fixture.ShutdownImpl(true)
	fixture.Start()

	/** Primary >= 5 AND Follower @ 5 **/
	expectedSyncRound = uint64(5)

	followClient = getFollowClient()
	rResp, err = followClient.GetSyncRound() // > 5
	a.NoError(err)
	a.LessOrEqual(expectedSyncRound, rResp.Round)
}
