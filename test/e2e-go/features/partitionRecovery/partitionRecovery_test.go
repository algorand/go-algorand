// Copyright (C) 2019-2021 Algorand, Inc.
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

package partitionrecovery

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/testpartitioning"
)

const partitionRecoveryTime = 20 * time.Minute // If we hit step 9, worst case recovery time can be ~2^8 * 5 ~= 20 mins
const inducePartitionTime = 6 * time.Second    // Try to minimize change of proceeding too many steps while stalled

func TestBasicPartitionRecovery(t *testing.T) {
	testpartitioning.PartitionTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Overview of this test:
	// Start a two-node network (with 50% each)
	// Let it run for a few blocks.
	// Stop one node (with 50% stake) to trigger a partition
	// Start it again and see if it recovers

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer fixture.Shutdown()

	// Get 2nd node so we wait until we know they're at target block
	nc, err := fixture.GetNodeController("Node")
	a.NoError(err)

	// Let the network make some progress
	waitForRound := uint64(3)
	err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(nc), waitForRound)
	a.NoError(err)

	// Now stop 2nd node
	nc.FullStop()

	// Give network a chance to stall
	time.Sleep(inducePartitionTime)

	// Use the fixture to start the node again so it supplies the correct peer addresses
	lg, err := fixture.StartNode(nc.GetDataDir())
	a.NoError(err)

	// Now wait for us to make progress again.
	status, err := lg.Status()
	a.NoError(err)

	err = fixture.WaitForRound(status.LastRound+1, partitionRecoveryTime)
	a.NoError(err)
}

func TestPartitionRecoverySwapStartup(t *testing.T) {
	testpartitioning.PartitionTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()

	// Overview of this test:
	// Start a three-node network (two with 50% each)
	// Let it run for a few blocks.
	// Stop one node (with 50% stake) to trigger a partition
	// Start it again and stop the other one (with 50% stake) and let it run.
	// Start the 2nd so they're both running, and see if it recovers

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachWithRelay.json"))
	defer fixture.Shutdown()

	runTestWithStaggeredStopStart(t, &fixture)
}

func TestPartitionRecoveryStaggerRestart(t *testing.T) {
	testpartitioning.PartitionTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()

	// Overview of this test:
	// Start a three-node network (with 33% stake each)
	// Let it run for a few blocks.
	// Stop one node (with 33% stake) to trigger a partition
	// Start it again and stop the other one (with 33% stake) and let it run.
	// Start the 2nd so they're both running, and see if it recovers

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "ThreeNodesEvenDist.json"))
	defer fixture.Shutdown()

	runTestWithStaggeredStopStart(t, &fixture)
}

func runTestWithStaggeredStopStart(t *testing.T, fixture *fixtures.RestClientFixture) {
	a := require.New(fixtures.SynchronizedTest(t))

	// Get Node1 so we can wait until it has reached the target round
	nc1, err := fixture.GetNodeController("Node1")
	a.NoError(err)

	// Let the network make some progress
	waitForRound := uint64(3)
	err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(nc1), waitForRound)
	a.NoError(err)

	// Stop Node1
	nc1.FullStop()

	time.Sleep(inducePartitionTime)

	// Use the fixture to start the node again so it supplies the correct peer addresses
	_, err = fixture.StartNode(nc1.GetDataDir())
	a.NoError(err)

	// Stop the 2nd node and give it a chance to stall (should stay stalled)
	nc2, err := fixture.GetNodeController("Node2")
	a.NoError(err)
	nc2.FullStop()
	time.Sleep(20 * time.Second)

	// Use the fixture to start the node again so it supplies the correct peer addresses
	_, err = fixture.StartNode(nc2.GetDataDir())
	a.NoError(err)

	// Now wait for us to make progress again.
	status, err := fixture.LibGoalClient.Status()
	a.NoError(err)

	a.Equal(waitForRound, status.LastRound, "We should not have made progress since stopping the first node")

	err = fixture.WaitForRound(status.LastRound+1, partitionRecoveryTime)
	a.NoError(err)
}

func TestBasicPartitionRecoveryPartOffline(t *testing.T) {
	testpartitioning.PartitionTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Overview of this test:
	// Start a three-node network capable of making progress.
	// Let it run for a few blocks.
	// Stop one node (with 33% stake / 50% of online) to trigger a partition
	// Stop the 33% offline node
	// Start the online node again and see if it recovers (while offline node remains offline)

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "ThreeNodesEvenDistOneOffline.json"))
	defer fixture.Shutdown()

	// Get Node1 so we can wait until it has reached the target round
	nc1, err := fixture.GetNodeController("Node1")
	a.NoError(err)

	// Let the network make some progress
	waitForRound := uint64(3)
	err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(nc1), waitForRound)
	a.NoError(err)

	// Stop Node1
	nc1.FullStop()

	// Stop the 2nd node and give network a chance to stall
	nc2, err := fixture.GetNodeController("Node2")
	a.NoError(err)
	nc2.FullStop()

	time.Sleep(inducePartitionTime)

	// Use the fixture to start the node again so it supplies the correct peer addresses
	_, err = fixture.StartNode(nc1.GetDataDir())
	a.NoError(err)

	// Now wait for us to make progress again.
	status, err := fixture.LibGoalClient.Status()
	a.NoError(err)

	a.Equal(waitForRound, status.LastRound, "We should not have made progress since stopping the first node")

	err = fixture.WaitForRound(status.LastRound+1, partitionRecoveryTime)
	a.NoError(err)
}

func TestPartitionHalfOffline(t *testing.T) {
	testpartitioning.PartitionTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Overview of this test:
	// Start a TenNodeDistributed network
	// Let it run for a few blocks.
	// Stop 50% of stake
	// Verify we're partitioned
	// Start all but 10% of stake and verify we recover

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TenNodesDistributedMultiWallet.json"))
	defer fixture.Shutdown()

	// Get the 1st node (with Node1-3 wallets) so we can wait until it has reached the target round
	nc1, err := fixture.GetNodeController("Node1-3")
	a.NoError(err)

	// Let the network make some progress
	client := fixture.LibGoalClient
	waitForRound := uint64(3)
	err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(nc1), waitForRound)
	a.NoError(err)

	// Stop nodes with 50% of stake
	nc1.FullStop()
	nc2, err := fixture.GetNodeController("Node4")
	a.NoError(err)
	nc2.FullStop()
	nc3, err := fixture.GetNodeController("Node5")
	a.NoError(err)
	nc3.FullStop()

	time.Sleep(inducePartitionTime)

	// Get main client to monitor
	status, err := client.Status()
	a.NoError(err)
	a.Equal(waitForRound, status.LastRound, "We should not have made progress since stopping the nodes")

	// Start 40 of 50% of the stake
	_, err = fixture.StartNode(nc1.GetDataDir())
	a.NoError(err)
	_, err = fixture.StartNode(nc2.GetDataDir())
	a.NoError(err)

	err = fixture.WaitForRound(status.LastRound+1, partitionRecoveryTime)
	a.NoError(err)
}
