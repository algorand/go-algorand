// Copyright (C) 2019-2020 Algorand, Inc.
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

package rewards

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func TestBasicCatchup(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(t)

	// Overview of this test:
	// Start a two-node network (primary has 0%, secondary has 100%)
	// Let it run for a few blocks.
	// Spin up a third node and see if it catches up

	var fixture fixtures.RestClientFixture
	// Give the second node (which starts up last) all the stake so that its proposal always has better credentials,
	// and so that its proposal isn't dropped. Otherwise the test burns 17s to recover. We don't care about stake
	// distribution for catchup so this is fine.
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes100Second.json"))
	defer fixture.Shutdown()

	// Get 2nd node so we wait until we know they're at target block
	nc, err := fixture.GetNodeController("Node")
	a.NoError(err)

	// Let the network make some progress
	a.NoError(err)
	waitForRound := uint64(3)
	err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(nc), waitForRound)
	a.NoError(err)

	// Now spin up third node
	cloneDataDir := filepath.Join(fixture.PrimaryDataDir(), "../clone")
	cloneLedger := false
	err = fixture.NC.Clone(cloneDataDir, cloneLedger)
	a.NoError(err)
	cloneClient, err := fixture.StartNode(cloneDataDir)
	a.NoError(err)
	defer shutdownClonedNode(cloneDataDir, &fixture, t)

	// Now, catch up
	err = fixture.LibGoalFixture.ClientWaitForRoundWithTimeout(cloneClient, waitForRound)
	a.NoError(err)
}

func TestCatchupOverGossip(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip()
	}
	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(t)
	// Overview of this test:
	// Start a two-node network (Primary with 0% stake, Secondary with 100% stake)
	// Kill the primary for a few blocks. (Note that primary only has incoming connections)
	// Now, revive the primary, and see if it catches up.

	var fixture fixtures.RestClientFixture
	// Give the second node (which starts up last) all the stake so that its proposal always has better credentials,
	// and so that its proposal isn't dropped. Otherwise the test burns 17s to recover. We don't care about stake
	// distribution for catchup so this is fine.
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes100Second.json"))
	defer fixture.Shutdown()
	ncPrim, err := fixture.GetNodeController("Primary")
	a.NoError(err)

	// Kill the primary
	ncPrim.FullStop()

	// Get 2nd node, which makes all the progress
	nc, err := fixture.GetNodeController("Node")
	a.NoError(err)

	// Let the network make some progress

	waitForRound := uint64(5)
	err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(nc), waitForRound)
	a.NoError(err)

	// Now, revive the primary
	lg, err := fixture.StartNode(ncPrim.GetDataDir())
	a.NoError(err)

	status, err := lg.Status()
	a.NoError(err)
	a.True(status.LastRound < waitForRound)

	// Now, kill the secondary and restart it to reinitiate inbound connection
	nc.FullStop()
	_, err = fixture.StartNode(nc.GetDataDir())
	a.NoError(err)

	// Now, catch up
	err = fixture.LibGoalFixture.ClientWaitForRoundWithTimeout(lg, waitForRound)
	a.NoError(err)
}

func TestStoppedCatchupOnUnsupported(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(t)

	defer os.Unsetenv("ALGORAND_TEST_UNUPGRADEDPROTOCOL_DELETE_UPGRADE")	
	os.Setenv("ALGORAND_TEST_UNUPGRADEDPROTOCOL_DELETE_UPGRADE", "0")

	// Overview of this test:
	// Start a two-node network (primary has 0%, secondary has 100%)
	// Let it run for a few blocks.
	// Spin up a third node and see if it catches up

	var fixture fixtures.RestClientFixture
	// Give the second node (which starts up last) all the stake so that its proposal always has better credentials,
	// and so that its proposal isn't dropped. Otherwise the test burns 17s to recover. We don't care about stake
	// distribution for catchup so this is fine.
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes100SecondTestUnupgradedProtocol.json"))
	defer fixture.Shutdown()

	// Get 2nd node so we wait until we know they're at target block
	nc, err := fixture.GetNodeController("Node")
	a.NoError(err)

	// Let the network make some progress
	a.NoError(err)
	waitForRound := uint64(3) // UpgradeVoteRounds + DefaultUpgradeWaitRounds
	err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(nc), waitForRound)
	a.NoError(err)

	os.Setenv("ALGORAND_TEST_UNUPGRADEDPROTOCOL_DELETE_UPGRADE", "1")

	// Now spin up third node
	cloneDataDir := filepath.Join(fixture.PrimaryDataDir(), "../clone")
	cloneLedger := false
	err = fixture.NC.Clone(cloneDataDir, cloneLedger)
	a.NoError(err)
	cloneClient, err := fixture.StartNode(cloneDataDir)
	a.NoError(err)
	defer shutdownClonedNode(cloneDataDir, &fixture, t)	

	// Now, catch up
	err = fixture.LibGoalFixture.ClientWaitForRoundWithTimeout(cloneClient, waitForRound)
	a.NoError(err)

	timeout := time.NewTimer(20 * time.Second)
	loop := true
	for loop { // loop until timeout, error from Status() or the node stops making progress
		status, err := cloneClient.Status()

		select {
		case <-timeout.C: // timeout
			loop = false
		default:
			if err != nil { // error from Status()
				loop = false
				break
			}
			// Continue looping as long as:
			// (1) next version is the same as current version, or
			// (2) next version is a different protocol (test knows it is not supported), but
			//     last round in current protocol is not yet added to the ledger (status.LastRound)
			// And check that status.StoppedAtUnsupportedRound is false

			if status.NextVersion == status.LastVersion || // next is not a new protocol, or
				// next is a new protocol but,
				(status.NextVersion != status.LastVersion &&
					// the new protocol version is not the next round
					status.LastRound+1 != status.NextVersionRound) {
				// libgoal Client StoppedAtUnsupportedRound in v1.NodeStatus should be false
				a.False(status.StoppedAtUnsupportedRound)
				// Give some time for the next round
				time.Sleep(800 * time.Millisecond)
			} else {
				loop = false
			}
		}
	}

	a.NoError(err)
	status, err := cloneClient.Status()
	// Stopped at the first protocol
	a.Equal("test-unupgraded-protocol", status.LastVersion)
	// Next version is different (did not upgrade to it)
	a.NotEqual(status.NextVersion, status.LastVersion)
	// Next round is when the upgrade happens
	a.True(!status.NextVersionSupported && status.LastRound+1 == status.NextVersionRound)
	// libgoal Client StoppedAtUnsupportedRound in v1.NodeStatus should now be true
	a.True(status.StoppedAtUnsupportedRound)
}

// shutdownClonedNode replicates the behavior of fixture.Shutdown() for network nodes on cloned node
// It deletes the directory if the test passes, otherwise it preserves it 
func shutdownClonedNode(nodeDataDir string, f * fixtures.RestClientFixture, t *testing.T) {
	nc := f.LibGoalFixture.GetNodeControllerForDataDir(nodeDataDir)
	nc.FullStop()
	if !t.Failed() {
		os.RemoveAll(nodeDataDir)
	}
}
