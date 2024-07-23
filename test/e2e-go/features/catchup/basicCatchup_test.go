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

package catchup

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestBasicCatchup(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Overview of this test:
	// Start a two-node network (primary has 0%, secondary has 100%)
	// Let it run for a few blocks.
	// Spin up a third node and see if it catches up

	var fixture fixtures.RestClientFixture
	// Give the second node (which starts up last) all the stake so that its proposal always has better credentials,
	// and so that its proposal isn't dropped. Otherwise, the test burns 17s to recover. We don't care about stake
	// distribution for catchup so this is fine.
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes100Second.json"))
	defer fixture.Shutdown()

	// Get 2nd node, so we wait until we know they're at target block
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

// TestCatchupOverGossip tests catchup across network versions
// The current versions are the original v1 and the upgraded to v2.1
func TestCatchupOverGossip(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	syncTest := fixtures.SynchronizedTest(t)
	supportedVersions := network.SupportedProtocolVersions
	require.LessOrEqual(syncTest, len(supportedVersions), 3)

	subTest := func(tt *testing.T, ledgerVer, fetcherVer string) {
		tt.Run(fmt.Sprintf("ledger=%s,fetcher=%s", ledgerVer, fetcherVer),
			func(t *testing.T) { runCatchupOverGossip(t, ledgerVer, fetcherVer) })
	}

	// ledger node upgraded version, fetcher node upgraded version
	// Run with the default values. Instead of "", pass the default value
	// to exercise loading it from the config file.
	runCatchupOverGossip(syncTest, supportedVersions[0], supportedVersions[0])
	for i := 1; i < len(supportedVersions); i++ {
		subTest(t, supportedVersions[i], "")
		subTest(t, "", supportedVersions[i])
		subTest(t, supportedVersions[i], supportedVersions[i])
	}
}

func runCatchupOverGossip(t fixtures.TestingTB,
	ledgerNodeDowngradeTo,
	fetcherNodeDowngradeTo string) {

	if testing.Short() {
		t.Skip()
	}
	a := require.New(t)
	// Overview of this test:
	// Start a two-node network (Primary with 0% stake, Secondary with 100% stake)
	// Kill the primary for a few blocks. (Note that primary only has incoming connections)
	// Now, revive the primary, and see if it catches up.

	var fixture fixtures.RestClientFixture
	// Give the second node (which starts up last) all the stake so that its proposal always has better credentials,
	// and so that its proposal isn't dropped. Otherwise the test burns 17s to recover. We don't care about stake
	// distribution for catchup so this is fine.
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "TwoNodes100Second.json"))

	if ledgerNodeDowngradeTo != "" {
		// Force the node to only support v1
		dir, err := fixture.GetNodeDir("Node")
		a.NoError(err)
		cfg, err := config.LoadConfigFromDisk(dir)
		a.NoError(err)
		a.Empty(cfg.NetworkProtocolVersion)
		cfg.NetworkProtocolVersion = ledgerNodeDowngradeTo
		cfg.SaveToDisk(dir)
	}

	if fetcherNodeDowngradeTo != "" {
		// Force the node to only support v1
		dir := fixture.PrimaryDataDir()
		cfg, err := config.LoadConfigFromDisk(dir)
		a.NoError(err)
		a.Empty(cfg.NetworkProtocolVersion)
		cfg.NetworkProtocolVersion = fetcherNodeDowngradeTo
		cfg.SaveToDisk(dir)
	}

	defer fixture.Shutdown()
	ncPrim, err := fixture.GetNodeController("Primary")
	a.NoError(err)

	// Get 2nd node, which makes all the progress
	nc, err := fixture.GetNodeController("Node")
	a.NoError(err)

	// Start the secondary
	_, err = fixture.StartNode(nc.GetDataDir())
	a.NoError(err)

	// Let the secondary make progress up to round 3, while the primary was never startred ( hence, it's on round = 0)
	waitForRound := uint64(3)
	err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(nc), waitForRound)
	a.NoError(err)

	// stop the secondary, which is on round 3 or more.
	nc.FullStop()

	// Now, start both primary and secondary, and let the primary catchup up.
	fixture.Start()
	lg, err := fixture.StartNode(ncPrim.GetDataDir())
	a.NoError(err)

	// Now, catch up
	err = fixture.LibGoalFixture.ClientWaitForRoundWithTimeout(lg, waitForRound)
	a.NoError(err)

	waitStart := time.Now()
	// wait until the round number on the secondary node matches the round number on the primary node.
	for {
		nodeLibGoalClient := fixture.LibGoalFixture.GetLibGoalClientFromDataDir(nc.GetDataDir())
		nodeStatus, err := nodeLibGoalClient.Status()
		a.NoError(err)

		primaryStatus, err := lg.Status()
		a.NoError(err)
		if nodeStatus.LastRound <= primaryStatus.LastRound && waitForRound < nodeStatus.LastRound {
			//t.Logf("Both nodes reached round %d\n", primaryStatus.LastRound)
			break
		}

		if time.Now().Sub(waitStart) > time.Minute {
			// it's taking too long.
			a.FailNow("Waiting too long for catchup to complete")
		}

		time.Sleep(50 * time.Millisecond)
	}
}

// consensusTestUnupgradedProtocol is a version of ConsensusCurrentVersion
// that allows the control of the upgrade from consensusTestUnupgradedProtocol to
// consensusTestUnupgradedToProtocol
const consensusTestUnupgradedProtocol = protocol.ConsensusVersion("test-unupgraded-protocol")

// consensusTestUnupgradedToProtocol is a version of ConsensusCurrentVersion
// It is used as an upgrade from consensusTestUnupgradedProtocol
const consensusTestUnupgradedToProtocol = protocol.ConsensusVersion("test-unupgradedto-protocol")

func TestStoppedCatchupOnUnsupported(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	consensus := make(config.ConsensusProtocols)
	// The following two protocols: testUnupgradedProtocol and testUnupgradedToProtocol
	// are used to test the case when some nodes in the network do not make progress.

	// testUnupgradedToProtocol is derived from ConsensusCurrentVersion and upgraded
	// from testUnupgradedProtocol.
	testUnupgradedToProtocol := config.Consensus[protocol.ConsensusCurrentVersion]
	testUnupgradedToProtocol.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	consensus[consensusTestUnupgradedToProtocol] = testUnupgradedToProtocol

	// testUnupgradedProtocol is used to control the upgrade of a node. This is used
	// to construct and run a network where some node is upgraded, and some other
	// node is not upgraded.
	// testUnupgradedProtocol is derived from ConsensusCurrentVersion and upgrades to
	// testUnupgradedToProtocol.
	testUnupgradedProtocol := config.Consensus[protocol.ConsensusCurrentVersion]
	testUnupgradedProtocol.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}

	testUnupgradedProtocol.UpgradeVoteRounds = 3
	testUnupgradedProtocol.UpgradeThreshold = 2
	testUnupgradedProtocol.DefaultUpgradeWaitRounds = 3
	testUnupgradedProtocol.MinUpgradeWaitRounds = 0

	testUnupgradedProtocol.ApprovedUpgrades[consensusTestUnupgradedToProtocol] = 0
	consensus[consensusTestUnupgradedProtocol] = testUnupgradedProtocol

	// Overview of this test:
	// Start a two-node network (primary has 0%, secondary has 100%)
	// Let it run for a few blocks.
	// Spin up a third node and see if it catches up

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
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

	// Now spin up third node
	cloneDataDir := filepath.Join(fixture.PrimaryDataDir(), "../clone")
	cloneLedger := false
	err = fixture.NC.Clone(cloneDataDir, cloneLedger)
	a.NoError(err)

	delete(consensus, consensusTestUnupgradedToProtocol)
	fixture.GetNodeControllerForDataDir(cloneDataDir).SetConsensus(consensus)
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
func shutdownClonedNode(nodeDataDir string, f *fixtures.RestClientFixture, t *testing.T) {
	nc := f.LibGoalFixture.GetNodeControllerForDataDir(nodeDataDir)
	nc.FullStop()
	if !t.Failed() {
		os.RemoveAll(nodeDataDir)
	}
}

// TestBasicCatchupCompletes confirms the the catchup eventually completes and stops.
func TestBasicCatchupCompletes(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Make the network progress faster
	consensus := make(config.ConsensusProtocols)
	fastProtocol := config.Consensus[protocol.ConsensusCurrentVersion]
	fastProtocol.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	fastProtocol.AgreementFilterTimeoutPeriod0 = 400 * time.Millisecond
	fastProtocol.AgreementFilterTimeout = 400 * time.Millisecond
	consensus[protocol.ConsensusCurrentVersion] = fastProtocol

	// Setup the fixture with the modified fast consensus
	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes100Second.json"))
	defer fixture.Shutdown()

	// Get 2nd node so we wait until we know they're at target block
	nc, err := fixture.GetNodeController("Node")
	a.NoError(err)

	// Let the network make some progress.
	// Make it long enough so the catchup to it is longer than a single round agreement
	a.NoError(err)
	waitForRound := uint64(100)

	// Now prepare a third node
	cloneDataDir := filepath.Join(fixture.PrimaryDataDir(), "../clone")
	cloneLedger := false
	err = fixture.NC.Clone(cloneDataDir, cloneLedger)
	a.NoError(err)

	// Wait for the network to make some progess.
	err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(nc), waitForRound)
	a.NoError(err)

	// Start the third node to catchup.
	startTime := time.Now()
	cloneClient, err := fixture.StartNode(cloneDataDir)
	a.NoError(err)
	defer shutdownClonedNode(cloneDataDir, &fixture, t)

	// Wait for it to catchup
	err = fixture.LibGoalFixture.ClientWaitForRoundWithTimeout(cloneClient, waitForRound)
	a.NoError(err)

	// Calculate the catchup time
	catchupTime := time.Since(startTime)

	// Check if curStatus.CatchupTime, the "Time since last block" is less than the catchup time.
	// - If the catchup has not stopped, this value will keep on growing, and eventually be larger than the time
	//   of a single round agreement.
	// - If the catchup stops after it completes, this value will be the time since the last round was
	//   obtained through the agreement, and be much smaller than the catchup time.
	client := fixture.GetAlgodClientForController(fixture.LibGoalFixture.GetNodeControllerForDataDir(cloneDataDir))

	// Prevent false positive
	// - Since obtaining the exact catchup time is not possible, wait catchupTime again, to make sure curStatus.CatchupTime
	//   will be at least our estimated catchupTime (since it keeps on growing if catchup has not stopped).
	time.Sleep(catchupTime)

	// Prevent false negative
	// The network may have made some progress since waitForRound, it could be that the
	// third node is still catching up even after getting to waitForRound.
	// Moreover, it takes some time to transition from the catchup to agreement.
	// Give it some more time and check again..
	pass := false
	for x := 0; x < 100; x++ {
		curStatus, statusErr := client.Status()
		require.NoError(t, statusErr, "fixture should be able to get node status")
		currentStateMsec := time.Duration(curStatus.CatchupTime).Milliseconds()
		catchupMsec := catchupTime.Milliseconds()
		pass = currentStateMsec < catchupMsec
		if pass {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	a.True(pass)
}
