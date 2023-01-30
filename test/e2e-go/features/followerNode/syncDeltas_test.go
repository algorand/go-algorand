package followerNode

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestBasicSyncMode(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	// Overview of this test:
	// Start a two-node network (primary has 0%, secondary has 100%)
	// Let it run for a few blocks.
	// Spin up a third node in follower mode and retrieve deltas for some rounds using sync round calls.

	var fixture fixtures.RestClientFixture
	// Give the second node (which starts up last) all the stake so that its proposal always has better credentials,
	// and so that its proposal isn't dropped. Otherwise the test burns 17s to recover. We don't care about stake
	// distribution so this is fine.
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes100Second.json"))
	defer fixture.Shutdown()

	// Get 2nd node so we wait until we know they're at target block
	nc, err := fixture.GetNodeController("Node")
	a.NoError(err)

	// Let the network make some progress
	a.NoError(err)
	waitForRound := uint64(5)
	err = fixture.ClientWaitForRoundWithTimeout(fixture.GetAlgodClientForController(nc), waitForRound)
	a.NoError(err)

	// Now spin up third node in follower mode
	cloneDataDir := filepath.Join(fixture.PrimaryDataDir(), "../clone")
	cloneLedger := false
	err = fixture.NC.Clone(cloneDataDir, cloneLedger)
	a.NoError(err)
	// Set config.Local::EnableFollowMode = true
	cfg := config.GetDefaultLocal()
	cfg.EnableFollowMode = true
	cloneCfg := filepath.Join(cloneDataDir, config.ConfigFilename)
	err = cfg.SaveToFile(cloneCfg)
	a.NoError(err)
	// Start the node
	cloneClient, err := fixture.StartNode(cloneDataDir)
	a.NoError(err)
	defer shutdownClonedNode(cloneDataDir, &fixture, t)
	// Now, catch up round by round, retrieving state deltas for each
	for round := uint64(1); round <= waitForRound; round++ {
		// assert sync round set
		rResp, err := cloneClient.GetSyncRound()
		a.NoError(err)
		a.Equal(round, rResp.Round)
		// retrieve state delta
		gResp, err := cloneClient.GetLedgerStateDelta(round)
		a.NoError(err)
		a.NotNil(gResp)
		// set sync round next
		err = cloneClient.SetSyncRound(round + 1)
		a.NoError(err)
	}
	err = fixture.LibGoalFixture.ClientWaitForRoundWithTimeout(cloneClient, waitForRound)
	a.NoError(err)
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
