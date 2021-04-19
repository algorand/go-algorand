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

package fixtures

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/gen"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/netdeploy"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/e2e-go/globals"
	"github.com/algorand/go-algorand/util/db"
)

// LibGoalFixture is a test fixture for tests requiring a running node with a algod and kmd clients
type LibGoalFixture struct {
	baseFixture

	LibGoalClient  libgoal.Client
	NC             nodecontrol.NodeController
	rootDir        string
	Name           string
	network        netdeploy.Network
	t              TestingTB
	tMu            deadlock.RWMutex
	clientPartKeys map[string][]account.Participation
	consensus      config.ConsensusProtocols
}

// SetConsensus applies a new consensus settings which would get deployed before
// any of the nodes starts
func (f *RestClientFixture) SetConsensus(consensus config.ConsensusProtocols) {
	f.consensus = consensus
}

// Setup is called to initialize the test fixture for the test(s)
func (f *LibGoalFixture) Setup(t TestingTB, templateFile string) {
	f.setup(t, t.Name(), templateFile, true)
}

// SetupNoStart is called to initialize the test fixture for the test(s)
// but does not start the network before returning.  Call NC.Start() to start later.
func (f *LibGoalFixture) SetupNoStart(t TestingTB, templateFile string) {
	f.setup(t, t.Name(), templateFile, false)
}

// SetupShared is called to initialize the test fixture that will be used for multiple tests
func (f *LibGoalFixture) SetupShared(testName string, templateFile string) {
	f.setup(nil, testName, templateFile, true)
}

// Genesis returns the genesis data for this fixture
func (f *LibGoalFixture) Genesis() gen.GenesisData {
	return f.network.Genesis()
}

func (f *LibGoalFixture) setup(test TestingTB, testName string, templateFile string, startNetwork bool) {
	// Call initialize for our base implementation
	f.initialize(f)
	f.t = SynchronizedTest(test)
	f.rootDir = filepath.Join(f.testDir, testName)

	// In case we're running tests against the same rootDir, purge it to avoid errors from already-exists
	os.RemoveAll(f.rootDir)
	templateFile = filepath.Join(f.testDataDir, templateFile)
	importKeys := false // Don't automatically import root keys when creating folders, we'll import on-demand
	network, err := netdeploy.CreateNetworkFromTemplate("test", f.rootDir, templateFile, f.binDir, importKeys, f.nodeExitWithError, f.consensus)
	f.failOnError(err, "CreateNetworkFromTemplate failed: %v")
	f.network = network

	if startNetwork {
		f.Start()
	}
}

// nodeExitWithError is a callback from the network indicating that the node exit with an error after a successful startup.
// i.e. node terminated, and not due to shutdown.. this is likely to be a crash/panic.
func (f *LibGoalFixture) nodeExitWithError(nc *nodecontrol.NodeController, err error) {
	if err == nil {
		return
	}

	f.tMu.RLock()
	defer f.tMu.RUnlock()
	if f.t == nil {
		return
	}
	exitError, ok := err.(*exec.ExitError)
	if !ok {
		require.NoError(f.t, err, "Node at %s has terminated with an error", nc.GetDataDir())
		return
	}
	ws := exitError.Sys().(syscall.WaitStatus)
	exitCode := ws.ExitStatus()

	require.NoError(f.t, err, "Node at %s has terminated with error code %d", nc.GetDataDir(), exitCode)
}

func (f *LibGoalFixture) importRootKeys(lg *libgoal.Client, dataDir string) {
	genID, err := lg.GenesisID()
	if err != nil {
		return
	}

	keyDir := filepath.Join(dataDir, genID)
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return
	}

	accountsWithRootKeys := make(map[string]bool)
	var allPartKeys []account.Participation

	// For each of these files
	for _, info := range files {
		var handle db.Accessor

		filename := info.Name()

		// If it isn't a key file we care about, skip it
		if config.IsRootKeyFilename(filename) {
			// Fetch a handle to this database
			handle, err = db.MakeAccessor(filepath.Join(keyDir, filename), false, false)
			if err != nil {
				// Couldn't open it, skip it
				err = nil
				continue
			}

			// Fetch an account.Root from the database
			root, err := account.RestoreRoot(handle)
			if err != nil {
				// Couldn't read it, skip it
				err = nil
				continue
			}

			secretKey := root.Secrets().SK
			wh, err := lg.GetUnencryptedWalletHandle()
			f.failOnError(err, "couldn't get default wallet handle: %v")
			_, err = lg.ImportKey(wh, secretKey[:])
			if err != nil && !strings.Contains(err.Error(), "key already exists") {
				f.failOnError(err, "couldn't import secret: %v")
			}
			accountsWithRootKeys[root.Address().String()] = true
		} else if config.IsPartKeyFilename(filename) {
			// Fetch a handle to this database
			handle, err = db.MakeErasableAccessor(filepath.Join(keyDir, filename))
			if err != nil {
				// Couldn't open it, skip it
				err = nil
				continue
			}

			// Fetch an account.Participation from the database
			participation, err := account.RestoreParticipation(handle)
			if err != nil {
				// Couldn't read it, skip it
				err = nil
				continue
			}

			// Early reject partkeys if we already have a rootkey for the account
			if !accountsWithRootKeys[participation.Address().String()] {
				allPartKeys = append(allPartKeys, participation)
			}
		}
	}

	// Go through final set of non-filtered part keys and add the partkey-only keys to our collection
	for _, part := range allPartKeys {
		if !accountsWithRootKeys[part.Address().String()] {
			f.addParticipationForClient(*lg, part)
		}
	}
}

// GetLibGoalClientFromNodeController returns the LibGoal Client for a given node controller
func (f *LibGoalFixture) GetLibGoalClientFromNodeController(nc nodecontrol.NodeController) libgoal.Client {
	return f.GetLibGoalClientFromDataDir(nc.GetDataDir())
}

// GetLibGoalClientFromDataDir returns the LibGoal Client for a given data directory
func (f *LibGoalFixture) GetLibGoalClientFromDataDir(dataDir string) libgoal.Client {
	client, err := libgoal.MakeClientWithBinDir(f.binDir, dataDir, dataDir, libgoal.KmdClient)
	f.failOnError(err, "make libgoal client failed: %v")
	f.importRootKeys(&client, dataDir)
	return client
}

// GetLibGoalClientForNamedNode returns the LibGoal Client for a given named node
func (f *LibGoalFixture) GetLibGoalClientForNamedNode(nodeName string) libgoal.Client {
	nodeDir, err := f.network.GetNodeDir(nodeName)
	client, err := libgoal.MakeClientWithBinDir(f.binDir, nodeDir, nodeDir, libgoal.KmdClient)
	f.failOnError(err, "make libgoal client failed: %v")
	f.importRootKeys(&client, nodeDir)
	return client
}

// GetLibGoalClientFromNodeControllerNoKeys returns the LibGoal Client for a given node controller
func (f *LibGoalFixture) GetLibGoalClientFromNodeControllerNoKeys(nc nodecontrol.NodeController) libgoal.Client {
	return f.GetLibGoalClientFromDataDirNoKeys(nc.GetDataDir())
}

// GetLibGoalClientFromDataDirNoKeys returns the LibGoal Client for a given data directory
func (f *LibGoalFixture) GetLibGoalClientFromDataDirNoKeys(dataDir string) libgoal.Client {
	client, err := libgoal.MakeClientWithBinDir(f.binDir, dataDir, dataDir, libgoal.AlgodClient)
	f.failOnError(err, "make libgoal client failed: %v")
	return client
}

// GetLibGoalClientForNamedNodeNoKeys returns the LibGoal Client for a given named node
func (f *LibGoalFixture) GetLibGoalClientForNamedNodeNoKeys(nodeName string) libgoal.Client {
	nodeDir, err := f.network.GetNodeDir(nodeName)
	client, err := libgoal.MakeClientWithBinDir(f.binDir, nodeDir, nodeDir, libgoal.AlgodClient)
	f.failOnError(err, "make libgoal client failed: %v")
	return client
}

func (f *LibGoalFixture) addParticipationForClient(lg libgoal.Client, part account.Participation) {
	f.clientPartKeys[lg.DataDir()] = append(f.clientPartKeys[lg.DataDir()], part)
}

// GetNodeControllerForDataDir returns a NodeController for the specified nodeDataDir
func (f *LibGoalFixture) GetNodeControllerForDataDir(nodeDataDir string) nodecontrol.NodeController {
	return nodecontrol.MakeNodeController(f.binDir, nodeDataDir)
}

// Start can be called to start the fixture's network if SetupNoStart() was used.
func (f *LibGoalFixture) Start() {
	err := f.network.Start(f.binDir, true)
	f.failOnError(err, "error starting network: %v")

	client, err := libgoal.MakeClientWithBinDir(f.binDir, f.PrimaryDataDir(), f.PrimaryDataDir(), libgoal.FullClient)
	f.failOnError(err, "make libgoal client failed: %v")
	f.LibGoalClient = client
	f.NC = nodecontrol.MakeNodeController(f.binDir, f.network.PrimaryDataDir())
	algodKmdPath, _ := filepath.Abs(filepath.Join(f.PrimaryDataDir(), libgoal.DefaultKMDDataDir))
	f.NC.SetKMDDataDir(algodKmdPath)
	f.clientPartKeys = make(map[string][]account.Participation)
	f.importRootKeys(&f.LibGoalClient, f.PrimaryDataDir())
}

// SetTestContext should be called within each test using a shared fixture.
// It ensures the current test context is set and then reset after the test ends
// It should be called in the form of "defer fixture.SetTestContext(t)()"
func (f *LibGoalFixture) SetTestContext(t TestingTB) func() {
	f.tMu.Lock()
	defer f.tMu.Unlock()
	f.t = SynchronizedTest(t)
	return func() {
		f.tMu.Lock()
		defer f.tMu.Unlock()
		f.t = nil
	}
}

// Run implements the Fixture.Run method
func (f *LibGoalFixture) Run(m *testing.M) int {
	return f.run(m)
}

// RunAndExit implements the Fixture.RunAndExit method
func (f *LibGoalFixture) RunAndExit(m *testing.M) {
	f.runAndExit(m)
}

// Shutdown implements the Fixture.Shutdown method
func (f *LibGoalFixture) Shutdown() {
	// Shutdown() should not be called by shared fixtures (this will panic as f.t should be null)
	f.ShutdownImpl(f.t.Failed())
}

// ShutdownImpl implements the Fixture.ShutdownImpl method
func (f *LibGoalFixture) ShutdownImpl(preserveData bool) {
	f.NC.StopKMD()
	if preserveData {
		f.network.Stop(f.binDir)
	} else {
		f.network.Delete(f.binDir)

		// Remove the test dir, if it was created by us as a temporary
		// directory and it is empty.  If there's anything still in the
		// test dir, os.Remove()'s rmdir will fail and have no effect;
		// we ignore this error.
		if f.testDirTmp {
			os.Remove(f.testDir)
		}
	}
}

// intercept baseFixture.failOnError so we can clean up any algods that are still alive
func (f *LibGoalFixture) failOnError(err error, message string) {
	if err != nil {
		f.network.Stop(f.binDir)
		f.baseFixture.failOnError(err, message)
	}
}

// PrimaryDataDir returns the data directory for the PrimaryNode for the network
func (f *LibGoalFixture) PrimaryDataDir() string {
	return f.network.PrimaryDataDir()
}

// NodeDataDirs returns the (non-Primary) data directories for the network
func (f *LibGoalFixture) NodeDataDirs() []string {
	return f.network.NodeDataDirs()
}

// GetNodeDir returns the node directory that is associated with the given node name.
func (f *LibGoalFixture) GetNodeDir(nodeName string) (string, error) {
	return f.network.GetNodeDir(nodeName)
}

// GetNodeController returns the node controller that is associated with the given node name.
func (f *LibGoalFixture) GetNodeController(nodeName string) (nodecontrol.NodeController, error) {
	return f.network.GetNodeController(f.binDir, nodeName)
}

// GetBinDir retrives the bin directory
func (f *LibGoalFixture) GetBinDir() string {
	return f.binDir
}

// StartNode can be called to start a node after the network has been started
// (with the correct PeerAddresses for configured relays)
func (f *LibGoalFixture) StartNode(nodeDir string) (libgoal.Client, error) {
	err := f.network.StartNode(f.binDir, nodeDir, true)
	if err != nil {
		return libgoal.Client{}, err
	}
	var c libgoal.Client
	if c, err = libgoal.MakeClientWithBinDir(f.binDir, nodeDir, nodeDir, libgoal.DynamicClient); err != nil {
		return libgoal.Client{}, err
	}
	return c, nil
}

// GetParticipationOnlyAccounts returns accounts that only have participation keys
func (f *LibGoalFixture) GetParticipationOnlyAccounts(lg libgoal.Client) []account.Participation {
	return f.clientPartKeys[lg.DataDir()]
}

// WaitForRoundWithTimeout waits for a given round to reach. The implementation also ensures to limit the wait time for each round to the
// globals.MaxTimePerRound so we can alert when we're getting "hung" before waiting for all the expected rounds to reach.
func (f *LibGoalFixture) WaitForRoundWithTimeout(roundToWaitFor uint64) error {
	return f.ClientWaitForRoundWithTimeout(f.LibGoalClient, roundToWaitFor)
}

// ClientWaitForRoundWithTimeout waits for a given round to be reached by the specific client/node. The implementation
// also ensures to limit the wait time for each round to the globals.MaxTimePerRound so we can alert when we're
// getting "hung" before waiting for all the expected rounds to reach.
func (f *LibGoalFixture) ClientWaitForRoundWithTimeout(client libgoal.Client, roundToWaitFor uint64) error {
	status, err := client.Status()
	require.NoError(f.t, err)
	lastRound := status.LastRound

	// If node is already at or past target round, we're done
	if lastRound >= roundToWaitFor {
		return nil
	}

	roundTime := globals.MaxTimePerRound * 10 // For first block, we wait much longer
	roundComplete := make(chan error, 2)

	for nextRound := lastRound + 1; lastRound < roundToWaitFor; {
		roundStarted := time.Now()

		go func(done chan error) {
			err := f.ClientWaitForRound(client, nextRound, roundTime)
			done <- err
		}(roundComplete)

		select {
		case lastError := <-roundComplete:
			if lastError != nil {
				close(roundComplete)
				return lastError
			}
		case <-time.After(roundTime):
			// we've timed out.
			time := time.Now().Sub(roundStarted)
			return fmt.Errorf("fixture.WaitForRound took %3.2f seconds between round %d and %d", time.Seconds(), lastRound, nextRound)
		}

		roundTime = singleRoundMaxTime
		lastRound++
		nextRound++
	}
	return nil
}

// ClientWaitForRound waits up to the specified amount of time for
// the network to reach or pass the specified round, on the specific client/node
func (f *LibGoalFixture) ClientWaitForRound(client libgoal.Client, round uint64, waitTime time.Duration) error {
	timeout := time.NewTimer(waitTime)
	for {
		status, err := client.Status()
		if err != nil {
			return err
		}
		if status.LastRound >= round {
			return nil
		}
		select {
		case <-timeout.C:
			return fmt.Errorf("timeout waiting for round %v", round)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// CurrentConsensusParams returns the consensus parameters for the currently active protocol
func (f *LibGoalFixture) CurrentConsensusParams() (consensus config.ConsensusParams, err error) {
	status, err := f.LibGoalClient.Status()
	if err != nil {
		return
	}

	return f.ConsensusParams(status.LastRound)
}

// ConsensusParams returns the consensus parameters for the protocol from the specified round
func (f *LibGoalFixture) ConsensusParams(round uint64) (consensus config.ConsensusParams, err error) {
	block, err := f.LibGoalClient.Block(round)
	if err != nil {
		return
	}
	version := protocol.ConsensusVersion(block.CurrentProtocol)
	if f.consensus != nil {
		consensus, has := f.consensus[version]
		if has {
			return consensus, nil
		}
	}
	consensus = config.Consensus[version]
	return
}

// CurrentMinFeeAndBalance returns the MinTxnFee and MinBalance for the currently active protocol
// If MinBalance is 0, we provide a reasonable default of the current consensus version's minBalance,
// to ensure accounts have funds when MinBalance is used to fund new accounts
func (f *LibGoalFixture) CurrentMinFeeAndBalance() (minFee, minBalance uint64, err error) {
	params, err := f.CurrentConsensusParams()
	if err != nil {
		return
	}
	minBalance = params.MinBalance
	if minBalance == 0 {
		defaultParams := config.Consensus[protocol.ConsensusCurrentVersion]
		minBalance = defaultParams.MinBalance
	}
	return params.MinTxnFee, minBalance, nil
}

// MinFeeAndBalance returns the MinTxnFee and MinBalance for the protocol from the specified round
// If MinBalance is 0, we provide a resonable default of 1000 to ensure accounts have funds when
// MinBalance is used to fund new accounts
func (f *LibGoalFixture) MinFeeAndBalance(round uint64) (minFee, minBalance uint64, err error) {
	params, err := f.ConsensusParams(round)
	if err != nil {
		return
	}
	minBalance = params.MinBalance
	if minBalance == 0 {
		minBalance = 1000
	}
	return params.MinTxnFee, minBalance, nil
}
