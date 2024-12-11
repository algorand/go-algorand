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

package fixtures

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/gen"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/netdeploy"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/protocol"
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

// AlterConsensus allows the caller to modify the consensus settings for a given version.
func (f *RestClientFixture) AlterConsensus(ver protocol.ConsensusVersion, alter func(config.ConsensusParams) config.ConsensusParams) {
	if f.consensus == nil {
		f.consensus = make(config.ConsensusProtocols)
	}
	f.consensus[ver] = alter(f.ConsensusParamsFromVer(ver))
}

// FasterConsensus speeds up the given consensus version in two ways. The seed
// refresh lookback is set to 8 (instead of 80), so the 320 round balance
// lookback becomes 32.  And, if the architecture implies it can be handled,
// round times are shortened by lowering vote timeouts.
func (f *RestClientFixture) FasterConsensus(ver protocol.ConsensusVersion, timeout time.Duration, lookback basics.Round) {
	f.AlterConsensus(ver, func(fast config.ConsensusParams) config.ConsensusParams {
		// balanceRound is 4 * SeedRefreshInterval
		if lookback%4 != 0 {
			panic(fmt.Sprintf("lookback must be a multiple of 4, got %d", lookback))
		}
		fast.SeedRefreshInterval = uint64(lookback) / 4
		// and speed up the rounds while we're at it
		if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
			fast.AgreementFilterTimeoutPeriod0 = timeout
			fast.AgreementFilterTimeout = timeout
		}
		return fast
	})
}

// Setup is called to initialize the test fixture for the test(s)
func (f *LibGoalFixture) Setup(t TestingTB, templateFile string, overrides ...netdeploy.TemplateOverride) {
	f.setup(t, t.Name(), templateFile, true, overrides...)
}

// SetupNoStart is called to initialize the test fixture for the test(s)
// but does not start the network before returning.  Call NC.Start() to start later.
func (f *LibGoalFixture) SetupNoStart(t TestingTB, templateFile string, overrides ...netdeploy.TemplateOverride) {
	f.setup(t, t.Name(), templateFile, false, overrides...)
}

// SetupShared is called to initialize the test fixture that will be used for multiple tests
func (f *LibGoalFixture) SetupShared(testName string, templateFile string, overrides ...netdeploy.TemplateOverride) {
	f.setup(nil, testName, templateFile, true, overrides...)
}

// Genesis returns the genesis data for this fixture
func (f *LibGoalFixture) Genesis() gen.GenesisData {
	return f.network.Genesis()
}

func (f *LibGoalFixture) setup(test TestingTB, testName string, templateFile string, startNetwork bool, overrides ...netdeploy.TemplateOverride) {
	// Call initialize for our base implementation
	f.initialize(f)
	f.t = SynchronizedTest(test)
	f.rootDir = filepath.Join(f.testDir, testName)

	// In case we're running tests against the same rootDir, purge it to avoid errors from already-exists
	os.RemoveAll(f.rootDir)
	templateFile = filepath.Join(f.testDataDir, templateFile)
	importKeys := false // Don't automatically import root keys when creating folders, we'll import on-demand
	file, err := os.Open(templateFile)
	f.failOnError(err, "Template file could not be opened: %v")
	network, err := netdeploy.CreateNetworkFromTemplate("test", f.rootDir, file, f.binDir, importKeys, f.nodeExitWithError, f.consensus, overrides...)
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

	debugLog := func() {
		fmt.Fprintf(os.Stderr, "Node at %s has terminated with an error: %v. Dumping logs...\n", nc.GetDataDir(), err)
		f.dumpLogs(filepath.Join(nc.GetDataDir(), "node.log"))
	}

	exitError, ok := err.(*exec.ExitError)
	if !ok {
		debugLog()
		require.NoError(f.t, err)
		return
	}
	ws := exitError.Sys().(syscall.WaitStatus)
	exitCode := ws.ExitStatus()

	fmt.Fprintf(os.Stderr, "Node at %s has terminated with error code %d (%v)\n", nc.GetDataDir(), exitCode, *exitError)
	debugLog()
	require.NoError(f.t, err)
}

func (f *LibGoalFixture) importRootKeys(lg *libgoal.Client, dataDir string) {
	genID, err := lg.GenesisID()
	if err != nil {
		return
	}

	keyDir := filepath.Join(dataDir, genID)
	files, err := os.ReadDir(keyDir)
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
				continue
			}

			// Fetch an account.Root from the database
			root, err := account.RestoreRoot(handle)
			if err != nil {
				// Couldn't read it, skip it
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
			handle.Close()
		} else if config.IsPartKeyFilename(filename) {
			// Fetch a handle to this database
			handle, err = db.MakeErasableAccessor(filepath.Join(keyDir, filename))
			if err != nil {
				// Couldn't open it, skip it
				continue
			}

			// Fetch an account.Participation from the database
			participation, err := account.RestoreParticipation(handle)
			if err != nil {
				// Couldn't read it, skip it
				handle.Close()
				continue
			}

			// Early reject partkeys if we already have a rootkey for the account
			if !accountsWithRootKeys[participation.Address().String()] {
				allPartKeys = append(allPartKeys, participation.Participation)
			}

			// close the database handle.
			participation.Close()
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
	f.failOnError(err, "network.GetNodeDir failed: %v")
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
	f.failOnError(err, "network.GetNodeDir failed: %v")
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
		err := f.network.Stop(f.binDir)
		if err != nil {
			f.t.Logf("Fixture %s shutdown caught a network stop error: %v", f.Name, err)
		}
		for _, relayDir := range f.RelayDataDirs() {
			f.dumpLogs(filepath.Join(relayDir, "node.log"))
		}
		for _, nodeDir := range f.NodeDataDirs() {
			f.dumpLogs(filepath.Join(nodeDir, "node.log"))
		}
	} else {
		err := f.network.Stop(f.binDir)
		if err == nil {
			// no error, proceed with cleanup
			delErr := f.network.Delete(f.binDir)
			if delErr != nil {
				f.t.Logf("Fixture %s shutdown caught a network delete error: %v", f.Name, delErr)
			}
			// Remove the test dir, if it was created by us as a temporary
			// directory and it is empty.  If there's anything still in the
			// test dir, os.Remove()'s rmdir will fail and have no effect;
			// we ignore this error.
			if f.testDirTmp {
				os.Remove(f.testDir)
			}
		} else {
			f.t.Logf("Fixture %s shutdown caught a network stop error: %v", f.Name, err)
		}
	}
}

// dumpLogs prints out log files for the running nodes
func (f *LibGoalFixture) dumpLogs(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open %s\n", filePath)
		return
	}
	defer file.Close()

	fmt.Fprintf(os.Stderr, "=================================\n")
	parts := strings.Split(filePath, "/")
	fmt.Fprintf(os.Stderr, "%s/%s:\n", parts[len(parts)-2], parts[len(parts)-1]) // Primary/node.log
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fmt.Fprintln(os.Stderr, scanner.Text())
	}
	fmt.Fprintln(os.Stderr)
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

// RelayDataDirs returns the relays data directories for the network (including the primary relay)
func (f *LibGoalFixture) RelayDataDirs() []string {
	return f.network.RelayDataDirs()
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

// CurrentConsensusParams returns the consensus parameters for the currently active protocol
func (f *LibGoalFixture) CurrentConsensusParams() (consensus config.ConsensusParams, err error) {
	status, err := f.LibGoalClient.Status()
	if err != nil {
		return
	}

	return f.ConsensusParams(status.LastRound)
}

// ConsensusParams returns the consensus parameters for the protocol from the specified round
func (f *LibGoalFixture) ConsensusParams(round uint64) (config.ConsensusParams, error) {
	block, err := f.LibGoalClient.BookkeepingBlock(round)
	if err != nil {
		return config.ConsensusParams{}, err
	}
	return f.ConsensusParamsFromVer(block.CurrentProtocol), nil
}

// ConsensusParamsFromVer looks up a consensus version, allowing for override
func (f *LibGoalFixture) ConsensusParamsFromVer(cv protocol.ConsensusVersion) config.ConsensusParams {
	if consensus, has := f.consensus[cv]; has {
		return consensus
	}
	return config.Consensus[cv]
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

// TransactionProof returns a proof for usage in merkle array verification for the provided transaction.
func (f *LibGoalFixture) TransactionProof(txid string, round uint64, hashType crypto.HashType) (model.TransactionProofResponse, merklearray.SingleLeafProof, error) {
	proofResp, err := f.LibGoalClient.TransactionProof(txid, round, hashType)
	if err != nil {
		return model.TransactionProofResponse{}, merklearray.SingleLeafProof{}, err
	}

	proof, err := merklearray.ProofDataToSingleLeafProof(string(proofResp.Hashtype), proofResp.Proof)
	if err != nil {
		return model.TransactionProofResponse{}, merklearray.SingleLeafProof{}, err
	}

	return proofResp, proof, nil
}

// LightBlockHeaderProof returns a proof for usage in merkle array verification for the provided block's light block header.
func (f *LibGoalFixture) LightBlockHeaderProof(round uint64) (model.LightBlockHeaderProofResponse, merklearray.SingleLeafProof, error) {
	proofResp, err := f.LibGoalClient.LightBlockHeaderProof(round)

	if err != nil {
		return model.LightBlockHeaderProofResponse{}, merklearray.SingleLeafProof{}, err
	}

	proof, err := merklearray.ProofDataToSingleLeafProof(crypto.Sha256.String(), proofResp.Proof)
	if err != nil {
		return model.LightBlockHeaderProofResponse{}, merklearray.SingleLeafProof{}, err
	}

	return proofResp, proof, nil
}
