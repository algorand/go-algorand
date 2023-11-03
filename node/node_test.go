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

package node

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/stateproof"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/execpool"
)

var expectedAgreementTime = 2*config.Protocol.BigLambda + config.Protocol.SmallLambda + config.Consensus[protocol.ConsensusCurrentVersion].AgreementFilterTimeout + 2*time.Second

var sinkAddr = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

var defaultConfig = config.Local{
	Archival:                 false,
	GossipFanout:             4,
	NetAddress:               "",
	BaseLoggerDebugLevel:     1,
	IncomingConnectionsLimit: -1,
}

func setupFullNodes(t *testing.T, proto protocol.ConsensusVersion, verificationPool execpool.BacklogPool, customConsensus config.ConsensusProtocols) ([]*AlgorandFullNode, []string) {
	util.SetFdSoftLimit(1000)
	f, _ := os.Create(t.Name() + ".log")
	logging.Base().SetJSONFormatter()
	logging.Base().SetOutput(f)
	logging.Base().SetLevel(logging.Debug)

	numAccounts := 10
	minMoneyAtStart := 10000
	maxMoneyAtStart := 100000

	firstRound := basics.Round(0)
	lastRound := basics.Round(200)

	genesis := make(map[basics.Address]basics.AccountData)
	gen := rand.New(rand.NewSource(2))
	neighbors := make([]string, numAccounts)
	for i := range neighbors {
		neighbors[i] = "127.0.0.1:" + strconv.Itoa(10000+i)
	}

	wallets := make([]string, numAccounts)
	nodes := make([]*AlgorandFullNode, numAccounts)
	rootDirs := make([]string, 0)

	// The genesis configuration is missing allocations, but that's OK
	// because we explicitly generated the sqlite database above (in
	// installFullNode).
	g := bookkeeping.Genesis{
		SchemaID:    "go-test-node-genesis",
		Proto:       proto,
		Network:     config.Devtestnet,
		FeeSink:     sinkAddr.String(),
		RewardsPool: poolAddr.String(),
	}

	for i := range wallets {
		rootDirectory := t.TempDir()
		rootDirs = append(rootDirs, rootDirectory)

		defaultConfig.NetAddress = neighbors[i]
		defaultConfig.SaveToDisk(rootDirectory)

		// Save empty phonebook - we'll add peers after they've been assigned listening ports
		err := config.SavePhonebookToDisk(make([]string, 0), rootDirectory)
		require.NoError(t, err)

		genesisDir := filepath.Join(rootDirectory, g.ID())
		os.Mkdir(genesisDir, 0700)

		wname := config.RootKeyFilename(t.Name() + "wallet" + strconv.Itoa(i))
		pname := config.PartKeyFilename(t.Name()+"wallet"+strconv.Itoa(i), uint64(firstRound), uint64(lastRound))

		wallets[i] = wname

		filename := filepath.Join(genesisDir, wname)
		access, err := db.MakeAccessor(filename, false, false)
		if err != nil {
			panic(err)
		}
		root, err := account.GenerateRoot(access)
		access.Close()
		if err != nil {
			panic(err)
		}

		filename = filepath.Join(genesisDir, pname)
		access, err = db.MakeAccessor(filename, false, false)
		if err != nil {
			panic(err)
		}
		part, err := account.FillDBWithParticipationKeys(access, root.Address(), firstRound, lastRound, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
		if err != nil {
			panic(err)
		}
		access.Close()

		data := basics.AccountData{
			Status:      basics.Online,
			MicroAlgos:  basics.MicroAlgos{Raw: uint64(minMoneyAtStart + (gen.Int() % (maxMoneyAtStart - minMoneyAtStart)))},
			SelectionID: part.VRFSecrets().PK,
			VoteID:      part.VotingSecrets().OneTimeSignatureVerifier,
		}
		short := root.Address()
		genesis[short] = data
	}
	genesis[poolAddr] = basics.AccountData{
		Status:     basics.Online,
		MicroAlgos: basics.MicroAlgos{Raw: uint64(100000)},
	}

	bootstrap := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)

	for i, rootDirectory := range rootDirs {
		genesisDir := filepath.Join(rootDirectory, g.ID())
		ledgerFilenamePrefix := filepath.Join(genesisDir, config.LedgerFilenamePrefix)
		if customConsensus != nil {
			err := config.SaveConfigurableConsensus(genesisDir, customConsensus)
			require.Nil(t, err)
		}
		err1 := config.LoadConfigurableConsensusProtocols(genesisDir)
		require.Nil(t, err1)
		nodeID := fmt.Sprintf("Node%d", i)
		const inMem = false
		cfg, err := config.LoadConfigFromDisk(rootDirectory)
		require.NoError(t, err)
		cfg.Archival = true
		_, err = data.LoadLedger(logging.Base().With("name", nodeID), ledgerFilenamePrefix, inMem, g.Proto, bootstrap, g.ID(), g.Hash(), nil, cfg)
		require.NoError(t, err)
	}

	for i := range nodes {
		var nodeNeighbors []string
		nodeNeighbors = append(nodeNeighbors, neighbors[:i]...)
		nodeNeighbors = append(nodeNeighbors, neighbors[i+1:]...)
		rootDirectory := rootDirs[i]
		cfg, err := config.LoadConfigFromDisk(rootDirectory)
		require.NoError(t, err)
		node, err := MakeFull(logging.Base().With("source", t.Name()+strconv.Itoa(i)), rootDirectory, cfg, nodeNeighbors, g)
		nodes[i] = node
		require.NoError(t, err)
	}

	return nodes, wallets
}

func TestSyncingFullNode(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Skip("Flaky in nightly test environment")

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	nodes, wallets := setupFullNodes(t, protocol.ConsensusCurrentVersion, backlogPool, nil)
	for i := 0; i < len(nodes); i++ {
		defer os.Remove(wallets[i])
		defer nodes[i].Stop()
	}

	initialRound := nodes[0].ledger.NextRound()

	startAndConnectNodes(nodes, true)

	counter := 0
	for tests := uint64(0); tests < 16; tests++ {
		timer := time.NewTimer(30*time.Second + 2*expectedAgreementTime)
		for i := range wallets {
			select {
			case <-nodes[i].ledger.Wait(initialRound + basics.Round(tests)):
				if i == 0 {
					counter++
					if counter == 5 {
						go func() {
							// after 5 blocks, have this node partitioned
							nodes[0].net.DisconnectPeers()
							time.Sleep(20 * time.Second)
							nodes[0].net.RequestConnectOutgoing(false, nil)
						}()
					}
				}
			case <-timer.C:
				require.Fail(t, fmt.Sprintf("no block notification for account: %d - %v. Iteration: %v", i, wallets[i], tests))
				return
			}
		}
	}

	roundsCompleted := nodes[0].ledger.LastRound()
	for i := basics.Round(0); i < roundsCompleted; i++ {
		for wallet := range wallets {
			e0, err := nodes[0].ledger.Block(i)
			if err != nil {
				panic(err)
			}
			ei, err := nodes[wallet].ledger.Block(i)
			if err != nil {
				panic(err)
			}
			require.Equal(t, e0.Hash(), ei.Hash())
		}
	}
}

func TestInitialSync(t *testing.T) {
	partitiontest.PartitionTest(t)

	if testing.Short() {
		t.Skip("Test takes ~25 seconds.")
	}

	if (runtime.GOARCH == "arm" || runtime.GOARCH == "arm64") &&
		strings.ToUpper(os.Getenv("CIRCLECI")) == "TRUE" {
		t.Skip("Test is too heavy for amd64 builder running in parallel with other packages")
	}

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	nodes, wallets := setupFullNodes(t, protocol.ConsensusCurrentVersion, backlogPool, nil)
	for i := 0; i < len(nodes); i++ {
		defer os.Remove(wallets[i])
		defer nodes[i].Stop()
	}
	initialRound := nodes[0].ledger.NextRound()

	startAndConnectNodes(nodes, true)

	select {
	case <-nodes[0].ledger.Wait(initialRound):
		e0, err := nodes[0].ledger.Block(initialRound)
		if err != nil {
			panic(err)
		}
		e1, err := nodes[1].ledger.Block(initialRound)
		if err != nil {
			panic(err)
		}
		require.Equal(t, e1.Hash(), e0.Hash())
	case <-time.After(60 * time.Second):
		require.Fail(t, fmt.Sprintf("no block notification for wallet: %v.", wallets[0]))
		return
	}
}

func TestSimpleUpgrade(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Skip("Flaky in nightly test environment.")

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	// ConsensusTest0 is a version of ConsensusV0 used for testing
	// (it has different approved upgrade paths).
	const consensusTest0 = protocol.ConsensusVersion("test0")

	// ConsensusTest1 is an extension of ConsensusTest0 that
	// supports a sorted-list balance commitment.
	const consensusTest1 = protocol.ConsensusVersion("test1")

	configurableConsensus := make(config.ConsensusProtocols)

	testParams0 := config.Consensus[protocol.ConsensusCurrentVersion]
	testParams0.MinUpgradeWaitRounds = 0
	testParams0.SupportGenesisHash = false
	testParams0.UpgradeVoteRounds = 2
	testParams0.UpgradeThreshold = 1
	testParams0.DefaultUpgradeWaitRounds = 2
	testParams0.MaxVersionStringLen = 64
	testParams0.MaxTxnBytesPerBlock = 1000000
	testParams0.DefaultKeyDilution = 10000
	testParams0.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{
		consensusTest1: 0,
	}
	configurableConsensus[consensusTest0] = testParams0

	testParams1 := config.Consensus[protocol.ConsensusCurrentVersion]
	testParams1.MinUpgradeWaitRounds = 0
	testParams1.SupportGenesisHash = false
	testParams1.UpgradeVoteRounds = 10
	testParams1.UpgradeThreshold = 8
	testParams1.DefaultUpgradeWaitRounds = 10
	testParams1.MaxVersionStringLen = 64
	testParams1.MaxTxnBytesPerBlock = 1000000
	testParams1.DefaultKeyDilution = 10000
	testParams1.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	configurableConsensus[consensusTest1] = testParams1

	nodes, wallets := setupFullNodes(t, consensusTest0, backlogPool, configurableConsensus)
	for i := 0; i < len(nodes); i++ {
		defer os.Remove(wallets[i])
		defer nodes[i].Stop()
	}

	initialRound := nodes[0].ledger.NextRound()

	startAndConnectNodes(nodes, false)

	maxRounds := basics.Round(16)
	roundsCheckedForUpgrade := 0

	for tests := basics.Round(0); tests < maxRounds; tests++ {
		blocks := make([]bookkeeping.Block, len(wallets), len(wallets))
		for i := range wallets {
			select {
			case <-nodes[i].ledger.Wait(initialRound + tests):
				blk, err := nodes[i].ledger.Block(initialRound + tests)
				if err != nil {
					panic(err)
				}
				blocks[i] = blk
			case <-time.After(60 * time.Second):
				require.Fail(t, fmt.Sprintf("no block notification for account: %v. Iteration: %v", wallets[i], tests))
				return
			}
		}

		blockDigest := blocks[0].Hash()

		for i := range wallets {
			require.Equal(t, blockDigest, blocks[i].Hash())
		}

		// On the first round, check that we did not upgrade
		if tests == 0 {
			roundsCheckedForUpgrade++

			for i := range wallets {
				require.Equal(t, consensusTest0, blocks[i].CurrentProtocol)
			}
		}

		// On the last round, check that we upgraded
		if tests == maxRounds-1 {
			roundsCheckedForUpgrade++

			for i := range wallets {
				require.Equal(t, consensusTest1, blocks[i].CurrentProtocol)
			}
		}
	}

	require.Equal(t, 2, roundsCheckedForUpgrade)
}

func startAndConnectNodes(nodes []*AlgorandFullNode, delayStartFirstNode bool) {
	var wg sync.WaitGroup
	for i := range nodes {
		if delayStartFirstNode && i == 0 {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			nodes[i].Start()
		}(i)
	}
	wg.Wait()

	if delayStartFirstNode {
		connectPeers(nodes[1:])
		delayStartNode(nodes[0], nodes[1:], 20*time.Second)
	} else {
		connectPeers(nodes)
	}
}

func connectPeers(nodes []*AlgorandFullNode) {
	for _, node := range nodes {
		node.net.RequestConnectOutgoing(false, nil)
	}
}

func delayStartNode(node *AlgorandFullNode, peers []*AlgorandFullNode, delay time.Duration) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(delay)
		node.Start()
	}()
	wg.Wait()

	for _, peer := range peers {
		peer.net.RequestConnectOutgoing(false, nil)
	}
	node.net.RequestConnectOutgoing(false, nil)
}

func TestStatusReport_TimeSinceLastRound(t *testing.T) {
	partitiontest.PartitionTest(t)

	type fields struct {
		LastRoundTimestamp time.Time
	}

	tests := []struct {
		name      string
		fields    fields
		want      time.Duration
		wantError bool
	}{
		// test cases
		{
			name: "test1",
			fields: fields{
				LastRoundTimestamp: time.Time{},
			},
			want:      time.Duration(0),
			wantError: false,
		},
		{
			name: "test2",
			fields: fields{
				LastRoundTimestamp: time.Now(),
			},
			want:      time.Duration(0),
			wantError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := StatusReport{
				LastRoundTimestamp: tt.fields.LastRoundTimestamp,
			}
			if got := status.TimeSinceLastRound(); got != tt.want {
				if !tt.wantError {
					t.Errorf("StatusReport.TimeSinceLastRound() = %v, want = %v", got, tt.want)
				}
			} else if tt.wantError {
				t.Errorf("StatusReport.TimeSinceLastRound() = %v, want != %v", got, tt.want)
			}
		})
	}
}

type mismatchingDirectroyPermissionsLog struct {
	logging.Logger
	t *testing.T
}

func (m mismatchingDirectroyPermissionsLog) Errorf(fmts string, args ...interface{}) {
	fmtStr := fmt.Sprintf(fmts, args...)
	require.Contains(m.t, fmtStr, "Unable to create genesis directory")
}

// TestMismatchingGenesisDirectoryPermissions tests to see that the os.MkDir check we have in MakeFull works as expected. It tests both the return error as well as the logged error.
func TestMismatchingGenesisDirectoryPermissions(t *testing.T) {
	partitiontest.PartitionTest(t)

	testDirectroy := t.TempDir()

	genesis := bookkeeping.Genesis{
		SchemaID:    "go-test-node-genesis",
		Proto:       protocol.ConsensusCurrentVersion,
		Network:     config.Devtestnet,
		FeeSink:     sinkAddr.String(),
		RewardsPool: poolAddr.String(),
	}

	log := mismatchingDirectroyPermissionsLog{logging.TestingLog(t), t}

	require.NoError(t, os.Chmod(testDirectroy, 0200))

	node, err := MakeFull(log, testDirectroy, config.GetDefaultLocal(), []string{}, genesis)

	require.Nil(t, node)
	require.Error(t, err)
	require.Contains(t, err.Error(), "permission denied")

	require.NoError(t, os.Chmod(testDirectroy, 1700))
	require.NoError(t, os.RemoveAll(testDirectroy))
}

// TestDefaultResourcePaths confirms that when no extra configuration is provided, all resources are created in the dataDir
func TestDefaultResourcePaths(t *testing.T) {
	partitiontest.PartitionTest(t)

	testDirectory := t.TempDir()

	genesis := bookkeeping.Genesis{
		SchemaID:    "gen",
		Proto:       protocol.ConsensusCurrentVersion,
		Network:     config.Devtestnet,
		FeeSink:     sinkAddr.String(),
		RewardsPool: poolAddr.String(),
	}

	cfg := config.GetDefaultLocal()

	// the logger is set up by the server, so we don't test this here
	log := logging.Base()

	n, err := MakeFull(log, testDirectory, cfg, []string{}, genesis)

	n.Start()
	defer n.Stop()

	require.NoError(t, err)

	// confirm genesis dir exists in the data dir, and that resources exist in the expected locations
	require.DirExists(t, filepath.Join(testDirectory, genesis.ID()))

	_, err = os.Stat(filepath.Join(testDirectory, genesis.ID(), "ledger.tracker.sqlite"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(testDirectory, genesis.ID(), "stateproof.sqlite"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(testDirectory, genesis.ID(), "ledger.block.sqlite"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(testDirectory, genesis.ID(), "partregistry.sqlite"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(testDirectory, genesis.ID(), "crash.sqlite"))
	require.NoError(t, err)
}

// TestConfiguredDataDirs tests to see that when HotDataDir and ColdDataDir are set, underlying resources are created in the correct locations
// Not all resources are tested here, because not all resources use the paths provided to them immediately. For example, catchpoint only creates
// a directory when writing a catchpoint file, which is not being done here with this simple node
func TestConfiguredDataDirs(t *testing.T) {
	partitiontest.PartitionTest(t)

	testDirectory := t.TempDir()
	testDirHot := t.TempDir()
	testDirCold := t.TempDir()

	genesis := bookkeeping.Genesis{
		SchemaID:    "go-test-node-genesis",
		Proto:       protocol.ConsensusCurrentVersion,
		Network:     config.Devtestnet,
		FeeSink:     sinkAddr.String(),
		RewardsPool: poolAddr.String(),
	}

	cfg := config.GetDefaultLocal()

	cfg.HotDataDir = testDirHot
	cfg.ColdDataDir = testDirCold
	cfg.CatchpointTracking = 2
	cfg.CatchpointInterval = 1

	// the logger is set up by the server, so we don't test this here
	log := logging.Base()

	n, err := MakeFull(log, testDirectory, cfg, []string{}, genesis)
	require.NoError(t, err)

	n.Start()
	defer n.Stop()

	// confirm hot data dir exists and contains a genesis dir
	require.DirExists(t, filepath.Join(testDirHot, genesis.ID()))

	// confirm the tracker is in the genesis dir of hot data dir
	require.FileExists(t, filepath.Join(testDirHot, genesis.ID(), "ledger.tracker.sqlite"))

	// confirm the stateproof db in the genesis dir of hot data dir
	require.FileExists(t, filepath.Join(testDirHot, genesis.ID(), "stateproof.sqlite"))

	// confirm cold data dir exists and contains a genesis dir
	require.DirExists(t, filepath.Join(testDirCold, genesis.ID()))

	// confirm the blockdb is in the genesis dir of cold data dir
	require.FileExists(t, filepath.Join(testDirCold, genesis.ID(), "ledger.block.sqlite"))

	// confirm the partregistry is in the genesis dir of cold data dir
	require.FileExists(t, filepath.Join(testDirCold, genesis.ID(), "partregistry.sqlite"))

	// confirm the agreement crash DB is in the genesis dir of hot data dir
	require.FileExists(t, filepath.Join(testDirHot, genesis.ID(), "crash.sqlite"))
}

// TestConfiguredResourcePaths tests to see that when TrackerDbFilePath, BlockDbFilePath, StateproofDir, and CrashFilePath are set, underlying resources are created in the correct locations
func TestConfiguredResourcePaths(t *testing.T) {
	partitiontest.PartitionTest(t)

	testDirectory := t.TempDir()
	testDirHot := t.TempDir()
	testDirCold := t.TempDir()

	// add a path for each resource now
	trackerPath := filepath.Join(testDirectory, "custom_tracker")
	blockPath := filepath.Join(testDirectory, "custom_block")
	stateproofDir := filepath.Join(testDirectory, "custom_stateproof")
	crashPath := filepath.Join(testDirectory, "custom_crash")

	genesis := bookkeeping.Genesis{
		SchemaID:    "go-test-node-genesis",
		Proto:       protocol.ConsensusCurrentVersion,
		Network:     config.Devtestnet,
		FeeSink:     sinkAddr.String(),
		RewardsPool: poolAddr.String(),
	}

	cfg := config.GetDefaultLocal()

	cfg.HotDataDir = testDirHot
	cfg.ColdDataDir = testDirCold
	cfg.TrackerDBDir = trackerPath
	cfg.BlockDBDir = blockPath
	cfg.StateproofDir = stateproofDir
	cfg.CrashDBDir = crashPath

	// the logger is set up by the server, so we don't test this here
	log := logging.Base()

	n, err := MakeFull(log, testDirectory, cfg, []string{}, genesis)
	require.NoError(t, err)

	n.Start()
	defer n.Stop()

	// confirm hot data dir exists and contains a genesis dir
	require.DirExists(t, filepath.Join(testDirHot, genesis.ID()))

	// the tracker shouldn't be in the hot data dir, but rather the custom path's genesis dir
	require.NoFileExists(t, filepath.Join(testDirHot, genesis.ID(), "ledger.tracker.sqlite"))
	require.FileExists(t, filepath.Join(cfg.TrackerDBDir, genesis.ID(), "ledger.tracker.sqlite"))

	// same with stateproofs
	require.NoFileExists(t, filepath.Join(testDirHot, genesis.ID(), "stateproof.sqlite"))
	require.FileExists(t, filepath.Join(cfg.StateproofDir, genesis.ID(), "stateproof.sqlite"))

	// confirm cold data dir exists and contains a genesis dir
	require.DirExists(t, filepath.Join(testDirCold, genesis.ID()))

	// block db shouldn't be in the cold data dir, but rather the custom path's genesis dir
	require.NoFileExists(t, filepath.Join(testDirCold, genesis.ID(), "ledger.block.sqlite"))
	require.FileExists(t, filepath.Join(cfg.BlockDBDir, genesis.ID(), "ledger.block.sqlite"))

	require.NoFileExists(t, filepath.Join(testDirCold, genesis.ID(), "crash.sqlite"))
	require.FileExists(t, filepath.Join(cfg.CrashDBDir, genesis.ID(), "crash.sqlite"))
}

// TestOfflineOnlineClosedBitStatus a test that validates that the correct bits are being set
func TestOfflineOnlineClosedBitStatus(t *testing.T) {
	partitiontest.PartitionTest(t)

	tests := []struct {
		name        string
		acctData    basics.OnlineAccountData
		expectedInt int
	}{
		{"online 1", basics.OnlineAccountData{
			VotingData:            basics.VotingData{VoteFirstValid: 1, VoteLastValid: 100},
			MicroAlgosWithRewards: basics.MicroAlgos{Raw: 0}}, 0},
		{"online 2", basics.OnlineAccountData{
			VotingData:            basics.VotingData{VoteFirstValid: 1, VoteLastValid: 100},
			MicroAlgosWithRewards: basics.MicroAlgos{Raw: 1}}, 0},
		{"offline & not closed", basics.OnlineAccountData{
			VotingData:            basics.VotingData{VoteFirstValid: 0, VoteLastValid: 0},
			MicroAlgosWithRewards: basics.MicroAlgos{Raw: 1}}, 0 | bitAccountOffline},
		{"offline & closed", basics.OnlineAccountData{
			VotingData:            basics.VotingData{VoteFirstValid: 0, VoteLastValid: 0},
			MicroAlgosWithRewards: basics.MicroAlgos{Raw: 0}}, 0 | bitAccountOffline | bitAccountIsClosed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expectedInt, getOfflineClosedStatus(test.acctData))
		})
	}
}

// TestMaxSizesCorrect tests that constants defined in the protocol package are correct
// and match the MaxSize() values of associated msgp encodable structs.
// the test is located here since it needs to import various other packages.
//
// If this test fails, DO NOT JUST UPDATE THE CONSTANTS OR MODIFY THE TEST!
// Instead you need to introduce a new version of the protocol and mechanisms
// to ensure that nodes on different proto versions don't reject each others messages due to exceeding
// max size network protocol version
func TestMaxSizesCorrect(t *testing.T) {
	partitiontest.PartitionTest(t)

	/************************************************
	 * ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! *
	 *  Read the comment before touching this test!  *
	 * ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! *
	 *************************************************
	 */ ////////////////////////////////////////////////
	avSize := uint64(agreement.UnauthenticatedVoteMaxSize())
	require.Equal(t, avSize, protocol.AgreementVoteTag.MaxMessageSize())
	miSize := uint64(network.MessageOfInterestMaxSize())
	require.Equal(t, miSize, protocol.MsgOfInterestTag.MaxMessageSize())
	npSize := uint64(NetPrioResponseSignedMaxSize())
	require.Equal(t, npSize, protocol.NetPrioResponseTag.MaxMessageSize())
	nsSize := uint64(network.IdentityVerificationMessageSignedMaxSize())
	require.Equal(t, nsSize, protocol.NetIDVerificationTag.MaxMessageSize())
	piSize := uint64(network.PingLength)
	require.Equal(t, piSize, protocol.PingTag.MaxMessageSize())
	pjSize := uint64(network.PingLength)
	require.Equal(t, pjSize, protocol.PingReplyTag.MaxMessageSize())
	ppSize := uint64(agreement.TransmittedPayloadMaxSize())
	require.Equal(t, ppSize, protocol.ProposalPayloadTag.MaxMessageSize())
	spSize := uint64(stateproof.SigFromAddrMaxSize())
	require.Equal(t, spSize, protocol.StateProofSigTag.MaxMessageSize())
	txSize := uint64(transactions.SignedTxnMaxSize())
	require.Equal(t, txSize, protocol.TxnTag.MaxMessageSize())
	msSize := uint64(crypto.DigestMaxSize())
	require.Equal(t, msSize, protocol.MsgDigestSkipTag.MaxMessageSize())

	// UE is a handrolled message not using msgp
	// including here for completeness ensured by protocol.TestMaxSizesTested
	ueSize := uint64(67)
	require.Equal(t, ueSize, protocol.UniEnsBlockReqTag.MaxMessageSize())

	// VB and TS are the largest messages and are using the default network max size
	// including here for completeness ensured by protocol.TestMaxSizesTested
	vbSize := uint64(network.MaxMessageLength)
	require.Equal(t, vbSize, protocol.VoteBundleTag.MaxMessageSize())
	tsSize := uint64(network.MaxMessageLength)
	require.Equal(t, tsSize, protocol.TopicMsgRespTag.MaxMessageSize())
}
