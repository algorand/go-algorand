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
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/network/p2p"
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

type nodeInfo struct {
	idx     int
	host    string
	wsPort  int
	p2pPort int
	p2pID   p2p.PeerID
	rootDir string
	genesis bookkeeping.Genesis
}

func (ni nodeInfo) wsNetAddr() string {
	return fmt.Sprintf("%s:%d", ni.host, ni.wsPort)
}

func (ni nodeInfo) p2pNetAddr() string {
	return fmt.Sprintf("%s:%d", ni.host, ni.p2pPort)
}

func (ni nodeInfo) p2pMultiAddr() string {
	return fmt.Sprintf("/ip4/%s/tcp/%d/p2p/%s", ni.host, ni.p2pPort, ni.p2pID.String())
}

type configHook func(ni nodeInfo, cfg config.Local) (nodeInfo, config.Local)
type phonebookHook func([]nodeInfo, int) []string

func setupFullNodes(t *testing.T, proto protocol.ConsensusVersion, verificationPool execpool.BacklogPool, customConsensus config.ConsensusProtocols) ([]*AlgorandFullNode, []string) {
	minMoneyAtStart := 10000
	maxMoneyAtStart := 100000
	gen := rand.New(rand.NewSource(2))

	const numAccounts = 10
	acctStake := make([]basics.MicroAlgos, numAccounts)
	for i := range acctStake {
		acctStake[i] = basics.MicroAlgos{Raw: uint64(minMoneyAtStart + (gen.Int() % (maxMoneyAtStart - minMoneyAtStart)))}
	}

	configHook := func(ni nodeInfo, cfg config.Local) (nodeInfo, config.Local) {
		cfg.NetAddress = ni.wsNetAddr()
		return ni, cfg
	}

	phonebookHook := func(nodes []nodeInfo, nodeIdx int) []string {
		phonebook := make([]string, 0, len(nodes)-1)
		for i := range nodes {
			if i != nodeIdx {
				phonebook = append(phonebook, nodes[i].wsNetAddr())
			}
		}
		return phonebook
	}
	nodes, wallets := setupFullNodesEx(t, proto, verificationPool, customConsensus, acctStake, configHook, phonebookHook)
	require.Len(t, nodes, numAccounts)
	require.Len(t, wallets, numAccounts)
	return nodes, wallets
}

func setupFullNodesEx(
	t *testing.T, proto protocol.ConsensusVersion, verificationPool execpool.BacklogPool, customConsensus config.ConsensusProtocols,
	acctStake []basics.MicroAlgos, configHook configHook, phonebookHook phonebookHook,
) ([]*AlgorandFullNode, []string) {

	util.SetFdSoftLimit(1000)

	f, _ := os.Create(t.Name() + ".log")
	logging.Base().SetJSONFormatter()
	logging.Base().SetOutput(f)
	logging.Base().SetLevel(logging.Debug)
	t.Logf("Logging to %s\n", t.Name()+".log")

	firstRound := basics.Round(0)
	lastRound := basics.Round(200)

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

	genesis := make(map[basics.Address]basics.AccountData)
	numAccounts := len(acctStake)
	wallets := make([]string, numAccounts)
	nodeInfos := make([]nodeInfo, numAccounts)

	for i := range wallets {
		rootDirectory := t.TempDir()
		nodeInfos[i] = nodeInfo{
			idx:     i,
			host:    "127.0.0.1",
			wsPort:  10000 + 100*i,
			p2pPort: 10000 + 100*i + 1,
			rootDir: rootDirectory,
			genesis: g,
		}

		ni, cfg := configHook(nodeInfos[i], defaultConfig)
		nodeInfos[i] = ni
		cfg.SaveToDisk(rootDirectory)

		t.Logf("Root directory of node %d (%s): %s\n", i, ni.wsNetAddr(), rootDirectory)

		// // Save empty phonebook - we'll add peers after they've been assigned listening ports
		// err := config.SavePhonebookToDisk(make([]string, 0), rootDirectory)
		// require.NoError(t, err)

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
			MicroAlgos:  acctStake[i],
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

	for addr, data := range genesis {
		g.Allocation = append(g.Allocation, bookkeeping.GenesisAllocation{
			Address: addr.String(),
			State: bookkeeping.GenesisAccountData{
				Status:          data.Status,
				MicroAlgos:      data.MicroAlgos,
				VoteID:          data.VoteID,
				StateProofID:    data.StateProofID,
				SelectionID:     data.SelectionID,
				VoteFirstValid:  data.VoteFirstValid,
				VoteLastValid:   data.VoteLastValid,
				VoteKeyDilution: data.VoteKeyDilution,
			},
		})
	}

	nodes := make([]*AlgorandFullNode, numAccounts)
	for i := range nodes {
		rootDirectory := nodeInfos[i].rootDir
		genesisDir := filepath.Join(rootDirectory, g.ID())
		if customConsensus != nil {
			err0 := config.SaveConfigurableConsensus(genesisDir, customConsensus)
			require.Nil(t, err0)
			err0 = config.LoadConfigurableConsensusProtocols(genesisDir)
			require.Nil(t, err0)
		}

		cfg, err := config.LoadConfigFromDisk(rootDirectory)
		phonebook := phonebookHook(nodeInfos, i)
		require.NoError(t, err)
		node, err := MakeFull(logging.Base(), rootDirectory, cfg, phonebook, g)
		nodes[i] = node
		require.NoError(t, err)
	}

	return nodes, wallets
}

func TestSyncingFullNode(t *testing.T) {
	partitiontest.PartitionTest(t)

	if testing.Short() {
		t.Skip("Test takes ~50 seconds.")
	}

	if (runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" && runtime.GOOS != "darwin") &&
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

	startAndConnectNodes(nodes, defaultFirstNodeStartDelay)

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

	if (runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" && runtime.GOOS != "darwin") &&
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

	startAndConnectNodes(nodes, defaultFirstNodeStartDelay)

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

	if testing.Short() {
		t.Skip("Test takes ~50 seconds.")
	}

	if (runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" && runtime.GOOS != "darwin") &&
		strings.ToUpper(os.Getenv("CIRCLECI")) == "TRUE" {
		t.Skip("Test is too heavy for amd64 builder running in parallel with other packages")
	}

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

	startAndConnectNodes(nodes, nodelayFirstNodeStartDelay)

	maxRounds := basics.Round(16)
	roundsCheckedForUpgrade := 0

	for tests := basics.Round(0); tests < maxRounds; tests++ {
		blocks := make([]bookkeeping.Block, len(wallets))
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

const defaultFirstNodeStartDelay = 20 * time.Second
const nodelayFirstNodeStartDelay = 0

func startAndConnectNodes(nodes []*AlgorandFullNode, delayStartFirstNode time.Duration) {
	var wg sync.WaitGroup
	for i := range nodes {
		if delayStartFirstNode != nodelayFirstNodeStartDelay && i == 0 {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			nodes[i].Start()
		}(i)
	}
	wg.Wait()

	if delayStartFirstNode != nodelayFirstNodeStartDelay {
		connectPeers(nodes[1:])
		delayStartNode(nodes[0], nodes[1:], delayStartFirstNode)
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

// TestNodeHybridTopology set ups 3 nodes network with the following topology:
// N -- R -- A and ensures N can discover A and download blocks from it.
//
// N is a non-part node that joins the network later
// R is a non-archival relay node with block service disabled. It MUST NOT service blocks to force N to discover A.
// A is a archival node that can only provide blocks.
// Nodes N and A have only R in their initial phonebook, and all nodes are in hybrid mode.
func TestNodeHybridTopology(t *testing.T) {
	partitiontest.PartitionTest(t)

	const consensusTest0 = protocol.ConsensusVersion("test0")

	configurableConsensus := make(config.ConsensusProtocols)

	testParams0 := config.Consensus[protocol.ConsensusCurrentVersion]
	testParams0.AgreementFilterTimeoutPeriod0 = 500 * time.Millisecond
	configurableConsensus[consensusTest0] = testParams0

	minMoneyAtStart := 1_000_000
	maxMoneyAtStart := 100_000_000_000
	gen := rand.New(rand.NewSource(2))

	const numAccounts = 3
	acctStake := make([]basics.MicroAlgos, numAccounts)
	for i := range acctStake {
		acctStake[i] = basics.MicroAlgos{Raw: uint64(minMoneyAtStart + (gen.Int() % (maxMoneyAtStart - minMoneyAtStart)))}
	}
	acctStake[0] = basics.MicroAlgos{} // no stake at node 0

	configHook := func(ni nodeInfo, cfg config.Local) (nodeInfo, config.Local) {
		cfg = config.GetDefaultLocal()
		if ni.idx != 2 {
			cfg.EnableBlockService = false
			cfg.EnableGossipBlockService = false
			cfg.EnableLedgerService = false
			cfg.CatchpointInterval = 0
			cfg.Archival = false
		} else {
			// node 2 is archival
			cfg.EnableBlockService = true
			cfg.EnableGossipBlockService = true
			cfg.EnableLedgerService = true
			cfg.CatchpointInterval = 200
			cfg.Archival = true
		}
		if ni.idx == 0 {
			// do not allow node 0 (N) to make any outgoing connections
			cfg.GossipFanout = 0
		}

		cfg.NetAddress = ni.wsNetAddr()
		cfg.EnableP2PHybridMode = true
		cfg.EnableDHTProviders = true
		cfg.P2PPersistPeerID = true
		privKey, err := p2p.GetPrivKey(cfg, ni.rootDir)
		require.NoError(t, err)
		ni.p2pID, err = p2p.PeerIDFromPublicKey(privKey.GetPublic())
		require.NoError(t, err)

		cfg.P2PListenAddress = ni.p2pNetAddr()
		return ni, cfg
	}

	phonebookHook := func(ni []nodeInfo, i int) []string {
		switch i {
		case 0:
			// node 0 (N) only accept connections to work around the peer selector
			// ConnectedOut priority. TODO: merge switching to archival peers from master
			// when ready.
			t.Logf("Node%d phonebook: empty", i)
			return []string{}
		case 1:
			// node 1 (R) connects to all
			t.Logf("Node%d phonebook: %s, %s, %s, %s", i, ni[0].wsNetAddr(), ni[2].wsNetAddr(), ni[0].p2pMultiAddr(), ni[2].p2pMultiAddr())
			return []string{ni[0].wsNetAddr(), ni[2].wsNetAddr(), ni[0].p2pMultiAddr(), ni[2].p2pMultiAddr()}
		case 2:
			// node 2 (A) connects to R
			t.Logf("Node%d phonebook: %s, %s", i, ni[1].wsNetAddr(), ni[1].p2pMultiAddr())
			return []string{ni[1].wsNetAddr(), ni[1].p2pMultiAddr()}
		default:
			t.Errorf("not expected number of nodes: %d", i)
			t.FailNow()
		}
		return nil
	}

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	nodes, wallets := setupFullNodesEx(t, consensusTest0, backlogPool, configurableConsensus, acctStake, configHook, phonebookHook)
	require.Len(t, nodes, 3)
	require.Len(t, wallets, 3)
	for i := 0; i < len(nodes); i++ {
		defer os.Remove(wallets[i])
		defer nodes[i].Stop()
	}

	startAndConnectNodes(nodes, 10*time.Second)

	initialRound := nodes[0].ledger.NextRound()
	targetRound := initialRound + 10

	select {
	case <-nodes[0].ledger.Wait(targetRound):
		e0, err := nodes[0].ledger.Block(targetRound)
		require.NoError(t, err)
		e1, err := nodes[1].ledger.Block(targetRound)
		require.NoError(t, err)
		require.Equal(t, e1.Hash(), e0.Hash())
	case <-time.After(120 * time.Second):
		require.Fail(t, fmt.Sprintf("no block notification for wallet: %v.", wallets[0]))
	}
}

// TestNodeP2PRelays creates a network of 3 nodes with the following topology:
// R1 (relay, DHT) -> R2 (relay, phonebook) <- N (part node)
// Expect N to discover R1 via DHT and connect to it.
func TestNodeP2PRelays(t *testing.T) {
	partitiontest.PartitionTest(t)

	const consensusTest0 = protocol.ConsensusVersion("test0")

	configurableConsensus := make(config.ConsensusProtocols)

	testParams0 := config.Consensus[protocol.ConsensusCurrentVersion]
	testParams0.AgreementFilterTimeoutPeriod0 = 500 * time.Millisecond
	configurableConsensus[consensusTest0] = testParams0

	minMoneyAtStart := 1_000_000
	maxMoneyAtStart := 100_000_000_000
	gen := rand.New(rand.NewSource(2))

	const numAccounts = 3
	acctStake := make([]basics.MicroAlgos, numAccounts)
	// only node N has stake
	acctStake[2] = basics.MicroAlgos{Raw: uint64(minMoneyAtStart + (gen.Int() % (maxMoneyAtStart - minMoneyAtStart)))}

	configHook := func(ni nodeInfo, cfg config.Local) (nodeInfo, config.Local) {
		cfg = config.GetDefaultLocal()
		cfg.BaseLoggerDebugLevel = uint32(logging.Debug)
		cfg.EnableP2P = true
		cfg.NetAddress = ""
		cfg.EnableDHTProviders = true

		cfg.P2PPersistPeerID = true
		privKey, err := p2p.GetPrivKey(cfg, ni.rootDir)
		require.NoError(t, err)
		ni.p2pID, err = p2p.PeerIDFromPublicKey(privKey.GetPublic())
		require.NoError(t, err)

		switch ni.idx {
		case 2:
			// N is not a relay
		default:
			cfg.NetAddress = ni.p2pNetAddr()
		}
		return ni, cfg
	}

	phonebookHook := func(ni []nodeInfo, i int) []string {
		switch i {
		case 0:
			// node R1 connects to R2
			t.Logf("Node%d phonebook: %s", i, ni[1].p2pMultiAddr())
			return []string{ni[1].p2pMultiAddr()}
		case 1:
			// node R2 connects to none one
			t.Logf("Node%d phonebook: empty", i)
			return []string{}
		case 2:
			// node N only connects to R1
			t.Logf("Node%d phonebook: %s", i, ni[1].p2pMultiAddr())
			return []string{ni[1].p2pMultiAddr()}
		default:
			t.Errorf("not expected number of nodes: %d", i)
			t.FailNow()
		}
		return nil
	}

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	nodes, wallets := setupFullNodesEx(t, consensusTest0, backlogPool, configurableConsensus, acctStake, configHook, phonebookHook)
	require.Len(t, nodes, 3)
	require.Len(t, wallets, 3)
	for i := 0; i < len(nodes); i++ {
		defer os.Remove(wallets[i])
		defer nodes[i].Stop()
	}

	startAndConnectNodes(nodes, nodelayFirstNodeStartDelay)

	require.Eventually(t, func() bool {
		connectPeers(nodes)

		// since p2p open streams based on peer ID, there is no way to judge
		// connectivity based on exact In/Out so count both
		return len(nodes[0].net.GetPeers(network.PeersConnectedIn, network.PeersConnectedOut)) >= 1 &&
			len(nodes[1].net.GetPeers(network.PeersConnectedIn, network.PeersConnectedOut)) >= 2 &&
			len(nodes[2].net.GetPeers(network.PeersConnectedIn, network.PeersConnectedOut)) >= 1
	}, 60*time.Second, 1*time.Second)

	t.Log("Nodes connected to R2")

	// wait until N gets R1 in its phonebook
	require.Eventually(t, func() bool {
		// refresh N's peers in order to learn DHT data faster
		nodes[2].net.RequestConnectOutgoing(false, nil)
		return len(nodes[2].net.GetPeers(network.PeersPhonebookRelays)) == 2
	}, 80*time.Second, 1*time.Second)
}
