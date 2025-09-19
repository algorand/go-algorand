// Copyright (C) 2019-2025 Algorand, Inc.
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
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const basicTestCatchpointInterval = 4

func waitForCatchpointGeneration(t *testing.T, fixture *fixtures.RestClientFixture, client client.RestClient, catchpointRound basics.Round) string {
	err := client.WaitForRoundWithTimeout(catchpointRound + 1)
	if err != nil {
		return ""
	}

	var round basics.Round
	var status model.NodeStatusResponse
	catchpointConfirmed := false
	for i := 0; i < 1000; i++ {
		status, err = client.Status()
		require.NoError(t, err)
		if status.LastCatchpoint != nil && len(*status.LastCatchpoint) > 0 {
			round, _, err = ledgercore.ParseCatchpointLabel(*status.LastCatchpoint)
			require.NoError(t, err)
			if round >= catchpointRound {
				catchpointConfirmed = true
				if i > 80 {
					fmt.Printf("%s: waited for catchpont for %d sec\n", t.Name(), (i*250)/1000)
				}
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !catchpointConfirmed {
		require.Failf(t, "timeout waiting on a catchpoint", "target: %d, got %d", catchpointRound, round)
	}
	return *status.LastCatchpoint
}

func denyRoundRequestsWebProxy(a *require.Assertions, listeningAddress string, round basics.Round) *fixtures.WebProxy {
	log := logging.NewLogger()
	log.SetLevel(logging.Info)

	wp, err := fixtures.MakeWebProxy(listeningAddress, log, func(response http.ResponseWriter, request *http.Request, next http.HandlerFunc) {
		// prevent requests for the given block to go through.
		if request.URL.String() == fmt.Sprintf("/v1/test-v1/block/%d", round) {
			response.WriteHeader(http.StatusBadRequest)
			response.Write([]byte(fmt.Sprintf("webProxy prevents block %d from serving", round)))
			return
		}
		next(response, request)
	})
	a.NoError(err)
	log.Infof("web proxy listens at %s\n", wp.GetListenAddress())
	return wp
}

func getFirstCatchpointRound(consensusParams *config.ConsensusParams) basics.Round {
	// fast catchup downloads some blocks back from catchpoint round - CatchpointLookback
	expectedBlocksToDownload := consensusParams.MaxTxnLife + consensusParams.DeeperBlockHeaderHistory
	const restrictedBlockRound = 2 // block number that is rejected to be downloaded to ensure fast catchup and not regular catchup is running
	// calculate the target round: this is the next round after catchpoint
	// that is greater than expectedBlocksToDownload before the restrictedBlock block number
	minRound := restrictedBlockRound + consensusParams.CatchpointLookback
	return basics.Round(((expectedBlocksToDownload+minRound)/basicTestCatchpointInterval + 1) * basicTestCatchpointInterval)
}

func applyCatchpointConsensusChanges(consensusParams *config.ConsensusParams) {
	// MaxBalLookback  =  2 x SeedRefreshInterval x SeedLookback
	// ref. https://github.com/algorandfoundation/specs/blob/master/dev/abft.md
	consensusParams.SeedLookback = 2
	consensusParams.SeedRefreshInterval = 2
	consensusParams.MaxBalLookback = 2 * consensusParams.SeedLookback * consensusParams.SeedRefreshInterval // 8
	consensusParams.MaxTxnLife = 13
	consensusParams.CatchpointLookback = consensusParams.MaxBalLookback
	consensusParams.EnableCatchpointsWithSPContexts = true
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		// amd64 and arm64 platforms are generally quite capable, so accelerate the round times to make the test run faster.
		consensusParams.AgreementFilterTimeoutPeriod0 = 1 * time.Second
		consensusParams.AgreementFilterTimeout = 1 * time.Second
	}
	consensusParams.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
}

func configureCatchpointGeneration(a *require.Assertions, nodeController *nodecontrol.NodeController) {
	cfg, err := config.LoadConfigFromDisk(nodeController.GetDataDir())
	a.NoError(err)

	cfg.CatchpointInterval = basicTestCatchpointInterval
	cfg.Archival = false                 // make it explicit non-archival
	cfg.MaxBlockHistoryLookback = 20000  // to save blocks beyond MaxTxnLife=13
	cfg.CatchpointTracking = 2           // to enable catchpoints on non-archival nodes
	cfg.CatchpointFileHistoryLength = 30 // to store more than 2 default catchpoints
	cfg.MaxAcctLookback = 2
	err = cfg.SaveToDisk(nodeController.GetDataDir())
	a.NoError(err)
}

func configureCatchpointUsage(a *require.Assertions, nodeController *nodecontrol.NodeController) {
	cfg, err := config.LoadConfigFromDisk(nodeController.GetDataDir())
	a.NoError(err)

	cfg.MaxAcctLookback = 2
	cfg.Archival = false
	cfg.CatchpointInterval = 0
	cfg.NetAddress = ""
	cfg.EnableLedgerService = false
	cfg.EnableBlockService = false
	cfg.BaseLoggerDebugLevel = uint32(logging.Debug)
	cfg.CatchupBlockValidateMode = 12
	err = cfg.SaveToDisk(nodeController.GetDataDir())
	a.NoError(err)
}

type nodeExitErrorCollector struct {
	errors   []error
	messages []string
	mu       deadlock.Mutex
	a        *require.Assertions
}

func (ec *nodeExitErrorCollector) nodeExitWithError(nc *nodecontrol.NodeController, err error) {
	if err == nil {
		return
	}

	exitError, ok := err.(*exec.ExitError)
	if !ok {
		if err != nil {
			ec.mu.Lock()
			ec.errors = append(ec.errors, err)
			ec.messages = append(ec.messages, "Node at %s has terminated with an error", nc.GetDataDir())
			ec.mu.Unlock()
		}
		return
	}
	ws := exitError.Sys().(syscall.WaitStatus)
	exitCode := ws.ExitStatus()

	if err != nil {
		ec.mu.Lock()
		ec.errors = append(ec.errors, err)
		ec.messages = append(ec.messages, fmt.Sprintf("Node at %s has terminated with error code %d", nc.GetDataDir(), exitCode))
		ec.mu.Unlock()
	}
}

func (ec *nodeExitErrorCollector) Print() {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	for i, err := range ec.errors {
		ec.a.NoError(err, ec.messages[i])
	}
}

func startCatchpointGeneratingNode(a *require.Assertions, fixture *fixtures.RestClientFixture, nodeName string) (
	nodecontrol.NodeController, client.RestClient, *nodeExitErrorCollector) {
	nodeController, err := fixture.GetNodeController(nodeName)
	a.NoError(err)

	configureCatchpointGeneration(a, &nodeController)

	errorsCollector := nodeExitErrorCollector{a: a}
	_, err = nodeController.StartAlgod(nodecontrol.AlgodStartArgs{
		PeerAddress:       "",
		ListenIP:          "",
		RedirectOutput:    true,
		RunUnderHost:      false,
		TelemetryOverride: "",
		ExitErrorCallback: errorsCollector.nodeExitWithError,
	})
	a.NoError(err)

	restClient := fixture.GetAlgodClientForController(nodeController)
	// We don't want to start using the node without it being properly initialized.
	err = restClient.WaitForRoundWithTimeout(1)
	a.NoError(err)

	return nodeController, restClient, &errorsCollector
}

func startCatchpointUsingNode(a *require.Assertions, fixture *fixtures.RestClientFixture, nodeName string, peerAddress string) (
	nodecontrol.NodeController, client.RestClient, *fixtures.WebProxy, *nodeExitErrorCollector) {
	nodeController, err := fixture.GetNodeController(nodeName)
	a.NoError(err)

	configureCatchpointUsage(a, &nodeController)

	wp := denyRoundRequestsWebProxy(a, peerAddress, 2)
	errorsCollector := nodeExitErrorCollector{a: a}
	_, err = nodeController.StartAlgod(nodecontrol.AlgodStartArgs{
		PeerAddress:       wp.GetListenAddress(),
		ListenIP:          "",
		RedirectOutput:    true,
		RunUnderHost:      false,
		TelemetryOverride: "",
		ExitErrorCallback: errorsCollector.nodeExitWithError,
	})
	a.NoError(err)

	restClient := fixture.GetAlgodClientForController(nodeController)
	// We don't want to start using the node without it being properly initialized.
	err = restClient.WaitForRoundWithTimeout(1)
	a.NoError(err)

	return nodeController, restClient, wp, &errorsCollector
}

func startCatchpointNormalNode(a *require.Assertions, fixture *fixtures.RestClientFixture, nodeName string, peerAddress string) (
	nodecontrol.NodeController, client.RestClient, *nodeExitErrorCollector) {
	nodeController, err := fixture.GetNodeController(nodeName)
	a.NoError(err)

	errorsCollector := nodeExitErrorCollector{a: a}
	_, err = nodeController.StartAlgod(nodecontrol.AlgodStartArgs{
		PeerAddress:       peerAddress,
		ListenIP:          "",
		RedirectOutput:    true,
		RunUnderHost:      false,
		TelemetryOverride: "",
		ExitErrorCallback: errorsCollector.nodeExitWithError,
	})
	a.NoError(err)

	restClient := fixture.GetAlgodClientForController(nodeController)
	// We don't want to start using the node without it being properly initialized.
	err = restClient.WaitForRoundWithTimeout(1)
	a.NoError(err)

	return nodeController, restClient, &errorsCollector
}

func getFixture(consensusParams *config.ConsensusParams) *fixtures.RestClientFixture {
	consensus := make(config.ConsensusProtocols)
	const consensusCatchpointCatchupTestProtocol = protocol.ConsensusVersion("catchpointtestingprotocol")
	consensus[consensusCatchpointCatchupTestProtocol] = *consensusParams

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	return &fixture
}

func TestCatchpointCatchupErr(t *testing.T) {
	// Overview of this test:
	// Start a two-node network (primary has 100%, using has 0%)
	// create a web proxy, have the using node use it as a peer, blocking all requests for round #2. ( and allowing everything else )
	// Let it run until the first usable catchpoint, as computed in getFirstCatchpointRound, is generated.
	// Shut down the primary node so that using node will have no peers for catchpoint catchup.
	// Instruct the using node to catchpoint catchup from the proxy.
	// Make sure starting the catchpoint service returns an error.
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}

	consensusParams := config.Consensus[protocol.ConsensusFuture]
	applyCatchpointConsensusChanges(&consensusParams)
	a := require.New(fixtures.SynchronizedTest(t))

	fixture := getFixture(&consensusParams)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "CatchpointCatchupTestNetwork.json"))

	primaryNode, primaryNodeRestClient, primaryErrorsCollector := startCatchpointGeneratingNode(a, fixture, "Primary")
	defer primaryNode.StopAlgod()

	primaryNodeAddr, err := primaryNode.GetListeningAddress()
	a.NoError(err)

	usingNode, usingNodeRestClient, wp, usingNodeErrorsCollector := startCatchpointUsingNode(a, fixture, "Node", primaryNodeAddr)
	defer usingNodeErrorsCollector.Print()
	defer wp.Close()
	defer usingNode.StopAlgod()

	targetCatchpointRound := getFirstCatchpointRound(&consensusParams)

	catchpointLabel := waitForCatchpointGeneration(t, fixture, primaryNodeRestClient, targetCatchpointRound)

	primaryErrorsCollector.Print()
	err = primaryNode.StopAlgod()
	a.NoError(err)

	_, err = usingNodeRestClient.Catchup(catchpointLabel, 0)
	a.ErrorContains(err, node.MakeStartCatchpointError(catchpointLabel, fmt.Errorf("")).Error())
}

func TestBasicCatchpointCatchup(t *testing.T) {
	// Overview of this test:
	// Start a two-node network (primary has 100%, using has 0%)
	// create a web proxy, have the using node use it as a peer, blocking all requests for round #2. ( and allowing everything else )
	// Let it run until the first usable catchpoint, as computed in getFirstCatchpointRound, is generated.
	// instruct the using node to catchpoint catchup from the proxy.
	// wait until the using node is caught up to catchpointRound+1, skipping the "impossible" hole of round #2 and
	// participating in consensus.
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}

	consensusParams := config.Consensus[protocol.ConsensusFuture]
	applyCatchpointConsensusChanges(&consensusParams)
	a := require.New(fixtures.SynchronizedTest(t))

	fixture := getFixture(&consensusParams)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "CatchpointCatchupTestNetwork.json"))

	primaryNode, primaryNodeRestClient, primaryErrorsCollector := startCatchpointGeneratingNode(a, fixture, "Primary")
	defer primaryErrorsCollector.Print()
	defer primaryNode.StopAlgod()

	primaryNodeAddr, err := primaryNode.GetListeningAddress()
	a.NoError(err)

	usingNode, usingNodeRestClient, wp, usingNodeErrorsCollector := startCatchpointUsingNode(a, fixture, "Node", primaryNodeAddr)
	defer usingNodeErrorsCollector.Print()
	defer wp.Close()
	defer usingNode.StopAlgod()

	targetCatchpointRound := getFirstCatchpointRound(&consensusParams)

	catchpointLabel := waitForCatchpointGeneration(t, fixture, primaryNodeRestClient, targetCatchpointRound)

	_, err = usingNodeRestClient.Catchup(catchpointLabel, 0)
	a.NoError(err)

	err = usingNodeRestClient.WaitForRoundWithTimeout(targetCatchpointRound + 1)
	a.NoError(err)

	// ensure the raw block can be downloaded (including cert)
	_, err = usingNodeRestClient.RawBlock(targetCatchpointRound)
	a.NoError(err)
}

func TestCatchpointLabelGeneration(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}

	testCases := []struct {
		catchpointInterval uint64
		archival           bool
		expectLabels       bool
	}{
		{4, true, true},
		{0, true, false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("CatchpointInterval_%v/Archival_%v", tc.catchpointInterval, tc.archival), func(t *testing.T) {
			a := require.New(fixtures.SynchronizedTest(t))
			log := logging.TestingLog(t)

			consensus := make(config.ConsensusProtocols)
			const consensusCatchpointCatchupTestProtocol = protocol.ConsensusVersion("catchpointtestingprotocol")
			catchpointCatchupProtocol := config.Consensus[protocol.ConsensusFuture]
			applyCatchpointConsensusChanges(&catchpointCatchupProtocol)
			consensus[consensusCatchpointCatchupTestProtocol] = catchpointCatchupProtocol

			var fixture fixtures.RestClientFixture
			fixture.SetConsensus(consensus)

			errorsCollector := nodeExitErrorCollector{a: a}
			defer errorsCollector.Print()

			fixture.SetupNoStart(t, filepath.Join("nettemplates", "CatchpointCatchupTestNetwork.json"))

			// Get primary node
			primaryNode, err := fixture.GetNodeController("Primary")
			a.NoError(err)

			cfg, err := config.LoadConfigFromDisk(primaryNode.GetDataDir())
			a.NoError(err)
			cfg.CatchpointInterval = tc.catchpointInterval
			cfg.Archival = tc.archival
			cfg.MaxAcctLookback = 2
			cfg.SaveToDisk(primaryNode.GetDataDir())

			// start the primary node
			_, err = primaryNode.StartAlgod(nodecontrol.AlgodStartArgs{
				PeerAddress:       "",
				ListenIP:          "",
				RedirectOutput:    true,
				RunUnderHost:      false,
				TelemetryOverride: "",
				ExitErrorCallback: errorsCollector.nodeExitWithError,
			})
			a.NoError(err)
			defer primaryNode.StopAlgod()

			// Let the network make some progress
			currentRound := basics.Round(1)
			targetRound := basics.Round(21)
			primaryNodeRestClient := fixture.GetAlgodClientForController(primaryNode)
			log.Infof("Building ledger history..")
			for {
				_, err = primaryNodeRestClient.WaitForRound(currentRound+1, 45*time.Second)
				a.NoError(err)
				if targetRound <= currentRound {
					break
				}
				currentRound++
			}
			log.Infof("done building!\n")

			primaryNodeStatus, err := primaryNodeRestClient.Status()
			a.NoError(err)
			a.NotNil(primaryNodeStatus.LastCatchpoint)
			if tc.expectLabels {
				a.NotEmpty(*primaryNodeStatus.LastCatchpoint)
			} else {
				a.Empty(*primaryNodeStatus.LastCatchpoint)
			}

			// download and inspect catchpoint file
			if tc.expectLabels {
				round, _, err := ledgercore.ParseCatchpointLabel(*primaryNodeStatus.LastCatchpoint)
				a.NoError(err)

				primaryNodeAddr, err := primaryNode.GetListeningAddress()
				a.NoError(err)

				chunks := downloadCatchpointFile(t, a, primaryNodeAddr, round)
				a.NotEmpty(chunks)
				validateCatchpointChunks(t, a, chunks, catchpointCatchupProtocol)
			}
		})
	}
}

func validateCatchpointChunks(t *testing.T, a *require.Assertions, chunks []ledger.CatchpointSnapshotChunkV6, params config.ConsensusParams) {
	// each chunk will contain only accounts, KVs, online accounts, and online round params
	// KVs will be skipped if there are none in ledger
	// online accounts and online round params only appear if params.EnableCatchpointsWithOnlineAccounts is true

	var sawAccounts, sawKVs, sawOnlineAccounts, sawOnlineRoundParams bool
	var numAccounts, numKVs, numOnlineAccounts, numOnlineRoundParams int
	for _, c := range chunks {
		if len(c.Balances) > 0 {
			sawAccounts = true
			numAccounts += len(c.Balances)
			a.Empty(c.KVs)
			a.Empty(c.OnlineAccounts)
			a.Empty(c.OnlineRoundParams)
		}
		if len(c.KVs) > 0 {
			a.True(sawAccounts)
			a.False(sawOnlineAccounts)
			a.False(sawOnlineRoundParams)
			sawKVs = true
			numKVs += len(c.KVs)
			a.Empty(c.Balances)
			a.Empty(c.OnlineAccounts)
			a.Empty(c.OnlineRoundParams)
		}
		if len(c.OnlineAccounts) > 0 {
			a.True(sawAccounts)
			a.False(sawOnlineRoundParams)
			sawOnlineAccounts = true
			numOnlineAccounts += len(c.OnlineAccounts)
			a.Empty(c.Balances)
			a.Empty(c.KVs)
			a.Empty(c.OnlineRoundParams)
		}
		if len(c.OnlineRoundParams) > 0 {
			a.True(sawAccounts)
			a.True(sawOnlineAccounts)
			a.False(sawOnlineRoundParams) // should only be one chunk with online round params
			sawOnlineRoundParams = true
			numOnlineRoundParams += len(c.OnlineRoundParams)
			a.Empty(c.Balances)
			a.Empty(c.KVs)
			a.Empty(c.OnlineAccounts)
		}
	}
	if params.EnableCatchpointsWithOnlineAccounts {
		a.True(sawOnlineAccounts)
		a.True(sawOnlineRoundParams)
		a.EqualValues(int(params.MaxBalLookback), numOnlineRoundParams,
			"online round params chunk should be same size as lookback %d", params.MaxBalLookback)
	}
	// could also add assertions on # of accounts, etc, more about data contents
	_ = sawKVs
}

func downloadCatchpointFile(t *testing.T, a *require.Assertions, baseURL string, round basics.Round) []ledger.CatchpointSnapshotChunkV6 {
	// download the catchpoint file
	url := fmt.Sprintf("%s/v1/test-v1/ledger/%s", baseURL, strconv.FormatUint(uint64(round), 36))
	t.Logf("Downloading catchpoint file for round %d from %s", round, url)
	resp, err := http.Get(url)
	a.NoError(err)
	a.Equal(200, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	a.NoError(err)
	t.Logf("Downloaded catchpoint file for round %d, size %d bytes", round, len(body))

	// decode in-memory: should be small (a few KB) for these test networks
	tarReader := tar.NewReader(bytes.NewReader(body))
	tarData := readCatchpointContent(t, tarReader)
	var chunks []ledger.CatchpointSnapshotChunkV6
	for _, d := range tarData {
		t.Logf("tar filename: %s, size %d", d.headerName, len(d.data))
		if after, ok := strings.CutPrefix(d.headerName, "balances."); ok { // chunk file
			idxStr := strings.TrimSuffix(after, ".msgpack")
			idx, err := strconv.Atoi(idxStr)
			a.NoError(err)
			var c ledger.CatchpointSnapshotChunkV6
			err = protocol.Decode(d.data, &c)
			a.NoError(err)
			t.Logf("chunk %d has balances: %d, kvs: %d, online accounts: %d, onlineroundparams: %d",
				idx, len(c.Balances), len(c.KVs), len(c.OnlineAccounts), len(c.OnlineRoundParams))
			chunks = append(chunks, c)
		}
	}
	return chunks
}

// copied from catchpointfilewriter_test.go
type decodedCatchpointChunkData struct {
	headerName string
	data       []byte
}

// copied from catchpointfilewriter_test.go
func readCatchpointContent(t *testing.T, tarReader *tar.Reader) []decodedCatchpointChunkData {
	result := make([]decodedCatchpointChunkData, 0)
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			break
		}
		data := make([]byte, header.Size)
		readComplete := int64(0)

		for readComplete < header.Size {
			bytesRead, err := tarReader.Read(data[readComplete:])
			readComplete += int64(bytesRead)
			if err != nil {
				if err == io.EOF {
					if readComplete == header.Size {
						break
					}
					require.NoError(t, err)
				}
				break
			}
		}

		result = append(result, decodedCatchpointChunkData{headerName: header.Name, data: data})
	}

	return result
}

// TestNodeTxHandlerRestart starts a two-node and one relay network
// Waits until a catchpoint is created
// Lets the primary node have the majority of the stake
// Sends a transaction from the second node
// The transaction will be confirmed only if the txHandler gets the transaction
func TestNodeTxHandlerRestart(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	a := require.New(fixtures.SynchronizedTest(t))

	consensus := make(config.ConsensusProtocols)
	protoVersion := protocol.ConsensusCurrentVersion
	catchpointCatchupProtocol := config.Consensus[protoVersion]
	applyCatchpointConsensusChanges(&catchpointCatchupProtocol)
	catchpointCatchupProtocol.StateProofInterval = 0
	consensus[protoVersion] = catchpointCatchupProtocol

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "TwoNodes50EachWithRelay.json"))

	// Get primary node
	primaryNode, err := fixture.GetNodeController("Node1")
	a.NoError(err)
	// Get secondary node
	secondNode, err := fixture.GetNodeController("Node2")
	a.NoError(err)
	// Get the relay
	relayNode, err := fixture.GetNodeController("Relay")
	a.NoError(err)

	// prepare it's configuration file to set it to generate a catchpoint every 16 rounds.
	cfg, err := config.LoadConfigFromDisk(primaryNode.GetDataDir())
	a.NoError(err)
	cfg.MaxAcctLookback = 2
	cfg.Archival = false

	cfg.TxSyncIntervalSeconds = 200000 // disable txSync

	cfg.SaveToDisk(primaryNode.GetDataDir())
	cfg.SaveToDisk(secondNode.GetDataDir())

	cfg, err = config.LoadConfigFromDisk(relayNode.GetDataDir())
	a.NoError(err)
	const catchpointInterval = 16
	cfg.CatchpointInterval = catchpointInterval
	cfg.Archival = false                 // make it explicit non-archival
	cfg.MaxBlockHistoryLookback = 20000  // to save blocks beyond MaxTxnLife=13
	cfg.CatchpointTracking = 2           // to enable catchpoints on non-archival nodes
	cfg.CatchpointFileHistoryLength = 30 // to store more than 2 default catchpoints
	cfg.TxSyncIntervalSeconds = 200000   // disable txSync
	cfg.SaveToDisk(relayNode.GetDataDir())

	fixture.Start()
	defer fixture.LibGoalFixture.Shutdown()

	client1 := fixture.GetLibGoalClientFromNodeController(primaryNode)
	client2 := fixture.GetLibGoalClientFromNodeController(secondNode)
	relayClient := fixture.GetAlgodClientForController(relayNode)

	wallet1, err := client1.GetUnencryptedWalletHandle()
	a.NoError(err)
	wallet2, err := client2.GetUnencryptedWalletHandle()
	a.NoError(err)
	addrs1, err := client1.ListAddresses(wallet1)
	a.NoError(err)
	addrs2, err := client2.ListAddresses(wallet2)
	a.NoError(err)

	// let the second node have insufficient stake for proposing a block
	tx, err := client2.SendPaymentFromUnencryptedWallet(addrs2[0], addrs1[0], 1000, 4999999999000000, nil)
	a.NoError(err)
	status, err := client1.Status()
	a.NoError(err)
	_, err = fixture.WaitForConfirmedTxn(status.LastRound+100, tx.ID().String())
	a.NoError(err)
	targetCatchpointRound := status.LastRound

	lastCatchpoint := waitForCatchpointGeneration(t, &fixture, relayClient, basics.Round(targetCatchpointRound))

	// let the primary node catchup
	_, err = client1.Catchup(lastCatchpoint, 0)
	a.NoError(err)

	status1, err := client1.Status()
	a.NoError(err)
	targetRound := status1.LastRound + 5

	// Wait for the network to start making progress again
	primaryNodeRestClient := fixture.GetAlgodClientForController(primaryNode)
	_, err = primaryNodeRestClient.WaitForRound(targetRound, 10*catchpointCatchupProtocol.AgreementFilterTimeout)
	a.NoError(err)

	// let the 2nd client send a transaction
	tx, err = client2.SendPaymentFromUnencryptedWallet(addrs2[0], addrs1[0], 1000, 50000, nil)
	a.NoError(err)

	status, err = client2.Status()
	a.NoError(err)
	_, err = fixture.WaitForConfirmedTxn(status.LastRound+50, tx.ID().String())
	a.NoError(err)
}

// TestReadyEndpoint starts a two-node network (derived mainly from TestNodeTxHandlerRestart)
// Lets the primary node have the majority of the stake
// Waits until a catchpoint is created
// Let primary node catch up against the catchpoint, confirm ready endpoint is 503
// Wait the primary node catch up to target round, and confirm ready endpoint is 200
func TestReadyEndpoint(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	a := require.New(fixtures.SynchronizedTest(t))

	consensus := make(config.ConsensusProtocols)
	protoVersion := protocol.ConsensusCurrentVersion
	catchpointCatchupProtocol := config.Consensus[protoVersion]
	applyCatchpointConsensusChanges(&catchpointCatchupProtocol)
	catchpointCatchupProtocol.StateProofInterval = 0
	consensus[protoVersion] = catchpointCatchupProtocol

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "TwoNodes50EachWithRelay.json"))

	// Get primary node
	primaryNode, err := fixture.GetNodeController("Node1")
	a.NoError(err)
	// Get secondary node
	secondNode, err := fixture.GetNodeController("Node2")
	a.NoError(err)
	// Get the relay
	relayNode, err := fixture.GetNodeController("Relay")
	a.NoError(err)

	// prepare its configuration file to set it to generate a catchpoint every 16 rounds.
	cfg, err := config.LoadConfigFromDisk(primaryNode.GetDataDir())
	a.NoError(err)
	cfg.MaxAcctLookback = 2
	cfg.Archival = false
	cfg.TxSyncIntervalSeconds = 200000 // disable txSync

	err = cfg.SaveToDisk(primaryNode.GetDataDir())
	a.NoError(err)
	err = cfg.SaveToDisk(secondNode.GetDataDir())
	a.NoError(err)

	cfg, err = config.LoadConfigFromDisk(relayNode.GetDataDir())
	a.NoError(err)
	const catchpointInterval = 16
	cfg.CatchpointInterval = catchpointInterval
	cfg.Archival = false                 // make it explicit non-archival
	cfg.MaxBlockHistoryLookback = 20000  // to save blocks beyond MaxTxnLife=13
	cfg.CatchpointTracking = 2           // to enable catchpoints on non-archival nodes
	cfg.CatchpointFileHistoryLength = 30 // to store more than 2 default catchpoints
	cfg.TxSyncIntervalSeconds = 200000   // disable txSync
	cfg.SaveToDisk(relayNode.GetDataDir())

	fixture.Start()
	defer fixture.LibGoalFixture.Shutdown()

	client1 := fixture.GetLibGoalClientFromNodeController(primaryNode)
	client2 := fixture.GetLibGoalClientFromNodeController(secondNode)
	relayClient := fixture.GetAlgodClientForController(relayNode)
	wallet1, err := client1.GetUnencryptedWalletHandle()
	a.NoError(err)
	wallet2, err := client2.GetUnencryptedWalletHandle()
	a.NoError(err)
	addrs1, err := client1.ListAddresses(wallet1)
	a.NoError(err)
	addrs2, err := client2.ListAddresses(wallet2)
	a.NoError(err)

	// let the second node have insufficient stake for proposing a block
	tx, err := client2.SendPaymentFromUnencryptedWallet(addrs2[0], addrs1[0], 1000, 4999999999000000, nil)
	a.NoError(err)
	status, err := client1.Status()
	a.NoError(err)
	_, err = fixture.WaitForConfirmedTxn(status.LastRound+100, tx.ID().String())
	a.NoError(err)
	targetCatchpointRound := status.LastRound

	// ensure the catchpoint is created for targetCatchpointRound
	lastCatchpoint := waitForCatchpointGeneration(t, &fixture, relayClient, basics.Round(targetCatchpointRound))

	//////////
	// NOTE //
	//////////
	// THE *REAL* TEST STARTS HERE:
	// We first ensure when a primary node is catching up, it is not ready
	// Then when the primary node is at target round, it should satisfy ready 200 condition

	// let the primary node catchup
	_, err = client1.Catchup(lastCatchpoint, 0)
	a.NoError(err)

	// The primary node is catching up with its previous catchpoint
	// Its status contain a catchpoint it is catching-up against,
	// so it should not be ready, and ready-ness endpoint should 503 err.
	a.Error(fixture.GetAlgodClientForController(primaryNode).ReadyCheck())

	status1, err := client1.Status()
	a.NoError(err)
	targetRound := status1.LastRound + 5

	// Wait for the network to start making progress again
	primaryNodeRestClient := fixture.GetAlgodClientForController(primaryNode)
	_, err = primaryNodeRestClient.WaitForRound(targetRound, 10*catchpointCatchupProtocol.AgreementFilterTimeout)
	a.NoError(err)

	// The primary node has reached the target round,
	// - the sync-time (aka catchup time should be 0.0)
	// - the catchpoint should be empty (len == 0)
	timer := time.NewTimer(100 * time.Second)

	for {
		err = primaryNodeRestClient.ReadyCheck()

		if err != nil {
			select {
			case <-timer.C:
				a.Fail("timeout")
				break
			default:
				time.Sleep(250 * time.Millisecond)
				continue
			}
		}

		status1, err = client1.Status()
		a.NoError(err)
		a.Equal(status1.CatchupTime, int64(0))
		a.Empty(status1.Catchpoint)
		break
	}
}

// TestNodeTxSyncRestart starts a two-node and one relay network
// Waits until a catchpoint is created
// Lets the primary node have the majority of the stake
// Stops the primary node to miss the next transaction
// Sends a transaction from the second node
// Starts the primary node, and immediately after start the catchup
// The transaction will be confirmed only when the TxSync of the pools passes the transaction to the primary node
func TestNodeTxSyncRestart(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	a := require.New(fixtures.SynchronizedTest(t))

	consensus := make(config.ConsensusProtocols)
	protoVersion := protocol.ConsensusCurrentVersion
	catchpointCatchupProtocol := config.Consensus[protoVersion]
	prevMaxTxnLife := catchpointCatchupProtocol.MaxTxnLife
	applyCatchpointConsensusChanges(&catchpointCatchupProtocol)
	catchpointCatchupProtocol.MaxTxnLife = prevMaxTxnLife
	catchpointCatchupProtocol.StateProofInterval = 0
	consensus[protoVersion] = catchpointCatchupProtocol

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "TwoNodes50EachWithRelay.json"))

	// Get primary node
	primaryNode, err := fixture.GetNodeController("Node1")
	a.NoError(err)
	// Get secondary node
	secondNode, err := fixture.GetNodeController("Node2")
	a.NoError(err)
	// Get the relay
	relayNode, err := fixture.GetNodeController("Relay")
	a.NoError(err)

	// prepare it's configuration file to set it to generate a catchpoint every 16 rounds.
	cfg, err := config.LoadConfigFromDisk(primaryNode.GetDataDir())
	a.NoError(err)
	cfg.MaxAcctLookback = 2
	cfg.Archival = false

	// Shorten the txn sync interval so the test can run faster
	cfg.TxSyncIntervalSeconds = 4

	cfg.SaveToDisk(primaryNode.GetDataDir())
	cfg.SaveToDisk(secondNode.GetDataDir())

	cfg, err = config.LoadConfigFromDisk(relayNode.GetDataDir())
	a.NoError(err)
	const catchpointInterval = 16
	cfg.CatchpointInterval = catchpointInterval
	cfg.CatchpointTracking = 2
	cfg.TxSyncIntervalSeconds = 4
	cfg.SaveToDisk(relayNode.GetDataDir())

	fixture.Start()
	defer fixture.LibGoalFixture.Shutdown()

	client1 := fixture.GetLibGoalClientFromNodeController(primaryNode)
	client2 := fixture.GetLibGoalClientFromNodeController(secondNode)
	relayClient := fixture.GetAlgodClientForController(relayNode)
	wallet1, err := client1.GetUnencryptedWalletHandle()
	a.NoError(err)
	wallet2, err := client2.GetUnencryptedWalletHandle()
	a.NoError(err)
	addrs1, err := client1.ListAddresses(wallet1)
	a.NoError(err)
	addrs2, err := client2.ListAddresses(wallet2)
	a.NoError(err)

	// let the second node have insufficient stake for proposing a block
	tx, err := client2.SendPaymentFromUnencryptedWallet(addrs2[0], addrs1[0], 1000, 4999999999000000, nil)
	a.NoError(err)
	status, err := client1.Status()
	a.NoError(err)
	_, err = fixture.WaitForConfirmedTxn(status.LastRound+100, tx.ID().String())
	a.NoError(err)
	targetCatchpointRound := status.LastRound

	// ensure the catchpoint is created for targetCatchpointRound
	lastCatchpoint := waitForCatchpointGeneration(t, &fixture, relayClient, basics.Round(targetCatchpointRound))

	// stop the primary node
	client1.FullStop()

	// let the 2nd client send a transaction
	tx, err = client2.SendPaymentFromUnencryptedWallet(addrs2[0], addrs1[0], 1000, 50000, nil)
	a.NoError(err)

	// now that the primary missed the transaction, start it, and let it catchup
	_, err = fixture.StartNode(primaryNode.GetDataDir())
	a.NoError(err)
	// let the primary node catchup
	_, err = client1.Catchup(lastCatchpoint, 0)
	a.NoError(err)

	// the transaction should not be confirmed yet
	_, err = fixture.WaitForConfirmedTxn(0, tx.ID().String())
	a.Error(err)

	// Wait for the catchup
	for t := 0; t < 10; t++ {
		status1, err := client1.Status()
		a.NoError(err)
		status2, err := client2.Status()
		a.NoError(err)

		if status1.LastRound+1 >= status2.LastRound {
			// if the primary node is within 1 round of the secondary node, then it has
			// caught up
			break
		}
		time.Sleep(catchpointCatchupProtocol.AgreementFilterTimeout)
	}

	status, err = client2.Status()
	a.NoError(err)
	_, err = fixture.WaitForConfirmedTxn(status.LastRound+50, tx.ID().String())
	a.NoError(err)
}
