// Copyright (C) 2019-2022 Algorand, Inc.
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
	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	algodclient "github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type nodeExitErrorCollector struct {
	errors   []error
	messages []string
	mu       deadlock.Mutex
	t        fixtures.TestingTB
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
		require.NoError(ec.t, err, ec.messages[i])
	}
}

// awaitCatchpointCreation attempts catchpoint retrieval with retries when the catchpoint is not yet available.
func awaitCatchpointCreation(client algodclient.RestClient, fixture fixtures.RestClientFixture, roundWaitCount uint8) (generatedV2.NodeStatusResponse, error) {
	s, err := client.Status()
	if err != nil {
		return generatedV2.NodeStatusResponse{}, err
	}

	if len(*s.LastCatchpoint) > 0 {
		return s, nil

	}

	if roundWaitCount-1 > 0 {
		err = fixture.ClientWaitForRound(client, s.LastRound+1, 10*time.Second)
		if err != nil {
			return generatedV2.NodeStatusResponse{}, err
		}

		return awaitCatchpointCreation(client, fixture, roundWaitCount-1)
	}

	return generatedV2.NodeStatusResponse{}, fmt.Errorf("No catchpoint exists")
}

func TestBasicCatchpointCatchup(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	a := require.New(fixtures.SynchronizedTest(t))
	log := logging.TestingLog(t)

	// Overview of this test:
	// Start a two-node network (primary has 100%, secondary has 0%)
	// Nodes are having a consensus allowing balances history of 32 rounds and transaction history of 33 rounds.
	// Let it run for 37 rounds.
	// create a web proxy, and connect it to the primary node, blocking all requests for round #1. ( and allowing everything else )
	// start a secondary node, and instuct it to catchpoint catchup from the proxy. ( which would be for round 36 )
	// wait until the clone node cought up, skipping the "impossible" hole of round #1.

	consensus := make(config.ConsensusProtocols)
	const consensusCatchpointCatchupTestProtocol = protocol.ConsensusVersion("catchpointtestingprotocol")
	catchpointCatchupProtocol := config.Consensus[protocol.ConsensusCurrentVersion]
	catchpointCatchupProtocol.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	// MaxBalLookback  =  2 x SeedRefreshInterval x SeedLookback
	// ref. https://github.com/algorandfoundation/specs/blob/master/dev/abft.md
	catchpointCatchupProtocol.SeedLookback = 2
	catchpointCatchupProtocol.SeedRefreshInterval = 8
	catchpointCatchupProtocol.MaxBalLookback = 2 * catchpointCatchupProtocol.SeedLookback * catchpointCatchupProtocol.SeedRefreshInterval // 32
	catchpointCatchupProtocol.MaxTxnLife = 33
	catchpointCatchupProtocol.CatchpointLookback = catchpointCatchupProtocol.MaxBalLookback
	catchpointCatchupProtocol.EnableOnlineAccountCatchpoints = true

	if runtime.GOARCH == "amd64" {
		// amd64 platforms are generally quite capable, so accelerate the round times to make the test run faster.
		catchpointCatchupProtocol.AgreementFilterTimeoutPeriod0 = 1 * time.Second
		catchpointCatchupProtocol.AgreementFilterTimeout = 1 * time.Second
	}

	consensus[consensusCatchpointCatchupTestProtocol] = catchpointCatchupProtocol

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)

	errorsCollector := nodeExitErrorCollector{t: fixtures.SynchronizedTest(t)}
	defer errorsCollector.Print()

	fixture.SetupNoStart(t, filepath.Join("nettemplates", "CatchpointCatchupTestNetwork.json"))

	// Get primary node
	primaryNode, err := fixture.GetNodeController("Primary")
	a.NoError(err)
	// Get secondary node
	secondNode, err := fixture.GetNodeController("Node")
	a.NoError(err)

	// prepare it's configuration file to set it to generate a catchpoint every 4 rounds.
	cfg, err := config.LoadConfigFromDisk(primaryNode.GetDataDir())
	a.NoError(err)
	cfg.CatchpointInterval = 4
	cfg.MaxAcctLookback = 2
	cfg.SaveToDisk(primaryNode.GetDataDir())
	cfg.Archival = false
	cfg.NetAddress = ""
	cfg.EnableLedgerService = false
	cfg.EnableBlockService = false
	cfg.SaveToDisk(secondNode.GetDataDir())

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

	// Let the network make some progress
	currentRound := uint64(1)
	const targetRound = uint64(37)
	primaryNodeRestClient := fixture.GetAlgodClientForController(primaryNode)
	primaryNodeRestClient.SetAPIVersionAffinity(algodclient.APIVersionV2)
	log.Infof("Building ledger history..")
	for {
		err = fixture.ClientWaitForRound(primaryNodeRestClient, currentRound, 45*time.Second)
		a.NoError(err)
		if targetRound <= currentRound {
			break
		}
		currentRound++

	}
	log.Infof("done building!\n")
	primaryListeningAddress, err := primaryNode.GetListeningAddress()
	a.NoError(err)

	wp, err := fixtures.MakeWebProxy(primaryListeningAddress, func(response http.ResponseWriter, request *http.Request, next http.HandlerFunc) {
		// prevent requests for block #2 to go through.
		if request.URL.String() == "/v1/test-v1/block/2" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		next(response, request)
	})
	a.NoError(err)
	defer wp.Close()

	log.Infof("web proxy listens at %s\n", wp.GetListenAddress())
	// start the second node
	_, err = secondNode.StartAlgod(nodecontrol.AlgodStartArgs{
		PeerAddress:       wp.GetListenAddress(),
		ListenIP:          "",
		RedirectOutput:    true,
		RunUnderHost:      false,
		TelemetryOverride: "",
		ExitErrorCallback: errorsCollector.nodeExitWithError,
	})
	a.NoError(err)

	// wait until node is caught up.
	secondNodeRestClient := fixture.GetAlgodClientForController(secondNode)

	currentRound = uint64(1)
	secondNodeTargetRound := uint64(1)
	log.Infof("Second node catching up to round 1")
	for {
		err = fixture.ClientWaitForRound(secondNodeRestClient, currentRound, 10*time.Second)
		a.NoError(err)
		if secondNodeTargetRound <= currentRound {
			break
		}
		currentRound++

	}
	log.Infof(" - done catching up!\n")

	status, err := awaitCatchpointCreation(primaryNodeRestClient, fixture, 3)
	a.NoError(err)

	log.Infof("primary node latest catchpoint - %s!\n", status.LastCatchpoint)
	_, err = secondNodeRestClient.Catchup(*status.LastCatchpoint)
	a.NoError(err)

	currentRound = status.LastRound
	a.LessOrEqual(targetRound, currentRound)
	fixtureTargetRound := targetRound + 1
	log.Infof("Second node catching up to round %v", currentRound)
	for {
		err = fixture.ClientWaitForRound(secondNodeRestClient, currentRound, 10*time.Second)
		a.NoError(err)
		if fixtureTargetRound <= currentRound {
			break
		}
		currentRound++
	}
	log.Infof("done catching up!\n")

	secondNode.StopAlgod()
	primaryNode.StopAlgod()
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
		{4, false, true},
		{0, true, false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("CatchpointInterval_%v/Archival_%v", tc.catchpointInterval, tc.archival), func(t *testing.T) {
			a := require.New(fixtures.SynchronizedTest(t))
			log := logging.TestingLog(t)

			consensus := make(config.ConsensusProtocols)
			const consensusCatchpointCatchupTestProtocol = protocol.ConsensusVersion("catchpointtestingprotocol")
			catchpointCatchupProtocol := config.Consensus[protocol.ConsensusCurrentVersion]
			catchpointCatchupProtocol.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
			// MaxBalLookback  =  2 x SeedRefreshInterval x SeedLookback
			// ref. https://github.com/algorandfoundation/specs/blob/master/dev/abft.md
			catchpointCatchupProtocol.SeedLookback = 2
			catchpointCatchupProtocol.SeedRefreshInterval = 8
			catchpointCatchupProtocol.MaxBalLookback = 2 * catchpointCatchupProtocol.SeedLookback * catchpointCatchupProtocol.SeedRefreshInterval // 32
			catchpointCatchupProtocol.MaxTxnLife = 33
			catchpointCatchupProtocol.CatchpointLookback = catchpointCatchupProtocol.MaxBalLookback
			catchpointCatchupProtocol.EnableOnlineAccountCatchpoints = true

			if runtime.GOARCH == "amd64" {
				// amd64 platforms are generally quite capable, so accelerate the round times to make the test run faster.
				catchpointCatchupProtocol.AgreementFilterTimeoutPeriod0 = 1 * time.Second
				catchpointCatchupProtocol.AgreementFilterTimeout = 1 * time.Second
			}

			consensus[consensusCatchpointCatchupTestProtocol] = catchpointCatchupProtocol

			var fixture fixtures.RestClientFixture
			fixture.SetConsensus(consensus)

			errorsCollector := nodeExitErrorCollector{t: fixtures.SynchronizedTest(t)}
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

			// Let the network make some progress
			currentRound := uint64(1)
			targetRound := uint64(41)
			primaryNodeRestClient := fixture.GetAlgodClientForController(primaryNode)
			primaryNodeRestClient.SetAPIVersionAffinity(algodclient.APIVersionV2)
			log.Infof("Building ledger history..")
			for {
				err = fixture.ClientWaitForRound(primaryNodeRestClient, currentRound, 45*time.Second)
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
			primaryNode.StopAlgod()
		})
	}
}
