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

package catchup

import (
	"fmt"
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

func TestBasicCatchpointCatchup(t *testing.T) {
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
	targetRound := uint64(37)
	primaryNodeRestClient := fixture.GetAlgodClientForController(primaryNode)
	primaryNodeRestClient.SetAPIVersionAffinity(algodclient.APIVersionV2)
	log.Infof("Building ledger history..")
	for {
		err = fixture.ClientWaitForRound(primaryNodeRestClient, currentRound, 45000*time.Millisecond)
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
	targetRound = uint64(1)
	log.Infof("Second node catching up to round 1")
	for {
		err = fixture.ClientWaitForRound(secondNodeRestClient, currentRound, 10*time.Second)
		a.NoError(err)
		if targetRound <= currentRound {
			break
		}
		currentRound++

	}
	log.Infof(" - done catching up!\n")

	primaryNodeStatus, err := primaryNodeRestClient.Status()
	a.NoError(err)
	a.NotNil(primaryNodeStatus.LastCatchpoint)
	log.Infof("primary node latest catchpoint - %s!\n", *primaryNodeStatus.LastCatchpoint)
	secondNodeRestClient.Catchup(*primaryNodeStatus.LastCatchpoint)

	currentRound = primaryNodeStatus.LastRound
	targetRound = currentRound + 1
	log.Infof("Second node catching up to round 36")
	for {
		err = fixture.ClientWaitForRound(secondNodeRestClient, currentRound, 10*time.Second)
		a.NoError(err)
		if targetRound <= currentRound {
			break
		}
		currentRound++
	}
	log.Infof("done catching up!\n")

	secondNode.StopAlgod()
	primaryNode.StopAlgod()
}
