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
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	algodclient "github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func nodeExitWithError(t *testing.T, nc *nodecontrol.NodeController, err error) {
	if err == nil {
		return
	}

	exitError, ok := err.(*exec.ExitError)
	if !ok {
		require.NoError(t, err, "Node at %s has terminated with an error", nc.GetDataDir())
		return
	}
	ws := exitError.Sys().(syscall.WaitStatus)
	exitCode := ws.ExitStatus()

	require.NoError(t, err, "Node at %s has terminated with error code %d", nc.GetDataDir(), exitCode)
}

func TestBasicCatchpointCatchup(t *testing.T) {
	t.Skip("This test requires catchpoint catchup support")
	if testing.Short() {
		t.Skip()
	}
	a := require.New(t)
	log := logging.TestingLog(t)

	if runtime.GOARCH == "amd64" {
		// amd64 platforms are generally quite capable, so exceletate the round times to make the test run faster.
		os.Setenv("ALGOSMALLLAMBDAMSEC", "500")
	}

	// Overview of this test:
	// Start a two-node network (primary has 100%, secondary has 0%)
	// Nodes are having a consensus allowing balances history of 32 rounds and transaction history of 33 rounds.
	// Let it run for 37 rounds.
	// create a web proxy, and connect it to the primary node, blocking all requests for round #1. ( and allowing everything else )
	// start a secondary node, and instuct it to catchpoint catchup from the proxy. ( which would be for round 36 )
	// wait until the clone node cought up, skipping the "impossibe" hole of round #1.

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

	consensus[consensusCatchpointCatchupTestProtocol] = catchpointCatchupProtocol

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	// Give the second node (which starts up last) all the stake so that its proposal always has better credentials,
	// and so that its proposal isn't dropped. Otherwise the test burns 17s to recover. We don't care about stake
	// distribution for catchup so this is fine.
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "CatchpointCatchupTestNetwork.json"))
	//defer fixture.Shutdown()

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
		ExitErrorCallback: func(nc *nodecontrol.NodeController, err error) { nodeExitWithError(t, nc, err) },
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

	wp, err := makeWebProxy(primaryListeningAddress, func(response http.ResponseWriter, request *http.Request, next http.HandlerFunc) {
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
		ExitErrorCallback: func(nc *nodecontrol.NodeController, err error) { nodeExitWithError(t, nc, err) },
	})
	a.NoError(err)

	// wait until node is caught up.
	secondNodeRestClient := fixture.GetAlgodClientForController(secondNode)
	currentRound = uint64(1)
	targetRound = uint64(1)
	log.Infof("Second node catching up to round 1")
	for {
		err = fixture.ClientWaitForRound(secondNodeRestClient, currentRound, 10000*time.Millisecond)
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

	currentRound = uint64(36)
	targetRound = uint64(37)
	log.Infof("Second node catching up to round 36")
	for {
		err = fixture.ClientWaitForRound(secondNodeRestClient, currentRound, 10000*time.Millisecond)
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

type webProxyInterceptFunc func(http.ResponseWriter, *http.Request, http.HandlerFunc)

type webProxy struct {
	server      *http.Server
	listener    net.Listener
	destination string
	intercept   webProxyInterceptFunc
}

func makeWebProxy(destination string, intercept webProxyInterceptFunc) (wp *webProxy, err error) {
	if strings.HasPrefix(destination, "http://") {
		destination = destination[7:]
	}
	wp = &webProxy{
		destination: destination,
		intercept:   intercept,
	}
	wp.server = &http.Server{
		Handler: wp,
	}
	wp.listener, err = net.Listen("tcp", "localhost:")
	if err != nil {
		return nil, err
	}
	go func() {
		wp.server.Serve(wp.listener)
	}()
	return wp, nil
}

func (wp *webProxy) GetListenAddress() string {
	return wp.listener.Addr().String()
}

func (wp *webProxy) Close() {
	// we can't use shutdown, since we have tunneled websocket, which is a hijacked connection
	// that http.Server doens't know how to handle.
	wp.server.Close()
}

func (wp *webProxy) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	//fmt.Printf("incoming request for %v\n", request.URL)
	if wp.intercept == nil {
		wp.Passthrough(response, request)
		return
	}
	wp.intercept(response, request, wp.Passthrough)
}

func (wp *webProxy) Passthrough(response http.ResponseWriter, request *http.Request) {
	client := http.Client{}
	clientRequestURL := *request.URL
	clientRequestURL.Scheme = "http"
	clientRequestURL.Host = wp.destination
	clientRequest, err := http.NewRequest(request.Method, clientRequestURL.String(), request.Body)
	if err != nil {
		fmt.Printf("Passthrough request assembly error %v (%#v)\n", err, clientRequestURL)
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	if request.Header != nil {
		for headerKey, headerValues := range request.Header {
			for _, headerValue := range headerValues {
				clientRequest.Header.Add(headerKey, headerValue)
			}
		}
	}
	clientResponse, err := client.Do(clientRequest)
	if err != nil {
		fmt.Printf("Passthrough request error %v (%v)\n", err, request.URL.String())
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	if clientResponse.Header != nil {
		for headerKey, headerValues := range clientResponse.Header {
			for _, headerValue := range headerValues {
				response.Header().Add(headerKey, headerValue)
			}
		}
	}
	response.WriteHeader(clientResponse.StatusCode)
	ch := make(chan []byte, 10)
	go func(outCh chan []byte) {
		defer close(outCh)
		if clientResponse.Body == nil {
			return
		}
		defer clientResponse.Body.Close()
		for {
			buf := make([]byte, 4096)
			n, err := clientResponse.Body.Read(buf)
			if n > 0 {
				outCh <- buf[:n]
			}
			if err != nil {
				break
			}

		}
	}(ch)
	for bytes := range ch {
		response.Write(bytes)
		if flusher, has := response.(http.Flusher); has {
			flusher.Flush()
		}
	}
}
