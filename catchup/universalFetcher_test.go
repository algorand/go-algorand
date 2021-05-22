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
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

// TestUGetBlockWs tests the universal fetcher ws peer case
func TestUGetBlockWs(t *testing.T) {

	cfg := config.GetDefaultLocal()

	ledger, next, b, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}

	blockServiceConfig := config.GetDefaultLocal()
	blockServiceConfig.EnableBlockService = true

	net := &httpTestPeerSource{}

	up := makeTestUnicastPeer(net, t)
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, ledger, net, "test genesisID")
	ls.Start()

	fetcher := makeUniversalBlockFetcher(logging.TestingLog(t), net, cfg)

	var block *bookkeeping.Block
	var cert *agreement.Certificate
	var duration time.Duration

	block, cert, _, err = fetcher.fetchBlock(context.Background(), next, up)

	require.NoError(t, err)
	require.Equal(t, &b, block)
	require.GreaterOrEqual(t, int64(duration), int64(0))

	block, cert, duration, err = fetcher.fetchBlock(context.Background(), next+1, up)

	require.Error(t, err)
	require.Contains(t, err.Error(), "requested block is not available")
	require.Nil(t, block)
	require.Nil(t, cert)
	require.Equal(t, int64(duration), int64(0))
}

// TestUGetBlockHttp tests the universal fetcher http peer case
func TestUGetBlockHttp(t *testing.T) {

	cfg := config.GetDefaultLocal()

	ledger, next, b, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}

	blockServiceConfig := config.GetDefaultLocal()
	blockServiceConfig.EnableBlockService = true
	blockServiceConfig.EnableBlockServiceFallbackToArchiver = false

	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, ledger, net, "test genesisID")

	nodeA := basicRPCNode{}
	nodeA.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()

	net.addPeer(rootURL)
	fetcher := makeUniversalBlockFetcher(logging.TestingLog(t), net, cfg)

	var block *bookkeeping.Block
	var cert *agreement.Certificate
	var duration time.Duration
	block, cert, duration, err = fetcher.fetchBlock(context.Background(), next, net.GetPeers()[0])

	require.NoError(t, err)
	require.Equal(t, &b, block)
	require.GreaterOrEqual(t, int64(duration), int64(0))

	block, cert, duration, err = fetcher.fetchBlock(context.Background(), next+1, net.GetPeers()[0])

	require.Error(t, errNoBlockForRound, err)
	require.Contains(t, err.Error(), "No block available for given round")
	require.Nil(t, block)
	require.Nil(t, cert)
	require.Equal(t, int64(duration), int64(0))
}

// TestUGetBlockUnsupported tests the handling of an unsupported peer
func TestUGetBlockUnsupported(t *testing.T) {
	fetcher := universalBlockFetcher{}
	peer := ""
	block, cert, duration, err := fetcher.fetchBlock(context.Background(), 1, peer)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fetchBlock: UniversalFetcher only supports HTTPPeer and UnicastPeer")
	require.Nil(t, block)
	require.Nil(t, cert)
	require.Equal(t, int64(duration), int64(0))
}

// TestprocessBlockBytesErrors checks the error handling in processBlockBytes
func TestProcessBlockBytesErrors(t *testing.T) {

	blk := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round: basics.Round(22),
		},
	}

	blkData := protocol.Encode(&blk)
	bc := protocol.EncodeReflect(rpcs.PreEncodedBlockCert{
		Block: blkData,
	})

	// Check for cert error
	_, _, err := processBlockBytes(bc, 22, "test")
	require.Equal(t, err.Error(), "processBlockBytes(22): got wrong cert from peer test: wanted 22, got 0")

	// Check for round error
	_, _, err = processBlockBytes(bc, 20, "test")
	require.Equal(t, err.Error(), "processBlockBytes(20): got wrong block from peer test: wanted 20, got 22")

	// Check for undecodable
	bc[11] = 0
	_, _, err = processBlockBytes(bc, 22, "test")
	require.Equal(t, err.Error(), "processBlockBytes(22): cannot decode block from peer test: Unknown field: rn\x00 at Block")
}

// TestRequestBlockBytesErrors checks the error handling in requestBlockBytes
func TestRequestBlockBytesErrors(t *testing.T) {

	cfg := config.GetDefaultLocal()

	ledger, next, _, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}

	blockServiceConfig := config.GetDefaultLocal()
	blockServiceConfig.EnableBlockService = true

	net := &httpTestPeerSource{}

	up := makeTestUnicastPeer(net, t)
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, ledger, net, "test genesisID")
	ls.Start()

	fetcher := makeUniversalBlockFetcher(logging.TestingLog(t), net, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err = fetcher.fetchBlock(ctx, next, up)
	require.Equal(t, err.Error(), "wsFetcherClient(test).requestBlock(1): Request failed, context canceled")

	ctx = context.Background()

	responseOverride := network.Response{Topics: network.Topics{network.MakeTopic(rpcs.BlockDataKey, make([]byte, 0))}}
	up = makeTestUnicastPeerWithResponseOverride(net, t, &responseOverride)

	_, _, _, err = fetcher.fetchBlock(ctx, next, up)
	require.Equal(t, err.Error(), "wsFetcherClient(test): request failed: cert data not found")

	responseOverride = network.Response{Topics: network.Topics{network.MakeTopic(rpcs.CertDataKey, make([]byte, 0))}}
	up = makeTestUnicastPeerWithResponseOverride(net, t, &responseOverride)

	_, _, _, err = fetcher.fetchBlock(ctx, next, up)
	require.Equal(t, err.Error(), "wsFetcherClient(test): request failed: block data not found")

}

type TestHTTPHandler struct {
	exceedLimit bool
	status      int
	content     []string
}

func (thh *TestHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	for _, c := range thh.content {
		response.Header().Add("Content-Type", c)
	}
	response.WriteHeader(thh.status)
	bytes := make([]byte, 1)
	if thh.exceedLimit {
		bytes = make([]byte, fetcherMaxBlockBytes+1)
	}
	response.Write(bytes)
	return
}

// TestGetBlockBytesHTTPErrors tests the errors reported from getblockBytes for http peer
func TestGetBlockBytesHTTPErrors(t *testing.T) {

	cfg := config.GetDefaultLocal()
	net := &httpTestPeerSource{}

	ls := &TestHTTPHandler{}

	nodeA := basicRPCNode{}
	nodeA.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()

	net.addPeer(rootURL)
	fetcher := makeUniversalBlockFetcher(logging.TestingLog(t), net, cfg)

	ls.status = http.StatusBadRequest
	_, _, _, err := fetcher.fetchBlock(context.Background(), 1, net.GetPeers()[0])
	require.Regexp(t,
		"getBlockBytes error response status code 400 when requesting .* Response body",
		err.Error())

	ls.exceedLimit = true
	_, _, _, err = fetcher.fetchBlock(context.Background(), 1, net.GetPeers()[0])
	require.Regexp(t,
		"getBlockBytes error response status code 400 when requesting .* read limit exceeded",
		err.Error())

	ls.status = http.StatusOK
	ls.content = append(ls.content, "undefined")
	_, _, _, err = fetcher.fetchBlock(context.Background(), 1, net.GetPeers()[0])
	require.Regexp(t,
		"http block fetcher invalid content type 'undefined'",
		err.Error())

	ls.status = http.StatusOK
	ls.content = append(ls.content, "undefined2")
	_, _, _, err = fetcher.fetchBlock(context.Background(), 1, net.GetPeers()[0])
	require.Equal(t, "http block fetcher invalid content type count 2", err.Error())
}
