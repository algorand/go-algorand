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
	"context"
	"errors"
	"fmt"
	"math/rand"
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
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestUGetBlockWs tests the universal fetcher ws peer case
func TestUGetBlockWs(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	var noBlockErr noBlockForRoundError
	require.ErrorAs(t, err, &noBlockErr)
	require.Equal(t, next+1, err.(noBlockForRoundError).round)
	require.Equal(t, next, err.(noBlockForRoundError).latest)
	require.Nil(t, block)
	require.Nil(t, cert)
	require.Equal(t, int64(duration), int64(0))
}

// TestUGetBlockHTTP tests the universal fetcher http peer case
func TestUGetBlockHTTP(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()

	ledger, next, b, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}

	blockServiceConfig := config.GetDefaultLocal()
	blockServiceConfig.EnableBlockService = true

	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, ledger, net, "test genesisID")

	nodeA := basicRPCNode{}
	ls.RegisterHandlers(&nodeA)
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

	var noBlockErr noBlockForRoundError
	require.ErrorAs(t, err, &noBlockErr)
	require.Equal(t, next+1, err.(noBlockForRoundError).round)
	require.Equal(t, next, err.(noBlockForRoundError).latest)
	require.Contains(t, err.Error(), "no block available for given round")
	require.Nil(t, block)
	require.Nil(t, cert)
	require.Equal(t, int64(duration), int64(0))
}

// TestUGetBlockUnsupported tests the handling of an unsupported peer
func TestUGetBlockUnsupported(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

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
	var wcfpe errWrongCertFromPeer
	require.True(t, errors.As(err, &wcfpe))

	// Check for round error
	_, _, err = processBlockBytes(bc, 20, "test")
	var wbfpe errWrongBlockFromPeer
	require.True(t, errors.As(err, &wbfpe))

	// Check for undecodable
	bc[11] = 0
	_, _, err = processBlockBytes(bc, 22, "test")
	var cdbe errCannotDecodeBlock
	require.True(t, errors.As(err, &cdbe))
}

// TestRequestBlockBytesErrors checks the error handling in requestBlockBytes
func TestRequestBlockBytesErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()

	ledger, next, _, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}
	defer ledger.Ledger.Close()

	blockServiceConfig := config.GetDefaultLocal()
	blockServiceConfig.EnableBlockService = true

	net := &httpTestPeerSource{}

	up := makeTestUnicastPeer(net, t)
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, ledger, net, "test genesisID")
	ls.Start()
	defer ls.Stop()

	fetcher := makeUniversalBlockFetcher(logging.TestingLog(t), net, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err = fetcher.fetchBlock(ctx, next, up)
	var wrfe errWsFetcherRequestFailed
	require.ErrorAs(t, err, &wrfe)
	require.Equal(t, "context canceled", err.(errWsFetcherRequestFailed).cause)

	ctx = context.Background()

	responseOverride := network.Response{Topics: network.Topics{network.MakeTopic(rpcs.BlockDataKey, make([]byte, 0))}}
	up = makeTestUnicastPeerWithResponseOverride(net, t, &responseOverride)

	_, _, _, err = fetcher.fetchBlock(ctx, next, up)
	require.ErrorAs(t, err, &wrfe)
	require.Equal(t, "Cert data not found", err.(errWsFetcherRequestFailed).cause)

	responseOverride = network.Response{Topics: network.Topics{network.MakeTopic(rpcs.CertDataKey, make([]byte, 0))}}
	up = makeTestUnicastPeerWithResponseOverride(net, t, &responseOverride)

	_, _, _, err = fetcher.fetchBlock(ctx, next, up)
	require.ErrorAs(t, err, &wrfe)
	require.Equal(t, "Block data not found", err.(errWsFetcherRequestFailed).cause)
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
}

// TestGetBlockBytesHTTPErrors tests the errors reported from getblockBytes for http peer
func TestGetBlockBytesHTTPErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	var hre errHTTPResponse
	require.ErrorAs(t, err, &hre)
	require.Equal(t, "Response body '\x00'", err.(errHTTPResponse).cause)

	ls.exceedLimit = true
	_, _, _, err = fetcher.fetchBlock(context.Background(), 1, net.GetPeers()[0])
	require.ErrorAs(t, err, &hre)
	require.Equal(t, "read limit exceeded", err.(errHTTPResponse).cause)

	ls.status = http.StatusOK
	ls.content = append(ls.content, "undefined")
	_, _, _, err = fetcher.fetchBlock(context.Background(), 1, net.GetPeers()[0])
	var cte errHTTPResponseContentType
	require.ErrorAs(t, err, &cte)
	require.Equal(t, "undefined", err.(errHTTPResponseContentType).contentType)

	ls.status = http.StatusOK
	ls.content = append(ls.content, "undefined2")
	_, _, _, err = fetcher.fetchBlock(context.Background(), 1, net.GetPeers()[0])
	require.ErrorAs(t, err, &cte)
	require.Equal(t, 2, err.(errHTTPResponseContentType).contentTypeCount)
}

type ErrTest struct{}

func (et ErrTest) Error() string {
	return "test"
}

// TestErrorTypes tests the error types are implemented correctly
func TestErrorTypes(t *testing.T) {
	partitiontest.PartitionTest(t)

	err1 := makeErrWrongCertFromPeer(1, 2, "somepeer1")
	require.Equal(t, "processBlockBytes: got wrong cert from peer somepeer1: wanted 1, got 2", err1.Error())

	err2 := makeErrWrongBlockFromPeer(2, 3, "somepeer2")
	require.Equal(t, "processBlockBytes: got wrong block from peer somepeer2: wanted 2, got 3", err2.Error())

	err3 := makeErrCannotDecodeBlock(3, "somepeer3", fmt.Errorf("WrappedError %w", ErrTest{}))
	require.Equal(t, "processBlockBytes: cannot decode block 3 from peer somepeer3: WrappedError test", err3.Error())
	var et ErrTest
	require.True(t, errors.As(err3, &et))

	err4 := makeErrWsFetcherRequestFailed(4, "somepeer4", "somecause1")
	require.Equal(t, "wsFetcherClient(somepeer4).requestBlock(4): Request failed: somecause1", err4.Error())

	err5 := makeErrHTTPResponse(404, "someurl", "somecause2")
	require.Equal(t, "HTTPFetcher.getBlockBytes: error response status code 404 when requesting 'someurl': somecause2", err5.Error())

	err6 := errHTTPResponseContentType{contentTypeCount: 1, contentType: "UNDEFINED"}
	require.Equal(t, "HTTPFetcher.getBlockBytes: invalid content type: UNDEFINED", err6.Error())
}

// Block Request topics request is a handrolled msgpack message with deterministic size. This test ensures that it matches the defined
// constant in protocol
func TestMaxBlockRequestSize(t *testing.T) {
	partitiontest.PartitionTest(t)

	round := rand.Uint64()
	topics := makeBlockRequestTopics(basics.Round(round))
	nonce := rand.Uint64() - 1
	nonceTopic := network.MakeNonceTopic(nonce)
	topics = append(topics, nonceTopic)
	serializedMsg := topics.MarshallTopics()
	require.Equal(t, uint64(len(serializedMsg)), protocol.UniEnsBlockReqTag.MaxMessageSize())

}
