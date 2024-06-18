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

package rpcs

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type mockUnicastPeer struct {
	responseTopics network.Topics
	outMsg         network.OutgoingMessage
}

func (mup *mockUnicastPeer) GetAddress() string {
	return ""
}
func (mup *mockUnicastPeer) Unicast(ctx context.Context, data []byte, tag protocol.Tag) error {
	return nil
}
func (mup *mockUnicastPeer) Version() string {
	return "2.1"
}

// GetConnectionLatency returns the connection latency between the local node and this peer.
func (mup *mockUnicastPeer) GetConnectionLatency() time.Duration {
	return time.Duration(0)
}
func (mup *mockUnicastPeer) Request(ctx context.Context, tag network.Tag, topics network.Topics) (resp *network.Response, e error) {
	return nil, nil
}
func (mup *mockUnicastPeer) Respond(ctx context.Context, reqMsg network.IncomingMessage, outMsg network.OutgoingMessage) (e error) {
	mup.responseTopics = outMsg.Topics
	mup.outMsg = outMsg
	return nil
}

// TestHandleCatchupReqNegative covers the error reporting in handleCatchupReq
func TestHandleCatchupReqNegative(t *testing.T) {
	partitiontest.PartitionTest(t)

	reqMsg := network.IncomingMessage{
		Sender: &mockUnicastPeer{},
		Data:   nil, // topics
	}
	ls := BlockService{
		ledger: nil,
		log:    logging.TestingLog(t),
	}

	// case where topics is nil
	ls.handleCatchupReq(context.Background(), reqMsg)
	respTopics := reqMsg.Sender.(*mockUnicastPeer).responseTopics
	val, found := respTopics.GetValue(network.ErrorKey)
	require.Equal(t, true, found)
	require.Equal(t, "UnmarshallTopics: could not read the number of topics", string(val))

	// case where round number is missing
	reqTopics := network.Topics{}
	reqMsg.Data = reqTopics.MarshallTopics()
	ls.handleCatchupReq(context.Background(), reqMsg)
	respTopics = reqMsg.Sender.(*mockUnicastPeer).responseTopics

	val, found = respTopics.GetValue(network.ErrorKey)
	require.Equal(t, true, found)
	require.Equal(t, noRoundNumberErrMsg, string(val))

	// case where data type is missing
	roundNumberData := make([]byte, 0)
	reqTopics = network.Topics{network.MakeTopic(RoundKey, roundNumberData)}
	reqMsg.Data = reqTopics.MarshallTopics()
	ls.handleCatchupReq(context.Background(), reqMsg)
	respTopics = reqMsg.Sender.(*mockUnicastPeer).responseTopics

	val, found = respTopics.GetValue(network.ErrorKey)
	require.Equal(t, true, found)
	require.Equal(t, noDataTypeErrMsg, string(val))

	// case where round number is corrupted
	roundNumberData = make([]byte, 0)
	reqTopics = network.Topics{network.MakeTopic(RoundKey, roundNumberData),
		network.MakeTopic(RequestDataTypeKey, []byte(BlockAndCertValue)),
	}
	reqMsg.Data = reqTopics.MarshallTopics()
	ls.handleCatchupReq(context.Background(), reqMsg)
	respTopics = reqMsg.Sender.(*mockUnicastPeer).responseTopics

	val, found = respTopics.GetValue(network.ErrorKey)
	require.Equal(t, true, found)
	require.Equal(t, roundNumberParseErrMsg, string(val))
}

// TestRedirectFallbackEndpoints tests the case when the block service falls back to another from
// BlockServiceCustomFallbackEndpoints in the absence of a given block.
func TestRedirectFallbackEndpoints(t *testing.T) {
	partitiontest.PartitionTest(t)

	log := logging.TestingLog(t)

	ledger1 := makeLedger(t, "l1")
	defer ledger1.Close()
	ledger2 := makeLedger(t, "l2")
	defer ledger2.Close()
	addBlock(t, ledger1)
	addBlock(t, ledger2)
	addBlock(t, ledger2)

	net1 := &httpTestPeerSource{}
	net2 := &httpTestPeerSource{}

	nodeA := &basicRPCNode{}
	nodeB := &basicRPCNode{}
	nodeA.start()
	defer nodeA.stop()
	nodeB.start()
	defer nodeB.stop()

	config := config.GetDefaultLocal()
	// Set the first to a bad address, the second to self, and the third to the one that has the block.
	// If RR is right, should succeed.
	config.BlockServiceCustomFallbackEndpoints = fmt.Sprintf("://badaddress,%s,%s", nodeA.rootURL(), nodeB.rootURL())

	bs1 := MakeBlockService(log, config, ledger1, net1, "test-genesis-ID")
	bs2 := MakeBlockService(log, config, ledger2, net2, "test-genesis-ID")

	nodeA.RegisterHTTPHandler(BlockServiceBlockPath, bs1)
	nodeB.RegisterHTTPHandler(BlockServiceBlockPath, bs2)

	parsedURL, err := network.ParseHostOrURL(nodeA.rootURL())
	require.NoError(t, err)

	client := http.Client{}

	ctx := context.Background()
	parsedURL.Path = FormatBlockQuery(uint64(2), parsedURL.Path, net1)
	parsedURL.Path = strings.Replace(parsedURL.Path, "{genesisID}", "test-genesis-ID", 1)
	blockURL := parsedURL.String()
	request, err := http.NewRequest("GET", blockURL, nil)
	require.NoError(t, err)
	requestCtx, requestCancel := context.WithTimeout(ctx, time.Duration(config.CatchupHTTPBlockFetchTimeoutSec)*time.Second)
	defer requestCancel()
	request = request.WithContext(requestCtx)
	network.SetUserAgentHeader(request.Header)
	response, err := client.Do(request)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, response.StatusCode)
	bodyData, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NotEqual(t, 0, len(bodyData))
}

// TestBlockServiceShutdown tests that the block service is shutting down correctly.
func TestBlockServiceShutdown(t *testing.T) {
	partitiontest.PartitionTest(t)

	log := logging.TestingLog(t)

	ledger1 := makeLedger(t, "l1")
	addBlock(t, ledger1)

	net1 := &httpTestPeerSource{}

	config := config.GetDefaultLocal()
	bs1 := MakeBlockService(log, config, ledger1, net1, "test-genesis-ID")
	bs1.Start()

	nodeA := &basicRPCNode{}

	nodeA.RegisterHTTPHandler(BlockServiceBlockPath, bs1)
	nodeA.start()
	defer nodeA.stop()

	parsedURL, err := network.ParseHostOrURL(nodeA.rootURL())
	require.NoError(t, err)

	client := http.Client{}

	ctx := context.Background()
	parsedURL.Path = FormatBlockQuery(uint64(1), parsedURL.Path, net1)
	parsedURL.Path = strings.Replace(parsedURL.Path, "{genesisID}", "test-genesis-ID", 1)
	blockURL := parsedURL.String()
	request, err := http.NewRequest("GET", blockURL, nil)
	require.NoError(t, err)
	requestCtx, requestCancel := context.WithTimeout(ctx, time.Duration(config.CatchupHTTPBlockFetchTimeoutSec)*time.Second)
	defer requestCancel()
	request = request.WithContext(requestCtx)
	network.SetUserAgentHeader(request.Header)

	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		client.Do(request)
	}()

	bs1.Stop()
	ledger1.Close()

	<-requestDone
}

// TestRedirectOnFullCapacity tests the case when the block service
// fallback to another because its memory use is at capacity
func TestRedirectOnFullCapacity(t *testing.T) {
	partitiontest.PartitionTest(t)

	log1 := logging.TestingLog(t)
	logBuffer1 := bytes.NewBuffer(nil)
	log1.SetOutput(logBuffer1)

	log2 := logging.TestingLog(t)
	logBuffer2 := bytes.NewBuffer(nil)
	log2.SetOutput(logBuffer2)

	ledger1 := makeLedger(t, "l1")
	defer ledger1.Close()
	ledger2 := makeLedger(t, "l2")
	defer ledger2.Close()
	addBlock(t, ledger1)
	l1Block2Ts := addBlock(t, ledger1)
	addBlock(t, ledger2)
	l2Block2Ts := addBlock(t, ledger2)
	require.NotEqual(t, l1Block2Ts, l2Block2Ts)

	net1 := &httpTestPeerSource{}
	net2 := &httpTestPeerSource{}

	nodeA := &basicRPCNode{}
	nodeB := &basicRPCNode{}
	nodeA.start()
	defer nodeA.stop()
	nodeB.start()
	defer nodeB.stop()

	configWithRedirects := config.GetDefaultLocal()

	configWithRedirects.BlockServiceCustomFallbackEndpoints = nodeB.rootURL()

	bs1 := MakeBlockService(log1, configWithRedirects, ledger1, net1, "test-genesis-ID")

	// config with no redirects
	configNoRedirects := config.GetDefaultLocal()
	configNoRedirects.BlockServiceCustomFallbackEndpoints = ""

	bs2 := MakeBlockService(log2, configNoRedirects, ledger2, net2, "test-genesis-ID")
	// set the memory cap so that it can serve only 1 block at a time
	bs1.memoryCap = 250
	bs2.memoryCap = 250

	nodeA.RegisterHTTPHandler(BlockServiceBlockPath, bs1)

	nodeB.RegisterHTTPHandler(BlockServiceBlockPath, bs2)

	parsedURL, err := network.ParseHostOrURL(nodeA.rootURL())
	require.NoError(t, err)

	client := http.Client{}

	parsedURL.Path = FormatBlockQuery(uint64(2), parsedURL.Path, net1)
	parsedURL.Path = strings.Replace(parsedURL.Path, "{genesisID}", "test-genesis-ID", 1)
	blockURL := parsedURL.String()
	request, err := http.NewRequest("GET", blockURL, nil)
	require.NoError(t, err)
	network.SetUserAgentHeader(request.Header)

	var responses1, responses2, responses3, responses4 *http.Response
	var blk bookkeeping.Block
	var l2Failed bool
	xDone := 1000
	// Keep on sending 4 simultanious requests to the first node, to force it to redirect to node 2
	// then check the timestamp from the block header to confirm the redirection took place
	var x int
forloop:
	for ; x < xDone; x++ {
		wg := sync.WaitGroup{}
		wg.Add(4)
		go func() {
			defer wg.Done()
			responses1, _ = client.Do(request)
		}()
		go func() {
			defer wg.Done()
			responses2, _ = client.Do(request)
		}()
		go func() {
			defer wg.Done()
			responses3, _ = client.Do(request)
		}()
		go func() {
			defer wg.Done()
			responses4, _ = client.Do(request)
		}()

		wg.Wait()
		responses := [4]*http.Response{responses1, responses2, responses3, responses4}
		for p := 0; p < 4; p++ {
			if responses[p] == nil {
				continue
			}
			if responses[p].StatusCode == http.StatusServiceUnavailable {
				l2Failed = true
				require.Equal(t, "3", responses[p].Header["Retry-After"][0])
				continue
			}
			// parse the block to get the header timestamp
			// timestamp is needed to know which node served the block
			require.Equal(t, http.StatusOK, responses[p].StatusCode)
			bodyData, err := io.ReadAll(responses[p].Body)
			require.NoError(t, err)
			require.NotEqual(t, 0, len(bodyData))
			var blkCert PreEncodedBlockCert
			err = protocol.DecodeReflect(bodyData, &blkCert)
			require.NoError(t, err)
			err = protocol.Decode(blkCert.Block, &blk)
			require.NoError(t, err)
			if blk.TimeStamp == l2Block2Ts && l2Failed {
				break forloop
			}
		}
	}
	require.Less(t, x, xDone)
	// check if redirection happened
	require.Equal(t, blk.TimeStamp, l2Block2Ts)
	// check if node 2 was also overwhelmed and responded with retry-after, since it cannod redirect
	require.True(t, l2Failed)

	// First node redirects, does not return retry
	require.True(t, strings.Contains(logBuffer1.String(), "redirectRequest: redirected block request to"))
	require.False(t, strings.Contains(logBuffer1.String(), "ServeHTTP: returned retry-after: block service memory over capacity"))

	// Second node cannot redirect, it returns retry-after when over capacity
	require.False(t, strings.Contains(logBuffer2.String(), "redirectRequest: redirected block request to"))
	require.True(t, strings.Contains(logBuffer2.String(), "ServeHTTP: returned retry-after: block service memory over capacity"))
}

// TestWsBlockLimiting ensures that limits are applied correctly on the websocket side of the service
func TestWsBlockLimiting(t *testing.T) {
	partitiontest.PartitionTest(t)

	log := logging.TestingLog(t)
	logBuffer := bytes.NewBuffer(nil)
	log.SetOutput(logBuffer)

	ledger := makeLedger(t, "l1")
	defer ledger.Close()
	addBlock(t, ledger)
	addBlock(t, ledger)

	net1 := &httpTestPeerSource{}

	config := config.GetDefaultLocal()
	bs1 := MakeBlockService(log, config, ledger, net1, "test-genesis-ID")
	// set the memory cap so that it can serve only 1 block at a time
	bs1.memoryCap = 250

	peer := mockUnicastPeer{}
	reqMsg := network.IncomingMessage{
		Sender: &peer,
		Tag:    protocol.Tag("UE"),
	}
	roundBin := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(roundBin, uint64(2))
	topics := network.Topics{
		network.MakeTopic(RequestDataTypeKey,
			[]byte(BlockAndCertValue)),
		network.MakeTopic(
			RoundKey,
			roundBin),
	}
	reqMsg.Data = topics.MarshallTopics()
	require.Zero(t, bs1.wsMemoryUsed.Load())
	bs1.handleCatchupReq(context.Background(), reqMsg)
	// We should have received the message into the mock peer and the block service should have memoryUsed > 0
	data, found := peer.responseTopics.GetValue(BlockDataKey)
	require.True(t, found)
	blk, _, err := ledger.EncodedBlockCert(basics.Round(2))
	require.NoError(t, err)
	require.Equal(t, data, blk)
	require.Positive(t, bs1.wsMemoryUsed.Load())

	// Before making a new request save the callback since the new failed message will overwrite it in the mock peer
	callback := peer.outMsg.OnRelease

	// Now we should be over the max and the block service should not return a block
	// and should return an error instead
	bs1.handleCatchupReq(context.Background(), reqMsg)
	_, found = peer.responseTopics.GetValue(network.ErrorKey)
	require.True(t, found)

	// Now call the callback to free up memUsed
	require.Nil(t, peer.outMsg.OnRelease)
	callback()
	require.Zero(t, bs1.wsMemoryUsed.Load())
}

// TestRedirectExceptions tests exception cases:
// - the case when the peer is not a valid http peer
// - the case when the block service keeps redirecting and cannot get a block
func TestRedirectExceptions(t *testing.T) {
	partitiontest.PartitionTest(t)

	log1 := logging.TestingLog(t)
	log2 := logging.TestingLog(t)

	ledger1 := makeLedger(t, "l1")
	ledger2 := makeLedger(t, "l2")
	defer ledger1.Close()
	defer ledger2.Close()
	addBlock(t, ledger1)

	net1 := &httpTestPeerSource{}
	net2 := &httpTestPeerSource{}

	nodeA := &basicRPCNode{}
	nodeB := &basicRPCNode{}
	nodeA.start()
	defer nodeA.stop()
	nodeB.start()
	defer nodeB.stop()

	configInvalidRedirects := config.GetDefaultLocal()
	configInvalidRedirects.BlockServiceCustomFallbackEndpoints = "badAddress"

	configWithRedirectToSelf := config.GetDefaultLocal()
	configWithRedirectToSelf.BlockServiceCustomFallbackEndpoints = nodeB.rootURL()

	bs1 := MakeBlockService(log1, configInvalidRedirects, ledger1, net1, "{genesisID}")
	bs2 := MakeBlockService(log2, configWithRedirectToSelf, ledger2, net2, "{genesisID}")

	nodeA.RegisterHTTPHandler(BlockServiceBlockPath, bs1)
	nodeB.RegisterHTTPHandler(BlockServiceBlockPath, bs2)

	parsedURL, err := network.ParseHostOrURL(nodeA.rootURL())
	require.NoError(t, err)

	client := http.Client{}

	ctx := context.Background()
	parsedURL.Path = FormatBlockQuery(uint64(2), parsedURL.Path, net1)
	blockURL := parsedURL.String()
	request, err := http.NewRequest("GET", blockURL, nil)
	require.NoError(t, err)
	requestCtx, requestCancel := context.WithTimeout(ctx, time.Duration(configInvalidRedirects.CatchupHTTPBlockFetchTimeoutSec)*time.Second)
	defer requestCancel()
	request = request.WithContext(requestCtx)
	network.SetUserAgentHeader(request.Header)

	response, err := client.Do(request)
	require.NoError(t, err)
	require.Equal(t, response.StatusCode, http.StatusNotFound)

	parsedURLNodeB, err := network.ParseHostOrURL(nodeB.rootURL())
	require.NoError(t, err)

	parsedURLNodeB.Path = FormatBlockQuery(uint64(4), parsedURLNodeB.Path, net2)
	blockURLNodeB := parsedURLNodeB.String()
	requestNodeB, err := http.NewRequest("GET", blockURLNodeB, nil)
	_, err = client.Do(requestNodeB)

	require.Error(t, err)
	require.Contains(t, err.Error(), "stopped after 10 redirects")
}

var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var sinkAddr = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}

func makeLedger(t *testing.T, namePostfix string) *data.Ledger {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	genesis := make(map[basics.Address]basics.AccountData)
	genesis[sinkAddr] = basics.AccountData{
		Status:     basics.Online,
		MicroAlgos: basics.MicroAlgos{Raw: proto.MinBalance * 2000000},
	}
	genesis[poolAddr] = basics.AccountData{
		Status:     basics.Online,
		MicroAlgos: basics.MicroAlgos{Raw: proto.MinBalance * 2000000},
	}

	log := logging.TestingLog(t)
	genBal := bookkeeping.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	genHash := crypto.Digest{0x42}
	cfg := config.GetDefaultLocal()
	const inMem = true

	prefix := t.Name() + namePostfix
	ledger, err := data.LoadLedger(
		log, prefix, inMem, protocol.ConsensusCurrentVersion, genBal, "", genHash,
		nil, cfg,
	)
	require.NoError(t, err)
	return ledger
}

func addBlock(t *testing.T, ledger *data.Ledger) (timestamp int64) {
	blk, err := ledger.Block(ledger.LastRound())
	require.NoError(t, err)
	blk.BlockHeader.Round++
	blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100000 * 1000)
	blk.TxnCommitments, err = blk.PaysetCommit()
	require.NoError(t, err)

	var cert agreement.Certificate
	cert.Proposal.BlockDigest = blk.Digest()

	err = ledger.AddBlock(blk, cert)
	require.NoError(t, err)

	hdr, err := ledger.BlockHdr(blk.BlockHeader.Round)
	require.NoError(t, err)
	require.Equal(t, blk.BlockHeader, hdr)
	return blk.BlockHeader.TimeStamp
}

func TestErrMemoryAtCapacity(t *testing.T) {
	partitiontest.PartitionTest(t)

	macError := errMemoryAtCapacity{capacity: uint64(100), used: uint64(110)}
	errStr := macError.Error()
	require.Equal(t, "block service memory over capacity: 110 / 100", errStr)
}
