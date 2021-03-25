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

package rpcs

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

type mockUnicastPeer struct {
	responseTopics network.Topics
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
func (mup *mockUnicastPeer) Request(ctx context.Context, tag network.Tag, topics network.Topics) (resp *network.Response, e error) {
	return nil, nil
}
func (mup *mockUnicastPeer) Respond(ctx context.Context, reqMsg network.IncomingMessage, topics network.Topics) (e error) {
	mup.responseTopics = topics
	return nil
}

// TestHandleCatchupReqNegative covers the error reporting in handleCatchupReq
func TestHandleCatchupReqNegative(t *testing.T) {

	reqMsg := network.IncomingMessage{
		Sender: &mockUnicastPeer{},
		Data:   nil, // topics
	}
	ls := BlockService{
		ledger: nil,
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

// TestRedirectBasic tests the case when the block service redirects the request to elsewhere
func TestRedirectFallbackArchiver(t *testing.T) {
	ledger1 := makeLedger(t, "l1")
	defer ledger1.Close()
	ledger2 := makeLedger(t, "l2")
	defer ledger2.Close()
	addBlock(t, ledger1)
	addBlock(t, ledger2)
	addBlock(t, ledger2)

	net1 := &httpTestPeerSource{}
	net2 := &httpTestPeerSource{}

	config := config.GetDefaultLocal()
	bs1 := MakeBlockService(config, ledger1, net1, "{genesisID}")
	bs2 := MakeBlockService(config, ledger2, net2, "{genesisID}")

	nodeA := &basicRPCNode{}
	nodeB := &basicRPCNode{}

	nodeA.RegisterHTTPHandler(BlockServiceBlockPath, bs1)
	nodeA.start()
	defer nodeA.stop()

	nodeB.RegisterHTTPHandler(BlockServiceBlockPath, bs2)
	nodeB.start()
	defer nodeB.stop()

	net1.addPeer(nodeB.rootURL())

	parsedURL, err := network.ParseHostOrURL(nodeA.rootURL())
	require.NoError(t, err)

	client := http.Client{}

	ctx := context.Background()
 	parsedURL.Path = FormatBlockQuery(uint64(2), parsedURL.Path, net1)
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
}


// TestRedirectBasic tests the case when the block service redirects the request to elsewhere
func TestRedirectFallbackEndpoints(t *testing.T) {
	ledger1 := makeLedger(t, "l1")
	defer ledger1.Close()
	ledger2 := makeLedger(t, "l2")
	defer ledger2.Close()
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
	config.BlockServiceCustomFallbackEndpoints=fmt.Sprintf("://badaddress,%s,%s", nodeA.rootURL(), nodeB.rootURL())
	bs1 := MakeBlockService(config, ledger1, net1, "{genesisID}")
	bs2 := MakeBlockService(config, ledger2, net2, "{genesisID}")

	nodeA.RegisterHTTPHandler(BlockServiceBlockPath, bs1)
	nodeB.RegisterHTTPHandler(BlockServiceBlockPath, bs2)

	parsedURL, err := network.ParseHostOrURL(nodeA.rootURL())
	require.NoError(t, err)

	client := http.Client{}

	ctx := context.Background()
	parsedURL.Path = FormatBlockQuery(uint64(1), parsedURL.Path, net1)
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
}

// TestRedirectExceptions tests exception cases:
// - the case when the peer is not a valid http peer
// - the case when the block service keeps redirecting and cannot get a block
func TestRedirectExceptions(t *testing.T) {
	ledger1 := makeLedger(t, "l1")
	defer ledger1.Close()
	addBlock(t, ledger1)

	net1 := &httpTestPeerSource{}

	config := config.GetDefaultLocal()
	bs1 := MakeBlockService(config, ledger1, net1, "{genesisID}")

	nodeA := &basicRPCNode{}

	nodeA.RegisterHTTPHandler(BlockServiceBlockPath, bs1)
	nodeA.start()
	defer nodeA.stop()

	net1.peers = append(net1.peers, "invalidPeer")

	parsedURL, err := network.ParseHostOrURL(nodeA.rootURL())
	require.NoError(t, err)

	client := http.Client{}

	ctx := context.Background()
	parsedURL.Path = FormatBlockQuery(uint64(2), parsedURL.Path, net1)
	blockURL := parsedURL.String()
	request, err := http.NewRequest("GET", blockURL, nil)
	require.NoError(t, err)
	requestCtx, requestCancel := context.WithTimeout(ctx, time.Duration(config.CatchupHTTPBlockFetchTimeoutSec)*time.Second)
	defer requestCancel()
	request = request.WithContext(requestCtx)
	network.SetUserAgentHeader(request.Header)

	response, err := client.Do(request)
	require.NoError(t, err)
	require.Equal(t, response.StatusCode, http.StatusNotFound)
	
	net1.addPeer(nodeA.rootURL())
	_, err = client.Do(request)
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
	genBal := data.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	genHash := crypto.Digest{0x42}
	cfg := config.GetDefaultLocal()
	const inMem = true

	ledger, err := data.LoadLedger(
		log, t.Name()+namePostfix, inMem, protocol.ConsensusCurrentVersion, genBal, "", genHash,
		nil, cfg,
	)
	require.NoError(t, err)
	return ledger
}

func addBlock(t *testing.T, ledger *data.Ledger) {
	blk, err := ledger.Block(ledger.LastRound())
	require.NoError(t, err)
	blk.BlockHeader.Round++
	blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
	blk.TxnRoot, err = blk.PaysetCommit()
	require.NoError(t, err)

	var cert agreement.Certificate
	cert.Proposal.BlockDigest = blk.Digest()

	err = ledger.AddBlock(blk, cert)
	require.NoError(t, err)

	hdr, err := ledger.BlockHdr(blk.BlockHeader.Round)
	require.NoError(t, err)
	require.Equal(t, blk.BlockHeader, hdr)
}
