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
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

func buildTestLedger(t *testing.T, blk bookkeeping.Block) (ledger *data.Ledger, next basics.Round, b bookkeeping.Block, err error) {
	var user basics.Address
	user[0] = 123

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	genesis := make(map[basics.Address]basics.AccountData)
	genesis[user] = basics.AccountData{
		Status:     basics.Online,
		MicroAlgos: basics.MicroAlgos{Raw: proto.MinBalance * 2000000},
	}
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
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err = data.LoadLedger(
		log, t.Name(), inMem, protocol.ConsensusCurrentVersion, genBal, "", genHash,
		nil, cfg,
	)
	if err != nil {
		t.Fatal("couldn't build ledger", err)
		return
	}
	next = ledger.NextRound()
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      user,
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  next,
			LastValid:   next,
			GenesisHash: genHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: user,
			Amount:   basics.MicroAlgos{Raw: 2},
		},
	}
	signedtx := transactions.SignedTxn{
		Txn: tx,
	}

	prev, err := ledger.Block(ledger.LastRound())
	require.NoError(t, err)
	b = blk
	b.BlockHeader.RewardsState.RewardsPool = poolAddr
	b.RewardsLevel = prev.RewardsLevel
	b.BlockHeader.Round = next
	b.BlockHeader.GenesisHash = genHash
	b.CurrentProtocol = protocol.ConsensusCurrentVersion
	txib, err := b.EncodeSignedTxn(signedtx, transactions.ApplyData{})
	require.NoError(t, err)
	b.Payset = []transactions.SignedTxnInBlock{
		txib,
	}
	b.TxnRoot, err = b.PaysetCommit()
	require.NoError(t, err)
	require.NoError(t, ledger.AddBlock(b, agreement.Certificate{Round: next}))
	return
}

func addBlocks(t *testing.T, ledger *data.Ledger, blk bookkeeping.Block, numBlocks int) {
	var err error
	for i := 0; i < numBlocks; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		blk.TxnRoot, err = blk.PaysetCommit()
		require.NoError(t, err)

		err := ledger.AddBlock(blk, agreement.Certificate{Round: blk.BlockHeader.Round})
		require.NoError(t, err)

		hdr, err := ledger.BlockHdr(blk.BlockHeader.Round)
		require.NoError(t, err)
		require.Equal(t, blk.BlockHeader, hdr)
	}
}

type basicRPCNode struct {
	listener net.Listener
	server   http.Server
	rmux     *mux.Router
	peers    []network.Peer
	mocks.MockNetwork
}

func (b *basicRPCNode) RegisterHTTPHandler(path string, handler http.Handler) {
	if b.rmux == nil {
		b.rmux = mux.NewRouter()
	}
	b.rmux.Handle(path, handler)
}

func (b *basicRPCNode) RegisterHandlers(dispatch []network.TaggedMessageHandler) {
}

func (b *basicRPCNode) start() bool {
	var err error
	b.listener, err = net.Listen("tcp", "")
	if err != nil {
		logging.Base().Error("tcp listen", err)
		return false
	}
	if b.rmux == nil {
		b.rmux = mux.NewRouter()
	}
	b.server.Handler = b.rmux
	go b.server.Serve(b.listener)
	return true
}
func (b *basicRPCNode) rootURL() string {
	addr := b.listener.Addr().String()
	rootURL := url.URL{Scheme: "http", Host: addr, Path: ""}
	return rootURL.String()
}

func (b *basicRPCNode) stop() {
	b.server.Close()
}

func (b *basicRPCNode) GetPeers(options ...network.PeerOption) []network.Peer {
	return b.peers
}

func (b *basicRPCNode) SubstituteGenesisID(rawURL string) string {
	return strings.Replace(rawURL, "{genesisID}", "test genesisID", -1)
}

type httpTestPeerSource struct {
	peers []network.Peer
	mocks.MockNetwork
	dispatchHandlers []network.TaggedMessageHandler
}

func (s *httpTestPeerSource) GetPeers(options ...network.PeerOption) []network.Peer {
	return s.peers
}

func (s *httpTestPeerSource) RegisterHandlers(dispatch []network.TaggedMessageHandler) {
	s.dispatchHandlers = append(s.dispatchHandlers, dispatch...)
}

func (s *httpTestPeerSource) SubstituteGenesisID(rawURL string) string {
	return strings.Replace(rawURL, "{genesisID}", "test genesisID", -1)
}

// implement network.HTTPPeer
type testHTTPPeer string

func (p *testHTTPPeer) GetAddress() string {
	return string(*p)
}
func (p *testHTTPPeer) GetHTTPClient() *http.Client {
	return &http.Client{}
}
func (p *testHTTPPeer) GetHTTPPeer() network.HTTPPeer {
	return p
}

func (s *httpTestPeerSource) addPeer(rootURL string) {
	peer := testHTTPPeer(rootURL)
	s.peers = append(s.peers, &peer)
}

func nodePair() (*basicRPCNode, *basicRPCNode) {
	nodeA := &basicRPCNode{}
	nodeA.start()
	nodeB := &basicRPCNode{}
	nodeB.start()
	httpPeerA := testHTTPPeer(nodeA.rootURL())
	httpPeerB := testHTTPPeer(nodeB.rootURL())
	nodeB.peers = []network.Peer{&httpPeerA}
	nodeA.peers = []network.Peer{&httpPeerB}
	return nodeA, nodeB
}

// implement network.UnicastPeer
type testUnicastPeer struct {
	gn               network.GossipNode
	version          string
	responseChannels map[uint64]chan *network.Response
	t                *testing.T
	responseOverride *network.Response
}

func (p *testUnicastPeer) GetAddress() string {
	return "test"
}

func (p *testUnicastPeer) Request(ctx context.Context, tag protocol.Tag, topics network.Topics) (resp *network.Response, e error) {

	responseChannel := make(chan *network.Response, 1)
	p.responseChannels[0] = responseChannel

	ps := p.gn.(*httpTestPeerSource)
	var dispather network.MessageHandler
	for _, v := range ps.dispatchHandlers {
		if v.Tag == tag {
			dispather = v.MessageHandler
			break
		}
	}
	require.NotNil(p.t, dispather)
	dispather.Handle(network.IncomingMessage{Tag: tag, Data: topics.MarshallTopics(), Sender: p, Net: p.gn})

	if p.responseOverride != nil {
		return p.responseOverride, nil
	}

	// wait for the channel.
	select {
	case resp = <-responseChannel:
		return resp, nil
	case <-ctx.Done():
		return resp, ctx.Err()
	}
}

func (p *testUnicastPeer) Respond(ctx context.Context, reqMsg network.IncomingMessage, responseTopics network.Topics) (e error) {

	hashKey := uint64(0)
	channel, found := p.responseChannels[hashKey]
	if !found {
	}

	select {
	case channel <- &network.Response{Topics: responseTopics}:
	default:
	}

	return nil
}

func (p *testUnicastPeer) Version() string {
	return p.version
}

func (p *testUnicastPeer) Unicast(ctx context.Context, msg []byte, tag protocol.Tag) error {
	ps := p.gn.(*httpTestPeerSource)
	var dispather network.MessageHandler
	for _, v := range ps.dispatchHandlers {
		if v.Tag == tag {
			dispather = v.MessageHandler
			break
		}
	}
	require.NotNil(p.t, dispather)
	dispather.Handle(network.IncomingMessage{Tag: tag, Data: msg, Sender: p, Net: p.gn})
	return nil
}

func makeTestUnicastPeer(gn network.GossipNode, t *testing.T) network.UnicastPeer {
	return makeTestUnicastPeerWithResponseOverride(gn, t, nil)
}

func makeTestUnicastPeerWithResponseOverride(gn network.GossipNode, t *testing.T, responseOverride *network.Response) network.UnicastPeer {
	wsp := testUnicastPeer{}
	wsp.gn = gn
	wsp.t = t
	wsp.version = network.ProtocolVersion
	wsp.responseChannels = make(map[uint64]chan *network.Response)
	wsp.responseOverride = responseOverride
	return &wsp
}
