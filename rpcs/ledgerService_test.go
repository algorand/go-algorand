// Copyright (C) 2020 Algorand, Inc.
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
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
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

const defaultRewardUnit = 1e6

var sinkAddr = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type httpTestPeerSource struct {
	peers []network.Peer
	Registrar
}

func (s *httpTestPeerSource) GetPeers(options ...network.PeerOption) []network.Peer {
	return s.peers
}

// implement network.HTTPPeer
type testHTTPPeer struct {
	rootURL string
	client  http.Client
}

func (p *testHTTPPeer) GetAddress() string {
	return p.rootURL
}
func (p *testHTTPPeer) PrepareURL(x string) string {
	return strings.Replace(x, "{genesisID}", "test genesisID", -1)
}
func (p *testHTTPPeer) GetHTTPClient() *http.Client {
	return &p.client
}
func (p *testHTTPPeer) GetHTTPPeer() network.HTTPPeer {
	return p
}

func buildTestHTTPPeerSource(rootURL string) PeerSource {
	peer := testHTTPPeer{rootURL: rootURL}
	var wat network.HTTPPeer
	wat = &peer
	logging.Base().Infof("wat %#v", wat)
	return &httpTestPeerSource{peers: []network.Peer{&peer}}
}

// Build a ledger with genesis and one block, start an HTTPServer around it, use NetworkFetcher to fetch the block.
// For smaller test, nee ledgerService_test.go TestGetBlockHTTP
func TestGetBlockHTTP(t *testing.T) {
	// start server
	ledger, next, b, err := buildTestLedger(t)
	if err != nil {
		t.Fatal(err)
		return
	}
	ls := LedgerService{ledger: ledger, genesisID: "test genesisID"}
	nodeA := BasicRPCNode{}
	nodeA.RegisterHTTPHandler(LedgerServiceBlockPath, &ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()

	// run fetcher
	net := buildTestHTTPPeerSource(rootURL)
	_, ok := net.GetPeers(network.PeersConnectedOut)[0].(network.HTTPPeer)
	require.True(t, ok)
	factory := MakeNetworkFetcherFactory(net, numberOfPeers, nil)
	factory.log = logging.TestingLog(t)
	fetcher := factory.New()
	// we have one peer, the HTTP block server
	require.Equal(t, len(fetcher.(*NetworkFetcher).peers), 1)

	var block *bookkeeping.Block
	var cert *agreement.Certificate
	var client FetcherClient

	start := time.Now()
	block, cert, client, err = fetcher.FetchBlock(context.Background(), next)
	require.NotNil(t, client)
	require.NoError(t, err)
	end := time.Now()
	require.True(t, end.Sub(start) < goExecTime+10*time.Millisecond)
	require.Equal(t, &b, block)
	if err == nil {
		require.NotEqual(t, nil, block)
		require.NotEqual(t, nil, cert)
	}
}

type testUnicastPeerSrc struct {
	peers   []network.Peer
	handler network.MessageHandler
}

func (s *testUnicastPeerSrc) GetPeers(options ...network.PeerOption) []network.Peer {
	if options[0] == network.PeersConnectedIn {
		return s.peers
	}
	return nil
}

func (s *testUnicastPeerSrc) RegisterHTTPHandler(path string, handler http.Handler) {}
func (s *testUnicastPeerSrc) RegisterHandlers(dispatch []network.TaggedMessageHandler) {
	if dispatch[0].Tag == protocol.UniCatchupResTag {
		s.handler = dispatch[0].MessageHandler
	}
}

// implement network.UnicastPeer
type testUnicastPeer struct {
	c chan network.IncomingMessage
	h *testUnicastPeerSrc
}

func (p *testUnicastPeer) GetAddress() string {
	return "test"
}

func (p *testUnicastPeer) Unicast(ctx context.Context, msg []byte, tag protocol.Tag) error {
	if tag == protocol.UniCatchupReqTag { // we reuse this peer for both inbound and outbound messages
		// deliver to ledger service
		p.c <- network.IncomingMessage{Sender: p, Data: msg, Tag: tag} // fine to block when testing
	} else if tag == protocol.UniCatchupResTag {
		// this is from the ledger service
		p.h.handler.Handle(network.IncomingMessage{Sender: p, Data: msg, Tag: tag})
	}
	return nil
}

func makeTestUnicastPeer(target chan network.IncomingMessage, delegate *testUnicastPeerSrc) network.UnicastPeer {
	wsp := testUnicastPeer{}
	wsp.c = target
	wsp.h = delegate
	return &wsp
}

func buildTestUnicastPeerSrc(t *testing.T, target chan network.IncomingMessage) *testUnicastPeerSrc {
	ps := new(testUnicastPeerSrc)
	up := makeTestUnicastPeer(target, ps)
	ps.peers = []network.Peer{up}
	return ps
}

// A quick GetBlock over websockets test hitting a mocked websocket server (no actual connection)
func TestGetBlockWS(t *testing.T) {
	// start server
	ledger, next, b, err := buildTestLedger(t)
	if err != nil {
		t.Fatal(err)
		return
	}
	c := make(chan network.IncomingMessage, 50)
	ls := LedgerService{ledger: ledger, genesisID: "test genesisID", catchupReqs: c}
	ls.Start()

	// get ws fetcher
	net := buildTestUnicastPeerSrc(t, c)
	fs := RegisterWsFetcherService(logging.TestingLog(t), net)

	_, ok := net.GetPeers(network.PeersConnectedIn)[0].(network.UnicastPeer)
	require.True(t, ok)
	factory := MakeNetworkFetcherFactory(net, numberOfPeers, fs)
	factory.log = logging.TestingLog(t)
	fetcher := factory.NewOverGossip(protocol.UniCatchupReqTag)
	// we have one peer, the Ws block server
	require.Equal(t, fetcher.NumPeers(), 1)

	var block *bookkeeping.Block
	var cert *agreement.Certificate
	var client FetcherClient

	start := time.Now()
	block, cert, client, err = fetcher.FetchBlock(context.Background(), next)
	require.NotNil(t, client)
	require.NoError(t, err)
	end := time.Now()
	require.True(t, end.Sub(start) < goExecTime+10*time.Millisecond)
	require.Equal(t, &b, block)
	if err == nil {
		require.NotEqual(t, nil, block)
		require.NotEqual(t, nil, cert)
	}
	fetcher.Close()
}

type BasicRPCNode struct {
	listener net.Listener
	server   http.Server
	rmux     *mux.Router
	peers    []network.Peer
}

func (b *BasicRPCNode) RegisterHTTPHandler(path string, handler http.Handler) {
	if b.rmux == nil {
		b.rmux = mux.NewRouter()
	}
	b.rmux.Handle(path, handler)
}

func (b *BasicRPCNode) RegisterHandlers(dispatch []network.TaggedMessageHandler) {
}

func (b *BasicRPCNode) start() bool {
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
func (b *BasicRPCNode) rootURL() string {
	addr := b.listener.Addr().String()
	rootURL := url.URL{Scheme: "http", Host: addr, Path: ""}
	return rootURL.String()
}

func (b *BasicRPCNode) stop() {
	b.server.Close()
}

func (b *BasicRPCNode) GetPeers(options ...network.PeerOption) []network.Peer {
	return b.peers
}

func nodePair() (*BasicRPCNode, *BasicRPCNode) {
	nodeA := &BasicRPCNode{}
	nodeA.start()
	nodeB := &BasicRPCNode{}
	nodeB.start()
	nodeB.peers = []network.Peer{&testHTTPPeer{rootURL: nodeA.rootURL()}}
	nodeA.peers = []network.Peer{&testHTTPPeer{rootURL: nodeB.rootURL()}}
	return nodeA, nodeB
}

func TestGetBlockMocked(t *testing.T) {
	var user basics.Address
	user[0] = 123

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	genesis := make(map[basics.Address]basics.AccountData)
	genesis[user] = basics.AccountData{
		Status:     basics.Online,
		MicroAlgos: basics.MicroAlgos{Raw: proto.MinBalance * 2},
	}
	genesis[sinkAddr] = basics.AccountData{
		Status:     basics.Online,
		MicroAlgos: basics.MicroAlgos{Raw: proto.MinBalance * 2},
	}
	genesis[poolAddr] = basics.AccountData{
		Status:     basics.Online,
		MicroAlgos: basics.MicroAlgos{Raw: proto.MinBalance * 2},
	}

	log := logging.TestingLog(t)
	// A network with two nodes, A and B
	nodeA, nodeB := nodePair()
	defer nodeA.stop()
	defer nodeB.stop()

	// A is running the ledger service and will respond to fetch requests
	genBal := data.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	const inMem = true
	const archival = true
	ledgerA, err := data.LoadLedger(
		log.With("name", "A"), t.Name(), inMem,
		protocol.ConsensusCurrentVersion, genBal, "", crypto.Digest{},
		nil, archival,
	)
	if err != nil {
		t.Errorf("Couldn't make ledger: %v", err)
	}
	RegisterLedgerService(config.GetDefaultLocal(), ledgerA, nodeA, "test genesisID")

	next := ledgerA.NextRound()
	genHash := crypto.Digest{0x42}
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
	signedtx.InitCaches()

	var b bookkeeping.Block
	prev, err := ledgerA.Block(ledgerA.LastRound())
	require.NoError(t, err)
	b.RewardsLevel = prev.RewardsLevel
	b.BlockHeader.Round = next
	b.BlockHeader.GenesisHash = genHash
	b.CurrentProtocol = protocol.ConsensusCurrentVersion
	txib, err := b.EncodeSignedTxn(signedtx, transactions.ApplyData{})
	require.NoError(t, err)
	b.Payset = []transactions.SignedTxnInBlock{
		txib,
	}
	require.NoError(t, ledgerA.AddBlock(b, agreement.Certificate{Round: next}))

	// B tries to fetch block
	factory := MakeNetworkFetcherFactory(nodeB, 10, nil)
	factory.log = logging.TestingLog(t)
	nodeBRPC := factory.New()
	ctx, cf := context.WithTimeout(context.Background(), time.Second)
	defer cf()
	eblock, _, _, err := nodeBRPC.FetchBlock(ctx, next)
	if err != nil {
		t.Errorf("Error fetching block: %v", err)
	}
	block, err := ledgerA.Block(next)
	if err != nil {
		panic(err)
	}
	if eblock.Hash() != block.Hash() {
		t.Errorf("FetchBlock returned wrong block: expected %v; got %v", block.Hash(), eblock)
	}
}

func TestGetFutureBlock(t *testing.T) {
	log := logging.TestingLog(t)
	// A network with two nodes, A and B
	nodeA, nodeB := nodePair()
	defer nodeA.stop()
	defer nodeB.stop()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	genesis := make(map[basics.Address]basics.AccountData)
	genesis[sinkAddr] = basics.AccountData{
		Status:     basics.Online,
		MicroAlgos: basics.MicroAlgos{Raw: proto.MinBalance * 2},
	}
	genesis[poolAddr] = basics.AccountData{
		Status:     basics.Online,
		MicroAlgos: basics.MicroAlgos{Raw: proto.MinBalance * 2},
	}

	gen := data.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	// A is running the ledger service and will respond to fetch requests
	const inMem = true
	const archival = true
	ledgerA, err := data.LoadLedger(
		log.With("name", "A"), t.Name(), inMem,
		protocol.ConsensusCurrentVersion, gen, "", crypto.Digest{},
		nil, archival,
	)
	if err != nil {
		t.Errorf("Couldn't make ledger: %v", err)
	}
	RegisterLedgerService(config.GetDefaultLocal(), ledgerA, nodeA, "test genesisID")

	// B tries to fetch block 4
	factory := MakeNetworkFetcherFactory(nodeB, 10, nil)
	factory.log = logging.TestingLog(t)
	nodeBRPC := factory.New()
	ctx, cf := context.WithTimeout(context.Background(), time.Second)
	defer cf()
	_, _, client, err := nodeBRPC.FetchBlock(ctx, ledgerA.NextRound())
	require.Error(t, err)
	require.Nil(t, client)
}

func buildTestLedger(t *testing.T) (ledger *data.Ledger, next basics.Round, b bookkeeping.Block, err error) {
	var user basics.Address
	user[0] = 123

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	genesis := make(map[basics.Address]basics.AccountData)
	genesis[user] = basics.AccountData{
		Status:     basics.Online,
		MicroAlgos: basics.MicroAlgos{Raw: proto.MinBalance * 2},
	}
	genesis[sinkAddr] = basics.AccountData{
		Status:     basics.Online,
		MicroAlgos: basics.MicroAlgos{Raw: proto.MinBalance * 2},
	}
	genesis[poolAddr] = basics.AccountData{
		Status:     basics.Online,
		MicroAlgos: basics.MicroAlgos{Raw: proto.MinBalance * 2},
	}

	log := logging.TestingLog(t)
	genBal := data.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	genHash := crypto.Digest{0x42}
	const inMem = true
	const archival = true
	ledger, err = data.LoadLedger(
		log, t.Name(), inMem, protocol.ConsensusCurrentVersion, genBal, "", genHash,
		nil, archival,
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
	b.RewardsLevel = prev.RewardsLevel
	b.BlockHeader.Round = next
	b.BlockHeader.GenesisHash = genHash
	b.CurrentProtocol = protocol.ConsensusCurrentVersion
	txib, err := b.EncodeSignedTxn(signedtx, transactions.ApplyData{})
	require.NoError(t, err)
	b.Payset = []transactions.SignedTxnInBlock{
		txib,
	}

	require.NoError(t, ledger.AddBlock(b, agreement.Certificate{Round: next}))
	return
}
