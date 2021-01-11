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
	"errors"
	"net"
	"net/http"
	"net/rpc"
	"net/url"
	"strings"
	"testing"
	"time"

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
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/util/bloom"
)

type mockRunner struct {
	ran           bool
	done          chan *rpc.Call
	failWithNil   bool
	failWithError bool
	txgroups      [][]transactions.SignedTxn
}

type mockRPCClient struct {
	client  *mockRunner
	closed  bool
	rootURL string
	log     logging.Logger
}

func (client *mockRPCClient) Close() error {
	client.closed = true
	return nil
}

func (client *mockRPCClient) Address() string {
	return "mock.address."
}
func (client *mockRPCClient) Sync(ctx context.Context, bloom *bloom.Filter) (txgroups [][]transactions.SignedTxn, err error) {
	client.log.Info("MockRPCClient.Sync")
	select {
	case <-ctx.Done():
		return nil, errors.New("cancelled")
	default:
	}
	if client.client.failWithNil {
		return nil, errors.New("old failWithNil")
	}
	if client.client.failWithError {
		return nil, errors.New("failing call")
	}
	return client.client.txgroups, nil
}
func (client *mockRPCClient) GetBlockBytes(ctx context.Context, r basics.Round) (data []byte, err error) {
	return nil, nil
}

// network.HTTPPeer interface
func (client *mockRPCClient) GetAddress() string {
	return client.rootURL
}
func (client *mockRPCClient) GetHTTPClient() *http.Client {
	return nil
}

type mockClientAggregator struct {
	mocks.MockNetwork
	peers []network.Peer
}

func (mca *mockClientAggregator) GetPeers(options ...network.PeerOption) []network.Peer {
	return mca.peers
}

const numberOfPeers = 10

func makeMockClientAggregator(t *testing.T, failWithNil bool, failWithError bool) *mockClientAggregator {
	clients := make([]network.Peer, 0)
	for i := 0; i < numberOfPeers; i++ {
		runner := mockRunner{failWithNil: failWithNil, failWithError: failWithError, done: make(chan *rpc.Call)}
		clients = append(clients, &mockRPCClient{client: &runner, log: logging.TestingLog(t)})
	}
	t.Logf("len(mca.clients) = %d", len(clients))
	return &mockClientAggregator{peers: clients}
}

func getAllClientsSelectedForRound(t *testing.T, fetcher *NetworkFetcher, round basics.Round) map[FetcherClient]basics.Round {
	selected := make(map[FetcherClient]basics.Round, 0)
	for i := 0; i < 1000; i++ {
		c, err := fetcher.selectClient(round)
		if err != nil {
			return selected
		}
		selected[c.(FetcherClient)] = fetcher.roundUpperBound[c]
	}
	return selected
}

func TestSelectValidRemote(t *testing.T) {
	network := makeMockClientAggregator(t, false, false)
	cfg := config.GetDefaultLocal()
	factory := MakeNetworkFetcherFactory(network, numberOfPeers, nil, &cfg)
	factory.log = logging.TestingLog(t)
	fetcher := factory.New()
	require.Equal(t, numberOfPeers, len(fetcher.(*NetworkFetcher).peers))

	var oldClient FetcherClient
	var newClient FetcherClient
	i := 0
	for _, client := range fetcher.(*NetworkFetcher).peers {
		if i == 0 {
			oldClient = client
			r := basics.Round(2)
			fetcher.(*NetworkFetcher).roundUpperBound[client] = r
		} else if i == 1 {
			newClient = client
			r := basics.Round(4)
			fetcher.(*NetworkFetcher).roundUpperBound[client] = r
		} else if i > 2 {
			r := basics.Round(3)
			fetcher.(*NetworkFetcher).roundUpperBound[client] = r
		} // skip i == 2
		i++
	}

	require.Equal(t, numberOfPeers, len(fetcher.(*NetworkFetcher).availablePeers(1)))
	selected := getAllClientsSelectedForRound(t, fetcher.(*NetworkFetcher), 1)
	require.Equal(t, numberOfPeers, len(selected))
	_, hasOld := selected[oldClient]
	require.True(t, hasOld)

	_, hasNew := selected[newClient]
	require.True(t, hasNew)

	require.Equal(t, numberOfPeers-1, len(fetcher.(*NetworkFetcher).availablePeers(2)))
	selected = getAllClientsSelectedForRound(t, fetcher.(*NetworkFetcher), 2)
	require.Equal(t, numberOfPeers-1, len(selected))
	_, hasOld = selected[oldClient]
	require.False(t, hasOld)
	_, hasNew = selected[newClient]
	require.True(t, hasNew)

	require.Equal(t, 2, len(fetcher.(*NetworkFetcher).availablePeers(3)))
	selected = getAllClientsSelectedForRound(t, fetcher.(*NetworkFetcher), 3)
	require.Equal(t, 2, len(selected))
	_, hasOld = selected[oldClient]
	require.False(t, hasOld)
	_, hasNew = selected[newClient]
	require.True(t, hasNew)

	require.Equal(t, 1, len(fetcher.(*NetworkFetcher).availablePeers(4)))
	selected = getAllClientsSelectedForRound(t, fetcher.(*NetworkFetcher), 4)
	require.Equal(t, 1, len(selected))
	_, hasOld = selected[oldClient]
	require.False(t, hasOld)
	_, hasNew = selected[newClient]
	require.False(t, hasNew)
}

type dummyFetcher struct {
	failWithNil   bool
	failWithError bool
	fetchTimeout  time.Duration
}

// FetcherClient interface
func (df *dummyFetcher) GetBlockBytes(ctx context.Context, r basics.Round) (data []byte, err error) {
	if df.failWithNil {
		return nil, nil
	}
	if df.failWithError {
		return nil, errors.New("failing call")
	}

	timer := time.NewTimer(df.fetchTimeout)
	defer timer.Stop()

	// Fill in the dummy response with the correct round
	dummyBlock := rpcs.EncodedBlockCert{
		Block: bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: r,
			},
		},
		Certificate: agreement.Certificate{
			Round: r,
		},
	}

	encodedData := protocol.Encode(&dummyBlock)

	select {
	case <-timer.C:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return encodedData, nil
}

// FetcherClient interface
func (df *dummyFetcher) Address() string {
	//logging.Base().Debug("dummyFetcher Address")
	return "dummyFetcher address"
}

// FetcherClient interface
func (df *dummyFetcher) Close() error {
	//logging.Base().Debug("dummyFetcher Close")
	return nil
}

func makeDummyFetchers(failWithNil bool, failWithError bool, timeout time.Duration) []FetcherClient {
	out := make([]FetcherClient, numberOfPeers)
	for i := range out {
		out[i] = &dummyFetcher{failWithNil, failWithError, timeout}
	}
	return out
}

func TestFetchBlock(t *testing.T) {
	fetcher := &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           makeDummyFetchers(false, false, 100*time.Millisecond),
		log:             logging.TestingLog(t),
	}

	var err error
	var block *bookkeeping.Block
	var cert *agreement.Certificate
	var client FetcherClient

	fetched := false
	for i := 0; i < numberOfPeers; i++ {
		start := time.Now()
		block, cert, client, err = fetcher.FetchBlock(context.Background(), basics.Round(numberOfPeers))
		require.NoError(t, err)
		require.NotNil(t, client)
		end := time.Now()
		require.True(t, end.Sub(start) > 100*time.Millisecond)
		require.True(t, end.Sub(start) < 100*time.Millisecond+5*time.Second) // we want to have a higher margin here, as the machine we're running on might be slow.
		if err == nil {
			require.NotEqual(t, nil, block)
			require.NotEqual(t, nil, cert)
			_, _, client, err = fetcher.FetchBlock(context.Background(), basics.Round(numberOfPeers))
			require.NotNil(t, client)
			require.NoError(t, err)
			fetched = true
		}
	}
	require.True(t, fetched)
}

func TestFetchBlockFail(t *testing.T) {
	fetcher := &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           makeDummyFetchers(true, false, 100*time.Millisecond),
		log:             logging.TestingLog(t),
	}

	for i := 0; i < numberOfPeers; i++ {
		require.False(t, fetcher.OutOfPeers(basics.Round(numberOfPeers)))
		_, _, _, err := fetcher.FetchBlock(context.Background(), basics.Round(numberOfPeers))
		require.Error(t, err)
	}
	require.True(t, fetcher.OutOfPeers(basics.Round(numberOfPeers)))
}

func TestFetchBlockAborted(t *testing.T) {
	fetcher := &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           makeDummyFetchers(false, false, 2*time.Second),
		log:             logging.TestingLog(t),
	}

	ctx, cf := context.WithCancel(context.Background())
	defer cf()
	go func() {
		cf()
	}()
	start := time.Now()
	_, _, client, err := fetcher.FetchBlock(ctx, basics.Round(1))
	end := time.Now()
	require.True(t, strings.Contains(err.Error(), context.Canceled.Error()))
	require.Nil(t, client)
	require.True(t, end.Sub(start) < 10*time.Second)
}

func TestFetchBlockTimeout(t *testing.T) {
	fetcher := &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           makeDummyFetchers(false, false, 10*time.Second),
		log:             logging.TestingLog(t),
	}
	start := time.Now()
	ctx, cf := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cf()
	_, _, client, err := fetcher.FetchBlock(ctx, basics.Round(1))
	end := time.Now()
	require.True(t, strings.Contains(err.Error(), context.DeadlineExceeded.Error()))
	require.Nil(t, client)
	require.True(t, end.Sub(start) >= 500*time.Millisecond)
	require.True(t, end.Sub(start) < 10*time.Second)
}

func TestFetchBlockErrorCall(t *testing.T) {
	fetcher := &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           makeDummyFetchers(false, true, 10*time.Millisecond),
		log:             logging.TestingLog(t),
	}

	require.False(t, fetcher.OutOfPeers(basics.Round(numberOfPeers)))
	_, _, client, err := fetcher.FetchBlock(context.Background(), basics.Round(numberOfPeers))
	require.Error(t, err)
	require.Nil(t, client)
}

func TestFetchBlockComposedNoOp(t *testing.T) {
	f := &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           makeDummyFetchers(false, false, 1*time.Millisecond),
		log:             logging.TestingLog(t),
	}
	fetcher := &ComposedFetcher{fetchers: []Fetcher{f, nil}}

	var err error
	var block *bookkeeping.Block
	var cert *agreement.Certificate
	var client FetcherClient

	fetched := false
	for i := 0; i < numberOfPeers; i++ {
		start := time.Now()
		block, cert, client, err = fetcher.FetchBlock(context.Background(), basics.Round(numberOfPeers))
		require.NoError(t, err)
		require.NotNil(t, client)
		end := time.Now()
		require.True(t, end.Sub(start) >= 1*time.Millisecond)
		require.True(t, end.Sub(start) < 1*time.Millisecond+10*time.Second) // we take a very high margin here for the fetcher to complete.
		if err == nil {
			require.NotEqual(t, nil, block)
			require.NotEqual(t, nil, cert)
			_, _, client, err = fetcher.FetchBlock(context.Background(), basics.Round(numberOfPeers))
			require.NotNil(t, client)
			require.NoError(t, err)
			fetched = true
		}
	}
	require.True(t, fetched)
}

// Make sure composed fetchers are hit in priority order
func TestFetchBlockComposedFail(t *testing.T) {
	f := &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           makeDummyFetchers(true, false, 1*time.Millisecond),
		log:             logging.TestingLog(t),
	}
	f2 := &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           makeDummyFetchers(false, false, 1*time.Millisecond),
		log:             logging.TestingLog(t),
	}
	fetcher := &ComposedFetcher{fetchers: []Fetcher{f, f2}}

	for i := 0; i < numberOfPeers; i++ {
		require.False(t, fetcher.OutOfPeers(basics.Round(numberOfPeers)))
		_, _, _, err := fetcher.FetchBlock(context.Background(), basics.Round(numberOfPeers))
		require.Error(t, err)
	}
	require.False(t, fetcher.OutOfPeers(basics.Round(numberOfPeers)))
	for i := 0; i < numberOfPeers; i++ {
		require.False(t, fetcher.OutOfPeers(basics.Round(numberOfPeers)))
		_, _, client, err := fetcher.FetchBlock(context.Background(), basics.Round(numberOfPeers))
		require.NotNil(t, client)
		require.NoError(t, err)
	}
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

// Build a ledger with genesis and one block, start an HTTPServer around it, use NetworkFetcher to fetch the block.
// For smaller test, see blockService_test.go TestGetBlockHTTP
// todo - fix this one
func TestGetBlockHTTP(t *testing.T) {
	// start server
	ledger, next, b, err := buildTestLedger(t)
	if err != nil {
		t.Fatal(err)
		return
	}
	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(config.GetDefaultLocal(), ledger, net, "test genesisID")

	nodeA := basicRPCNode{}
	nodeA.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()

	// run fetcher
	net.addPeer(rootURL)
	_, ok := net.GetPeers(network.PeersConnectedOut)[0].(network.HTTPPeer)
	require.True(t, ok)
	cfg := config.GetDefaultLocal()
	factory := MakeNetworkFetcherFactory(net, numberOfPeers, nil, &cfg)
	factory.log = logging.TestingLog(t)
	fetcher := factory.New()
	// we have one peer, the HTTP block server
	require.Equal(t, len(fetcher.(*NetworkFetcher).peers), 1)

	var block *bookkeeping.Block
	var cert *agreement.Certificate
	var client FetcherClient

	start := time.Now()
	block, cert, client, err = fetcher.FetchBlock(context.Background(), next)
	end := time.Now()
	require.NotNil(t, client)
	require.NoError(t, err)

	require.True(t, end.Sub(start) < 10*time.Second)
	require.Equal(t, &b, block)
	if err == nil {
		require.NotEqual(t, nil, block)
		require.NotEqual(t, nil, cert)
	}
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
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledgerA, err := data.LoadLedger(
		log.With("name", "A"), t.Name(), inMem,
		protocol.ConsensusCurrentVersion, genBal, "", crypto.Digest{},
		nil, cfg,
	)
	if err != nil {
		t.Errorf("Couldn't make ledger: %v", err)
	}
	blockServiceConfig := config.GetDefaultLocal()
	blockServiceConfig.EnableBlockService = true
	rpcs.MakeBlockService(blockServiceConfig, ledgerA, nodeA, "test genesisID")

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
	factory := MakeNetworkFetcherFactory(nodeB, 10, nil, &cfg)
	factory.log = logging.TestingLog(t)
	nodeBRPC := factory.New()
	ctx, cf := context.WithTimeout(context.Background(), time.Second)
	defer cf()
	eblock, _, _, err := nodeBRPC.FetchBlock(ctx, next)
	if err != nil {
		require.Failf(t, "Error fetching block", "%v", err)
	}
	block, err := ledgerA.Block(next)
	require.NoError(t, err)
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
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledgerA, err := data.LoadLedger(
		log.With("name", "A"), t.Name(), inMem,
		protocol.ConsensusCurrentVersion, gen, "", crypto.Digest{},
		nil, cfg,
	)
	if err != nil {
		t.Errorf("Couldn't make ledger: %v", err)
	}
	rpcs.MakeBlockService(config.GetDefaultLocal(), ledgerA, nodeA, "test genesisID")

	// B tries to fetch block 4
	factory := MakeNetworkFetcherFactory(nodeB, 10, nil, &cfg)
	factory.log = logging.TestingLog(t)
	nodeBRPC := factory.New()
	ctx, cf := context.WithTimeout(context.Background(), time.Second)
	defer cf()
	_, _, client, err := nodeBRPC.FetchBlock(ctx, ledgerA.NextRound())
	require.Error(t, err)
	require.Nil(t, client)
}

// implement network.UnicastPeer
type testUnicastPeer struct {
	gn               network.GossipNode
	version          string
	responseChannels map[uint64]chan *network.Response
	t                *testing.T
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

func makeTestUnicastPeer(gn network.GossipNode, version string, t *testing.T) network.UnicastPeer {
	wsp := testUnicastPeer{}
	wsp.gn = gn
	wsp.t = t
	wsp.version = version
	wsp.responseChannels = make(map[uint64]chan *network.Response)
	return &wsp
}

// A quick GetBlock over websockets test hitting a mocked websocket server (no actual connection)
func TestGetBlockWS(t *testing.T) {
	// test the WS fetcher:
	// 1. fetcher sends UniCatchupReqTag to http peer
	// 2. peer send message to gossip node
	// 3. gossip node send message to ledger service
	// 4. ledger service responds with UniCatchupResTag sending it back to the http peer
	// 5. the http peer send it to the network
	// 6. the network send it back to the fetcher

	// start server
	ledger, next, b, err := buildTestLedger(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	cfg := config.GetDefaultLocal()

	versions := []string{"1", "2.1"}
	for _, version := range versions { // range network.SupportedProtocolVersions {

		net := &httpTestPeerSource{}
		blockServiceConfig := config.GetDefaultLocal()
		blockServiceConfig.CatchupParallelBlocks = 5
		blockServiceConfig.EnableBlockService = true
		ls := rpcs.MakeBlockService(blockServiceConfig, ledger, net, "test genesisID")

		ls.Start()

		up := makeTestUnicastPeer(net, version, t)
		net.peers = append(net.peers, up)

		fs := rpcs.MakeWsFetcherService(logging.TestingLog(t), net)
		fs.Start()

		_, ok := net.GetPeers(network.PeersConnectedIn)[0].(network.UnicastPeer)
		require.True(t, ok)
		factory := MakeNetworkFetcherFactory(net, numberOfPeers, fs, &cfg)
		factory.log = logging.TestingLog(t)
		fetcher := factory.NewOverGossip(protocol.UniCatchupReqTag)
		// we have one peer, the Ws block server
		require.Equal(t, fetcher.NumPeers(), 1)

		var block *bookkeeping.Block
		var cert *agreement.Certificate
		var client FetcherClient

		//		start := time.Now()
		block, cert, client, err = fetcher.FetchBlock(context.Background(), next)
		require.NotNil(t, client)
		require.NoError(t, err)
		//		end := time.Now()
		//		require.True(t, end.Sub(start) < 10*time.Second)
		require.Equal(t, &b, block)
		if err == nil {
			require.NotEqual(t, nil, block)
			require.NotEqual(t, nil, cert)
		}
		fetcher.Close()
	}
}
