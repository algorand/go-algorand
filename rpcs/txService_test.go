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

package rpcs

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	p2ptesting "github.com/algorand/go-algorand/network/p2p/testing"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/bloom"
)

func TestMain(m *testing.M) {
	logging.Base().SetLevel(logging.Debug)
	os.Exit(m.Run())
}

type httpTestPeerSource struct {
	peers []network.Peer
	mocks.MockNetwork
}

func (s *httpTestPeerSource) GetPeers(options ...network.PeerOption) []network.Peer {
	return s.peers
}

func (s *httpTestPeerSource) addPeer(rootURL string) {
	peer := testHTTPPeer(rootURL)
	s.peers = append(s.peers, &peer)
}

// implement network.HTTPPeer
type testHTTPPeer string

func (p testHTTPPeer) GetAddress() string {
	return string(p)
}
func (p *testHTTPPeer) GetHTTPClient() *http.Client {
	return &http.Client{
		Transport: &network.HTTPPAddressBoundTransport{
			Addr:           p.GetAddress(),
			InnerTransport: http.DefaultTransport},
	}
}
func (p *testHTTPPeer) GetHTTPPeer() network.HTTPPeer {
	return p
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

func (b *basicRPCNode) RegisterHTTPHandlerFunc(path string, handler func(http.ResponseWriter, *http.Request)) {
	if b.rmux == nil {
		b.rmux = mux.NewRouter()
	}
	b.rmux.HandleFunc(path, handler)
}

func (b *basicRPCNode) RegisterHandlers(dispatch []network.TaggedMessageHandler) {
}

func (b *basicRPCNode) start() bool {
	var err error
	b.listener, err = net.Listen("tcp", "127.0.0.1:")
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

func (b *basicRPCNode) GetGenesisID() string { return "test genesisID" }

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

func nodePairP2p(tb testing.TB) (*p2ptesting.HTTPNode, *p2ptesting.HTTPNode) {
	nodeA := p2ptesting.MakeHTTPNode(tb)
	addrsA := nodeA.Addrs()
	require.Greater(tb, len(addrsA), 0)

	nodeB := p2ptesting.MakeHTTPNode(tb)
	addrsB := nodeA.Addrs()
	require.Greater(tb, len(addrsB), 0)

	nodeA.SetPeers(nodeB)
	nodeB.SetPeers(nodeA)
	nodeA.SetGenesisID("test genesisID")
	nodeB.SetGenesisID("test genesisID")

	nodeA.Start()
	nodeB.Start()

	return nodeA, nodeB
}

// TestTxSync checks txsync on a network with two nodes, A and B
func TestTxSync(t *testing.T) {
	partitiontest.PartitionTest(t)

	type txSyncNode interface {
		Registrar
		network.GossipNode
	}

	tests := []struct {
		name  string
		setup func(t *testing.T) (txSyncNode, txSyncNode, func())
	}{
		{
			name: "tcp",
			setup: func(t *testing.T) (txSyncNode, txSyncNode, func()) {
				nodeA, nodeB := nodePair()
				cleanup := func() {
					nodeA.stop()
					nodeB.stop()
				}
				return nodeA, nodeB, cleanup
			},
		},
		{
			name: "p2p",
			setup: func(t *testing.T) (txSyncNode, txSyncNode, func()) {
				nodeA, nodeB := nodePairP2p(t)
				cleanup := func() {
					nodeA.Stop()
					nodeB.Stop()
				}
				return nodeA, nodeB, cleanup
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// A network with two nodes, A and B
			nodeA, nodeB, cleanupFn := test.setup(t)
			defer cleanupFn()

			pool := makeMockPendingTxAggregate(3)
			RegisterTxService(pool, nodeA, "test genesisID", config.GetDefaultLocal().TxPoolSize, config.GetDefaultLocal().TxSyncServeResponseSize)

			// B tries to fetch block
			handler := mockHandler{}
			syncInterval := time.Second
			syncTimeout := time.Second
			syncerPool := makeMockPendingTxAggregate(0)
			syncer := MakeTxSyncer(syncerPool, nodeB, &handler, syncInterval, syncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
			// Since syncer is not Started, set the context here
			syncer.ctx, syncer.cancel = context.WithCancel(context.Background())
			require.NoError(t, syncer.sync())
			require.Equal(t, int32(3), handler.messageCounter.Load())
		})
	}
}

func BenchmarkTxSync(b *testing.B) {
	// A network with two nodes, A and B
	nodeA, nodeB := nodePair()
	defer nodeA.stop()
	defer nodeB.stop()

	pool := makeMockPendingTxAggregate(10000)
	RegisterTxService(pool, nodeA, "test genesisID", config.GetDefaultLocal().TxPoolSize, config.GetDefaultLocal().TxSyncServeResponseSize)

	b.ResetTimer()
	wg := sync.WaitGroup{}
	wg.Add(30)
	for i := 0; i < 30; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < b.N/30; j++ {
				handler := mockHandler{}
				syncInterval := time.Second
				syncTimeout := time.Second
				syncPool := makeMockPendingTxAggregate(config.GetDefaultLocal().TxPoolSize)
				syncer := MakeTxSyncer(syncPool, nodeB, &handler, syncInterval, syncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
				syncer.sync()
			}
		}()
	}
	wg.Wait()
}

func BenchmarkTransactionFilteringPerformance(b *testing.B) {
	pool := makeMockPendingTxAggregate(config.GetDefaultLocal().TxPoolSize)
	txService := makeTxService(pool, "test genesisID", config.GetDefaultLocal().TxPoolSize, config.GetDefaultLocal().TxSyncServeResponseSize)

	clientPool := makeMockPendingTxAggregate(config.GetDefaultLocal().TxPoolSize)
	pending := clientPool.PendingTxIDs()
	sizeBits, numHashes := bloom.Optimal(len(pending), bloomFilterFalsePositiveRate)
	filter := bloom.New(sizeBits, numHashes, 0)
	for _, txid := range pending {
		filter.Set(txid[:])
	}

	txService.updateTxCache()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		txService.getFilteredTxns(filter)
		i += config.GetDefaultLocal().TxPoolSize - 1
	}
}
