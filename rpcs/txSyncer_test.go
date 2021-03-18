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
	"errors"
	"net/http"
	"net/rpc"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/bloom"
)

type mockPendingTxAggregate struct {
	txns []transactions.SignedTxn
}

func makeMockPendingTxAggregate(txCount int) mockPendingTxAggregate {
	var secret [32]byte
	crypto.RandBytes(secret[:])
	sk := crypto.GenerateSignatureSecrets(crypto.Seed(secret))
	mock := mockPendingTxAggregate{
		txns: make([]transactions.SignedTxn, txCount),
	}

	for i := 0; i < txCount; i++ {
		var note [16]byte
		crypto.RandBytes(note[:])
		tx := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Note: note[:],
			},
		}
		stx := tx.Sign(sk)
		mock.txns[i] = stx
	}
	return mock
}

func (mock mockPendingTxAggregate) PendingTxIDs() []transactions.Txid {
	// return all but one ID
	ids := make([]transactions.Txid, 0)
	for _, tx := range mock.txns {
		ids = append(ids, tx.ID())
	}
	return ids
}
func makeSignedTxGroup(source [][]transactions.SignedTxn) (result []transactions.SignedTxGroup) {
	result = make([]transactions.SignedTxGroup, len(source))
	for i := range source {
		result[i].Transactions = source[i]
	}
	return
}

func (mock mockPendingTxAggregate) PendingTxGroups() (result []transactions.SignedTxGroup) {
	return makeSignedTxGroup(bookkeeping.SignedTxnsToGroups(mock.txns))
}

type mockHandler struct {
	messageCounter int32
	err            error
}

func (handler *mockHandler) Handle(txgroup []transactions.SignedTxn) error {
	atomic.AddInt32(&handler.messageCounter, 1)
	return handler.err
}

const testSyncInterval = 5 * time.Second
const testSyncTimeout = 4 * time.Second

type mockRunner struct {
	ran           bool
	done          chan *rpc.Call
	failWithNil   bool
	failWithError bool
	txgroups      []transactions.SignedTxGroup
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
	txgroups = make([][]transactions.SignedTxn, len(client.client.txgroups))
	for i := range txgroups {
		txgroups[i] = client.client.txgroups[i].Transactions
	}
	return txgroups, nil
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
func (mca *mockClientAggregator) SubstituteGenesisID(rawURL string) string {
	return strings.Replace(rawURL, "{genesisID}", "test genesisID", -1)
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

func TestSyncFromClient(t *testing.T) {
	clientPool := makeMockPendingTxAggregate(2)
	serverPool := makeMockPendingTxAggregate(1)
	runner := mockRunner{failWithNil: false, failWithError: false, txgroups: serverPool.PendingTxGroups()[len(serverPool.PendingTxGroups())-1:], done: make(chan *rpc.Call)}
	client := mockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := mockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncer := MakeTxSyncer(clientPool, &clientAgg, &handler, testSyncInterval, testSyncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)

	require.NoError(t, syncer.syncFromClient(&client))
	require.Equal(t, int32(1), atomic.LoadInt32(&handler.messageCounter))
}

func TestSyncFromUnsupportedClient(t *testing.T) {
	pool := makeMockPendingTxAggregate(3)
	runner := mockRunner{failWithNil: true, failWithError: false, txgroups: pool.PendingTxGroups()[len(pool.PendingTxGroups())-1:], done: make(chan *rpc.Call)}
	client := mockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := mockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncer := MakeTxSyncer(pool, &clientAgg, &handler, testSyncInterval, testSyncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)

	require.Error(t, syncer.syncFromClient(&client))
	require.Zero(t, atomic.LoadInt32(&handler.messageCounter))
}

func TestSyncFromClientAndQuit(t *testing.T) {
	pool := makeMockPendingTxAggregate(3)
	runner := mockRunner{failWithNil: false, failWithError: false, txgroups: pool.PendingTxGroups()[len(pool.PendingTxGroups())-1:], done: make(chan *rpc.Call)}
	client := mockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := mockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncer := MakeTxSyncer(pool, &clientAgg, &handler, testSyncInterval, testSyncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)
	syncer.cancel()
	require.Error(t, syncer.syncFromClient(&client))
	require.Zero(t, atomic.LoadInt32(&handler.messageCounter))
}

func TestSyncFromClientAndError(t *testing.T) {

	pool := makeMockPendingTxAggregate(3)
	runner := mockRunner{failWithNil: false, failWithError: true, txgroups: pool.PendingTxGroups()[len(pool.PendingTxGroups())-1:], done: make(chan *rpc.Call)}
	client := mockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := mockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncer := MakeTxSyncer(pool, &clientAgg, &handler, testSyncInterval, testSyncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)
	require.Error(t, syncer.syncFromClient(&client))
	require.Zero(t, atomic.LoadInt32(&handler.messageCounter))
}

func TestSyncFromClientAndTimeout(t *testing.T) {
	pool := makeMockPendingTxAggregate(3)
	runner := mockRunner{failWithNil: false, failWithError: false, txgroups: pool.PendingTxGroups()[len(pool.PendingTxGroups())-1:], done: make(chan *rpc.Call)}
	client := mockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := mockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncTimeout := time.Duration(0)
	syncer := MakeTxSyncer(pool, &clientAgg, &handler, testSyncInterval, syncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)
	require.Error(t, syncer.syncFromClient(&client))
	require.Zero(t, atomic.LoadInt32(&handler.messageCounter))
}

func TestSync(t *testing.T) {
	pool := makeMockPendingTxAggregate(1)
	nodeA := basicRPCNode{}
	txservice := makeTxService(pool, "test genesisID", config.GetDefaultLocal().TxPoolSize, config.GetDefaultLocal().TxSyncServeResponseSize)
	nodeA.RegisterHTTPHandler(TxServiceHTTPPath, txservice)
	nodeA.start()
	nodeAURL := nodeA.rootURL()

	runner := mockRunner{failWithNil: false, failWithError: false, txgroups: pool.PendingTxGroups()[len(pool.PendingTxGroups())-1:], done: make(chan *rpc.Call)}
	client := mockRPCClient{client: &runner, rootURL: nodeAURL, log: logging.TestingLog(t)}
	clientAgg := mockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncerPool := makeMockPendingTxAggregate(3)
	syncer := MakeTxSyncer(syncerPool, &clientAgg, &handler, testSyncInterval, testSyncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)

	require.NoError(t, syncer.sync())
	require.Equal(t, int32(1), atomic.LoadInt32(&handler.messageCounter))
}

func TestNoClientsSync(t *testing.T) {
	pool := makeMockPendingTxAggregate(3)
	clientAgg := mockClientAggregator{peers: []network.Peer{}}
	handler := mockHandler{}
	syncer := MakeTxSyncer(pool, &clientAgg, &handler, testSyncInterval, testSyncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)

	require.NoError(t, syncer.sync())
	require.Zero(t, atomic.LoadInt32(&handler.messageCounter))
}

func TestStartAndStop(t *testing.T) {
	t.Skip("TODO: replace this test in new client paradigm")
	pool := makeMockPendingTxAggregate(3)
	runner := mockRunner{failWithNil: false, failWithError: false, txgroups: pool.PendingTxGroups()[len(pool.PendingTxGroups())-1:], done: make(chan *rpc.Call)}
	client := mockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := mockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncInterval := time.Second
	syncTimeout := time.Second
	syncer := MakeTxSyncer(pool, &clientAgg, &handler, syncInterval, syncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)

	// ensure that syncing doesn't start
	canStart := make(chan struct{})
	syncer.Start(canStart)
	time.Sleep(2 * time.Second)
	require.Zero(t, atomic.LoadInt32(&handler.messageCounter))

	// signal that syncing can start
	close(canStart)
	time.Sleep(2 * time.Second)
	require.Equal(t, int32(1), atomic.LoadInt32(&handler.messageCounter))

	// stop syncing and ensure it doesn't happen
	syncer.Stop()
	time.Sleep(2 * time.Second)
	require.Equal(t, int32(1), atomic.LoadInt32(&handler.messageCounter))
}

func TestStartAndQuit(t *testing.T) {
	pool := makeMockPendingTxAggregate(3)
	runner := mockRunner{failWithNil: false, failWithError: false, txgroups: pool.PendingTxGroups()[len(pool.PendingTxGroups())-1:], done: make(chan *rpc.Call)}
	client := mockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := mockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncInterval := time.Second
	syncTimeout := time.Second
	syncer := MakeTxSyncer(pool, &clientAgg, &handler, syncInterval, syncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)

	// ensure that syncing doesn't start
	canStart := make(chan struct{})
	syncer.Start(canStart)
	time.Sleep(2 * time.Second)
	require.Zero(t, atomic.LoadInt32(&handler.messageCounter))

	syncer.cancel()
	time.Sleep(50 * time.Millisecond)
	// signal that syncing can start, but ensure that it doesn't start (since we quit)
	close(canStart)
	time.Sleep(2 * time.Second)
	require.Zero(t, atomic.LoadInt32(&handler.messageCounter))
}
