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
	"net/rpc"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
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
		stx.InitCaches()
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
func (mock mockPendingTxAggregate) Pending() [][]transactions.SignedTxn {
	return bookkeeping.SignedTxnsToGroups(mock.txns)
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

func TestSyncFromClient(t *testing.T) {
	clientPool := makeMockPendingTxAggregate(2)
	serverPool := makeMockPendingTxAggregate(1)
	runner := MockRunner{failWithNil: false, failWithError: false, txgroups: serverPool.Pending()[len(serverPool.Pending())-1:], done: make(chan *rpc.Call)}
	client := MockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := MockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncer := MakeTxSyncer(clientPool, &clientAgg, &handler, testSyncInterval, testSyncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)

	require.NoError(t, syncer.syncFromClient(&client))
	require.Equal(t, int32(1), atomic.LoadInt32(&handler.messageCounter))
}

func TestSyncFromUnsupportedClient(t *testing.T) {
	pool := makeMockPendingTxAggregate(3)
	runner := MockRunner{failWithNil: true, failWithError: false, txgroups: pool.Pending()[len(pool.Pending())-1:], done: make(chan *rpc.Call)}
	client := MockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := MockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncer := MakeTxSyncer(pool, &clientAgg, &handler, testSyncInterval, testSyncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)

	require.Error(t, syncer.syncFromClient(&client))
	require.Zero(t, atomic.LoadInt32(&handler.messageCounter))
}

func TestSyncFromClientAndQuit(t *testing.T) {
	pool := makeMockPendingTxAggregate(3)
	runner := MockRunner{failWithNil: false, failWithError: false, txgroups: pool.Pending()[len(pool.Pending())-1:], done: make(chan *rpc.Call)}
	client := MockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := MockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncer := MakeTxSyncer(pool, &clientAgg, &handler, testSyncInterval, testSyncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)
	syncer.cancel()
	require.Error(t, syncer.syncFromClient(&client))
	require.Zero(t, atomic.LoadInt32(&handler.messageCounter))
}

func TestSyncFromClientAndError(t *testing.T) {

	pool := makeMockPendingTxAggregate(3)
	runner := MockRunner{failWithNil: false, failWithError: true, txgroups: pool.Pending()[len(pool.Pending())-1:], done: make(chan *rpc.Call)}
	client := MockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := MockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncer := MakeTxSyncer(pool, &clientAgg, &handler, testSyncInterval, testSyncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)
	require.Error(t, syncer.syncFromClient(&client))
	require.Zero(t, atomic.LoadInt32(&handler.messageCounter))
}

func TestSyncFromClientAndTimeout(t *testing.T) {
	pool := makeMockPendingTxAggregate(3)
	runner := MockRunner{failWithNil: false, failWithError: false, txgroups: pool.Pending()[len(pool.Pending())-1:], done: make(chan *rpc.Call)}
	client := MockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := MockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncTimeout := time.Duration(0)
	syncer := MakeTxSyncer(pool, &clientAgg, &handler, testSyncInterval, syncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)
	require.Error(t, syncer.syncFromClient(&client))
	require.Zero(t, atomic.LoadInt32(&handler.messageCounter))
}

func TestSync(t *testing.T) {
	pool := makeMockPendingTxAggregate(1)
	nodeA := BasicRPCNode{}
	txservice := makeTxService(pool, "test genesisID", config.GetDefaultLocal().TxPoolSize, config.GetDefaultLocal().TxSyncServeResponseSize)
	nodeA.RegisterHTTPHandler(TxServiceHTTPPath, txservice)
	nodeA.start()
	nodeAURL := nodeA.rootURL()

	runner := MockRunner{failWithNil: false, failWithError: false, txgroups: pool.Pending()[len(pool.Pending())-1:], done: make(chan *rpc.Call)}
	client := MockRPCClient{client: &runner, rootURL: nodeAURL, log: logging.TestingLog(t)}
	clientAgg := MockClientAggregator{peers: []network.Peer{&client}}
	handler := mockHandler{}
	syncerPool := makeMockPendingTxAggregate(3)
	syncer := MakeTxSyncer(syncerPool, &clientAgg, &handler, testSyncInterval, testSyncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)

	require.NoError(t, syncer.sync())
	require.Equal(t, int32(1), atomic.LoadInt32(&handler.messageCounter))
}

func TestNoClientsSync(t *testing.T) {
	pool := makeMockPendingTxAggregate(3)
	clientAgg := MockClientAggregator{peers: []network.Peer{}}
	handler := mockHandler{}
	syncer := MakeTxSyncer(pool, &clientAgg, &handler, testSyncInterval, testSyncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	syncer.log = logging.TestingLog(t)

	require.NoError(t, syncer.sync())
	require.Zero(t, atomic.LoadInt32(&handler.messageCounter))
}

func TestStartAndStop(t *testing.T) {
	t.Skip("TODO: replace this test in new client paradigm")
	pool := makeMockPendingTxAggregate(3)
	runner := MockRunner{failWithNil: false, failWithError: false, txgroups: pool.Pending()[len(pool.Pending())-1:], done: make(chan *rpc.Call)}
	client := MockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := MockClientAggregator{peers: []network.Peer{&client}}
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
	runner := MockRunner{failWithNil: false, failWithError: false, txgroups: pool.Pending()[len(pool.Pending())-1:], done: make(chan *rpc.Call)}
	client := MockRPCClient{client: &runner, log: logging.TestingLog(t)}
	clientAgg := MockClientAggregator{peers: []network.Peer{&client}}
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
