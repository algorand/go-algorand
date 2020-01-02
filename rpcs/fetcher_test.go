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
	"errors"
	"net/http"
	"net/rpc"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/bloom"
)

type MockRunner struct {
	ran           bool
	done          chan *rpc.Call
	failWithNil   bool
	failWithError bool
	txgroups      [][]transactions.SignedTxn
}

const goExecTime = 100 * time.Millisecond

type MockRPCClient struct {
	client  *MockRunner
	closed  bool
	rootURL string
	log     logging.Logger
}

func (client *MockRPCClient) Close() error {
	client.closed = true
	return nil
}

func (client *MockRPCClient) Address() string {
	return "mock.address."
}
func (client *MockRPCClient) Sync(ctx context.Context, bloom *bloom.Filter) (txgroups [][]transactions.SignedTxn, err error) {
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
func (client *MockRPCClient) GetBlockBytes(ctx context.Context, r basics.Round) (data []byte, err error) {
	return nil, nil
}

// network.HTTPPeer interface
func (client *MockRPCClient) GetAddress() string {
	return client.rootURL
}
func (client *MockRPCClient) GetHTTPClient() *http.Client {
	return nil
}
func (client *MockRPCClient) PrepareURL(x string) string {
	return strings.Replace(x, "{genesisID}", "test genesisID", -1)
}

type MockClientAggregator struct {
	peers []network.Peer
	Registrar
}

func (mca *MockClientAggregator) GetPeers(options ...network.PeerOption) []network.Peer {
	return mca.peers
}

const numberOfPeers = 10

func makeMockClientAggregator(t *testing.T, failWithNil bool, failWithError bool) *MockClientAggregator {
	clients := make([]network.Peer, 0)
	for i := 0; i < numberOfPeers; i++ {
		runner := MockRunner{failWithNil: failWithNil, failWithError: failWithError, done: make(chan *rpc.Call)}
		clients = append(clients, &MockRPCClient{client: &runner, log: logging.TestingLog(t)})
	}
	t.Logf("len(mca.clients) = %d", len(clients))
	return &MockClientAggregator{peers: clients}
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
	factory := MakeNetworkFetcherFactory(network, numberOfPeers, nil)
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
}

// FetcherClient interface
func (df *dummyFetcher) GetBlockBytes(ctx context.Context, r basics.Round) (data []byte, err error) {
	if df.failWithNil {
		return nil, nil
	}
	if df.failWithError {
		return nil, errors.New("failing call")
	}
	timer := time.NewTimer(goExecTime)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Fill in the dummy response with the correct round
	dummyBlock := EncodedBlockCert{
		Block: bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: r,
			},
		},
		Certificate: agreement.Certificate{
			Round: r,
		},
	}

	return protocol.Encode(dummyBlock), nil
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

func makeDummyFetchers(failWithNil bool, failWithError bool) []FetcherClient {
	out := make([]FetcherClient, numberOfPeers)
	for i := range out {
		out[i] = &dummyFetcher{failWithNil, failWithError}
	}
	return out
}

func TestFetchBlock(t *testing.T) {
	fetcher := &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           makeDummyFetchers(false, false),
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
		require.True(t, end.Sub(start) > goExecTime)
		require.True(t, end.Sub(start) < goExecTime+10*time.Millisecond)
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
		peers:           makeDummyFetchers(true, false),
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
		peers:           makeDummyFetchers(false, false),
		log:             logging.TestingLog(t),
	}

	start := time.Now()
	ctx, cf := context.WithTimeout(context.Background(), goExecTime/2)
	defer cf()
	_, _, client, err := fetcher.FetchBlock(ctx, basics.Round(1))
	end := time.Now()
	require.Error(t, err)
	require.Nil(t, client)
	require.True(t, end.Sub(start) > goExecTime/2)
	require.True(t, end.Sub(start) < goExecTime/2+10*time.Millisecond)
}

func TestFetchBlockTimeout(t *testing.T) {
	fetcher := &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           makeDummyFetchers(false, false),
		log:             logging.TestingLog(t),
	}

	start := time.Now()
	ctx, cf := context.WithTimeout(context.Background(), goExecTime/2)
	defer cf()
	_, _, client, err := fetcher.FetchBlock(ctx, basics.Round(1))
	end := time.Now()
	require.Error(t, err)
	require.Nil(t, client)
	require.True(t, end.Sub(start) > goExecTime/2)
	require.True(t, end.Sub(start) < goExecTime/2+10*time.Millisecond)
}

func TestFetchBlockErrorCall(t *testing.T) {
	fetcher := &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           makeDummyFetchers(false, true),
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
		peers:           makeDummyFetchers(false, false),
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
		require.True(t, end.Sub(start) > goExecTime)
		require.True(t, end.Sub(start) < goExecTime+10*time.Millisecond)
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
		peers:           makeDummyFetchers(true, false),
		log:             logging.TestingLog(t),
	}
	f2 := &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           makeDummyFetchers(false, false),
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
