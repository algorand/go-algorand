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
	"fmt"
	"math/rand"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

// Fetcher queries the current block of the network, and fetches agreed-upon blocks
type Fetcher interface {
	// FetchBlock fetches a block for a given round.
	FetchBlock(ctx context.Context, r basics.Round) (*bookkeeping.Block, *agreement.Certificate, FetcherClient, error)

	// Whether the fetcher has anyone available to ask for the block associated with round
	OutOfPeers(round basics.Round) bool

	// NumPeers return the number of peers that this fetcher has available
	NumPeers() int

	// Close cleans up this fetcher
	Close()
}

// FetcherFactory creates fetchers
type FetcherFactory interface {
	// Create a new fetcher
	New() Fetcher
	// Create a new fetcher that also fetches from backup peers over gossip network utilising given message tag
	NewOverGossip(requestTag protocol.Tag) Fetcher
}

// NetworkFetcherFactory creates network fetchers
type NetworkFetcherFactory struct {
	net       network.GossipNode
	peerLimit int
	cfg       *config.Local

	log logging.Logger
}

func (factory NetworkFetcherFactory) makeHTTPFetcherFromPeer(log logging.Logger, peer network.Peer) FetcherClient {
	hp, ok := peer.(network.HTTPPeer)
	if ok {
		return MakeHTTPFetcher(log, hp, factory.net, factory.cfg)
	}
	log.Errorf("%T %#v is not HTTPPeer", peer, peer)
	return nil
}

// MakeNetworkFetcherFactory returns a network fetcher factory, that associates fetchers with no more than peerLimit peers from the aggregator.
// WSClientSource can be nil, if no network exists to create clients from (defaults to http clients)
func MakeNetworkFetcherFactory(net network.GossipNode, peerLimit int, cfg *config.Local) NetworkFetcherFactory {
	var factory NetworkFetcherFactory
	factory.net = net
	factory.peerLimit = peerLimit
	factory.log = logging.Base()
	factory.cfg = cfg
	return factory
}

// BuildFetcherClients returns a set of clients we can fetch blocks from
func (factory NetworkFetcherFactory) BuildFetcherClients() []FetcherClient {
	peers := factory.net.GetPeers(network.PeersPhonebookRelays)
	factory.log.Debugf("%d outgoing peers", len(peers))
	if len(peers) == 0 {
		factory.log.Warn("no outgoing peers for BuildFetcherClients")
		return nil
	}
	out := make([]FetcherClient, 0, len(peers))
	for _, peer := range peers {
		fetcher := factory.makeHTTPFetcherFromPeer(factory.log, peer)
		if fetcher != nil {
			out = append(out, fetcher)
		}
	}
	return out
}

// New returns a new fetcher
func (factory NetworkFetcherFactory) New() Fetcher {
	return &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           factory.BuildFetcherClients(),
		log:             logging.Base(),
	}
}

// NewOverGossip returns a fetcher using the given message tag.
// If there are gossip peers, then it returns a fetcher over gossip
// Otherwise, it returns an HTTP fetcher
// We should never build two fetchers utilising the same tag. Why?
func (factory NetworkFetcherFactory) NewOverGossip(tag protocol.Tag) Fetcher {
	gossipPeers := factory.net.GetPeers(network.PeersConnectedIn)
	factory.log.Debugf("%d gossip peers", len(gossipPeers))
	if len(gossipPeers) == 0 {
		factory.log.Info("no gossip peers for NewOverGossip")
		return factory.New()
	}
	f := MakeWsFetcher(factory.log, tag, gossipPeers, factory.cfg)
	return &ComposedFetcher{fetchers: []Fetcher{factory.New(), f}}
}

// NetworkFetcher fetches data from remote RPC clients
type NetworkFetcher struct {
	roundUpperBound map[FetcherClient]basics.Round
	activeFetches   map[FetcherClient]int
	peers           []FetcherClient
	mu              deadlock.RWMutex
	log             logging.Logger
}

func (networkFetcher *NetworkFetcher) availablePeers(round basics.Round) []FetcherClient {
	// filter clients who don't claim to have the round we want, and
	// return clients that have the fewest active fetches right now.
	minActiveFetches := -1
	for client, activeFetches := range networkFetcher.activeFetches {
		roundUpperBound, exists := networkFetcher.roundUpperBound[client]
		if exists && round >= roundUpperBound {
			continue
		}

		if minActiveFetches == -1 {
			minActiveFetches = activeFetches
		}
		if activeFetches < minActiveFetches {
			minActiveFetches = activeFetches
		}
	}

	pool := make([]FetcherClient, 0)
	for _, client := range networkFetcher.peers {
		activeFetches, exists := networkFetcher.activeFetches[client]
		if exists && activeFetches > minActiveFetches && minActiveFetches != -1 {
			continue
		}
		if roundUpperBound, exists := networkFetcher.roundUpperBound[client]; !exists || round < roundUpperBound {
			// client doesn't have this block
			pool = append(pool, client)
		}
	}

	return pool
}

func (networkFetcher *NetworkFetcher) selectClient(r basics.Round) (FetcherClient, error) {
	networkFetcher.mu.Lock()
	defer networkFetcher.mu.Unlock()

	availableClients := networkFetcher.availablePeers(r)
	if len(availableClients) == 0 {
		return nil, errors.New("no peers to ask")
	}

	// select one of the peers at random
	i := rand.Uint64() % uint64(len(availableClients))
	client := availableClients[i]
	networkFetcher.activeFetches[client] = networkFetcher.activeFetches[client] + 1
	return client, nil
}

func (networkFetcher *NetworkFetcher) releaseClient(client FetcherClient) {
	networkFetcher.mu.Lock()
	defer networkFetcher.mu.Unlock()
	networkFetcher.activeFetches[client] = networkFetcher.activeFetches[client] - 1
}

func (networkFetcher *NetworkFetcher) markPeerLastRound(client FetcherClient, round basics.Round) {
	networkFetcher.mu.Lock()
	defer networkFetcher.mu.Unlock()

	currentLastRound, hasBound := networkFetcher.roundUpperBound[client]
	if !hasBound || currentLastRound > round {
		networkFetcher.roundUpperBound[client] = round
	}
}

// FetchBlock returns a block for round r
func (networkFetcher *NetworkFetcher) FetchBlock(ctx context.Context, r basics.Round) (blk *bookkeeping.Block, cert *agreement.Certificate, rpcc FetcherClient, err error) {
	client, err := networkFetcher.selectClient(r)
	if err != nil {
		return
	}
	defer networkFetcher.releaseClient(client)
	networkFetcher.log.Infof("networkFetcher.FetchBlock: asking client %v for block %v", client.Address(), r)

	fetchedBuf, err := client.GetBlockBytes(ctx, r)
	if err != nil {
		networkFetcher.markPeerLastRound(client, r)
		err = fmt.Errorf("Peer %v: %v", client.Address(), err)
		return
	}
	block, cert, err := processBlockBytes(fetchedBuf, r, client.Address())
	if err != nil {
		networkFetcher.markPeerLastRound(client, r)
		return
	}
	return block, cert, client, nil
}

// NumPeers return the number of peers that this fetcher has available
func (networkFetcher *NetworkFetcher) NumPeers() int {
	networkFetcher.mu.RLock()
	defer networkFetcher.mu.RUnlock()

	return len(networkFetcher.peers)
}

// OutOfPeers returns whether there are any peers that may have the block of a particular round
func (networkFetcher *NetworkFetcher) OutOfPeers(round basics.Round) bool {
	networkFetcher.mu.RLock()
	defer networkFetcher.mu.RUnlock()

	return len(networkFetcher.availablePeers(round)) == 0
}

// Close implements Fetcher. Nothing to clean up here.
func (networkFetcher *NetworkFetcher) Close() {}

// ComposedFetcher wraps multiple fetchers in some priority order
type ComposedFetcher struct {
	fetchers []Fetcher // ordered by priority
}

// NumPeers implements Fetcher.NumPeers
func (cf *ComposedFetcher) NumPeers() int {
	g := 0
	for _, f := range cf.fetchers {
		g += f.NumPeers()
	}
	return g
}

// OutOfPeers implements Fetcher.OutOfPeers
func (cf *ComposedFetcher) OutOfPeers(round basics.Round) bool {
	for _, f := range cf.fetchers {
		if !f.OutOfPeers(round) {
			return false
		}
	}
	return true
}

// FetchBlock implements Fetcher.FetchBlock
func (cf *ComposedFetcher) FetchBlock(ctx context.Context, r basics.Round) (blk *bookkeeping.Block, cert *agreement.Certificate, rpcc FetcherClient, err error) {
	for _, f := range cf.fetchers {
		if f.OutOfPeers(r) {
			continue
		}
		return f.FetchBlock(ctx, r)
	}
	err = errors.New("no peers in any fetchers")
	return
}

// Close implements Fetcher.Close
func (cf *ComposedFetcher) Close() {
	for _, f := range cf.fetchers {
		f.Close()
	}
}

/* Utils */

func processBlockBytes(fetchedBuf []byte, r basics.Round, debugStr string) (blk *bookkeeping.Block, cert *agreement.Certificate, err error) {
	var decodedEntry rpcs.EncodedBlockCert
	err = protocol.Decode(fetchedBuf, &decodedEntry)
	if err != nil {
		err = fmt.Errorf("networkFetcher.FetchBlock(%d): cannot decode block from peer %v: %v", r, debugStr, err)
		return
	}

	if decodedEntry.Block.Round() != r {
		err = fmt.Errorf("networkFetcher.FetchBlock(%d): got wrong block from peer %v: wanted %v, got %v", r, debugStr, r, decodedEntry.Block.Round())
		return
	}

	if decodedEntry.Certificate.Round != r {
		err = fmt.Errorf("networkFetcher.FetchBlock(%d): got wrong cert from peer %v: wanted %v, got %v", r, debugStr, r, decodedEntry.Certificate.Round)
		return
	}
	return &decodedEntry.Block, &decodedEntry.Certificate, nil
}
