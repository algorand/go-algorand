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
	"fmt"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
)

// UniversalFetcher fetches blocks either from an http peer or ws peer.
type universalFetcher struct {
	config config.Local
	net    network.GossipNode
	log    logging.Logger
}

// Fetcher queries the current block of the network, and fetches agreed-upon blocks
type blockFetcher interface {
	// fetchBlock fetches a block for a given round.
	fetchBlock(ctx context.Context, round basics.Round, peer network.Peer) (blk *bookkeeping.Block,
		cert *agreement.Certificate, downloadDuration time.Duration, err error)
}

// FetcherFactory creates fetchers
type blockFetcherFactory interface {
	// Create a new fetcher
	newBlockFetcher() blockFetcher
}

type universalBlockFetcherFactory struct {
	log    logging.Logger
	net    network.GossipNode
	config config.Local
}

func makeUniversalBlockFetcherFactory(log logging.Logger, net network.GossipNode, config config.Local) blockFetcherFactory {
	return &universalBlockFetcherFactory{
		log:    log,
		net:    net,
		config: config}
}

func (uff *universalBlockFetcherFactory) newBlockFetcher() blockFetcher {
	return makeUniversalBlockFetcher(uff.log, uff.net, uff.config)
}

// MakeUniversalFetcher returns a fetcher for http and ws peers.
func makeUniversalBlockFetcher(log logging.Logger, net network.GossipNode, config config.Local) blockFetcher {
	return &universalFetcher{
		config: config,
		net:    net,
		log:    log}
}

// FetchBlock returns a block from the peer. The peer can be either an http or ws peer.
func (uf *universalFetcher) fetchBlock(ctx context.Context, round basics.Round, peer network.Peer) (blk *bookkeeping.Block,
	cert *agreement.Certificate, downloadDuration time.Duration, err error) {

	var fetcherClient FetcherClient
	httpPeer, validHTTPPeer := peer.(network.HTTPPeer)
	if validHTTPPeer {
		fetcherClient = &HTTPFetcher{
			peer:    httpPeer,
			rootURL: httpPeer.GetAddress(),
			net:     uf.net,
			client:  httpPeer.GetHTTPClient(),
			log:     uf.log,
			config:  &uf.config}
	} else if wsPeer, validWSPeer := peer.(network.UnicastPeer); validWSPeer {
		fetcherClient = &wsFetcherClient{
			target:      wsPeer,
			pendingCtxs: make(map[context.Context]context.CancelFunc),
			config:      &uf.config,
		}
	} else {
		return nil, nil, time.Duration(0), fmt.Errorf("FetchBlock: UniversalFetcher only supports HTTPPeer or UnicastPeer")
	}

	fetchedBuf, err := fetcherClient.GetBlockBytes(ctx, round)
	if err != nil {
		return nil, nil, time.Duration(0), err
	}
	block, cert, err := processBlockBytes(fetchedBuf, round, fetcherClient.Address())
	if err != nil {
		return nil, nil, time.Duration(0), err
	}
	return block, cert, downloadDuration, err
}
