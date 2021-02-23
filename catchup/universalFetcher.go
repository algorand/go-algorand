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
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
)

// UniversalFetcher fetches blocks either from an http peer or ws peer.
type UniversalFetcher struct {
	config config.Local
	net    network.GossipNode
	log    logging.Logger
}

// MakeUniversalFetcher returns a fetcher for http and ws peers.
func MakeUniversalFetcher(config config.Local, net network.GossipNode, log logging.Logger) UniversalFetcher {
	return UniversalFetcher{
		config: config,
		net:    net,
		log:    log}
}

// FetchBlock returns a block from the peer. The peer can be either an http or ws peer.
func (uf *UniversalFetcher) FetchBlock(ctx context.Context, round basics.Round, peer network.Peer) (blk *bookkeeping.Block,
	cert *agreement.Certificate, downloadDuration time.Duration, err error) {

	httpPeer, validHTTPPeer := peer.(network.HTTPPeer)
	if validHTTPPeer {
		fetcher := makeHTTPFetcher(uf.log, httpPeer, uf.net, &uf.config)
		blk, cert, downloadDuration, err = uf.fetchBlockHTTP(ctx, fetcher, round)

	} else {
		fetcher := MakeWsFetcher(uf.log, []network.Peer{peer}, &uf.config)
		blk, cert, downloadDuration, err = uf.fetchBlockWs(ctx, fetcher, round)
	}
	return blk, cert, downloadDuration, err
}

func (uf *UniversalFetcher) fetchBlockWs(ctx context.Context, wsf Fetcher, round basics.Round) (*bookkeeping.Block,
	*agreement.Certificate, time.Duration, error) {
	blockDownloadStartTime := time.Now()
	blk, cert, client, err := wsf.FetchBlock(ctx, round)
	if err != nil {
		return nil, nil, time.Duration(0), err
	}
	client.Close()
	downloadDuration := time.Now().Sub(blockDownloadStartTime)
	return blk, cert, downloadDuration, nil
}

func (uf *UniversalFetcher) fetchBlockHTTP(ctx context.Context, hf *HTTPFetcher, round basics.Round) (blk *bookkeeping.Block,
	cert *agreement.Certificate, dur time.Duration, err error) {
	blockDownloadStartTime := time.Now()
	blk, cert, err = hf.FetchBlock(ctx, round)
	downloadDuration := time.Now().Sub(blockDownloadStartTime)
	if err != nil {
		return nil, nil, time.Duration(0), err
	}
	return blk, cert, downloadDuration, err
}
