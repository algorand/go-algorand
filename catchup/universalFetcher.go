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
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

// UniversalFetcher fetches blocks either from an http peer or ws peer.
type universalBlockFetcher struct {
	config config.Local
	net    network.GossipNode
	log    logging.Logger
}

// makeUniversalFetcher returns a fetcher for http and ws peers.
func makeUniversalBlockFetcher(log logging.Logger, net network.GossipNode, config config.Local) *universalBlockFetcher {
	return &universalBlockFetcher{
		config: config,
		net:    net,
		log:    log}
}

// FetchBlock returns a block from the peer. The peer can be either an http or ws peer.
func (uf *universalBlockFetcher) fetchBlock(ctx context.Context, round basics.Round, peer network.Peer) (blk *bookkeeping.Block,
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

func processBlockBytes(fetchedBuf []byte, r basics.Round, debugStr string) (blk *bookkeeping.Block, cert *agreement.Certificate, err error) {
	var decodedEntry rpcs.EncodedBlockCert
	if uint64(r) == 0 {
		r = 0
	}
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
