// Copyright (C) 2019-2022 Algorand, Inc.
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
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
)

// NetworkFetcher is the interface used to export fetchBlock function from universalFetcher
type NetworkFetcher interface {
	// FetchBlock function creates a new universalBlockFetcher and calls the internal fetchBlock method
	// for a given context and round number
	FetchBlock(ctx context.Context, round basics.Round) (blk *bookkeeping.Block,
		cert *agreement.Certificate, downloadDuration time.Duration, err error)
}

type networkFetcherImpl struct {
	log          logging.Logger
	cfg          config.Local
	net          network.GossipNode
	peerSelector *peerSelector
}

// NewNetworkFetcher initializes a NetworkFetcher service
func NewNetworkFetcher(log logging.Logger, net network.GossipNode, cfg config.Local, pipelineFetch bool) NetworkFetcher {
	netFetcher := &networkFetcherImpl{
		net: net,
		cfg: cfg,
		log: log,
	}
	// creating peerselector for the network fetcher
	netFetcher.peerSelector = createPeerSelector(net, cfg, pipelineFetch)
	return netFetcher
}

// FetchBlock function creates a new universalBlockFetcher and calls the internal fetchBlock method for a given context and round number
func (netFetcher *networkFetcherImpl) FetchBlock(ctx context.Context, round basics.Round) (blk *bookkeeping.Block,
	cert *agreement.Certificate, downloadDuration time.Duration, err error) {
	fetch := makeUniversalBlockFetcher(netFetcher.log, netFetcher.net, netFetcher.cfg)
	psp, err := netFetcher.peerSelector.getNextPeer()
	if err != nil {
		return
	}
	peer := psp.Peer
	httpPeer, ok := peer.(network.HTTPPeer)
	if !ok {
		netFetcher.log.Warnf("fetchBlock: non-HTTP peer was provided by the peer selector")
	}
	blk, cert, _, err = fetch.fetchBlock(ctx, round, httpPeer)
	if err != nil {
		return
	}
	// Check that the block's contents match the block header (necessary with an untrusted block because b.Hash() only hashes the header)
	if blk == nil || cert == nil {
		err = errors.New("invalid block download")
	} else if !blk.ContentsMatchHeader() && blk.Round() > 0 {
		netFetcher.peerSelector.rankPeer(psp, peerRankInvalidDownload)
		// Check if this mismatch is due to an unsupported protocol version
		if _, ok := config.Consensus[blk.BlockHeader.CurrentProtocol]; !ok {
			netFetcher.log.Errorf("fetchAndWrite(%v): unsupported protocol version detected: '%v'", round, blk.BlockHeader.CurrentProtocol)
		}
		netFetcher.log.Warnf("fetchAndWrite(%v): block contents do not match header (attempt %d)", round, 1)
		// continue // retry the fetch: add a loop over here
		err = errors.New("invalid block download")
	}
	return

}
