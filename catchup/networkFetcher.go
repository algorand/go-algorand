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
	"fmt"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
)

// retryCount keeps count of attempts made to fetch a block from peers
var retryCount int

// NetworkFetcher is the struct used to export fetchBlock function from universalFetcher
type NetworkFetcher struct {
	log          logging.Logger
	net          network.GossipNode
	cfg          config.Local
	peerSelector *peerSelector
}

// MakeNetworkFetcher initializes a NetworkFetcher service
func MakeNetworkFetcher(log logging.Logger, net network.GossipNode, cfg config.Local, pipelineFetch bool) *NetworkFetcher {
	netFetcher := &NetworkFetcher{
		log:          log,
		net:          net,
		cfg:          cfg,
		peerSelector: createPeerSelector(net, cfg, pipelineFetch),
	}
	return netFetcher
}

func (netFetcher *NetworkFetcher) getHTTPPeer() (network.HTTPPeer, *peerSelectorPeer, error) {
	for ; retryCount < netFetcher.cfg.CatchupBlockDownloadRetryAttempts; retryCount++ {
		psp, err := netFetcher.peerSelector.getNextPeer()
		if err != nil {
			if err == errPeerSelectorNoPeerPoolsAvailable {
				netFetcher.log.Infof("FetchBlock: unable to obtain a list of peers to download the block from; will retry shortly.")
				// this is a possible on startup, since the network package might have yet to retrieve the list of peers.
				time.Sleep(noPeersAvailableSleepInterval)
			}
			err = fmt.Errorf("FetchBlock: unable to obtain a list of peers to download the block from : %w", err)
			return nil, nil, err
		}
		peer := psp.Peer
		httpPeer, ok := peer.(network.HTTPPeer)
		if ok {
			return httpPeer, psp, nil
		}
		netFetcher.log.Warnf("FetchBlock: non-HTTP peer was provided by the peer selector")
		netFetcher.peerSelector.rankPeer(psp, peerRankInvalidDownload)
	}
	return nil, nil, errors.New("FetchBlock: recurring non-HTTP peer was provided by the peer selector")
}

// FetchBlock function given a round number returns a block from a http peer
func (netFetcher *NetworkFetcher) FetchBlock(ctx context.Context, round basics.Round) (*bookkeeping.Block,
	*agreement.Certificate, time.Duration, error) {
	// internal retry attempt to fetch the block
	retryCount = 0
	for ; retryCount < netFetcher.cfg.CatchupBlockDownloadRetryAttempts; retryCount++ {
		// keep retrying until a valid http peer is selected by the peerSelector
		httpPeer, psp, err := netFetcher.getHTTPPeer()
		if err != nil {
			return nil, nil, time.Duration(0), err
		}
		fetcher := makeUniversalBlockFetcher(netFetcher.log, netFetcher.net, netFetcher.cfg)
		blk, cert, downloadDuration, err := fetcher.fetchBlock(ctx, round, httpPeer)
		if err != nil {
			if ctx.Err() != nil {
				// caller of the function decided to cancel the download
				return nil, nil, time.Duration(0), err
			}
			netFetcher.log.Infof("FetchBlock: failed to download block %d on attempt %d out of %d. %v", round, retryCount, netFetcher.cfg.CatchupBlockDownloadRetryAttempts, err)
			netFetcher.peerSelector.rankPeer(psp, peerRankDownloadFailed)
		} else if !blk.ContentsMatchHeader() && blk.Round() > 0 {
			netFetcher.peerSelector.rankPeer(psp, peerRankInvalidDownload)
			// Check if this mismatch is due to an unsupported protocol version
			if _, ok := config.Consensus[blk.BlockHeader.CurrentProtocol]; !ok {
				netFetcher.log.Errorf("FetchBlock: downloaded block(%v) unsupported protocol version detected: '%v'", round, blk.BlockHeader.CurrentProtocol)
			}
			netFetcher.log.Warnf("FetchBlock: downloaded block(%v) contents do not match header", round)
			netFetcher.log.Infof("FetchBlock: failed to download block %d on attempt %d out of %d. %v", round, retryCount, netFetcher.cfg.CatchupBlockDownloadRetryAttempts, err)
		} else {
			// upon successful download rank the peer according to the download speed
			peerRank := netFetcher.peerSelector.peerDownloadDurationToRank(psp, downloadDuration)
			netFetcher.peerSelector.rankPeer(psp, peerRank)
			return blk, cert, downloadDuration, err
		}
	}
	return nil, nil, time.Duration(0), errors.New("FetchBlock failed after multiple blocks download attempts")
}
