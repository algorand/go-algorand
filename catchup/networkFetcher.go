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

// NetworkFetcher is the struct used to export fetchBlock function from universalFetcher
type NetworkFetcher struct {
	log          logging.Logger
	cfg          config.Local
	auth         BlockAuthenticator
	peerSelector *peerSelector
	fetcher      *universalBlockFetcher
}

// MakeNetworkFetcher initializes a NetworkFetcher service
func MakeNetworkFetcher(log logging.Logger, net network.GossipNode, cfg config.Local, auth BlockAuthenticator, pipelineFetch bool) *NetworkFetcher {
	netFetcher := &NetworkFetcher{
		log:          log,
		cfg:          cfg,
		auth:         auth,
		peerSelector: createPeerSelector(net, cfg, pipelineFetch),
		fetcher:      makeUniversalBlockFetcher(log, net, cfg),
	}
	return netFetcher
}

func (netFetcher *NetworkFetcher) getHTTPPeer() (network.HTTPPeer, *peerSelectorPeer, error) {
	for retryCount := 0; retryCount < netFetcher.cfg.CatchupBlockDownloadRetryAttempts; retryCount++ {
		psp, err := netFetcher.peerSelector.getNextPeer()
		if err != nil {
			if err != errPeerSelectorNoPeerPoolsAvailable {
				err = fmt.Errorf("FetchBlock: unable to obtain a list of peers to download the block from : %w", err)
				return nil, nil, err
			}
			// this is a possible on startup, since the network package might have yet to retrieve the list of peers.
			netFetcher.log.Infof("FetchBlock: unable to obtain a list of peers to download the block from; will retry shortly.")
			time.Sleep(noPeersAvailableSleepInterval)
			continue
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
	for retryCount := 0; retryCount < netFetcher.cfg.CatchupBlockDownloadRetryAttempts; retryCount++ {
		httpPeer, psp, err := netFetcher.getHTTPPeer()
		if err != nil {
			return nil, nil, time.Duration(0), err
		}

		blk, cert, downloadDuration, err := netFetcher.fetcher.fetchBlock(ctx, round, httpPeer)
		if err != nil {
			if ctx.Err() != nil {
				// caller of the function decided to cancel the download
				return nil, nil, time.Duration(0), err
			}
			netFetcher.log.Infof("FetchBlock: failed to download block %d on attempt %d out of %d. %v",
				round, retryCount+1, netFetcher.cfg.CatchupBlockDownloadRetryAttempts, err)
			netFetcher.peerSelector.rankPeer(psp, peerRankDownloadFailed)
			continue // retry the fetch
		}

		// Check that the block's contents match the block header
		if !blk.ContentsMatchHeader() && blk.Round() > 0 {
			netFetcher.peerSelector.rankPeer(psp, peerRankInvalidDownload)
			// Check if this mismatch is due to an unsupported protocol version
			if _, ok := config.Consensus[blk.BlockHeader.CurrentProtocol]; !ok {
				netFetcher.log.Errorf("FetchBlock: downloaded block(%v) unsupported protocol version detected: '%v'",
					round, blk.BlockHeader.CurrentProtocol)
			}
			netFetcher.log.Warnf("FetchBlock: downloaded block(%v) contents do not match header", round)
			netFetcher.log.Infof("FetchBlock: failed to download block %d on attempt %d out of %d. %v",
				round, retryCount+1, netFetcher.cfg.CatchupBlockDownloadRetryAttempts, err)
			continue // retry the fetch
		}

		// Authenticate the block. for correct execution, caller should call FetchBlock only when the lookback block is available
		if netFetcher.cfg.CatchupVerifyCertificate() {
			err = netFetcher.auth.Authenticate(blk, cert)
			if err != nil {
				netFetcher.log.Warnf("FetchBlock: cert authenticatation failed for block %d on attempt %d out of %d. %v",
					round, retryCount+1, netFetcher.cfg.CatchupBlockDownloadRetryAttempts, err)
				netFetcher.peerSelector.rankPeer(psp, peerRankInvalidDownload)
				continue // retry the fetch
			}
		}

		// upon successful download rank the peer according to the download speed
		peerRank := netFetcher.peerSelector.peerDownloadDurationToRank(psp, downloadDuration)
		netFetcher.peerSelector.rankPeer(psp, peerRank)
		return blk, cert, downloadDuration, err

	}
	err := fmt.Errorf("FetchBlock failed after multiple blocks download attempts: %v unsuccessful attempts",
		netFetcher.cfg.CatchupBlockDownloadRetryAttempts)
	return nil, nil, time.Duration(0), err
}
