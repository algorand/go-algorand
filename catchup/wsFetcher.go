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

// Buffer messages from the network to have fewer drops.
const numBufferedInternalMsg = 1

// WsFetcher implements Fetcher, getting the block over
// a custom websockets interface (bidirectional). Internally it keeps track
// of multiple peers and handles dropping them appropriately using a NetworkFetcher.
type WsFetcher struct {
	tag protocol.Tag // domain separation per request

	f       *NetworkFetcher
	clients map[network.Peer]*wsFetcherClient
	config  *config.Local

	// service
	service *rpcs.WsFetcherService

	// metadata
	log logging.Logger
	mu  deadlock.RWMutex
}

// MakeWsFetcher creates a fetcher that fetches over the gossip network.
// It instantiates a NetworkFetcher under the hood, registers as a handler for the given message tag,
// and demuxes messages appropriately to the corresponding fetcher clients.
func MakeWsFetcher(log logging.Logger, tag protocol.Tag, peers []network.Peer, service *rpcs.WsFetcherService, cfg *config.Local) Fetcher {
	f := &WsFetcher{
		log:    log,
		tag:    tag,
		config: cfg,
	}
	f.clients = make(map[network.Peer]*wsFetcherClient)
	p := make([]FetcherClient, len(peers))
	for i, peer := range peers {
		fc := &wsFetcherClient{
			target:      peer.(network.UnicastPeer),
			tag:         f.tag,
			pendingCtxs: make(map[context.Context]context.CancelFunc),
			service:     service,
			config:      cfg,
		}
		p[i] = fc
		f.clients[peer] = fc
	}
	f.f = &NetworkFetcher{
		roundUpperBound: make(map[FetcherClient]basics.Round),
		activeFetches:   make(map[FetcherClient]int),
		peers:           p,
		log:             f.log,
	}
	f.service = service
	return f
}

// FetchBlock implements Fetcher interface
func (wsf *WsFetcher) FetchBlock(ctx context.Context, r basics.Round) (*bookkeeping.Block, *agreement.Certificate, FetcherClient, error) {
	return wsf.f.FetchBlock(ctx, r)
}

// OutOfPeers implements Fetcher interface
func (wsf *WsFetcher) OutOfPeers(round basics.Round) bool {
	return wsf.f.OutOfPeers(round)
}

// NumPeers implements Fetcher interface
func (wsf *WsFetcher) NumPeers() int {
	return wsf.f.NumPeers()
}

// Close calls a delegate close fn passed in by the parent of this fetcher
func (wsf *WsFetcher) Close() {
	wsf.f.Close()
}

// a stub fetcherClient to satisfy the NetworkFetcher interface
type wsFetcherClient struct {
	target      network.UnicastPeer                    // the peer where we're going to send the request.
	tag         protocol.Tag                           // the tag that is associated with the request/
	service     *rpcs.WsFetcherService                 // the fetcher service. This is where we perform the actual request and waiting for the response.
	pendingCtxs map[context.Context]context.CancelFunc // a map of all the current pending contexts.
	config      *config.Local

	closed bool // a flag indicating that the fetcher will not perform additional block retrivals.

	mu deadlock.Mutex
}

// GetBlockBytes implements FetcherClient
func (w *wsFetcherClient) GetBlockBytes(ctx context.Context, r basics.Round) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, fmt.Errorf("wsFetcherClient(%d): shutdown", r)
	}

	childCtx, cancelFunc := context.WithTimeout(ctx, time.Duration(w.config.CatchupGossipBlockFetchTimeoutSec)*time.Second)
	w.pendingCtxs[childCtx] = cancelFunc
	w.mu.Unlock()

	defer func() {
		cancelFunc()
		// note that we don't need to have additional Unlock here since
		// we already have a defered Unlock above ( which executes in reversed order )
		w.mu.Lock()
		delete(w.pendingCtxs, childCtx)
	}()

	resp, err := w.service.RequestBlock(childCtx, w.target, r, w.tag)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("wsFetcherClient(%d): server error, %v", r, resp.Error)
	}
	if len(resp.BlockBytes) == 0 {
		return nil, fmt.Errorf("wsFetcherClient(%d): empty response", r)
	}
	return resp.BlockBytes, nil
}

// Address implements FetcherClient
func (w *wsFetcherClient) Address() string {
	return fmt.Sprintf("[ws] (%v)", w.target.GetAddress())
}

// Close is part of FetcherClient interface
func (w *wsFetcherClient) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	for _, cancelFunc := range w.pendingCtxs {
		cancelFunc()
	}
	w.pendingCtxs = make(map[context.Context]context.CancelFunc)
	return nil
}
