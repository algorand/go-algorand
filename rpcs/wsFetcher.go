// Copyright (C) 2019 Algorand, Inc.
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
	"fmt"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
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

	// cleanup
	closeFn func(*WsFetcher)

	// metadata
	log logging.Logger
	mu  deadlock.RWMutex
}

// MakeWsFetcher creates a fetcher that fetches over the gossip network.
// It instantiates a NetworkFetcher under the hood, registers as a handler for the given message tag,
// and demuxes messages appropriately to the corresponding fetcher clients.
func MakeWsFetcher(log logging.Logger, tag protocol.Tag, peers []network.Peer, closeFn func(*WsFetcher)) Fetcher {
	f := &WsFetcher{
		log: log,
		tag: tag,
	}
	f.clients = make(map[network.Peer]*wsFetcherClient)
	p := make([]FetcherClient, len(peers))
	for i, peer := range peers {
		fc := &wsFetcherClient{
			target:    peer.(network.UnicastPeer),
			tag:       f.tag,
			listeners: map[uint64]chan WsGetBlockOut{},
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
	f.closeFn = closeFn
	return f
}

// HandleNetworkMsg is the entry point for replies from the network (routed from WsFetcherService).
func (wsf *WsFetcher) HandleNetworkMsg(msg network.IncomingMessage) (n network.OutgoingMessage) {
	if msg.Tag.Complement() != wsf.tag {
		wsf.log.Errorf("WsFetcher: configuration failed. Handling mismatched tag type %v != %v", wsf.tag, msg.Tag)
	}

	var reqErr error
	var resp WsGetBlockOut
	uniPeer := msg.Sender.(network.UnicastPeer)
	defer func() {
		// drop useless peers
		if reqErr != nil {
			// the request fundamentally failed
			wsf.log.Infof("WsFetcher(%v): request failed: %v", uniPeer.GetAddress(), reqErr)
			wsf.mu.RLock()
			client := wsf.clients[uniPeer]
			wsf.mu.RUnlock()
			client.Close()
		}
	}()

	if msg.Data == nil {
		reqErr = errors.New("catchup response no bytes sent")
		return
	}
	reqErr = protocol.Decode(msg.Data, &resp)
	if reqErr != nil {
		return
	}
	wsf.log.Debugf("WsFetcher(%v): received message: %v", uniPeer.GetAddress(), reqErr)
	// now, actually handle the block
	wsf.mu.RLock()
	client := wsf.clients[uniPeer]
	wsf.mu.RUnlock()
	clientCh := client.getChForRound(resp.Round)
	if clientCh != nil {
		clientCh <- resp
	}
	return
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
	if wsf.closeFn != nil {
		wsf.closeFn(wsf)
	}
}

// a stub fetcherClient to satisfy the NetworkFetcher interface
type wsFetcherClient struct {
	listeners map[uint64]chan WsGetBlockOut
	target    network.UnicastPeer
	tag       protocol.Tag

	closed bool

	mu deadlock.RWMutex
}

func (w *wsFetcherClient) getChForRound(r uint64) chan WsGetBlockOut {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	v, ok := w.listeners[r]
	if !ok {
		v = make(chan WsGetBlockOut, numBufferedInternalMsg)
		w.listeners[r] = v
	}
	return v
}

// GetBlockBytes implements FetcherClient
func (w *wsFetcherClient) GetBlockBytes(ctx context.Context, r basics.Round) ([]byte, error) {
	listen := w.getChForRound(uint64(r))
	if listen == nil {
		return nil, fmt.Errorf("wsFetcherClient(%d): preconnection closed", r)
	}

	// unicast
	req := WsGetBlockRequest{Round: uint64(r)}
	err := w.target.Unicast(ctx, protocol.Encode(req), w.tag)
	if err != nil {
		return nil, fmt.Errorf("wsFetcherClient(%d): unicast failed, %v", r, err)
	}

	// now, wait for reply
	select {
	case resp, ok := <-listen:
		if !ok {
			return nil, fmt.Errorf("wsFetcherClient(%d): connection closed", r)
		}
		if resp.Error != "" {
			return nil, fmt.Errorf("wsFetcherClient(%d): server error, %v", r, resp.Error)
		}
		if resp.BlockBytes == nil {
			return nil, fmt.Errorf("wsFetcherClient(%d): empty response", r)
		}
		return resp.BlockBytes, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("wsFetcherClient(%d): cancelled by caller", r)
	}
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
	for k, c := range w.listeners {
		close(c)
		delete(w.listeners, k)
	}
	return nil
}
