// Copyright (C) 2019-2024 Algorand, Inc.
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

// This package wraps and re-exports the libp2p functions on order to keep
// all go-libp2p imports in one place.

package p2p

import (
	"net/http"
	"testing"

	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/network/p2p"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

// HTTPNode is a mock network node that uses libp2p and http.
type HTTPNode struct {
	mocks.MockNetwork
	host.Host
	httpServer *p2p.HTTPServer
	peers      []network.Peer
	tb         testing.TB
	genesisID  string
}

// MakeHTTPNode returns a new P2PHTTPNode node.
func MakeHTTPNode(tb testing.TB) *HTTPNode {
	p2pHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(tb, err)

	return &HTTPNode{
		Host:       p2pHost,
		httpServer: p2p.MakeHTTPServer(p2pHost),
		tb:         tb,
	}
}

// RegisterHTTPHandler registers a http handler with a given path.
func (p *HTTPNode) RegisterHTTPHandler(path string, handler http.Handler) {
	p.httpServer.RegisterHTTPHandler(path, handler)
}

// RegisterHandlers not implemented.
func (p *HTTPNode) RegisterHandlers(dispatch []network.TaggedMessageHandler) {}

// Start starts http service
func (p *HTTPNode) Start() error {
	go func() {
		err := p.httpServer.Serve()
		require.NoError(p.tb, err)
	}()
	return nil
}

// Stop stops http service
func (p *HTTPNode) Stop() {
	p.httpServer.Close()
	p.Host.Close()
}

// GetHTTPPeer returns the http peer for connecting to this node
func (p *HTTPNode) GetHTTPPeer() network.Peer {
	addrInfo := peer.AddrInfo{ID: p.ID(), Addrs: p.Addrs()}
	return httpPeer{addrInfo, p.tb}
}

// GetGenesisID returns genesisID
func (p *HTTPNode) GetGenesisID() string { return p.genesisID }

// SetGenesisID sets genesisID
func (p *HTTPNode) SetGenesisID(genesisID string) { p.genesisID = genesisID }

type httpPeer struct {
	addrInfo peer.AddrInfo
	tb       testing.TB
}

// GetAddress implements HTTPPeer interface returns the address of the peer
func (p httpPeer) GetAddress() string {
	mas, err := peer.AddrInfoToP2pAddrs(&p.addrInfo)
	require.NoError(p.tb, err)
	require.Len(p.tb, mas, 1)
	return mas[0].String()
}

// GetHTTPClient implements HTTPPeer interface and returns the http client for a peer
func (p httpPeer) GetHTTPClient() *http.Client {
	c, err := p2p.MakeTestHTTPClient(&p.addrInfo)
	require.NoError(p.tb, err)
	return c
}

// SetPeers sets peers
func (p *HTTPNode) SetPeers(other *HTTPNode) {
	addrInfo := peer.AddrInfo{ID: other.ID(), Addrs: other.Addrs()}
	hpeer := httpPeer{addrInfo, p.tb}
	p.peers = append(p.peers, hpeer)
}

// GetPeers returns peers
func (p *HTTPNode) GetPeers(options ...network.PeerOption) []network.Peer {
	return p.peers
}
