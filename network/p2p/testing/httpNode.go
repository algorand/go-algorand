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

type P2PHTTPNode struct {
	mocks.MockNetwork
	host.Host
	httpServer *p2p.HTTPServer
	peers      []network.Peer
	tb         testing.TB
	genesisID  string
}

// MakeP2PHost returns a new libp2p host.
func MakeP2PHTTPNode(tb testing.TB) *P2PHTTPNode {
	p2pHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(tb, err)

	return &P2PHTTPNode{
		Host:       p2pHost,
		httpServer: p2p.MakeHTTPServer(p2pHost),
		tb:         tb,
	}
}

func (p *P2PHTTPNode) RegisterHTTPHandler(path string, handler http.Handler) {
	p.httpServer.RegisterHTTPHandler(path, handler)
}

func (p *P2PHTTPNode) RegisterHandlers(dispatch []network.TaggedMessageHandler) {}

func (p *P2PHTTPNode) Start() error {
	go p.httpServer.Serve()
	return nil
}

func (p *P2PHTTPNode) Stop() {
	p.httpServer.Close()
	p.Host.Close()
}

func (p *P2PHTTPNode) GetGenesisID() string          { return p.genesisID }
func (p *P2PHTTPNode) SetGenesisID(genesisID string) { p.genesisID = genesisID }

type httpPeer struct {
	addrInfo peer.AddrInfo
	tb       testing.TB
}

func (p httpPeer) GetAddress() string {
	mas, err := peer.AddrInfoToP2pAddrs(&p.addrInfo)
	require.NoError(p.tb, err)
	require.Len(p.tb, mas, 1)
	return mas[0].String()
}

func (p httpPeer) GetHTTPClient() *http.Client {
	c, err := p2p.MakeHTTPClient(&p.addrInfo)
	require.NoError(p.tb, err)
	return c
}

func (p *P2PHTTPNode) SetPeers(other *P2PHTTPNode) {
	addrInfo := peer.AddrInfo{ID: other.ID(), Addrs: other.Addrs()}
	httpPeer := httpPeer{addrInfo, p.tb}
	p.peers = append(p.peers, httpPeer)
}

func (p *P2PHTTPNode) GetPeers(options ...network.PeerOption) []network.Peer {
	return p.peers
}
