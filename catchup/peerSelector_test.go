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
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

type mockHTTPPeer struct {
	address string
}

func (d *mockHTTPPeer) GetAddress() string {
	return d.address
}
func (d *mockHTTPPeer) GetHTTPClient() *http.Client {
	return nil
}

type mockUnicastPeer struct {
	address string
}

func (d *mockUnicastPeer) GetAddress() string {
	return d.address
}
func (d *mockUnicastPeer) Unicast(ctx context.Context, data []byte, tag protocol.Tag) error {
	return nil
}
func (d *mockUnicastPeer) Version() string {
	return ""
}
func (d *mockUnicastPeer) Request(ctx context.Context, tag network.Tag, topics network.Topics) (resp *network.Response, e error) {
	return nil, nil
}
func (d *mockUnicastPeer) Respond(ctx context.Context, reqMsg network.IncomingMessage, topics network.Topics) (e error) {
	return nil
}

func TestPeerAddress(t *testing.T) {
	httpPeer := &mockHTTPPeer{address: "12345"}
	require.Equal(t, "12345", peerAddress(httpPeer))

	unicastPeer := &mockUnicastPeer{address: "67890"}
	require.Equal(t, "67890", peerAddress(unicastPeer))

	require.Equal(t, "", peerAddress(nil))
	require.Equal(t, "", peerAddress(t))
}

func TestDownloadDurationToRank(t *testing.T) {
	// verify mid value
	require.Equal(t, 1500, downloadDurationToRank(50*time.Millisecond, 0*time.Millisecond, 100*time.Millisecond, 1000, 2000))
	// check bottom
	require.Equal(t, 1000, downloadDurationToRank(0*time.Millisecond, 0*time.Millisecond, 100*time.Millisecond, 1000, 2000))
	// check top
	require.Equal(t, 2000, downloadDurationToRank(100*time.Millisecond, 0*time.Millisecond, 100*time.Millisecond, 1000, 2000))
	// check below bottom
	require.Equal(t, 1000, downloadDurationToRank(0*time.Millisecond, 100*time.Millisecond, 200*time.Millisecond, 1000, 2000))
	// check above top
	require.Equal(t, 2000, downloadDurationToRank(205*time.Millisecond, 100*time.Millisecond, 200*time.Millisecond, 1000, 2000))
}

type networkGetPeersStub struct {
	getPeersStub func(options ...network.PeerOption) []network.Peer
}

func (n *networkGetPeersStub) GetPeers(options ...network.PeerOption) []network.Peer {
	return n.getPeersStub(options...)
}

func makeNetworkGetPeersStub(fnc func(options ...network.PeerOption) []network.Peer) *networkGetPeersStub {
	return &networkGetPeersStub{
		getPeersStub: fnc,
	}
}
func TestPeerSelector(t *testing.T) {
	peers := []network.Peer{&mockHTTPPeer{address: "12345"}}

	peerSelector := makePeerSelector(
		makeNetworkGetPeersStub(func(options ...network.PeerOption) []network.Peer {
			return peers
		}), []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivers}},
	)

	peer, err := peerSelector.GetNextPeer()
	require.NoError(t, err)
	require.Equal(t, "12345", peerAddress(peer))

	// replace peer.
	peers = []network.Peer{&mockHTTPPeer{address: "54321"}}
	peer, err = peerSelector.GetNextPeer()
	require.NoError(t, err)
	require.Equal(t, "54321", peerAddress(peer))

	// add another peer
	peers = []network.Peer{&mockHTTPPeer{address: "54321"}, &mockHTTPPeer{address: "abcde"}}
	peerSelector.RankPeer(peer, 5)

	peer, err = peerSelector.GetNextPeer()
	require.NoError(t, err)
	require.Equal(t, "abcde", peerAddress(peer))

	peerSelector.RankPeer(peer, 10)

	peer, err = peerSelector.GetNextPeer()
	require.NoError(t, err)
	require.Equal(t, "54321", peerAddress(peer))

	return
}
