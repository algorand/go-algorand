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
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
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

	// repeat the above tests with zero rank range, and make sure the results are always zero
	// verify mid value
	require.Equal(t, 0, downloadDurationToRank(50*time.Millisecond, 0*time.Millisecond, 100*time.Millisecond, 0, 0))
	// check bottom
	require.Equal(t, 0, downloadDurationToRank(0*time.Millisecond, 0*time.Millisecond, 100*time.Millisecond, 0, 0))
	// check top
	require.Equal(t, 0, downloadDurationToRank(100*time.Millisecond, 0*time.Millisecond, 100*time.Millisecond, 0, 0))
	// check below bottom
	require.Equal(t, 0, downloadDurationToRank(0*time.Millisecond, 100*time.Millisecond, 200*time.Millisecond, 0, 0))
	// check above top
	require.Equal(t, 0, downloadDurationToRank(205*time.Millisecond, 100*time.Millisecond, 200*time.Millisecond, 0, 0))
}

type peersRetrieverStub struct {
	getPeersStub func(options ...network.PeerOption) []network.Peer
}

func (n *peersRetrieverStub) GetPeers(options ...network.PeerOption) []network.Peer {
	return n.getPeersStub(options...)
}

func makePeersRetrieverStub(fnc func(options ...network.PeerOption) []network.Peer) *peersRetrieverStub {
	return &peersRetrieverStub{
		getPeersStub: fnc,
	}
}
func TestPeerSelector(t *testing.T) {
	peers := []network.Peer{&mockHTTPPeer{address: "12345"}}

	peerSelector := makePeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) []network.Peer {
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
	require.True(t, peerSelector.RankPeer(peer, 5))

	peer, err = peerSelector.GetNextPeer()
	require.NoError(t, err)
	require.Equal(t, "abcde", peerAddress(peer))

	require.True(t, peerSelector.RankPeer(peer, 10))

	peer, err = peerSelector.GetNextPeer()
	require.NoError(t, err)
	require.Equal(t, "54321", peerAddress(peer))

	peers = []network.Peer{t} // include a non-peer object, to test the refreshAvailablePeers handling of empty addresses.
	peer, err = peerSelector.GetNextPeer()
	require.Equal(t, errPeerSelectorNoPeerPoolsAvailable, err)
	require.Nil(t, peer)

	// create an empty entry ( even though the code won't let it happen )
	peerSelector.pools = []peerPool{{rank: peerRankInitialFirstPriority}}
	peer, err = peerSelector.GetNextPeer()
	require.Equal(t, errPeerSelectorNoPeerPoolsAvailable, err)
	require.Nil(t, peer)

	require.False(t, peerSelector.RankPeer(nil, 10))
	require.False(t, peerSelector.RankPeer(&mockHTTPPeer{address: "abc123"}, 10))

	return
}

func TestPeerDownloadRanking(t *testing.T) {
	peers1 := []network.Peer{&mockHTTPPeer{address: "1234"}, &mockHTTPPeer{address: "5678"}}
	peers2 := []network.Peer{&mockHTTPPeer{address: "abcd"}, &mockHTTPPeer{address: "efgh"}}

	peerSelector := makePeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) (peers []network.Peer) {
			for _, opt := range options {
				if opt == network.PeersPhonebookArchivers {
					peers = append(peers, peers1...)
				} else {
					peers = append(peers, peers2...)
				}
			}
			return
		}), []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivers},
			{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays}},
	)
	archivalPeer, err := peerSelector.GetNextPeer()
	require.NoError(t, err)

	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank0LowBlockTime, peerRank0HighBlockTime), peerSelector.PeerDownloadDurationToRank(archivalPeer, 500*time.Millisecond))

	peerSelector.RankPeer(archivalPeer, peerRankInvalidDownload)

	archivalPeer, err = peerSelector.GetNextPeer()
	require.NoError(t, err)

	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank0LowBlockTime, peerRank0HighBlockTime), peerSelector.PeerDownloadDurationToRank(archivalPeer, 500*time.Millisecond))

	peerSelector.RankPeer(archivalPeer, peerRankInvalidDownload)

	// and now test the relay peers
	relayPeer, err := peerSelector.GetNextPeer()
	require.NoError(t, err)

	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank1LowBlockTime, peerRank1HighBlockTime), peerSelector.PeerDownloadDurationToRank(relayPeer, 500*time.Millisecond))

	peerSelector.RankPeer(relayPeer, peerRankInvalidDownload)

	relayPeer, err = peerSelector.GetNextPeer()
	require.NoError(t, err)

	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank1LowBlockTime, peerRank1HighBlockTime), peerSelector.PeerDownloadDurationToRank(relayPeer, 500*time.Millisecond))

	peerSelector.RankPeer(relayPeer, peerRankInvalidDownload)

	require.Equal(t, peerRankInvalidDownload, peerSelector.PeerDownloadDurationToRank(&mockHTTPPeer{address: "abc123"}, time.Millisecond))
}

func TestFindMissingPeer(t *testing.T) {
	peerSelector := makePeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) []network.Peer {
			return []network.Peer{}
		}), []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivers}},
	)

	poolIdx, peerIdx := peerSelector.findPeer(&mockHTTPPeer{address: "abcd"})
	require.Equal(t, -1, poolIdx)
	require.Equal(t, -1, peerIdx)
}


func TestHistoricData(t *testing.T) {

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}, &mockHTTPPeer{address: "a2"}, &mockHTTPPeer{address: "a3"}}
	peers2 := []network.Peer{&mockHTTPPeer{address: "abcd"}, &mockHTTPPeer{address: "efgh"}}

	peerSelector := makePeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) (peers []network.Peer) {
			for _, opt := range options {
				if opt == network.PeersPhonebookArchivers {
					peers = append(peers, peers1...)
				} else {
					peers = append(peers, peers2...)
				}
			}
			return
		}), []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivers},
			{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays}},
	)

	var counters [3]uint64
	for i := 0; i < 10000; i++ {
		peer, getPeerErr := peerSelector.GetNextPeer()

		switch peer.(*mockHTTPPeer).address {
		case "a1":
			counters[0]++
		case "a2":
			counters[1]++
		case "a3":
			counters[2]++
		}
		
		require.NoError(t, getPeerErr)
		var duration time.Duration
		randVal := float64(crypto.RandUint64() % uint64(200))/100
		if randVal > 1.8 {
			duration = time.Duration(8*time.Second)
		} else {
			switch peer.(*mockHTTPPeer).address {
			case "a1":
				duration = time.Duration(1500*float64(time.Millisecond)*randVal)
			case "a2":
				duration = time.Duration(500*float64(time.Millisecond)*randVal)
			case "a3":
				duration = time.Duration(100*float64(time.Millisecond)*randVal)
			}
		}
		
		peerRank := peerSelector.PeerDownloadDurationToRank(peer, duration)		
		//		fmt.Printf("%s %v %v\n", peer.(*mockHTTPPeer).address, duration, peerRank)
		peerSelector.RankPeer(peer, peerRank)
	}

	fmt.Printf("a1: %d\n", counters[0])
	fmt.Printf("a2: %d\n", counters[1])
	fmt.Printf("a3: %d\n", counters[2])
	require.Greater(t, counters[2], counters[1])
	require.Greater(t, counters[1], counters[0])
}
