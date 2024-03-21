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

package catchup

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
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
func (d *mockUnicastPeer) Respond(ctx context.Context, reqMsg network.IncomingMessage, outMsg network.OutgoingMessage) (e error) {
	return nil
}

// GetConnectionLatency returns the connection latency between the local node and this peer.
func (d *mockUnicastPeer) GetConnectionLatency() time.Duration {
	return time.Duration(0)
}

func TestPeerSelector_PeerAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	httpPeer := &mockHTTPPeer{address: "12345"}
	require.Equal(t, "12345", peerAddress(httpPeer))

	unicastPeer := &mockUnicastPeer{address: "67890"}
	require.Equal(t, "67890", peerAddress(unicastPeer))

	require.Equal(t, "", peerAddress(nil))
	require.Equal(t, "", peerAddress(t))
}

func TestPeerSelector_DownloadDurationToRank(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
func TestPeerSelector_RankPeer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	peers := []network.Peer{&mockHTTPPeer{address: "12345"}}

	peerSelector := makeRankPooledPeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) []network.Peer {
			return peers
		}), []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivalNodes}},
	)

	psp, err := peerSelector.getNextPeer()
	require.NoError(t, err)
	peer := psp.Peer
	require.Equal(t, "12345", peerAddress(peer))

	// replace peer.
	peers = []network.Peer{&mockHTTPPeer{address: "54321"}}
	psp, err = peerSelector.getNextPeer()
	require.NoError(t, err)
	peer = psp.Peer
	require.Equal(t, "54321", peerAddress(peer))

	// add another peer
	peers = []network.Peer{&mockHTTPPeer{address: "54321"}, &mockHTTPPeer{address: "abcde"}}
	r1, r2 := peerSelector.rankPeer(psp, 5)
	require.True(t, r1 != r2)

	psp, err = peerSelector.getNextPeer()
	require.NoError(t, err)
	peer = psp.Peer
	require.Equal(t, "abcde", peerAddress(peer))

	r1, r2 = peerSelector.rankPeer(psp, 200)
	require.True(t, r1 != r2)

	psp, err = peerSelector.getNextPeer()
	require.NoError(t, err)
	peer = psp.Peer
	require.Equal(t, "54321", peerAddress(peer))

	peers = []network.Peer{t} // include a non-peer object, to test the refreshAvailablePeers handling of empty addresses.
	psp, err = peerSelector.getNextPeer()
	require.Equal(t, errPeerSelectorNoPeerPoolsAvailable, err)
	require.Nil(t, psp)

	// create an empty entry ( even though the code won't let it happen )
	peerSelector.pools = []peerPool{{rank: peerRankInitialFirstPriority}}
	psp, err = peerSelector.getNextPeer()
	require.Equal(t, errPeerSelectorNoPeerPoolsAvailable, err)
	require.Nil(t, psp)

	r1, r2 = peerSelector.rankPeer(nil, 10)
	require.False(t, r1 != r2)
	r1, r2 = peerSelector.rankPeer(&peerSelectorPeer{&mockHTTPPeer{address: "abc123"}, 1}, 10)
	require.False(t, r1 != r2)
}

func TestPeerSelector_PeerDownloadRanking(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	peers1 := []network.Peer{&mockHTTPPeer{address: "1234"}, &mockHTTPPeer{address: "5678"}}
	peers2 := []network.Peer{&mockHTTPPeer{address: "abcd"}, &mockHTTPPeer{address: "efgh"}}

	peerSelector := makeRankPooledPeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) (peers []network.Peer) {
			for _, opt := range options {
				if opt == network.PeersPhonebookArchivalNodes {
					peers = append(peers, peers1...)
				} else {
					peers = append(peers, peers2...)
				}
			}
			return
		}), []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivalNodes},
			{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays}},
	)
	archivalPeer, err := peerSelector.getNextPeer()
	require.NoError(t, err)

	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank0LowBlockTime, peerRank0HighBlockTime), peerSelector.peerDownloadDurationToRank(archivalPeer, 500*time.Millisecond))

	peerSelector.rankPeer(archivalPeer, peerRankInvalidDownload)

	archivalPeer, err = peerSelector.getNextPeer()
	require.NoError(t, err)

	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank0LowBlockTime, peerRank0HighBlockTime), peerSelector.peerDownloadDurationToRank(archivalPeer, 500*time.Millisecond))

	peerSelector.rankPeer(archivalPeer, peerRankInvalidDownload)

	// and now test the relay peers
	relayPeer, err := peerSelector.getNextPeer()
	require.NoError(t, err)

	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank1LowBlockTime, peerRank1HighBlockTime), peerSelector.peerDownloadDurationToRank(relayPeer, 500*time.Millisecond))

	peerSelector.rankPeer(relayPeer, peerRankInvalidDownload)

	relayPeer, err = peerSelector.getNextPeer()
	require.NoError(t, err)

	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank1LowBlockTime, peerRank1HighBlockTime), peerSelector.peerDownloadDurationToRank(relayPeer, 500*time.Millisecond))

	peerSelector.rankPeer(relayPeer, peerRankInvalidDownload)

	require.Equal(t, peerRankInvalidDownload, peerSelector.peerDownloadDurationToRank(&peerSelectorPeer{mockHTTPPeer{address: "abc123"}, 0}, time.Millisecond))
}

func TestPeerSelector_FindMissingPeer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	peerSelector := makeRankPooledPeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) []network.Peer {
			return []network.Peer{}
		}), []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivalNodes}},
	)

	poolIdx, peerIdx := peerSelector.findPeer(&peerSelectorPeer{mockHTTPPeer{address: "abcd"}, 0})
	require.Equal(t, -1, poolIdx)
	require.Equal(t, -1, peerIdx)
}

func TestPeerSelector_HistoricData(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}, &mockHTTPPeer{address: "a2"}, &mockHTTPPeer{address: "a3"}}
	peers2 := []network.Peer{&mockHTTPPeer{address: "b1"}, &mockHTTPPeer{address: "b2"}}

	peerSelector := makeRankPooledPeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) (peers []network.Peer) {
			for _, opt := range options {
				if opt == network.PeersPhonebookArchivalNodes {
					peers = append(peers, peers1...)
				} else {
					peers = append(peers, peers2...)
				}
			}
			return
		}), []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivalNodes},
			{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays}},
	)

	var counters [5]int
	for i := 0; i < 1000; i++ {
		psp, getPeerErr := peerSelector.getNextPeer()
		require.NoError(t, getPeerErr)
		peer := psp.Peer

		switch peer.(*mockHTTPPeer).address {
		case "a1":
			counters[0]++
		case "a2":
			counters[1]++
		case "a3":
			counters[2]++
		case "b1":
			counters[3]++
		case "b2":
			counters[4]++
		default:
			require.Fail(t, "unexpected peer address `%s`", peer.(*mockHTTPPeer).address)
		}

		randVal := peerSelectorTestRandVal(t, i)
		if randVal < 1.98 {
			var duration time.Duration
			switch peer.(*mockHTTPPeer).address {
			case "a1":
				duration = time.Duration(1500 * float64(time.Millisecond) * randVal)
			case "a2":
				duration = time.Duration(500 * float64(time.Millisecond) * randVal)
			case "a3":
				duration = time.Duration(100 * float64(time.Millisecond) * randVal)
			}
			peerRank := peerSelector.peerDownloadDurationToRank(psp, duration)
			peerSelector.rankPeer(psp, peerRank)
		} else {
			peerSelector.rankPeer(psp, peerRankDownloadFailed)
		}
	}

	require.GreaterOrEqual(t, counters[2], counters[1])
	require.GreaterOrEqual(t, counters[2], counters[0])
	require.Equal(t, counters[3], 0)
	require.Equal(t, counters[4], 0)
}

func peerSelectorTestRandVal(t *testing.T, seed int) float64 {
	iterationDigest := crypto.Hash([]byte{byte(seed), byte(seed >> 8), byte(seed >> 16)})
	randUint64, err := binary.ReadUvarint(bytes.NewReader(append([]byte{0}, iterationDigest[:]...)))
	require.NoError(t, err)
	randVal := float64(randUint64%uint64(100)) / 100
	randVal = randVal + 1
	return randVal
}
func TestPeerSelector_PeersDownloadFailed(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}, &mockHTTPPeer{address: "a2"}, &mockHTTPPeer{address: "a3"}}
	peers2 := []network.Peer{&mockHTTPPeer{address: "b1"}, &mockHTTPPeer{address: "b2"}}

	peerSelector := makeRankPooledPeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) (peers []network.Peer) {
			for _, opt := range options {
				if opt == network.PeersPhonebookArchivalNodes {
					peers = append(peers, peers1...)
				} else {
					peers = append(peers, peers2...)
				}
			}
			return
		}), []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivalNodes},
			{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays}},
	)

	var counters [5]int
	for i := 0; i < 1000; i++ {
		psp, getPeerErr := peerSelector.getNextPeer()
		peer := psp.Peer

		switch peer.(*mockHTTPPeer).address {
		case "a1":
			counters[0]++
		case "a2":
			counters[1]++
		case "a3":
			counters[2]++
		case "b1":
			counters[3]++
		case "b2":
			counters[4]++
		}

		require.NoError(t, getPeerErr)

		if i < 500 || peerAddress(peer) == "b1" || peerAddress(peer) == "b2" {
			randVal := peerSelectorTestRandVal(t, i)
			if randVal < 1.98 {
				duration := time.Duration(100 * float64(time.Millisecond) * randVal)
				peerRank := peerSelector.peerDownloadDurationToRank(psp, duration)
				peerSelector.rankPeer(psp, peerRank)
			} else {
				peerSelector.rankPeer(psp, peerRankDownloadFailed)
			}
		} else {
			peerSelector.rankPeer(psp, peerRankDownloadFailed)
		}
	}

	require.GreaterOrEqual(t, counters[3], 20)
	require.GreaterOrEqual(t, counters[4], 20)

	b1orb2 := peerAddress(peerSelector.pools[0].peers[0].peer) == "b1" || peerAddress(peerSelector.pools[0].peers[0].peer) == "b2"
	require.True(t, b1orb2)
	if len(peerSelector.pools) == 2 {
		b1orb2 := peerAddress(peerSelector.pools[0].peers[1].peer) == "b1" || peerAddress(peerSelector.pools[0].peers[1].peer) == "b2"
		require.True(t, b1orb2)
		require.Equal(t, peerSelector.pools[1].rank, peerRankDownloadFailed)
		require.Equal(t, len(peerSelector.pools[1].peers), 3)
	} else { // len(pools) == 3
		b1orb2 := peerAddress(peerSelector.pools[1].peers[0].peer) == "b1" || peerAddress(peerSelector.pools[1].peers[0].peer) == "b2"
		require.True(t, b1orb2)
		require.Equal(t, peerSelector.pools[2].rank, peerRankDownloadFailed)
		require.Equal(t, len(peerSelector.pools[2].peers), 3)
	}

}

// TestPeerSelector_Penalty tests that the penalty is calculated correctly and one peer
// is not dominating all the selection.
func TestPeerSelector_Penalty(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}, &mockHTTPPeer{address: "a2"}, &mockHTTPPeer{address: "a3"}}
	peers2 := []network.Peer{&mockHTTPPeer{address: "b1"}, &mockHTTPPeer{address: "b2"}}

	peerSelector := makeRankPooledPeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) (peers []network.Peer) {
			for _, opt := range options {
				if opt == network.PeersPhonebookArchivalNodes {
					peers = append(peers, peers1...)
				} else {
					peers = append(peers, peers2...)
				}
			}
			return
		}), []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivalNodes},
			{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays}},
	)

	var counters [5]int
	for i := 0; i < 1000; i++ {
		psp, getPeerErr := peerSelector.getNextPeer()
		peer := psp.Peer
		switch peer.(*mockHTTPPeer).address {
		case "a1":
			counters[0]++
		case "a2":
			counters[1]++
		case "a3":
			counters[2]++
		case "b1":
			counters[3]++
		case "b2":
			counters[4]++
		}

		require.NoError(t, getPeerErr)
		var duration time.Duration
		switch peer.(*mockHTTPPeer).address {
		case "a1":
			duration = time.Duration(1500 * float64(time.Millisecond))
		case "a2":
			duration = time.Duration(500 * float64(time.Millisecond))
		case "a3":
			duration = time.Duration(100 * float64(time.Millisecond))
		}
		peerRank := peerSelector.peerDownloadDurationToRank(psp, duration)
		peerSelector.rankPeer(psp, peerRank)
	}

	require.GreaterOrEqual(t, counters[1], 50)
	require.GreaterOrEqual(t, counters[2], 2*counters[1])
	require.Equal(t, counters[3], 0)
	require.Equal(t, counters[4], 0)
}

// TestPeerSelector_PeerDownloadDurationToRank tests all the cases handled by peerDownloadDurationToRank
func TestPeerSelector_PeerDownloadDurationToRank(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}, &mockHTTPPeer{address: "a2"}, &mockHTTPPeer{address: "a3"}}
	peers2 := []network.Peer{&mockHTTPPeer{address: "b1"}, &mockHTTPPeer{address: "b2"}}
	peers3 := []network.Peer{&mockHTTPPeer{address: "c1"}, &mockHTTPPeer{address: "c2"}}
	peers4 := []network.Peer{&mockHTTPPeer{address: "d1"}, &mockHTTPPeer{address: "b2"}}

	peerSelector := makeRankPooledPeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) (peers []network.Peer) {
			for _, opt := range options {
				if opt == network.PeersPhonebookRelays {
					peers = append(peers, peers1...)
				} else if opt == network.PeersConnectedOut {
					peers = append(peers, peers2...)
				} else if opt == network.PeersPhonebookArchivalNodes {
					peers = append(peers, peers3...)
				} else { // PeersConnectedIn
					peers = append(peers, peers4...)
				}
			}
			return
		}), []peerClass{
			{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookRelays},
			{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersConnectedOut},
			{initialRank: peerRankInitialThirdPriority, peerClass: network.PeersPhonebookArchivalNodes},
			{initialRank: peerRankInitialFourthPriority, peerClass: network.PeersConnectedIn}},
	)

	_, err := peerSelector.getNextPeer()
	require.NoError(t, err)

	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank0LowBlockTime, peerRank0HighBlockTime),
		peerSelector.peerDownloadDurationToRank(&peerSelectorPeer{peers1[0], network.PeersPhonebookRelays}, 500*time.Millisecond))
	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank1LowBlockTime, peerRank1HighBlockTime),
		peerSelector.peerDownloadDurationToRank(&peerSelectorPeer{peers2[0], network.PeersConnectedOut}, 500*time.Millisecond))
	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank2LowBlockTime, peerRank2HighBlockTime),
		peerSelector.peerDownloadDurationToRank(&peerSelectorPeer{peers3[0], network.PeersPhonebookArchivalNodes}, 500*time.Millisecond))
	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank3LowBlockTime, peerRank3HighBlockTime),
		peerSelector.peerDownloadDurationToRank(&peerSelectorPeer{peers4[0], network.PeersConnectedIn}, 500*time.Millisecond))

}

func TestPeerSelector_LowerUpperBounds(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	classes := []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivalNodes},
		{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays},
		{initialRank: peerRankInitialThirdPriority, peerClass: network.PeersConnectedOut},
		{initialRank: peerRankInitialFourthPriority, peerClass: network.PeersConnectedIn},
		{initialRank: peerRankInitialFifthPriority, peerClass: network.PeersConnectedIn}}

	require.Equal(t, peerRank0LowBlockTime, lowerBound(classes[0]))
	require.Equal(t, peerRank1LowBlockTime, lowerBound(classes[1]))
	require.Equal(t, peerRank2LowBlockTime, lowerBound(classes[2]))
	require.Equal(t, peerRank3LowBlockTime, lowerBound(classes[3]))
	require.Equal(t, peerRank4LowBlockTime, lowerBound(classes[4]))

	require.Equal(t, peerRank0HighBlockTime, upperBound(classes[0]))
	require.Equal(t, peerRank1HighBlockTime, upperBound(classes[1]))
	require.Equal(t, peerRank2HighBlockTime, upperBound(classes[2]))
	require.Equal(t, peerRank3HighBlockTime, upperBound(classes[3]))
	require.Equal(t, peerRank4HighBlockTime, upperBound(classes[4]))
}

func TestPeerSelector_FullResetRequestPenalty(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	class := peerClass{initialRank: 0, peerClass: network.PeersPhonebookArchivalNodes}
	hs := makeHistoricStatus(10, class)
	hs.push(5, 1, class)
	require.Equal(t, 1, len(hs.requestGaps))

	hs.resetRequestPenalty(0, 0, class)
	require.Equal(t, 0, len(hs.requestGaps))
}

// TestPeerSelector_PenaltyBounds makes sure that the penalty does not demote the peer to a lower class,
// and resetting the penalty of a demoted peer does not promote it back
func TestPeerSelector_PenaltyBounds(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	class := peerClass{initialRank: peerRankInitialThirdPriority, peerClass: network.PeersPhonebookArchivalNodes}
	hs := makeHistoricStatus(peerHistoryWindowSize, class)
	for x := 0; x < 65; x++ {
		r0 := hs.push(peerRank2LowBlockTime+50, uint64(x+1), class)
		require.LessOrEqual(t, peerRank2LowBlockTime, r0)
		require.GreaterOrEqual(t, peerRank2HighBlockTime, r0)
	}

	r1 := hs.resetRequestPenalty(4, peerRankInitialThirdPriority, class)
	r2 := hs.resetRequestPenalty(10, peerRankInitialThirdPriority, class)
	r3 := hs.resetRequestPenalty(10, peerRankDownloadFailed, class)

	// r2 is at a better rank than r1 because it has one penalty less
	require.Greater(t, r1, r2)

	// r3 is worse rank at peerRankDownloadFailed because it was demoted and resetRequestPenalty should not improve it
	require.Equal(t, peerRankDownloadFailed, r3)
}

// TestPeerSelector_ClassUpperBound makes sure the peer rank does not exceed the class upper bound
// This was a bug where the resetRequestPenalty was not bounding the returned rank, and was having download failures.
// Initializing rankSamples to 0 makes this works, since the dropped value subtracts 0 from rankSum.
func TestPeerSelector_ClassUpperBound(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}, &mockHTTPPeer{address: "a2"}}
	pClass := peerClass{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookArchivalNodes}
	peerSelector := makeRankPooledPeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) (peers []network.Peer) {
			for _, opt := range options {
				if opt == network.PeersPhonebookArchivalNodes {
					peers = append(peers, peers1...)
				}
			}
			return
		}), []peerClass{pClass})

	_, err := peerSelector.getNextPeer()
	require.NoError(t, err)
	for i := 0; i < 200; i++ {
		psp, err := peerSelector.getNextPeer()
		require.NoError(t, err)
		if i < 6 {
			peerSelector.rankPeer(psp, peerRankDownloadFailed)
		} else {
			peerSelector.rankPeer(psp, upperBound(pClass))
		}
		for _, pool := range peerSelector.pools {
			require.LessOrEqual(t, pool.rank, upperBound(pClass))
		}
	}
}

// TestPeerSelector_ClassLowerBound makes sure the peer rank does not go under the class lower bound
// This was a bug where the resetRequestPenalty was not bounding the returned rank, and the rankSum was not
// initialized to give the average of class.initialRank
func TestPeerSelector_ClassLowerBound(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}, &mockHTTPPeer{address: "a2"}}
	pClass := peerClass{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookArchivalNodes}
	peerSelector := makeRankPooledPeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) (peers []network.Peer) {
			for _, opt := range options {
				if opt == network.PeersPhonebookArchivalNodes {
					peers = append(peers, peers1...)
				}
			}
			return
		}), []peerClass{pClass})

	_, err := peerSelector.getNextPeer()
	require.NoError(t, err)
	for i := 0; i < 10; i++ {
		psp, err := peerSelector.getNextPeer()
		require.NoError(t, err)
		peerSelector.rankPeer(psp, lowerBound(pClass))

		for _, pool := range peerSelector.pools {
			require.GreaterOrEqual(t, pool.rank, pool.peers[0].class.initialRank)
		}
	}
}

// TestPeerSelector_Eviction tests that the peer is evicted after several download failures, and it handles same address for different peer classes
func TestPeerSelector_EvictionAndUpgrade(t *testing.T) {
	partitiontest.PartitionTest(t)

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}}
	peers2 := []network.Peer{&mockHTTPPeer{address: "a1"}}

	peerSelector := makeRankPooledPeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) (peers []network.Peer) {
			for _, opt := range options {
				if opt == network.PeersPhonebookArchivalNodes {
					peers = append(peers, peers1...)
				} else {
					peers = append(peers, peers2...)
				}
			}
			return
		}), []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivalNodes},
			{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays}},
	)

	_, err := peerSelector.getNextPeer()
	require.NoError(t, err)
	for i := 0; i < 10; i++ {
		if peerSelector.pools[len(peerSelector.pools)-1].rank == peerRankDownloadFailed {
			require.Equal(t, 6, i)
			break
		}
		psp, err := peerSelector.getNextPeer()
		require.NoError(t, err)
		peerSelector.rankPeer(psp, peerRankDownloadFailed)
	}
	psp, err := peerSelector.getNextPeer()
	require.NoError(t, err)
	require.Equal(t, psp.peerClass, network.PeersPhonebookRelays)
}

// TestPeerSelector_RefreshAvailablePeers tests addition/removal of peers from the pool
func TestPeerSelector_RefreshAvailablePeers(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// check new peers added to the pool
	p1 := mockHTTPPeer{address: "p1"}
	p2 := mockHTTPPeer{address: "p2"}
	ps := rankPooledPeerSelector{
		peerClasses: []peerClass{
			{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersConnectedOut},
			{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookArchivalNodes},
		},
		pools: []peerPool{
			{
				rank: peerRankInitialFirstPriority,
				peers: []peerPoolEntry{
					{
						peer:  &p1,
						class: peerClass{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersConnectedOut},
					},
				},
			},
		},
	}

	ps.net = makePeersRetrieverStub(func(options ...network.PeerOption) []network.Peer {
		return []network.Peer{&p1, &p2}
	})

	ps.refreshAvailablePeers()

	peerComparer := func(x, y peerPoolEntry) bool {
		return reflect.DeepEqual(x.peer, y.peer)
	}

	require.Equal(t, 2, len(ps.pools))
	require.Equal(t, 2, len(ps.pools[0].peers))
	require.Equal(t, 2, len(ps.pools[1].peers))

	require.True(t, cmp.Equal(
		ps.pools[0].peers,
		[]peerPoolEntry{{peer: &p1}, {peer: &p2}},
		cmp.Comparer(peerComparer),
	))
	require.True(t, cmp.Equal(
		ps.pools[1].peers,
		[]peerPoolEntry{{peer: &p1}, {peer: &p2}},
		cmp.Comparer(peerComparer),
	))

	// ensure removal peers from a pool and pools themselves
	// when returning only p1 for the first class and empty for the second
	ps.net = makePeersRetrieverStub(func(options ...network.PeerOption) []network.Peer {
		if options[0] == network.PeersConnectedOut {
			return []network.Peer{&p1}
		}
		return []network.Peer{}
	})

	ps.refreshAvailablePeers()
	require.Equal(t, 1, len(ps.pools))
	require.Equal(t, 1, len(ps.pools[0].peers))
	require.True(t, cmp.Equal(
		ps.pools[0].peers,
		[]peerPoolEntry{{peer: &p1}},
		cmp.Comparer(peerComparer),
	))
}
