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
	"bytes"
	"context"
	"encoding/binary"
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
func (d *mockUnicastPeer) Unicast(ctx context.Context, msg []byte, tag protocol.Tag, callback network.UnicastWebsocketMessageStateCallback) error {
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
func (d *mockUnicastPeer) IsOutgoing() bool {
	return false
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
	r2, r2 = peerSelector.rankPeer(&peerSelectorPeer{&mockHTTPPeer{address: "abc123"}, 1}, 10)
	require.False(t, r1 != r2)

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

func TestFindMissingPeer(t *testing.T) {
	peerSelector := makePeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) []network.Peer {
			return []network.Peer{}
		}), []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivers}},
	)

	poolIdx, peerIdx := peerSelector.findPeer(&peerSelectorPeer{mockHTTPPeer{address: "abcd"}, 0})
	require.Equal(t, -1, poolIdx)
	require.Equal(t, -1, peerIdx)
}

func TestHistoricData(t *testing.T) {

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}, &mockHTTPPeer{address: "a2"}, &mockHTTPPeer{address: "a3"}}
	peers2 := []network.Peer{&mockHTTPPeer{address: "b1"}, &mockHTTPPeer{address: "b2"}}

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
func TestPeersDownloadFailed(t *testing.T) {

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}, &mockHTTPPeer{address: "a2"}, &mockHTTPPeer{address: "a3"}}
	peers2 := []network.Peer{&mockHTTPPeer{address: "b1"}, &mockHTTPPeer{address: "b2"}}

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
		require.Equal(t, peerSelector.pools[1].rank, 900)
		require.Equal(t, len(peerSelector.pools[1].peers), 3)
	} else { // len(pools) == 3
		b1orb2 := peerAddress(peerSelector.pools[1].peers[0].peer) == "b1" || peerAddress(peerSelector.pools[1].peers[0].peer) == "b2"
		require.True(t, b1orb2)
		require.Equal(t, peerSelector.pools[2].rank, 900)
		require.Equal(t, len(peerSelector.pools[2].peers), 3)
	}

}

// TestPenalty tests that the penalty is calculated correctly and one peer
// is not dominating all the selection.
func TestPenalty(t *testing.T) {

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}, &mockHTTPPeer{address: "a2"}, &mockHTTPPeer{address: "a3"}}
	peers2 := []network.Peer{&mockHTTPPeer{address: "b1"}, &mockHTTPPeer{address: "b2"}}

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

// TestPeerDownloadDurationToRank tests all the cases handled by peerDownloadDurationToRank
func TestPeerDownloadDurationToRank(t *testing.T) {

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}, &mockHTTPPeer{address: "a2"}, &mockHTTPPeer{address: "a3"}}
	peers2 := []network.Peer{&mockHTTPPeer{address: "b1"}, &mockHTTPPeer{address: "b2"}}
	peers3 := []network.Peer{&mockHTTPPeer{address: "c1"}, &mockHTTPPeer{address: "c2"}}
	peers4 := []network.Peer{&mockHTTPPeer{address: "d1"}, &mockHTTPPeer{address: "b2"}}

	peerSelector := makePeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) (peers []network.Peer) {
			for _, opt := range options {
				if opt == network.PeersPhonebookArchivers {
					peers = append(peers, peers1...)
				} else if opt == network.PeersPhonebookRelays {
					peers = append(peers, peers2...)
				} else if opt == network.PeersConnectedOut {
					peers = append(peers, peers3...)
				} else {
					peers = append(peers, peers4...)
				}
			}
			return
		}), []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivers},
			{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays},
			{initialRank: peerRankInitialThirdPriority, peerClass: network.PeersConnectedOut},
			{initialRank: peerRankInitialFourthPriority, peerClass: network.PeersConnectedIn}},
	)

	_, err := peerSelector.getNextPeer()
	require.NoError(t, err)

	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank0LowBlockTime, peerRank0HighBlockTime),
		peerSelector.peerDownloadDurationToRank(&peerSelectorPeer{peers1[0], network.PeersPhonebookArchivers}, 500*time.Millisecond))
	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank1LowBlockTime, peerRank1HighBlockTime),
		peerSelector.peerDownloadDurationToRank(&peerSelectorPeer{peers2[0], network.PeersPhonebookRelays}, 500*time.Millisecond))
	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank2LowBlockTime, peerRank2HighBlockTime),
		peerSelector.peerDownloadDurationToRank(&peerSelectorPeer{peers3[0], network.PeersConnectedOut}, 500*time.Millisecond))
	require.Equal(t, downloadDurationToRank(500*time.Millisecond, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank3LowBlockTime, peerRank3HighBlockTime),
		peerSelector.peerDownloadDurationToRank(&peerSelectorPeer{peers4[0], network.PeersConnectedIn}, 500*time.Millisecond))
}

func TestLowerUpperBounds(t *testing.T) {
	classes := []peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivers},
		{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays},
		{initialRank: peerRankInitialThirdPriority, peerClass: network.PeersConnectedOut},
		{initialRank: peerRankInitialFourthPriority, peerClass: network.PeersConnectedIn}}

	require.Equal(t, peerRank0LowBlockTime, lowerBound(classes[0]))
	require.Equal(t, peerRank1LowBlockTime, lowerBound(classes[1]))
	require.Equal(t, peerRank2LowBlockTime, lowerBound(classes[2]))
	require.Equal(t, peerRank3LowBlockTime, lowerBound(classes[3]))

	require.Equal(t, peerRank0HighBlockTime, upperBound(classes[0]))
	require.Equal(t, peerRank1HighBlockTime, upperBound(classes[1]))
	require.Equal(t, peerRank2HighBlockTime, upperBound(classes[2]))
	require.Equal(t, peerRank3HighBlockTime, upperBound(classes[3]))
}

func TestFullResetRequestPenalty(t *testing.T) {
	class := peerClass{initialRank: 10, peerClass: network.PeersPhonebookArchivers}
	hs := makeHistoricStatus(10, class)
	hs.push(5, 1, class)
	require.Equal(t, 1, len(hs.requestGaps))

	hs.resetRequestPenalty(0, 0, class)
	require.Equal(t, 0, len(hs.requestGaps))
}

// TestClassUpperBound makes sure the peer rank does not exceed the class upper bound
// This was a bug where the resetRequestPenalty was not bounding the returned rank, and was having download failures.
// Initializing rankSamples to 0 makes this works, since the dropped value subtracts 0 from rankSum.
func TestClassUpperBound(t *testing.T) {

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}, &mockHTTPPeer{address: "a2"}}
	pClass := peerClass{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookArchivers}
	peerSelector := makePeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) (peers []network.Peer) {
			for _, opt := range options {
				if opt == network.PeersPhonebookArchivers {
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

// TestClassLowerBound makes sure the peer rank does not go under the class lower bound
// This was a bug where the resetRequestPenalty was not bounding the returned rank, and the rankSum was not
// initialized to give the average of class.initialRank
func TestClassLowerBound(t *testing.T) {

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}, &mockHTTPPeer{address: "a2"}}
	pClass := peerClass{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookArchivers}
	peerSelector := makePeerSelector(
		makePeersRetrieverStub(func(options ...network.PeerOption) (peers []network.Peer) {
			for _, opt := range options {
				if opt == network.PeersPhonebookArchivers {
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

// TestEviction tests that the peer is evicted after several download failures, and it handles same address for different peer classes
func TestEvictionAndUpgrade(t *testing.T) {

	peers1 := []network.Peer{&mockHTTPPeer{address: "a1"}}
	peers2 := []network.Peer{&mockHTTPPeer{address: "a1"}}

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

	_, err := peerSelector.getNextPeer()
	require.NoError(t, err)
	for i := 0; i < 10; i++ {
		if peerSelector.pools[len(peerSelector.pools)-1].rank == 900 {
			require.Equal(t, 6, i)
			break
		}
		psp, err := peerSelector.getNextPeer()
		require.NoError(t, err)
		peerSelector.rankPeer(psp, peerRankDownloadFailed)
	}
	psp, err := peerSelector.getNextPeer()
	require.Equal(t, psp.peerClass, network.PeersPhonebookRelays)
}
