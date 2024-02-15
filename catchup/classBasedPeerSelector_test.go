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
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// Use to mock the wrapped peer selectors where warranted
type mockPeerSelector struct {
	mockRankPeer                   func(psp *peerSelectorPeer, rank int) (int, int)
	mockPeerDownloadDurationToRank func(psp *peerSelectorPeer, blockDownloadDuration time.Duration) (rank int)
	mockGetNextPeer                func() (psp *peerSelectorPeer, err error)
}

func (m mockPeerSelector) rankPeer(psp *peerSelectorPeer, rank int) (int, int) {
	return m.mockRankPeer(psp, rank)
}

func (m mockPeerSelector) peerDownloadDurationToRank(psp *peerSelectorPeer, blockDownloadDuration time.Duration) (rank int) {
	return m.mockPeerDownloadDurationToRank(psp, blockDownloadDuration)
}

func (m mockPeerSelector) getNextPeer() (psp *peerSelectorPeer, err error) {
	return m.mockGetNextPeer()
}

func TestClassBasedPeerSelector_makeClassBasedPeerSelector(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Intentionally put the selectors in non-priority order
	wrappedPeerSelectors := []*wrappedPeerSelector{
		{
			peerClass:       network.PeersConnectedOut,
			peerSelector:    mockPeerSelector{},
			priority:        peerRankInitialSecondPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
		{
			peerClass:       network.PeersPhonebookArchivalNodes,
			peerSelector:    mockPeerSelector{},
			priority:        peerRankInitialThirdPriority,
			toleranceFactor: 10,
			lastCheckedTime: time.Now(),
		},
		{
			peerClass:       network.PeersPhonebookRelays,
			peerSelector:    mockPeerSelector{},
			priority:        peerRankInitialFirstPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
	}

	cps := makeClassBasedPeerSelector(wrappedPeerSelectors)

	// The selectors should be sorted by priority
	require.Equal(t, 3, len(cps.peerSelectors))
	require.Equal(t, network.PeersPhonebookRelays, cps.peerSelectors[0].peerClass)
	require.Equal(t, network.PeersConnectedOut, cps.peerSelectors[1].peerClass)
	require.Equal(t, network.PeersPhonebookArchivalNodes, cps.peerSelectors[2].peerClass)
}

func TestClassBasedPeerSelector_rankPeer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	mockPeer := &peerSelectorPeer{}

	// Create a class based peer selector initially with the first wrapped peer selector not having the peer,
	// second one having it, and a third one not having it
	wrappedPeerSelectors := []*wrappedPeerSelector{
		{
			peerClass: network.PeersConnectedOut,
			peerSelector: mockPeerSelector{
				mockRankPeer: func(psp *peerSelectorPeer, rank int) (int, int) {
					return -1, -1
				},
			},
			priority:        peerRankInitialFirstPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
		{
			peerClass: network.PeersPhonebookRelays,
			peerSelector: mockPeerSelector{
				mockRankPeer: func(psp *peerSelectorPeer, rank int) (int, int) {
					if psp == mockPeer {
						return 10, rank
					}
					return -1, -1
				},
			},
			priority:        peerRankInitialSecondPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
		{
			peerClass: network.PeersPhonebookArchivalNodes,
			peerSelector: mockPeerSelector{
				mockRankPeer: func(psp *peerSelectorPeer, rank int) (int, int) {
					return -1, -1
				},
			},
			priority:        peerRankInitialThirdPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
	}
	cps := makeClassBasedPeerSelector(wrappedPeerSelectors)

	// Peer is found in second selector, rank is within range for a block found
	oldRank, newRank := cps.rankPeer(mockPeer, 50)

	require.Equal(t, 10, oldRank)
	require.Equal(t, 50, newRank)
	require.Equal(t, 0, cps.peerSelectors[1].downloadFailures)

	// Peer is found in second selector, rank is >= peerRankNoBlockForRound
	oldRank, newRank = cps.rankPeer(mockPeer, peerRankNoBlockForRound)

	require.Equal(t, 10, oldRank)
	require.Equal(t, peerRankNoBlockForRound, newRank)
	require.Equal(t, 1, cps.peerSelectors[1].downloadFailures)

	// We fail to find a block for round 3 more times, download failures should reflect that.
	cps.rankPeer(mockPeer, peerRankNoBlockForRound)
	oldRank, newRank = cps.rankPeer(mockPeer, peerRankNoBlockForRound)

	require.Equal(t, 10, oldRank)
	require.Equal(t, peerRankNoBlockForRound, newRank)
	require.Equal(t, 3, cps.peerSelectors[1].downloadFailures)

	oldRank, newRank = cps.rankPeer(mockPeer, peerRankNoBlockForRound)
	require.Equal(t, 10, oldRank)
	require.Equal(t, peerRankNoBlockForRound, newRank)
	require.Equal(t, 4, cps.peerSelectors[1].downloadFailures)

	// Now, feed a peer that is not in any of the selectors - it should return -1, -1
	mockPeer2 := &peerSelectorPeer{}
	oldRank, newRank = cps.rankPeer(mockPeer2, 50)
	require.Equal(t, -1, oldRank)
	require.Equal(t, -1, newRank)

	// Last sanity check, we should have zero download failures for the first and third selectors
	require.Equal(t, 0, cps.peerSelectors[0].downloadFailures)
	require.Equal(t, 0, cps.peerSelectors[2].downloadFailures)
}

func TestClassBasedPeerSelector_peerDownloadDurationToRank(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	mockPeer := &peerSelectorPeer{}
	testDuration := 50 * time.Millisecond

	// Create a class based peer selector initially with the first wrapped peer selector not having the peer,
	// second one having it, and a third one not having it
	wrappedPeerSelectors := []*wrappedPeerSelector{
		{
			peerClass: network.PeersConnectedOut,
			peerSelector: mockPeerSelector{
				mockPeerDownloadDurationToRank: func(psp *peerSelectorPeer, blockDownloadDuration time.Duration) (rank int) {
					return peerRankInvalidDownload
				},
			},
			priority:        peerRankInitialFirstPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
		{
			peerClass: network.PeersPhonebookRelays,
			peerSelector: mockPeerSelector{
				mockPeerDownloadDurationToRank: func(psp *peerSelectorPeer, blockDownloadDuration time.Duration) (rank int) {
					if psp == mockPeer && blockDownloadDuration == testDuration {
						return peerRank0HighBlockTime
					}
					return peerRankInvalidDownload
				},
			},
			priority:        peerRankInitialSecondPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
		{
			peerClass: network.PeersPhonebookArchivalNodes,
			peerSelector: mockPeerSelector{
				mockPeerDownloadDurationToRank: func(psp *peerSelectorPeer, blockDownloadDuration time.Duration) (rank int) {
					return peerRankInvalidDownload
				},
			},
			priority:        peerRankInitialThirdPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
	}
	cps := makeClassBasedPeerSelector(wrappedPeerSelectors)

	// The peer is found in the second selector, so the rank should be peerRank0HighBlockTime
	rank := cps.peerDownloadDurationToRank(mockPeer, testDuration)
	require.Equal(t, peerRank0HighBlockTime, rank)

	// The peer is not found in any of the selectors, so the rank should be peerRankInvalidDownload
	mockPeer2 := &peerSelectorPeer{}

	rank = cps.peerDownloadDurationToRank(mockPeer2, testDuration)
	require.Equal(t, peerRankInvalidDownload, rank)
}

func TestClassBasedPeerSelector_getNextPeer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	mockPeer := &peerSelectorPeer{}

	// Create a class based peer selector initially with the first wrapped peer selector not having any peers,
	// second one having a peer, and a third one not having any peers
	wrappedPeerSelectors := []*wrappedPeerSelector{
		{
			peerClass: network.PeersConnectedOut,
			peerSelector: mockPeerSelector{
				mockGetNextPeer: func() (psp *peerSelectorPeer, err error) {
					return nil, errPeerSelectorNoPeerPoolsAvailable
				},
			},
			priority:        peerRankInitialFirstPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
		{
			peerClass: network.PeersPhonebookRelays,
			peerSelector: mockPeerSelector{
				mockGetNextPeer: func() (psp *peerSelectorPeer, err error) {
					return mockPeer, nil
				},
			},
			priority:        peerRankInitialSecondPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
		{
			peerClass: network.PeersPhonebookArchivalNodes,
			peerSelector: mockPeerSelector{
				mockGetNextPeer: func() (psp *peerSelectorPeer, err error) {
					return nil, errPeerSelectorNoPeerPoolsAvailable
				},
			},
			priority:        peerRankInitialThirdPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
	}

	cps := makeClassBasedPeerSelector(wrappedPeerSelectors)

	peerResult, err := cps.getNextPeer()
	require.Nil(t, err)
	require.Equal(t, peerResult, mockPeer)

	// Update selector to not return any peers
	wrappedPeerSelectors[1].peerSelector = mockPeerSelector{
		mockGetNextPeer: func() (psp *peerSelectorPeer, err error) {
			return nil, errPeerSelectorNoPeerPoolsAvailable
		},
	}

	peerResult, err = cps.getNextPeer()
	require.Nil(t, peerResult)
	require.Equal(t, errPeerSelectorNoPeerPoolsAvailable, err)

	// Create a class based peer selector initially with all wrapped peer selectors having peers.
	// The peers should always come from the first one repeatedly since rankings are not changed.
	mockPeer2 := &peerSelectorPeer{}
	mockPeer3 := &peerSelectorPeer{}

	wrappedPeerSelectors = []*wrappedPeerSelector{
		{
			peerClass: network.PeersConnectedOut,
			peerSelector: mockPeerSelector{
				mockGetNextPeer: func() (psp *peerSelectorPeer, err error) {
					return mockPeer, nil
				},
				mockRankPeer: func(psp *peerSelectorPeer, rank int) (int, int) {
					if psp == mockPeer {
						return 10, rank
					}
					return -1, -1
				},
			},
			priority:        peerRankInitialFirstPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
		{
			peerClass: network.PeersPhonebookRelays,
			peerSelector: mockPeerSelector{
				mockGetNextPeer: func() (psp *peerSelectorPeer, err error) {
					return mockPeer2, nil
				},
				mockRankPeer: func(psp *peerSelectorPeer, rank int) (int, int) {
					if psp == mockPeer2 {
						return 10, rank
					}
					return -1, -1
				},
			},
			priority:        peerRankInitialSecondPriority,
			toleranceFactor: 10,
			lastCheckedTime: time.Now(),
		},
		{
			peerClass: network.PeersPhonebookArchivalNodes,
			peerSelector: mockPeerSelector{
				mockGetNextPeer: func() (psp *peerSelectorPeer, err error) {
					return mockPeer3, nil
				},
				mockRankPeer: func(psp *peerSelectorPeer, rank int) (int, int) {
					if psp == mockPeer3 {
						return 10, rank
					}
					return -1, -1
				},
			},
			priority:        peerRankInitialThirdPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
	}

	cps = makeClassBasedPeerSelector(wrappedPeerSelectors)

	// We should always get the peer from the top priority selector since rankings are not updated/list is not re-sorted.
	for i := 0; i < 10; i++ {
		peerResult, err = cps.getNextPeer()
		require.Nil(t, err)
		require.Equal(t, peerResult, mockPeer)
	}

	// Okay, record enough download failures to disable the first selector
	for i := 0; i < 4; i++ {
		cps.rankPeer(mockPeer, peerRankNoBlockForRound)
	}

	// Now, we should get the peer from the second selector
	peerResult, err = cps.getNextPeer()
	require.Nil(t, err)
	require.Equal(t, peerResult, mockPeer2)

	// Sanity check the download failures for each selector
	require.Equal(t, 4, cps.peerSelectors[0].downloadFailures)
	require.Equal(t, 0, cps.peerSelectors[1].downloadFailures)
	require.Equal(t, 0, cps.peerSelectors[2].downloadFailures)

	// Now, record download failures just under the tolerance factor for the second selector
	for i := 0; i < 9; i++ {
		cps.rankPeer(mockPeer2, peerRankNoBlockForRound)
	}

	peerResult, err = cps.getNextPeer()
	require.Nil(t, err)
	require.Equal(t, peerResult, mockPeer2)

	// One more should push us to the third selector
	cps.rankPeer(mockPeer2, peerRankNoBlockForRound)
	peerResult, err = cps.getNextPeer()
	require.Nil(t, err)
	require.Equal(t, peerResult, mockPeer3)

	// Final sanity check of the download failures for each selector
	require.Equal(t, 4, cps.peerSelectors[0].downloadFailures)
	require.Equal(t, 10, cps.peerSelectors[1].downloadFailures)
	require.Equal(t, 0, cps.peerSelectors[2].downloadFailures)
}
