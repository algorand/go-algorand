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

	// We fail to find a block for round 3 more times, so the peer selector should be re-sorted
	cps.rankPeer(mockPeer, peerRankNoBlockForRound)
	oldRank, newRank = cps.rankPeer(mockPeer, peerRankNoBlockForRound)

	require.Equal(t, 10, oldRank)
	require.Equal(t, peerRankNoBlockForRound, newRank)
	require.Equal(t, 3, cps.peerSelectors[1].downloadFailures)

	oldRank, newRank = cps.rankPeer(mockPeer, peerRankNoBlockForRound)
	require.Equal(t, 10, oldRank)
	require.Equal(t, peerRankNoBlockForRound, newRank)
	// Note that the download failures should be 0 in this position, as the peer selector should have been re-sorted to last
	require.Equal(t, 0, cps.peerSelectors[1].downloadFailures)
	require.Equal(t, 4, cps.peerSelectors[2].downloadFailures)

	// Now, feed a peer that is not in any of the selectors - it should return -1, -1
	mockPeer2 := &peerSelectorPeer{}
	oldRank, newRank = cps.rankPeer(mockPeer2, 50)
	require.Equal(t, -1, oldRank)
	require.Equal(t, -1, newRank)
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
			},
			priority:        peerRankInitialSecondPriority,
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
		{
			peerClass: network.PeersPhonebookArchivalNodes,
			peerSelector: mockPeerSelector{
				mockGetNextPeer: func() (psp *peerSelectorPeer, err error) {
					return mockPeer3, nil
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
}
