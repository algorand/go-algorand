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
	"errors"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-deadlock"
	"time"
)

// The duration after which we reset the downloadFailures for a rankPooledPeerSelector
const lastCheckedDuration = 10 * time.Minute

// classBasedPeerSelector is a rankPooledPeerSelector that tracks and ranks classes of peers based on their response behavior.
// It is used to select the most appropriate peers to download blocks from - this is most useful when catching up
// and needing to figure out whether the blocks can be retrieved from relay nodes or require archive nodes.
// The ordering of the peerSelectors directly determines the priority of the classes of peers.
type classBasedPeerSelector struct {
	mu            deadlock.Mutex
	peerSelectors []*wrappedPeerSelector
}

func makeClassBasedPeerSelector(peerSelectors []*wrappedPeerSelector) *classBasedPeerSelector {
	return &classBasedPeerSelector{
		peerSelectors: peerSelectors,
	}
}

func (c *classBasedPeerSelector) rankPeer(psp *peerSelectorPeer, rank int) (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldRank, newRank := -1, -1
	for _, wp := range c.peerSelectors {
		// See if the peer is in the class, ranking it appropriately if so
		if psp.peerClass != wp.peerClass {
			continue
		}

		oldRank, newRank = wp.peerSelector.rankPeer(psp, rank)
		if oldRank < 0 || newRank < 0 {
			// Peer not found in this selector
			continue
		}

		// Peer was in this class, if there was any kind of download issue, we increment the failure count
		if rank >= peerRankNoBlockForRound {
			wp.downloadFailures++
		}

		break
	}

	return oldRank, newRank
}

func (c *classBasedPeerSelector) peerDownloadDurationToRank(psp *peerSelectorPeer, blockDownloadDuration time.Duration) (rank int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, wp := range c.peerSelectors {
		rank = wp.peerSelector.peerDownloadDurationToRank(psp, blockDownloadDuration)
		// If rank is peerRankInvalidDownload, we check the next class's rankPooledPeerSelector
		if rank >= peerRankInvalidDownload {
			continue
		}
		// Should be a legit ranking, we return it
		return rank
	}
	// If we reached here, we have exhausted all classes without finding the peer
	return peerRankInvalidDownload
}

func (c *classBasedPeerSelector) getNextPeer() (psp *peerSelectorPeer, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, wp := range c.peerSelectors {
		if time.Since(wp.lastCheckedTime) > lastCheckedDuration {
			wp.downloadFailures = 0
		}

		if wp.downloadFailures > wp.toleranceFactor {
			// peerSelector is disabled for now, we move to the next one
			continue
		}
		psp, err = wp.peerSelector.getNextPeer()
		wp.lastCheckedTime = time.Now()
		if err != nil {
			// This is mostly just future-proofing, as we don't expect any other errors from getNextPeer
			if errors.Is(err, errPeerSelectorNoPeerPoolsAvailable) {
				// We penalize this class the equivalent of one download failure (in case this is transient)
				wp.downloadFailures++
			}
			continue
		}
		return psp, nil
	}
	// If we reached here, we have exhausted all classes and still have no peers
	return nil, errPeerSelectorNoPeerPoolsAvailable
}

type wrappedPeerSelector struct {
	peerSelector     peerSelector       // The underlying peerSelector for this class
	peerClass        network.PeerOption // The class of peers the peerSelector is responsible for
	toleranceFactor  int                // The number of times we can net fail for any reason before we move to the next class's rankPooledPeerSelector
	downloadFailures int                // The number of times we have failed to download a block from this class's rankPooledPeerSelector since it was last reset
	lastCheckedTime  time.Time          // The last time we tried to use the peerSelector
}

// makeCatchpointPeerSelector returns a classBasedPeerSelector that selects peers based on their class and response behavior.
// These are the preferred configurations for the catchpoint service.
func makeCatchpointPeerSelector(net peersRetriever) peerSelector {
	wrappedPeerSelectors := []*wrappedPeerSelector{
		{
			peerClass: network.PeersPhonebookRelays,
			peerSelector: makeRankPooledPeerSelector(net,
				[]peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookRelays}}),
			toleranceFactor: 3,
			lastCheckedTime: time.Now(),
		},
		{
			peerClass: network.PeersPhonebookArchivalNodes,
			peerSelector: makeRankPooledPeerSelector(net,
				[]peerClass{{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivalNodes}}),
			toleranceFactor: 10,
			lastCheckedTime: time.Now(),
		},
	}

	return makeClassBasedPeerSelector(wrappedPeerSelectors)
}
