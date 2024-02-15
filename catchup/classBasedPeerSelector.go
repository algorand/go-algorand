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
	"sort"
	"time"
)

// The duration after which we reset the downloadFailures for a rankPooledPeerSelector
const lastCheckedDuration = 10 * time.Minute

// classBasedPeerSelector is a rankPooledPeerSelector that tracks and ranks classes of peers based on their response behavior.
// It is used to select the most appropriate peers to download blocks from - this is most useful when catching up
// and needing to figure out whether the blocks can be retrieved from relay nodes or require archive nodes.
type classBasedPeerSelector struct {
	mu            deadlock.Mutex
	peerSelectors []*wrappedPeerSelector
}

func makeClassBasedPeerSelector(peerSelectors []*wrappedPeerSelector) *classBasedPeerSelector {
	// Sort the peerSelectors by priority
	sort.SliceStable(peerSelectors, func(i, j int) bool {
		return peerSelectors[i].priority < peerSelectors[j].priority
	})
	return &classBasedPeerSelector{
		peerSelectors: peerSelectors,
	}
}

func (c *classBasedPeerSelector) rankPeer(psp *peerSelectorPeer, rank int) (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	peerSelectorSortNeeded := false
	oldRank, newRank := -1, -1
	for _, wp := range c.peerSelectors {
		// See if the peer is in the class, ranking it appropriately if so
		oldRank, newRank = wp.peerSelector.rankPeer(psp, rank)
		if oldRank < 0 || newRank < 0 {
			// Peer not found in this class
			continue
		}
		// Peer was in this class, if there was any kind of download issue, we increment the failure count
		if rank >= peerRankNoBlockForRound {
			wp.downloadFailures++
		}

		// If we have failed more than the tolerance factor, we re-sort the slice of peerSelectors
		if wp.downloadFailures > wp.toleranceFactor {
			peerSelectorSortNeeded = true
		}
		break
	}

	if peerSelectorSortNeeded {
		c.sortPeerSelectors()
	}

	return oldRank, newRank
}

// sortPeerSelectors sorts the peerSelectors by tolerance factor violation, and then by priority
// It should only be called within a locked context
func (c *classBasedPeerSelector) sortPeerSelectors() {
	psUnderTolerance := make([]*wrappedPeerSelector, 0, len(c.peerSelectors))
	psOverTolerance := make([]*wrappedPeerSelector, 0, len(c.peerSelectors))
	for _, wp := range c.peerSelectors {
		// If the rankPooledPeerSelector's download failures have not been reset in a while, we reset them
		if time.Since(wp.lastCheckedTime) > lastCheckedDuration {
			wp.downloadFailures = 0
			// Reset again here, so we don't keep resetting the same rankPooledPeerSelector
			wp.lastCheckedTime = time.Now()
		}

		if wp.downloadFailures <= wp.toleranceFactor {
			psUnderTolerance = append(psUnderTolerance, wp)
		} else {
			psOverTolerance = append(psOverTolerance, wp)
		}

	}

	// Sort the two groups by priority
	sortByPriority := func(ps []*wrappedPeerSelector) {
		sort.SliceStable(ps, func(i, j int) bool {
			return ps[i].priority < ps[j].priority
		})
	}

	sortByPriority(psUnderTolerance)
	sortByPriority(psOverTolerance)

	//Append the two groups back together
	c.peerSelectors = append(psUnderTolerance, psOverTolerance...)
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
	return nil, err
}

type wrappedPeerSelector struct {
	peerSelector     peerSelector       // The underlying rankPooledPeerSelector for this class
	peerClass        network.PeerOption // The class of peers the rankPooledPeerSelector is responsible for
	toleranceFactor  int                // The number of times we can net fail for any reason before we move to the next class's rankPooledPeerSelector
	priority         int                // The original priority of the rankPooledPeerSelector, used for sorting
	downloadFailures int                // The number of times we have failed to download a block from this class's rankPooledPeerSelector since it was last reset
	lastCheckedTime  time.Time          // The last time we tried to use the rankPooledPeerSelector
}
