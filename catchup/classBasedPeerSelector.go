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
	"github.com/algorand/go-deadlock"
	"time"
)

// classBasedPeerSelector is a peerSelector that tracks and ranks classes of peers based on their response behavior.
// It is used to select the most appropriate peers to download blocks from - this is most useful when catching up
// and needing to figure out whether the blocks can be retrieved from relay nodes or require archive nodes.
type classBasedPeerSelector struct {
	mu            deadlock.Mutex
	peerSelectors []*wrappedPeerSelector
}

func (c *classBasedPeerSelector) rankPeer(psp *peerSelectorPeer, rank int) (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	peerSelectorSortNeeded := false
	poolIdx, peerIdx := -1, -1
	for _, wp := range c.peerSelectors {
		// See if the peer is in the class, ranking it appropriately if so
		poolIdx, peerIdx = wp.peerSelector.rankPeer(psp, rank)
		if poolIdx < 0 || peerIdx < 0 {
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
		// TODO: Implement sorting of peerSelectors
	}

	return poolIdx, peerIdx
}

func (c *classBasedPeerSelector) peerDownloadDurationToRank(psp *peerSelectorPeer, blockDownloadDuration time.Duration) (rank int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, wp := range c.peerSelectors {
		rank = wp.peerSelector.peerDownloadDurationToRank(psp, blockDownloadDuration)
		// If rank is peerRankInvalidDownload, we check the next class's peerSelector
		if rank >= peerRankInvalidDownload {
			continue
		}
		// Should be a legit ranking, we return it
		return
	}
	// If we reached here, we have exhausted all classes without finding the peer
	return peerRankInvalidDownload
}

func (c *classBasedPeerSelector) getNextPeer() (psp *peerSelectorPeer, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, wp := range c.peerSelectors {
		psp, err = wp.peerSelector.getNextPeer()
		if err != nil {
			// TODO: No peers available in this class, move to the end of our list???
			continue
		}
		return
	}
	// If we reached here, we have exhausted all classes and still have no peers
	return
}

type wrappedPeerSelector struct {
	peerSelector     peerSelector
	peerClass        network.PeerOption
	toleranceFactor  int // The number of times we can net fail for any reason before we move to the next class's peerSelector
	downloadFailures int
	// TODO: Add a lastUsed time.Duration to this struct
}

// Logic: We try a class's peerSelector Y times, and if it fails, we move to the next class.
// If we get to the last peerSelector and are still not getting blocks, we return an error.
// NOTE: if a peerselector has no pools, we do not use it??
