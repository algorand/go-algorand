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
	"errors"
	"sort"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/network"
)

const (
	// peerRankInitialFirstPriority is the high-priority peers group ( typically, archivers )
	peerRankInitialFirstPriority = 0
	peerRank0LowBlockTime        = 1
	peerRank0HighBlockTime       = 199

	// peerRankInitialSecondPriority is the second priority peers group ( typically, relays )
	peerRankInitialSecondPriority = 200
	peerRank1LowBlockTime         = 201
	peerRank1HighBlockTime        = 399

	// peerRankDownloadFailed is used for responses which could be temporary, such as missing files, or such that we don't
	// have clear resolution
	peerRankDownloadFailed = 900
	// peerRankInvalidDownload is used for responses which are likely to be invalid - whether it's serving the wrong content
	// or attempting to serve malicious content
	peerRankInvalidDownload = 1000

	// once a block is downloaded, the download duration is clamped into the range of [lowBlockDownloadThreshold..highBlockDownloadThreshold] and
	// then mapped into the a ranking range.
	lowBlockDownloadThreshold  = 50 * time.Millisecond
	highBlockDownloadThreshold = 8 * time.Second
)

var errPeerSelectorNoPeerPoolsAvailable = errors.New("no peer pools available")

// peerClass defines the type of peer we want to have in a particular "class",
// and define tnet network.PeerOption that would be used to retrieve that type of
// peer
type peerClass struct {
	initialRank int
	peerClass   network.PeerOption
}

// the networkGetPeers is a subset of the network.GossipNode used to ensure that we can create an instance of the peerSelector
// for testing purposes, providing just the above function.
type networkGetPeers interface {
	// Get a list of Peers we could potentially send a direct message to.
	GetPeers(options ...network.PeerOption) []network.Peer
}

// peerPoolEntry represents a single peer entry in the pool. It contains
// the underlying network peer as well as the peer class.
type peerPoolEntry struct {
	peer  network.Peer
	class peerClass
}

// peerPool is a single pool of peers that shares the same rank.
type peerPool struct {
	rank  int
	peers []peerPoolEntry
}

// peerSelector is a helper struct used to select the next peer to try and connect to
// for various catchup purposes. Unlike the underlying network GetPeers(), it allows the
// client to provide feedback regarding the peer's performance, and to have the subsequent
// query(s) take advantage of that intel.
type peerSelector struct {
	deadlock.Mutex
	net         networkGetPeers
	peerClasses []peerClass
	pools       []peerPool
}

// makePeerSelector creates a peerSelector, given a networkGetPeers and peerClass array.
func makePeerSelector(net networkGetPeers, initialPeersClasses []peerClass) *peerSelector {
	selector := &peerSelector{
		net:         net,
		peerClasses: initialPeersClasses,
	}
	sortNeeded := false
	for _, initClass := range initialPeersClasses {
		peers := net.GetPeers(initClass.peerClass)
		for _, peer := range peers {
			sortNeeded = sortNeeded || selector.addToPool(peer, initClass.initialRank, initClass)
		}
	}
	if sortNeeded {
		selector.sort()
	}
	return selector
}

// GetNextPeer returns the next peer. It randomally selects a peer from the lowest
// rank pool.
func (ps *peerSelector) GetNextPeer() (peer network.Peer, err error) {
	ps.Lock()
	defer ps.Unlock()
	ps.refreshAvailablePeers()
	for _, pool := range ps.pools {
		if len(pool.peers) > 0 {
			// the previous call to refreshAvailablePeers ensure that this would always be the case;
			// however, if we do have a zero length pool, we don't want to divide by zero, so this would
			// provide the needed test.
			// pick one of the peers from this pool at random
			peerIdx := crypto.RandUint64() % uint64(len(pool.peers))
			peer = pool.peers[peerIdx].peer
			return
		}
	}

	return nil, errPeerSelectorNoPeerPoolsAvailable
}

// RankPeer ranks a given peer.
// return true if the value was updated or false otherwise.
func (ps *peerSelector) RankPeer(peer network.Peer, rank int) bool {
	if peer == nil {
		return false
	}
	ps.Lock()
	defer ps.Unlock()

	poolIdx, peerIdx := ps.findPeer(peer)
	if poolIdx < 0 || peerIdx < 0 {
		return false
	}

	// we need to remove the peer from the pool so we can place it in a different location.
	pool := ps.pools[poolIdx]
	class := pool.peers[peerIdx].class
	if len(pool.peers) > 1 {
		pool.peers = append(pool.peers[:peerIdx], pool.peers[peerIdx+1:]...)
		ps.pools[poolIdx] = pool
	} else {
		// the last peer was removed from the pool; delete this pool.
		ps.pools = append(ps.pools[:poolIdx], ps.pools[poolIdx+1:]...)
	}

	sortNeeded := ps.addToPool(peer, rank, class)
	if sortNeeded {
		ps.sort()
	}
	return true
}

// PeerDownloadDurationToRank calculates the rank for a peer given a peer and the block download time.
func (ps *peerSelector) PeerDownloadDurationToRank(peer network.Peer, blockDownloadDuration time.Duration) (rank int) {
	poolIdx, peerIdx := ps.findPeer(peer)
	if poolIdx < 0 || peerIdx < 0 {
		return peerRankInvalidDownload
	}

	switch ps.pools[poolIdx].peers[peerIdx].class.initialRank {
	case peerRankInitialFirstPriority:
		return downloadDurationToRank(blockDownloadDuration, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank0LowBlockTime, peerRank0HighBlockTime)
	default: // i.e. peerRankInitialSecondPriority
		return downloadDurationToRank(blockDownloadDuration, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank1LowBlockTime, peerRank1HighBlockTime)
	}
}

// addToPool adds a given peer to the correct group. If no group exists for that peer's rank,
// a new group is created.
// The method return true if a new group was created ( suggesting that the pools list would need to be re-ordered ), or false otherwise.
func (ps *peerSelector) addToPool(peer network.Peer, rank int, class peerClass) bool {
	// see if we already have a list with that rank:
	for i, peersList := range ps.pools {
		if peersList.rank == rank {
			// we found an existing group, add this peer to the list.
			ps.pools[i] = peerPool{rank: rank, peers: append(peersList.peers, peerPoolEntry{peer: peer, class: class})}
			return false
		} else if peersList.rank > rank {
			break
		}
	}
	ps.pools = append(ps.pools, peerPool{rank: rank, peers: []peerPoolEntry{{peer: peer, class: class}}})
	return true
}

// sort the pools array in an accending order according to the rank of each pool.
func (ps *peerSelector) sort() {
	sort.SliceStable(ps.pools, func(i, j int) bool {
		return ps.pools[i].rank < ps.pools[j].rank
	})
}

// peerAddress returns the peer's underlying address. The network.Peer object cannot be compared
// to itself, since the network package dynamically creating a new instance on every network.GetPeers() call.
// The method retrun the peer address or an empty string if the peer is not one of HTTPPeer/UnicastPeer
func peerAddress(peer network.Peer) string {
	if httpPeer, ok := peer.(network.HTTPPeer); ok {
		return httpPeer.GetAddress()
	} else if unicastPeer, ok := peer.(network.UnicastPeer); ok {
		return unicastPeer.GetAddress()
	}
	return ""
}

// refreshAvailablePeers reload the available peers from the network package, add new peers along with their
// corresponding initial rank, and deletes peers that have been dropped by the network package.
func (ps *peerSelector) refreshAvailablePeers() {
	evalPeers := make(map[string]network.Peer)
	for _, pool := range ps.pools {
		for _, localPeer := range pool.peers {
			if peerAddress := peerAddress(localPeer.peer); peerAddress != "" {
				evalPeers[peerAddress] = localPeer.peer
			}
		}
	}
	sortNeeded := false
	for _, initClass := range ps.peerClasses {
		peers := ps.net.GetPeers(initClass.peerClass)
		for _, peer := range peers {
			peerAddress := peerAddress(peer)
			if peerAddress == "" {
				continue
			}
			if _, has := evalPeers[peerAddress]; has {
				delete(evalPeers, peerAddress)
				continue
			}
			// it's an entry which we did not had before.
			sortNeeded = sortNeeded || ps.addToPool(peer, initClass.initialRank, initClass)
		}
	}

	// delete the "old" entries.
	for poolIdx := len(ps.pools) - 1; poolIdx >= 0; poolIdx-- {
		pool := ps.pools[poolIdx]
		for peerIdx := len(pool.peers) - 1; peerIdx >= 0; peerIdx-- {
			peer := pool.peers[peerIdx].peer
			if peerAddress := peerAddress(peer); peerAddress != "" {
				if _, has := evalPeers[peerAddress]; has {
					// need to be removed.
					pool.peers = append(pool.peers[:peerIdx], pool.peers[peerIdx+1:]...)
				}
			}
		}
		if len(pool.peers) == 0 {
			ps.pools = append(ps.pools[:poolIdx], ps.pools[poolIdx+1:]...)
			sortNeeded = true
		} else {
			ps.pools[poolIdx] = pool
		}
	}

	if sortNeeded {
		ps.sort()
	}
}

// findPeer look into the peer pool and find the given peer.
// The method returns the pool and peer indices if a peer was found, or (-1, -1) otherwise.
func (ps *peerSelector) findPeer(peer network.Peer) (poolIdx, peerIdx int) {
	peerAddr := peerAddress(peer)
	if peerAddr != "" {
		for i, pool := range ps.pools {
			for j, localPeerEntry := range pool.peers {
				if peerAddress(localPeerEntry.peer) == peerAddr {
					return i, j
				}
			}
		}
	}
	return -1, -1
}

// calculate the duration rank by mapping the range of [minDownloadDuration..maxDownloadDuration] into the rank range of [minRank..maxRank]
func downloadDurationToRank(downloadDuration, minDownloadDuration, maxDownloadDuration time.Duration, minRank, maxRank int) (rank int) {
	if downloadDuration < minDownloadDuration {
		downloadDuration = minDownloadDuration
	} else if downloadDuration > maxDownloadDuration {
		downloadDuration = maxDownloadDuration
	}
	rank = minRank + int((downloadDuration-minDownloadDuration).Nanoseconds()*int64(maxRank-minRank)/(maxDownloadDuration-minDownloadDuration).Nanoseconds())
	return
}
