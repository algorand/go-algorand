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
	"math"
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

	peerRankInitialThirdPriority = 400
	peerRank2LowBlockTime        = 401
	peerRank2HighBlockTime       = 599

	peerRankInitialFourthPriority = 600
	peerRank3LowBlockTime         = 601
	peerRank3HighBlockTime        = 799

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

	// Is the lookback window size of peer usage statistics
	peerHistoryWindowSize = 100
)

var errPeerSelectorNoPeerPoolsAvailable = errors.New("no peer pools available")

// peerClass defines the type of peer we want to have in a particular "class",
// and define the network.PeerOption that would be used to retrieve that type of
// peer
type peerClass struct {
	initialRank int
	peerClass   network.PeerOption
}

// the peersRetriever is a subset of the network.GossipNode used to ensure that we can create an instance of the peerSelector
// for testing purposes, providing just the above function.
type peersRetriever interface {
	// Get a list of Peers we could potentially send a direct message to.
	GetPeers(options ...network.PeerOption) []network.Peer
}

// peerPoolEntry represents a single peer entry in the pool. It contains
// the underlying network peer as well as the peer class.
type peerPoolEntry struct {
	peer    network.Peer
	class   peerClass
	history *historicStats
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
	mu          deadlock.Mutex
	net         peersRetriever
	peerClasses []peerClass
	pools       []peerPool
	counter     uint64
}

// historicStats stores the past windowSize ranks for the peer
// The purpose of this structure is to compute the rank based on the
// performance of the peer in the past, and be forgiving of occasional
// errors or performance variations which may not be representative of
// the peer's overall performance.
type historicStats struct {
	windowSize  int
	rankSamples []int
	rankSum     uint64
	requestGaps []uint64
	gapSum      float64
	counter     uint64
}

func makeHistoricStatus(windowSize int) *historicStats {
	// Initialize the window (rankSamples) with zeros.
	// This way, every peer will slowly build up its profile.
	// Otherwise, if the best peer gets a bad download the first time,
	// may never be selected again.
	hs := historicStats{
		windowSize:  windowSize,
		rankSamples: make([]int, windowSize, windowSize),
		requestGaps: make([]uint64, 0, windowSize),
		rankSum:     0,
		gapSum:      0.0}
	return &hs
}

func (hs *historicStats) computerPenalty() float64 {
	return 1 + (math.Exp(hs.gapSum/10.0) / 1000)
}

func (hs *historicStats) updateRequestPenalty(counter uint64) float64 {
	newGap := counter - hs.counter
	hs.counter = counter
	hs.requestGaps = append(hs.requestGaps, newGap)
	hs.gapSum += 1.0 / float64(newGap)
	return hs.computerPenalty()
}

// removes steps least recent penalties and recomputes the rank with the new penalty value
func (hs *historicStats) resetRequestPenalty(steps int, initialRank int, class peerClass) int {
	if len(hs.requestGaps) == 0 {
		return initialRank
	}
	// resetRequestPenalty cannot move the peer to a better class if the peer was moved
	// to a lower class (e.g. failed downloads or invalid downloads)
	if upperBound(class) < initialRank {
		return initialRank
	}
	// if setps is 0, it is a full reset
	if steps == 0 {
		hs.requestGaps = make([]uint64, 0, hs.windowSize)
		hs.gapSum = 0.0
		return int(float64(hs.rankSum) / float64(len(hs.rankSamples)))
	}

	if steps > len(hs.requestGaps) {
		steps = len(hs.requestGaps)
	}
	for s := 0; s < steps; s++ {
		hs.gapSum -= 1.0 / float64(hs.requestGaps[s])
	}
	hs.requestGaps = hs.requestGaps[steps:]
	return int(hs.computerPenalty() * (float64(hs.rankSum) / float64(len(hs.rankSamples))))
}

// push pushes a new rank to the historicStats, and returns the new rank
// based on the average of ranks in the windowSize window
func (hs *historicStats) push(value int, counter uint64, class peerClass) (averagedRank int) {

	// This is the lowest ranking class, and is not subject to giving another chance.
	// Do not modify this value with historical data.
	if value == peerRankInvalidDownload {
		return value
	}

	// This is a moving window. Remore the least recent value once the window is full
	if len(hs.rankSamples) == hs.windowSize {
		hs.rankSum -= uint64(hs.rankSamples[0])
		hs.rankSamples = hs.rankSamples[1:]
	}

	if len(hs.requestGaps) == hs.windowSize {
		hs.gapSum -= 1.0 / float64(hs.requestGaps[0])
		hs.requestGaps = hs.requestGaps[1:]
	}

	initialRank := value

	// Download may fail for various reasons. Give it additional tries
	// and see if it recovers/improves.
	if value == peerRankDownloadFailed {
		// Set the rank to 1 + the class upper bound, to evict
		// the peer from the class if it is repeatedly
		// failing. This is to make sure to switch to the next
		// class when all peers in this class are failing.
		// Here, +10 is added. This is of little consequence, and the
		// purpose is to avoid rounding errors.
		value = upperBound(class) + 10
	}

	hs.rankSamples = append(hs.rankSamples, value)
	hs.rankSum += uint64(value)

	// The average performance of the peer
	average := float64(hs.rankSum) / float64(len(hs.rankSamples))

	if int(average) > upperBound(class) && initialRank == peerRankDownloadFailed {
		// peerRankDownloadFailed will be delayed, to give the peer
		// additional time to improve. If odes not improve over time,
		// the average will exceed the class limit. At this point,
		// it will be pushed down to download failed class.
		return peerRankDownloadFailed
	}

	// A penalty is added relative to how freequently the peer is used
	penalty := hs.updateRequestPenalty(counter)

	// The rank based on the performance and the freequency
	avgWithPenalty := int(penalty * average)

	// Keep the peer in the same class. The rank will be within bounds, but
	// the penalty may push it over. Prevent it here.
	bounded := boundRankByClass(avgWithPenalty, class)
	return bounded
}

// makePeerSelector creates a peerSelector, given a peersRetriever and peerClass array.
func makePeerSelector(net peersRetriever, initialPeersClasses []peerClass) *peerSelector {
	selector := &peerSelector{
		net:         net,
		peerClasses: initialPeersClasses,
	}
	return selector
}

// GetNextPeer returns the next peer. It randomally selects a peer from a pool that has
// the lowest rank value. Given that the peers are grouped by their ranks, allow us to
// prioritize peers based on their class and/or performance.
func (ps *peerSelector) GetNextPeer() (peer network.Peer, err error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
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
	ps.mu.Lock()
	defer ps.mu.Unlock()

	poolIdx, peerIdx := ps.findPeer(peer)
	if poolIdx < 0 || peerIdx < 0 {
		return false
	}
	sortNeeded := false

	// we need to remove the peer from the pool so we can place it in a different location.
	pool := ps.pools[poolIdx]
	ps.counter++
	rank = pool.peers[peerIdx].history.push(rank, ps.counter, pool.peers[peerIdx].class)
	if pool.rank != rank {
		class := pool.peers[peerIdx].class
		peerHistory := pool.peers[peerIdx].history
		if len(pool.peers) > 1 {
			pool.peers = append(pool.peers[:peerIdx], pool.peers[peerIdx+1:]...)
			ps.pools[poolIdx] = pool
		} else {
			// the last peer was removed from the pool; delete this pool.
			ps.pools = append(ps.pools[:poolIdx], ps.pools[poolIdx+1:]...)
		}

		sortNeeded = ps.addToPool(peer, rank, class, peerHistory)
	}

	// Update the ranks of the peers by reducing the penalty for not beeing selected
	for pl := len(ps.pools) - 1; pl >= 0; pl-- {
		pool := ps.pools[pl]
		for pr := len(pool.peers) - 1; pr >= 0; pr-- {
			localPeer := pool.peers[pr]
			if pool.peers[pr].peer == peer {
				continue
			}
			// make the removal of penalty at a faster rate than adding it, so that the
			// performance of the peer dominates in the evaluation over the freequency.
			// Otherwise, the peer selection will oscillate between the good performing and
			// a bad performing peers when sufficient penalty is accumulated to the good peer.
			newRank := localPeer.history.resetRequestPenalty(5, pool.rank, pool.peers[pr].class)
			if newRank != pool.rank {
				upeer := pool.peers[pr].peer
				class := pool.peers[pr].class
				peerHistory := pool.peers[pr].history
				if len(pool.peers) > 1 {
					pool.peers = append(pool.peers[:pr], pool.peers[pr+1:]...)
					ps.pools[pl] = pool
				} else {
					// the last peer was removed from the pool; delete this pool.
					ps.pools = append(ps.pools[:pl], ps.pools[pl+1:]...)
				}
				sortNeeded = ps.addToPool(upeer, newRank, class, peerHistory) || sortNeeded
			}
		}
	}
	if sortNeeded {
		ps.sort()
	}
	return true
}

// PeerDownloadDurationToRank calculates the rank for a peer given a peer and the block download time.
func (ps *peerSelector) PeerDownloadDurationToRank(peer network.Peer, blockDownloadDuration time.Duration) (rank int) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	poolIdx, peerIdx := ps.findPeer(peer)
	if poolIdx < 0 || peerIdx < 0 {
		return peerRankInvalidDownload
	}

	switch ps.pools[poolIdx].peers[peerIdx].class.initialRank {
	case peerRankInitialFirstPriority:
		return downloadDurationToRank(blockDownloadDuration, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank0LowBlockTime, peerRank0HighBlockTime)
	case peerRankInitialSecondPriority:
		return downloadDurationToRank(blockDownloadDuration, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank1LowBlockTime, peerRank1HighBlockTime)
	case peerRankInitialThirdPriority:
		return downloadDurationToRank(blockDownloadDuration, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank2LowBlockTime, peerRank2HighBlockTime)
	default: // i.e. peerRankInitialFourthPriority
		return downloadDurationToRank(blockDownloadDuration, lowBlockDownloadThreshold, highBlockDownloadThreshold, peerRank3LowBlockTime, peerRank3HighBlockTime)
	}
}

// addToPool adds a given peer to the correct group. If no group exists for that peer's rank,
// a new group is created.
// The method return true if a new group was created ( suggesting that the pools list would need to be re-ordered ), or false otherwise.
func (ps *peerSelector) addToPool(peer network.Peer, rank int, class peerClass, peerHistory *historicStats) bool {
	// see if we already have a list with that rank:
	for i, pool := range ps.pools {
		if pool.rank == rank {
			// we found an existing group, add this peer to the list.
			ps.pools[i].peers = append(pool.peers, peerPoolEntry{peer: peer, class: class, history: peerHistory})
			return false
		}
	}
	ps.pools = append(ps.pools, peerPool{rank: rank, peers: []peerPoolEntry{{peer: peer, class: class, history: peerHistory}}})
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
	existingPeers := make(map[string]network.Peer)
	for _, pool := range ps.pools {
		for _, localPeer := range pool.peers {
			if peerAddress := peerAddress(localPeer.peer); peerAddress != "" {
				existingPeers[peerAddress] = localPeer.peer
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
			if _, has := existingPeers[peerAddress]; has {
				delete(existingPeers, peerAddress)
				continue
			}
			// it's an entry which we did not have before.
			sortNeeded = ps.addToPool(peer, initClass.initialRank, initClass, makeHistoricStatus(peerHistoryWindowSize)) || sortNeeded
		}
	}

	// delete from the pools array the peers that do not exist on the network anymore.
	for poolIdx := len(ps.pools) - 1; poolIdx >= 0; poolIdx-- {
		pool := ps.pools[poolIdx]
		for peerIdx := len(pool.peers) - 1; peerIdx >= 0; peerIdx-- {
			peer := pool.peers[peerIdx].peer
			if peerAddress := peerAddress(peer); peerAddress != "" {
				if _, has := existingPeers[peerAddress]; has {
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
	// clamp the downloadDuration into the range of [minDownloadDuration .. maxDownloadDuration]
	if downloadDuration < minDownloadDuration {
		downloadDuration = minDownloadDuration
	} else if downloadDuration > maxDownloadDuration {
		downloadDuration = maxDownloadDuration
	}
	// the formula below maps an element in the range of [minDownloadDuration .. maxDownloadDuration] onto the range of [minRank .. maxRank]
	rank = minRank + int((downloadDuration-minDownloadDuration).Nanoseconds()*int64(maxRank-minRank)/(maxDownloadDuration-minDownloadDuration).Nanoseconds())
	return
}

func lowerBound(class peerClass) int {
	switch class.initialRank {
	case peerRankInitialFirstPriority:
		return peerRank0LowBlockTime
	case peerRankInitialSecondPriority:
		return peerRank1LowBlockTime
	case peerRankInitialThirdPriority:
		return peerRank2LowBlockTime
	default: // i.e. peerRankInitialFourthPriority
		return peerRank3LowBlockTime
	}
}

func upperBound(class peerClass) int {
	switch class.initialRank {
	case peerRankInitialFirstPriority:
		return peerRank0HighBlockTime
	case peerRankInitialSecondPriority:
		return peerRank1HighBlockTime
	case peerRankInitialThirdPriority:
		return peerRank2HighBlockTime
	default: // i.e. peerRankInitialFourthPriority
		return peerRank3HighBlockTime
	}
}

func boundRankByClass(rank int, class peerClass) int {
	if rank < lowerBound(class) {
		return lowerBound(class)
	}
	if rank > upperBound(class) {
		return upperBound(class)
	}
	return rank
}
