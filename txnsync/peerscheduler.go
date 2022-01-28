// Copyright (C) 2019-2022 Algorand, Inc.
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

package txnsync

import (
	"container/heap"
	"sort"
	"time"
)

//msgp:ignore peerBuckets
type peerBuckets []peerBucket

type peerScheduler struct {
	peers     peerBuckets
	nextPeers map[*Peer][]int // nextPeers holds an array of ordered indices where this Peer object is on the peers peerBuckets
	node      NodeConnector
}

// makePeerScheduler initializes a peer scheduler object.
func makePeerScheduler() peerScheduler {
	return peerScheduler{
		nextPeers: make(map[*Peer][]int),
	}
}

//msgp:ignore peerBucket
type peerBucket struct {
	peer *Peer
	next time.Duration
}

// Push implements heap.Interface
func (p *peerScheduler) Push(x interface{}) {
	entry := x.(peerBucket)
	p.peers = append(p.peers, entry)
	p.nextPeers[entry.peer] = append(p.nextPeers[entry.peer], len(p.peers)-1)

	if len(p.nextPeers[entry.peer]) > 1 {
		peerIndices := p.nextPeers[entry.peer]
		sort.Slice(peerIndices, func(i, j int) bool {
			return p.peers[peerIndices[i]].next < p.peers[peerIndices[j]].next
		})
	}

}

// Pop implements heap.Interface
func (p *peerScheduler) Pop() interface{} {
	end := len(p.peers) - 1
	res := p.peers[end]

	// delete from the map only if it's the last entry
	peerIndices := p.nextPeers[res.peer]

	if peerIndices[0] != end {
		// this case is possible when the peer has two elements in p.peers.
		// and both have the same next value.
		for idx, x := range peerIndices {
			if x == end {
				peerIndices[0], peerIndices[idx] = peerIndices[idx], peerIndices[0]
				break
			}
		}
	}
	// the peer index must be the first entry.
	peerIndices = peerIndices[1:]

	// store if non-empty.
	if len(peerIndices) > 0 {
		p.nextPeers[res.peer] = peerIndices
	} else {
		delete(p.nextPeers, res.peer)
	}

	p.peers[end] = peerBucket{}
	p.peers = p.peers[0:end]
	return res
}

// Len implements heap.Interface
func (p *peerScheduler) Len() int {
	return len(p.peers)
}

func (p *peerScheduler) replaceIndices(indices []int, i, j int) {

	for idx, x := range indices {
		if x == i {
			indices[idx] = j
		} else if x == j {
			indices[idx] = i
		}
	}
	sort.Slice(indices, func(i, j int) bool {
		return p.peers[indices[i]].next < p.peers[indices[j]].next
	})
}

// Swap implements heap.Interface
func (p *peerScheduler) Swap(i, j int) {
	p.peers[i], p.peers[j] = p.peers[j], p.peers[i]
	if p.peers[i].peer == p.peers[j].peer {
		indices := p.nextPeers[p.peers[i].peer]
		sort.Slice(indices, func(x, y int) bool {
			return p.peers[indices[x]].next < p.peers[indices[y]].next
		})
		return
	}
	p.replaceIndices(p.nextPeers[p.peers[i].peer], i, j)
	p.replaceIndices(p.nextPeers[p.peers[j].peer], i, j)
}

// Less implements heap.Interface
func (p *peerScheduler) Less(i, j int) bool {
	return p.peers[i].next < p.peers[j].next
}

// refresh the current schedule by creating new schedule for each of the peers.
func (p *peerScheduler) scheduleNewRound(peers []*Peer) {
	// clear the existings peers list.
	p.peers = make(peerBuckets, 0, len(peers))
	p.nextPeers = make(map[*Peer][]int)
	for _, peer := range peers {
		peerEntry := peerBucket{peer: peer}
		peerEntry.next = kickoffTime + time.Duration(p.node.Random(uint64(randomRange)))

		p.peers = append(p.peers, peerEntry)
		p.nextPeers[peer] = []int{len(p.peers) - 1}
	}
	heap.Init(p)
}

func (p *peerScheduler) nextDuration() time.Duration {
	if len(p.peers) == 0 {
		return time.Duration(0)
	}
	return p.peers[0].next
}

func (p *peerScheduler) getNextPeers() (outPeers []*Peer) {
	next := p.nextDuration()

	// pull out of the heap all the entries that have next smaller or equal to the above next.
	for len(p.peers) > 0 && p.peers[0].next <= next {
		bucket := heap.Remove(p, 0).(peerBucket)
		outPeers = append(outPeers, bucket.peer)
	}

	// in many cases, we'll have only a single peer; however, in case we have multiple
	// ( which is more likely when we're "running late" ), we want to make sure to remove
	// duplicate ones.
	if len(outPeers) > 1 {
		// note that the algorithm here ensures that we retain the peer order from above
		// while dropping off recurring peers.
		peersMap := make(map[*Peer]bool, len(outPeers))
		offset := 0
		peersMap[outPeers[0]] = true
		for i := 1; i < len(outPeers); i++ {
			if peersMap[outPeers[i]] {
				// we already had this peer.
				offset++
				continue
			}
			// we haven't seen this peer.
			outPeers[i-offset] = outPeers[i]
			peersMap[outPeers[i]] = true
		}
		outPeers = outPeers[:len(outPeers)-offset]
	}
	return
}

func (p *peerScheduler) schedulePeer(peer *Peer, next time.Duration) {
	bucket := peerBucket{peer: peer, next: next}
	heap.Push(p, bucket)
}

func (p *peerScheduler) peerDuration(peer *Peer) time.Duration {
	peerIndices := p.nextPeers[peer]
	if len(peerIndices) == 0 {
		return time.Duration(0)
	}
	bucket := heap.Remove(p, peerIndices[0]).(peerBucket)
	return bucket.next
}
