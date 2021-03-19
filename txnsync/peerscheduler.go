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

package txnsync

import (
	"container/heap"
	//"fmt"
	"time"
)

//msgp:ignore peerBuckets
type peerBuckets []peerBucket

type peerScheduler struct {
	peers peerBuckets
	node  NodeConnector
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
}

// Pop implements heap.Interface
func (p *peerScheduler) Pop() interface{} {
	end := len(p.peers) - 1
	res := p.peers[end]
	p.peers[end] = peerBucket{}
	p.peers = p.peers[0:end]
	return res
}

// Len implements heap.Interface
func (p *peerScheduler) Len() int {
	return len(p.peers)
}

// Swap implements heap.Interface
func (p *peerScheduler) Swap(i, j int) {
	p.peers[i], p.peers[j] = p.peers[j], p.peers[i]
}

// Less implements heap.Interface
func (p *peerScheduler) Less(i, j int) bool {
	return p.peers[i].next < p.peers[j].next
}

// refresh the current schedule by creating new schedule for each of the peers.
func (p *peerScheduler) scheduleNewRound(peers []*Peer, isRelay bool) {
	// clear the existings peers list.
	p.peers = make(peerBuckets, 0, len(peers))
	for _, peer := range peers {
		if isRelay && peer.isOutgoing {
			continue
		}
		peerEntry := peerBucket{peer: peer}
		peerEntry.next = kickoffTime + time.Duration(p.node.Random(uint64(randomRange)))

		p.peers = append(p.peers, peerEntry)
	}
	heap.Init(p)

}

func (p *peerScheduler) nextDuration() time.Duration {
	if len(p.peers) == 0 {
		return time.Duration(0)
	}
	return p.peers[0].next
}

func (p *peerScheduler) nextPeers(granularityWindow time.Duration) (outPeers []*Peer) {
	next := p.nextDuration()
	next -= next % granularityWindow

	// pull out of the heap all the entries that have next smaller or equal to the above next.
	// make scheduling more granular, so that we can produce a single bloom filter for multiple outgoing messages.
	for len(p.peers) > 0 && (p.peers[0].next-p.peers[0].next%granularityWindow) <= next {
		bucket := heap.Remove(p, 0).(peerBucket)
		outPeers = append(outPeers, bucket.peer)
	}
	return
}

func (p *peerScheduler) schedulerPeer(peer *Peer, next time.Duration) {
	bucket := peerBucket{peer: peer, next: next}
	heap.Push(p, bucket)
	/*fmt.Printf("scheduling for %v\n", next.Nanoseconds())
	if next == 787500000 {
		panic(nil)
	}*/
}

func (p *peerScheduler) peerDuration(peer *Peer) time.Duration {
	for i := 0; i < len(p.peers); i++ {
		if p.peers[i].peer != peer {
			continue
		}
		bucket := heap.Remove(p, i).(peerBucket)
		return bucket.next
	}
	return time.Duration(0)
}
