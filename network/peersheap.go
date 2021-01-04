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

package network

type peersHeap struct {
	wn *WebsocketNetwork
}

// Push implements heap.Interface
func (ph peersHeap) Push(x interface{}) {
	wn := ph.wn
	p := x.(*wsPeer)
	wn.peers = append(wn.peers, p)
	p.peerIndex = len(wn.peers) - 1
}

// Pop implements heap.Interface
func (ph peersHeap) Pop() interface{} {
	wn := ph.wn
	end := len(wn.peers) - 1
	p := wn.peers[end]
	wn.peers[end] = nil // remove the entry from the peers list, so that the GC can recycle it's memory as needed.
	wn.peers = wn.peers[:end]
	return p
}

// Len implements heap.Interface
func (ph peersHeap) Len() int {
	wn := ph.wn
	return len(wn.peers)
}

// Swap implements heap.Interface
func (ph peersHeap) Swap(i, j int) {
	wn := ph.wn
	pi := wn.peers[i]
	pj := wn.peers[j]
	wn.peers[i] = pj
	wn.peers[j] = pi
	pi.peerIndex = j
	pj.peerIndex = i
}

// Less implements heap.Interface
func (ph peersHeap) Less(i, j int) bool {
	wn := ph.wn
	pi := wn.peers[i]
	pj := wn.peers[j]

	// Outgoing + explicitly listed peers are the highest priority
	if pj.outgoing || checkPrioPeers(wn, pj) {
		return false
	}
	if pi.outgoing || checkPrioPeers(wn, pi) {
		return true
	}

	// Bigger weight means lower position in wn.peers
	return pi.prioWeight > pj.prioWeight
}

func checkPrioPeers(wn *WebsocketNetwork, wp *wsPeer) bool {
	pp := wn.config.PriorityPeers
	if pp == nil {
		return false
	}

	addr := wp.OriginAddress()
	if addr == "" {
		return false
	}

	return pp[addr]
}
