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

package network

import (
	"container/heap"
)

// sendScheduler is a priority heap of wsPeer
// sendScheduler is sorted with relays first, high stake nodes next, then other peers
type sendScheduler struct {
	peers []*wsPeer
}

func (sched *sendScheduler) add(wp *wsPeer) bool {
	// if wp.inSendScheduler {
	// 	return false
	// }
	heap.Push(sched, wp)
	//wp.inSendScheduler = true
	return true
}
func (sched *sendScheduler) next() *wsPeer {
	if len(sched.peers) == 0 {
		return nil
	}
	wp := sched.peers[0]
	heap.Pop(sched)
	return wp
}

// Len is part of sort.Interface and heap.Interface
func (sched *sendScheduler) Len() int {
	return len(sched.peers)
}

// Less is part of sort.Interface and heap.Interface
// "Less" is more forward in the queue, higher weight is that.
func (sched *sendScheduler) Less(i, j int) bool {
	vi := sched.peers[i]
	vj := sched.peers[j]
	if vi.outgoing {
		// relays connections we have chosen are higher priority
		if !vj.outgoing {
			return true
		}
	} else if vj.outgoing {
		// relays connections we have chosen are higher priority
		return false
	}
	// TODO: rank other relays before other nodes
	return vi.prioWeight > vj.prioWeight
}

// Swap is part of sort.Interface and heap.Interface
func (sched *sendScheduler) Swap(i, j int) {
	t := sched.peers[i]
	sched.peers[i] = sched.peers[j]
	sched.peers[j] = t
}

func (sched *sendScheduler) Push(x interface{}) {
	v := x.(*wsPeer)
	sched.peers = append(sched.peers, v)
}

func (sched *sendScheduler) Pop() (x interface{}) {
	last := len(sched.peers) - 1
	x = sched.peers[last]
	sched.peers[last] = nil
	sched.peers = sched.peers[:last]
	return x
}
