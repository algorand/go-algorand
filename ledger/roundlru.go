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

package ledger

import (
	"container/heap"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/basics"
)

type lruEntry struct {
	useIndex int
	r        basics.Round
	x        interface{}
}

type lruHeap struct {
	heap   []lruEntry
	lookup map[basics.Round]int
}

// Len is part of heap.Interface
func (h *lruHeap) Len() int {
	return len(h.heap)
}

// Less reports whether the element with
// index i should sort before the element with index j.
func (h *lruHeap) Less(i, j int) bool {
	return h.heap[i].useIndex < h.heap[j].useIndex
}

// Swap swaps the elements with indexes i and j.
func (h *lruHeap) Swap(i, j int) {
	t := h.heap[i]
	h.heap[i] = h.heap[j]
	h.heap[j] = t
	h.lookup[h.heap[i].r] = i
	h.lookup[h.heap[j].r] = j
}
func (h *lruHeap) Push(x interface{}) {
	// add x as element Len()
	xv := x.(lruEntry)
	h.heap = append(h.heap, xv)
	h.lookup[xv.r] = len(h.heap) - 1
}
func (h *lruHeap) Pop() interface{} {
	// remove and return element Len() - 1.
	oldlen := len(h.heap)
	out := h.heap[oldlen-1]
	h.heap = h.heap[:oldlen-1]
	delete(h.lookup, out.r)
	return out
}

type heapLRUCache struct {
	entries      lruHeap
	lock         deadlock.Mutex
	nextUseIndex int
	maxEntries   int
}

func (hlc *heapLRUCache) Get(r basics.Round) (ob interface{}, exists bool) {
	hlc.lock.Lock()
	defer hlc.lock.Unlock()
	if i, present := hlc.entries.lookup[r]; present {
		out := hlc.entries.heap[i].x
		hlc.entries.heap[i].useIndex = hlc.nextUseIndex
		hlc.inc()
		heap.Fix(&hlc.entries, i)
		return out, true
	}
	return nil, false
}
func (hlc *heapLRUCache) Put(r basics.Round, data interface{}) {
	hlc.lock.Lock()
	defer hlc.lock.Unlock()
	if hlc.entries.heap == nil {
		hlc.entries.heap = make([]lruEntry, 1)
		hlc.entries.heap[0] = lruEntry{hlc.nextUseIndex, r, data}
		hlc.inc()
		hlc.entries.lookup = make(map[basics.Round]int)
		hlc.entries.lookup[r] = 0
		return
	}
	if i, present := hlc.entries.lookup[r]; present {
		// update data, but don't adjust LRU order
		hlc.entries.heap[i].x = data
		return
	}
	heap.Push(&hlc.entries, lruEntry{hlc.nextUseIndex, r, data})
	for len(hlc.entries.heap) > hlc.maxEntries {
		heap.Remove(&hlc.entries, 0)
	}
	hlc.inc()
}

// MaxInt is the maximum int which might be int32 or int64
const MaxInt = int((^uint(0)) >> 1)

func (hlc *heapLRUCache) inc() {
	hlc.nextUseIndex++
	if hlc.nextUseIndex == MaxInt {
		hlc.reIndex()
	}
}
func (hlc *heapLRUCache) reIndex() {
	if hlc.entries.heap == nil || len(hlc.entries.heap) == 0 {
		return
	}
	minprio := hlc.entries.heap[0].useIndex
	maxprio := hlc.entries.heap[0].useIndex
	for i := 1; i < len(hlc.entries.heap); i++ {
		xp := hlc.entries.heap[i].useIndex
		if xp < minprio {
			minprio = xp
		}
		if xp > maxprio {
			maxprio = xp
		}
	}
	for i := range hlc.entries.heap {
		hlc.entries.heap[i].useIndex -= minprio
	}
	hlc.nextUseIndex = maxprio + 1 - minprio
}
