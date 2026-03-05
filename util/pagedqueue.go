// Copyright (C) 2019-2026 Algorand, Inc.
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

package util

import "iter"

// PagedQueue is a linked list of "pages" of entries. It is unsynchronized, so
// `append` must be used single threaded, or externally synchronized.  Access
// with `get` can be from multiple threads, after all appends have been
// completed.  These are roughly the same rules that a growing slice would have,
// but PagedQueue avoids copying to grow by using a paged approach.  Random
// access would pay a penalty to access entries by folling the links, but
// processing in FIFO order has negligible extra cost.
//
// The zero value is a valid empty queue; NewPagedQueue is only needed to
// pre-allocate capacity for the first page.
type PagedQueue[T any] struct {
	next    *PagedQueue[T]
	entries []T
	baseIdx int
}

// NewPagedQueue constructs a new PagedQueue that can hold at least count items
// without allocating a new page.
func NewPagedQueue[T any](count int) *PagedQueue[T] {
	count = max(count, 4)
	return &PagedQueue[T]{
		entries: make([]T, 0, count),
	}
}

// Len returns the number of entries in the queue.
func (pq *PagedQueue[T]) Len() int {
	if pq.next != nil {
		return pq.next.Len()
	}
	return pq.baseIdx + len(pq.entries)
}

// Append places v on the queue, allocating a new page if the current one is
// full, and returning the active page.
func (pq *PagedQueue[T]) Append(v T) *PagedQueue[T] {
	// We are at capacity, add a page rather than allow append() to grow the
	// slice and perform copies.
	if len(pq.entries) == cap(pq.entries) {
		if pq.entries == nil {
			// We must have a zero value of PagedQueue, no need for a page, just
			// allocate an initial slice.
			pq.entries = make([]T, 0, 8)
		} else {
			pq.next = &PagedQueue[T]{
				entries: make([]T, 0, cap(pq.entries)*2),
				baseIdx: pq.baseIdx + len(pq.entries),
			}
			pq = pq.next
		}
	}
	pq.entries = append(pq.entries, v)
	return pq
}

// Get returns an entry at an index. Callers must have a pointer to the page
// that idx is on, or a previous page.  It is most efficient to call Get with
// ascending values, constantly updating your local pointer to the returned
// PagedQueue. If idx is too low, Get() panics.  If it is too high, the zero
// value is returned.  The asymmetry reflects the fact that a low index is
// certainly a programmer error, a high index is a natural result of scanning
// forward.
func (pq *PagedQueue[T]) Get(idx int) (*PagedQueue[T], T) {
	localIdx := idx - pq.baseIdx
	if len(pq.entries) > localIdx {
		return pq, pq.entries[localIdx]
	}
	if pq.next != nil {
		return pq.next.Get(idx)
	}
	var zero T
	return pq, zero
}

// All returns an iterator over all entries in the queue in insertion order.
func (pq *PagedQueue[T]) All() iter.Seq[T] {
	return func(yield func(T) bool) {
		for page := pq; page != nil; page = page.next {
			for _, t := range page.entries {
				if !yield(t) {
					return
				}
			}
		}
	}
}
