// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

import (
	"context"
	"slices"

	"github.com/algorand/go-deadlock"
)

// FairQueue is a bounded queue of values from many sources that serves the
// sources fairly rather than first in, first out. Two rules answer two
// different questions.
//
// Which source is served next: each source has its own queue, and Take takes
// one value from each source with values waiting in turn. A source that
// starts or resumes waiting joins the end of the turn, behind every source
// already waiting, so a value waits behind at most one value from each other
// source. Within a source, values are served in arrival order, so to a single
// source the queue behaves like the FIFO channel it replaces.
//
// Which value is lost when the queue is full: Offer makes room by dropping the
// oldest value of the source with the most waiting, since the oldest is the
// most likely to be stale. A source with fewer values waiting than another
// therefore always gets in. On a tie with the arriving source, the arriving
// source's own oldest value is dropped.
//
// A source sending alone can still use the whole queue. A source is any
// string, including the empty string.
//
// FairQueue is safe for concurrent use, but Next expects a single caller at a
// time: an Offer wakes at most one waiting Next.
type FairQueue[T any] struct {
	capacity int

	mu deadlock.Mutex
	// bySource holds the waiting values of each source with any, oldest
	// first, and order the same sources in the order they are served. next
	// is the index in order of the source served next.
	bySource map[string][]T
	order    []string
	next     int
	waiting  int

	// ready has a value when a value may have been added since Next last
	// looked.
	ready chan struct{}
}

// NewFairQueue returns an empty FairQueue that holds at most capacity values,
// or one value if capacity is less than 1.
func NewFairQueue[T any](capacity int) *FairQueue[T] {
	return &FairQueue[T]{
		capacity: max(1, capacity),
		bySource: make(map[string][]T),
		ready:    make(chan struct{}, 1),
	}
}

// Offer adds m from source to the queue, and reports whether that dropped
// another value to make room.
func (q *FairQueue[T]) Offer(source string, m T) (dropped bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.waiting >= q.capacity {
		// A tie with the arriving source drops from the arriving source.
		// The capacity is at least 1, so a full queue always has a victim.
		victim := source
		for s, values := range q.bySource {
			if len(values) > len(q.bySource[victim]) {
				victim = s
			}
		}
		q.removeOldest(victim)
		dropped = true
	}

	if _, ok := q.bySource[source]; !ok {
		// Insert just before the source served next, which is the end of
		// the turn. Appending to order instead would let a source that keeps
		// emptying and refilling ahead of next hold next in place, so the
		// sources behind it would never be reached.
		q.order = slices.Insert(q.order, q.next, source)
		q.next++
		if q.next >= len(q.order) {
			q.next = 0
		}
	}
	q.bySource[source] = append(q.bySource[source], m)
	q.waiting++
	select {
	case q.ready <- struct{}{}:
	default:
	}
	return dropped
}

// Take removes and returns the oldest value of the source whose turn it is,
// or returns false if the queue is empty.
func (q *FairQueue[T]) Take() (T, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.waiting == 0 {
		var zero T
		return zero, false
	}
	source := q.order[q.next]
	m := q.bySource[source][0]
	if !q.removeOldest(source) {
		q.next++
	}
	if q.next >= len(q.order) {
		q.next = 0
	}
	return m, true
}

// removeOldest drops the oldest value of source, which must have one. It
// reports whether that left source with none, in which case source is also
// removed from order.
func (q *FairQueue[T]) removeOldest(source string) bool {
	values := q.bySource[source]
	// clear the slot so the dropped value can be collected while the slice's
	// backing array is still in use
	var zero T
	values[0] = zero
	values = values[1:]
	q.waiting--
	if len(values) > 0 {
		q.bySource[source] = values
		return false
	}

	delete(q.bySource, source)
	for i, s := range q.order {
		if s != source {
			continue
		}
		q.order = append(q.order[:i], q.order[i+1:]...)
		if i < q.next {
			q.next--
		}
		break
	}
	if q.next >= len(q.order) {
		q.next = 0
	}
	return true
}

// Next waits for a value and takes it, or returns false once ctx is done.
func (q *FairQueue[T]) Next(ctx context.Context) (T, bool) {
	for {
		if m, ok := q.Take(); ok {
			return m, true
		}
		select {
		case <-q.ready:
		case <-ctx.Done():
			var zero T
			return zero, false
		}
	}
}
