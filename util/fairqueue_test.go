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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// offerFrom offers a value naming its source and sequence number, so the
// order of takes can be checked by content.
func offerFrom(q *FairQueue[string], source string, seq byte) (dropped bool) {
	return q.Offer(source, source+string('0'+seq))
}

func takeAll(q *FairQueue[string]) []string {
	var got []string
	for {
		m, ok := q.Take()
		if !ok {
			return got
		}
		got = append(got, m)
	}
}

func TestFairQueueRoundRobin(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	q := NewFairQueue[string](50)
	for seq := range byte(3) {
		offerFrom(q, "a", seq)
	}
	offerFrom(q, "b", 0)
	offerFrom(q, "c", 0)
	offerFrom(q, "c", 1)

	// One value from each source in turn, each source's oldest first.
	require.Equal(t, []string{"a0", "b0", "c0", "a1", "c1", "a2"}, takeAll(q))
	require.Zero(t, q.waiting)
	require.Empty(t, q.bySource)
	require.Empty(t, q.order)

	// A source that comes back after emptying joins the end of the turn.
	offerFrom(q, "a", 0)
	offerFrom(q, "b", 0)
	require.Equal(t, []string{"a0"}, takeAll(q)[:1])
	offerFrom(q, "a", 1)
	offerFrom(q, "b", 1)
	require.Equal(t, []string{"a1", "b1"}, takeAll(q))
}

func TestFairQueueFull(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// A source alone can fill the queue.
	q := NewFairQueue[string](4)
	for seq := range byte(4) {
		require.False(t, offerFrom(q, "a", seq))
	}

	// When full, a value from another source drops the oldest value of the
	// source with the most waiting.
	require.True(t, offerFrom(q, "b", 0))
	require.True(t, offerFrom(q, "c", 0))
	require.Equal(t, 4, q.waiting)

	// a has 2 waiting and b and c 1 each, so another value from a drops a's
	// own oldest.
	require.True(t, offerFrom(q, "a", 4))
	require.Equal(t, []string{"a3", "b0", "c0", "a4"}, takeAll(q))

	// Each source has 1 waiting, so the arriving source ties with all of
	// them and drops its own oldest.
	for _, s := range []string{"a", "b", "c", "d"} {
		offerFrom(q, s, 0)
	}
	require.True(t, offerFrom(q, "b", 1))
	require.Equal(t, []string{"a0", "c0", "d0", "b1"}, takeAll(q))
}

// TestFairQueueBoundedWait checks that a value already waiting is served
// within one turn however the other sources come and go, and that a source
// that joins while others wait is served after all of them.
func TestFairQueueBoundedWait(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// a1 waits behind a0 while b and c empty and refill on every take. It
	// must still come out after at most one value from each of them.
	q := NewFairQueue[string](50)
	offerFrom(q, "a", 0)
	offerFrom(q, "a", 1)
	offerFrom(q, "b", 0)
	offerFrom(q, "c", 0)
	m, ok := q.Take()
	require.True(t, ok)
	require.Equal(t, "a0", m)
	var before []string
	for {
		m, ok = q.Take()
		require.True(t, ok)
		if m == "a1" {
			break
		}
		before = append(before, m)
		require.LessOrEqual(t, len(before), 2, "a1 was not served within one turn")
		offerFrom(q, m[:1], 1)
	}
	require.Equal(t, []string{"b0", "c0"}, before)

	// With b and c waiting and a's turn just taken, d joins and a returns.
	// Both are served after b and c, in the order they joined.
	q = NewFairQueue[string](50)
	offerFrom(q, "a", 0)
	offerFrom(q, "b", 0)
	offerFrom(q, "c", 0)
	m, ok = q.Take()
	require.True(t, ok)
	require.Equal(t, "a0", m)
	offerFrom(q, "d", 0)
	offerFrom(q, "a", 1)
	require.Equal(t, []string{"b0", "c0", "d0", "a1"}, takeAll(q))
}

func TestFairQueueCapacityBelowOne(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, capacity := range []int{0, -1} {
		q := NewFairQueue[string](capacity)
		require.False(t, offerFrom(q, "a", 0))
		require.True(t, offerFrom(q, "b", 0))
		require.Equal(t, []string{"b0"}, takeAll(q))
	}
}

func TestFairQueueEmptySource(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	q := NewFairQueue[string](4)
	q.Offer("", "x0")
	offerFrom(q, "a", 0)
	q.Offer("", "x1")
	require.Equal(t, []string{"x0", "a0", "x1"}, takeAll(q))
}

func TestFairQueueNext(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	q := NewFairQueue[string](4)
	ctx, cancel := context.WithCancel(context.Background())

	got := make(chan string, 1)
	go func() {
		if m, ok := q.Next(ctx); ok {
			got <- m
		}
	}()
	offerFrom(q, "a", 0)
	select {
	case m := <-got:
		require.Equal(t, "a0", m)
	case <-time.After(5 * time.Second):
		require.Fail(t, "Next did not return an offered value")
	}

	// It returns false once ctx is done.
	cancel()
	_, ok := q.Next(ctx)
	require.False(t, ok)
}
