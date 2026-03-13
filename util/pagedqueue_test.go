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

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestPagedQueueNew checks that the constructor enforces a minimum page size of 4.
func TestPagedQueueNew(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	pq := NewPagedQueue[int](10)
	require.NotNil(t, pq)
	require.Zero(t, pq.Len())
	require.Equal(t, 10, cap(pq.entries))

	// sizes below 4 are promoted to 4
	small := NewPagedQueue[int](2)
	require.Equal(t, 4, cap(small.entries))
	require.Empty(t, small.entries)
}

// TestPagedQueueAppendAndLen checks that Len tracks the count correctly as items are appended across pages.
func TestPagedQueueAppendAndLen(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	pq := NewPagedQueue[int](4)
	for i := 0; i < 10; i++ {
		pq = pq.Append(i)
		require.Equal(t, i+1, pq.Len())
	}
}

// TestPagedQueueGet checks retrieval by index starting from the head page.
func TestPagedQueueGet(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	head := NewPagedQueue[int](4)
	cur := head
	for i := 0; i < 10; i++ {
		cur = cur.Append(i)
	}

	// retrieve every element using the head page as the starting point
	for i := 0; i < 10; i++ {
		page, val := head.Get(i)
		require.NotNil(t, page)
		require.Equal(t, i, val)
	}
}

// TestPagedQueueGetAdvancingPage verifies that callers can advance their page pointer to avoid re-traversal from the head.
func TestPagedQueueGetAdvancingPage(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Demonstrate that callers can advance their page pointer to avoid
	// traversing from the head on every Get.
	head := NewPagedQueue[string](4)
	cur := head
	words := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	for _, w := range words {
		cur = cur.Append(w)
	}

	page := head
	for i, want := range words {
		var got string
		page, got = page.Get(i)
		require.Equal(t, want, got)
	}
}

// TestPagedQueueGetZeroValueBeyondEnd checks that an index past the last entry returns the zero value.
func TestPagedQueueGetZeroValueBeyondEnd(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	head := NewPagedQueue[int](4)
	cur := head
	for i := 0; i < 3; i++ {
		cur = cur.Append(i + 1)
	}

	// index past the end returns the zero value
	_, val := head.Get(100)
	require.Equal(t, 0, val)
}

// TestPagedQueueGetPanicOnLowIndex checks that asking a non-head page for an index that belongs to an earlier page panics.
func TestPagedQueueGetPanicOnLowIndex(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Fill two pages so the second page has baseIdx > 0.
	head := NewPagedQueue[int](4)
	cur := head
	for i := 0; i < 8; i++ {
		cur = cur.Append(i)
	}

	// Asking a non-head page for an index that belongs to an earlier page panics
	// because localIdx goes negative and entries[-n] is out of bounds.
	require.Panics(t, func() {
		cur.Get(0)
	})
}

// TestPagedQueuePtr checks that Ptr returns a stable pointer to the correct entry across page boundaries.
func TestPagedQueuePtr(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	head := NewPagedQueue[int](4)
	cur := head
	for i := 0; i < 10; i++ {
		cur = cur.Append(i)
	}

	// collect pointers to all entries, then mutate through them
	ptrs := make([]*int, 10)
	page := head
	for i := range 10 {
		page, ptrs[i] = page.Ptr(i)
		require.NotNil(t, ptrs[i])
		require.Equal(t, i, *ptrs[i])
	}

	for i, p := range ptrs {
		*p = i * 100
	}

	// verify mutations are visible via Get
	for i := range 10 {
		_, val := head.Get(i)
		require.Equal(t, i*100, val)
	}
}

// TestPagedQueuePtrBeyondEnd checks that Ptr returns nil for an out-of-bounds index.
func TestPagedQueuePtrBeyondEnd(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	head := NewPagedQueue[int](4)
	cur := head
	for i := 0; i < 3; i++ {
		cur = cur.Append(i)
	}

	_, p := head.Ptr(100)
	require.Nil(t, p)
}

// TestPagedQueuePtrPanicOnLowIndex checks that Ptr panics when the index is below the page's baseIdx.
func TestPagedQueuePtrPanicOnLowIndex(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	head := NewPagedQueue[int](4)
	cur := head
	for i := 0; i < 8; i++ {
		cur = cur.Append(i)
	}

	require.Panics(t, func() { cur.Ptr(0) })
}

// TestPagedQueueAllPtrs checks that AllPtrs yields stable pointers in insertion order.
func TestPagedQueueAllPtrs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	head := NewPagedQueue[int](4)
	cur := head
	const n = 15
	for i := 0; i < n; i++ {
		cur = cur.Append(i)
	}

	// collect pointers then mutate through them
	var ptrs []*int
	for p := range head.AllPtrs() {
		ptrs = append(ptrs, p)
	}
	require.Len(t, ptrs, n)
	for i, p := range ptrs {
		*p = i * 10
	}
	for idx, v := range head.All2() {
		require.Equal(t, idx*10, v)
	}
}

// TestPagedQueueAllPtrs2 checks that AllPtrs2 yields correct indices and stable pointers across page boundaries.
func TestPagedQueueAllPtrs2(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	head := NewPagedQueue[int](4)
	cur := head
	const n = 15
	for i := 0; i < n; i++ {
		cur = cur.Append(i)
	}

	for idx, p := range head.AllPtrs2() {
		require.Equal(t, idx, *p)
		*p = idx * 10
	}
	for idx, v := range head.All2() {
		require.Equal(t, idx*10, v)
	}
}

// TestPagedQueueAll checks that the iterator yields all entries in insertion order.
func TestPagedQueueAll(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	head := NewPagedQueue[int](4)
	cur := head
	const n = 15
	for i := 0; i < n; i++ {
		cur = cur.Append(i)
	}

	var collected []int
	for v := range head.All() {
		collected = append(collected, v)
	}
	require.Len(t, collected, n)
	for i := 0; i < n; i++ {
		require.Equal(t, i, collected[i])
	}
}

// TestPagedQueueAllEarlyReturn checks that breaking early from All() works without panicking.
func TestPagedQueueAllEarlyReturn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	head := NewPagedQueue[int](4)
	cur := head
	for i := 0; i < 12; i++ {
		cur = cur.Append(i)
	}

	// stopping early should not panic and should return only the first few items
	var collected []int
	for v := range head.All() {
		collected = append(collected, v)
		if len(collected) == 5 {
			break
		}
	}
	require.Len(t, collected, 5)
	for i := 0; i < 5; i++ {
		require.Equal(t, i, collected[i])
	}
}

// TestPagedQueueAll2 checks that All2 yields correct queue-wide indices and values across page boundaries.
func TestPagedQueueAll2(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	head := NewPagedQueue[int](4)
	cur := head
	const n = 15
	for i := 0; i < n; i++ {
		cur = cur.Append(i * 10)
	}

	for idx, v := range head.All2() {
		require.Equal(t, idx*10, v)
	}
}

// TestPagedQueueAll2EarlyReturn checks that breaking early from All2() works without panicking.
func TestPagedQueueAll2EarlyReturn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	head := NewPagedQueue[int](4)
	cur := head
	for i := 0; i < 12; i++ {
		cur = cur.Append(i)
	}

	var collected []int
	for idx, v := range head.All2() {
		require.Equal(t, idx, v)
		collected = append(collected, v)
		if len(collected) == 5 {
			break
		}
	}
	require.Len(t, collected, 5)
}

// TestPagedQueuePageGrowth checks that pages double in size and all values survive across many page boundaries.
func TestPagedQueuePageGrowth(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Each new page doubles in size relative to the previous one.
	head := NewPagedQueue[int](4)
	cur := head
	for i := 0; i < 100; i++ {
		cur = cur.Append(i)
	}

	require.Equal(t, 100, head.Len())

	// All values must be retrievable in order.
	var collected []int
	for v := range head.All() {
		collected = append(collected, v)
	}
	require.Len(t, collected, 100)
	for i, v := range collected {
		require.Equal(t, i, v)
	}
}

// TestPagedQueueEmptyAll checks that iterating an empty queue produces no values.
func TestPagedQueueEmptyAll(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	head := NewPagedQueue[int](8)
	var count int
	for range head.All() {
		count++
	}
	require.Equal(t, 0, count)
}
