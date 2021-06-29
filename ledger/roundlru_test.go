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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/testPartitioning"
)

func getEq(t *testing.T, cache *heapLRUCache, r basics.Round, expected string) {
	got, exists := cache.Get(r)
	if !exists {
		t.Fatalf("expected value for cache[%v] but not present", r)
		return
	}
	actual := got.(string)
	if actual != expected {
		t.Fatalf("expected %v but got %v for %v", expected, actual, r)
	}
}

func getNone(t *testing.T, cache *heapLRUCache, r basics.Round) {
	got, exists := cache.Get(r)
	if exists {
		t.Fatalf("expected none for cache[%v] but got %v", r, got)
		return
	}
}

func TestRoundLRUBasic(t *testing.T) {
	testPartitioning.PartitionTest(t)

	cache := heapLRUCache{maxEntries: 3}
	cache.Put(1, "one")
	cache.Put(2, "two")
	cache.Put(3, "three")
	getEq(t, &cache, 1, "one")
	getEq(t, &cache, 2, "two")
	getEq(t, &cache, 3, "three")
	cache.Put(4, "four")
	getNone(t, &cache, 1)
	getEq(t, &cache, 3, "three")
	cache.Put(5, "five")
	cache.Put(6, "six")
	getEq(t, &cache, 3, "three")
	getNone(t, &cache, 2)
	getNone(t, &cache, 4)
}

func TestRoundLRUReIndex(t *testing.T) {
	testPartitioning.PartitionTest(t)

	cache := heapLRUCache{
		entries: lruHeap{
			heap: []lruEntry{
				{
					useIndex: MaxInt - 2,
				},
				{
					useIndex: MaxInt - 1,
				},
				{
					useIndex: MaxInt - 3,
				},
			},
		},
		maxEntries:   3,
		nextUseIndex: MaxInt - 1,
	}

	cache.inc()

	require.Equal(t, 3, cache.nextUseIndex)
	require.Equal(t, 1, cache.entries.heap[0].useIndex)
	require.Equal(t, 2, cache.entries.heap[1].useIndex)
	require.Equal(t, 0, cache.entries.heap[2].useIndex)
}
