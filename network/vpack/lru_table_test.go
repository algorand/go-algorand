// Copyright (C) 2019-2025 Algorand, Inc.
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

package vpack

import (
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/require"
)

func TestLRUTableInsertLookupFetch(t *testing.T) {
	var tab lruTable[int]

	const bucketHash = 42          // deterministic hash for test
	const baseID = bucketHash << 1 // slot-bit is OR-ed below

	// first insert on empty table sees MRU bit 0, so slot 1 is LRU
	id1 := tab.insert(100, bucketHash)
	// id1 is baseID | 1 (value was stored in slot 1)
	require.EqualValues(t, baseID|1, id1)
	// on insert, our slot 1 is now the MRU, so LRU is slot 0
	require.Equal(t, lruSlotIndex(0), tab.lruSlot(lruBucketIndex(bucketHash)))

	// lookup for same value and bucketHash returns the same ID
	id, ok := tab.lookup(100, bucketHash)
	require.True(t, ok)
	require.EqualValues(t, id1, id)
	// MRU/LRU is unchanged
	require.Equal(t, lruSlotIndex(0), tab.lruSlot(lruBucketIndex(bucketHash)))

	// second insert with new value for same hash sees MRU bit 1, so slot 0 is LRU
	id2 := tab.insert(200, bucketHash)
	require.EqualValues(t, baseID, id2)
	// MRU/LRU is flipped
	require.Equal(t, lruSlotIndex(1), tab.lruSlot(lruBucketIndex(bucketHash)))

	// old key (100) is still in slot 1
	_, ok = tab.lookup(100, bucketHash)
	require.True(t, ok)
	// the act of lookup 100 flips the MRU bit to 1
	require.Equal(t, lruSlotIndex(0), tab.lruSlot(lruBucketIndex(bucketHash)))

	// lookup for 200 (slot 0) → MRU bit flips to 0
	_, ok = tab.lookup(200, bucketHash)
	require.True(t, ok)
	require.Equal(t, lruSlotIndex(1), tab.lruSlot(lruBucketIndex(bucketHash)))

	// third insert: evicts and replaces slot 1, and now MRU is slot 1
	id3 := tab.insert(300, bucketHash)
	require.EqualValues(t, baseID|1, id3)
	require.Equal(t, lruSlotIndex(0), tab.lruSlot(lruBucketIndex(bucketHash)))

	// fetch(id3) returns the value 300 and keeps the MRU bit at slot 1
	val, ok := tab.fetch(id3)
	require.True(t, ok)
	require.Equal(t, 300, val)
	require.Equal(t, lruSlotIndex(0), tab.lruSlot(lruBucketIndex(bucketHash)))

	// after insert for a new value, slot 0 is evicted and assigned
	id4 := tab.insert(400, bucketHash)
	require.EqualValues(t, baseID, id4)
	// now slot 1 is LRU
	require.Equal(t, lruSlotIndex(1), tab.lruSlot(lruBucketIndex(bucketHash)))

	// fetch of 300 (slot 1) makes it the new MRU
	val, ok = tab.fetch(id3)
	require.True(t, ok)
	require.Equal(t, 300, val)
	require.Equal(t, lruSlotIndex(0), tab.lruSlot(lruBucketIndex(bucketHash)))

	// fetch of 400 (slot 0) makes it the new MRU
	val, ok = tab.fetch(id4)
	require.True(t, ok)
	require.Equal(t, 400, val)
	require.Equal(t, lruSlotIndex(1), tab.lruSlot(lruBucketIndex(bucketHash)))
}

// TestLRUEvictionOrder verifies that the LRU table correctly evicts the least recently used item
// when inserting into a full bucket. This test will fail if the lruSlot implementation is incorrect.
func TestLRUEvictionOrder(t *testing.T) {
	var tab lruTable[int]
	bucketHash := uint64(42) // Use same hash to ensure both items go into the same bucket

	// Insert first value
	id1 := tab.insert(100, bucketHash)
	val1, ok := tab.fetch(id1)
	require.True(t, ok)
	require.Equal(t, 100, val1)

	// Insert second value to the same bucket
	id2 := tab.insert(200, bucketHash)
	val2, ok := tab.fetch(id2)
	require.True(t, ok)
	require.Equal(t, 200, val2)

	// Both values should still be accessible
	val, ok := tab.lookup(100, bucketHash)
	require.True(t, ok, "First inserted value should still exist")
	require.EqualValues(t, id1, val, "Reference ID for first value should match")

	val, ok = tab.lookup(200, bucketHash)
	require.True(t, ok, "Second inserted value should exist")
	require.EqualValues(t, id2, val, "Reference ID for second value should match")

	// Access the first value to make it MRU
	val, ok = tab.lookup(100, bucketHash)
	require.True(t, ok)
	require.EqualValues(t, id1, val)

	// Now the second value (200) should be LRU
	// Insert a third value - it should evict the second value (200)
	id3 := tab.insert(300, bucketHash)
	val3, ok := tab.fetch(id3)
	require.True(t, ok)
	require.Equal(t, 300, val3)

	// First value should still be accessible
	val, ok = tab.lookup(100, bucketHash)
	require.True(t, ok, "First value should still exist after third insert")

	// Second value should have been evicted
	_, ok = tab.lookup(200, bucketHash)
	require.False(t, ok, "Second value should be evicted as it was LRU")

	// But the third value should be accessible
	val, ok = tab.lookup(300, bucketHash)
	require.True(t, ok, "Third value should exist")
	require.EqualValues(t, id3, val)

	// Now make the third value MRU
	val, ok = tab.lookup(300, bucketHash)
	require.True(t, ok)

	// Insert a fourth value - it should evict the first value (100)
	id4 := tab.insert(400, bucketHash)
	val4, ok := tab.fetch(id4)
	require.True(t, ok)
	require.Equal(t, 400, val4)

	// First value should now be evicted
	_, ok = tab.lookup(100, bucketHash)
	require.False(t, ok, "First value should now be evicted as it became LRU")

	// Third and fourth values should be accessible
	val, ok = tab.lookup(300, bucketHash)
	require.True(t, ok, "Third value should still exist")
	val, ok = tab.lookup(400, bucketHash)
	require.True(t, ok, "Fourth value should exist")
}

// TestLRURefIDConsistency verifies that reference IDs remain consistent
// and that fetch/lookup operations correctly mark items as MRU
func TestLRURefIDConsistency(t *testing.T) {
	var tab lruTable[int]
	bucketHash := uint64(42)

	// Insert and get reference ID
	id1 := tab.insert(100, bucketHash)

	// Lookup should return the same reference ID
	ref, ok := tab.lookup(100, bucketHash)
	require.True(t, ok)
	require.Equal(t, id1, ref, "Reference ID from lookup should match insert")

	// Fetch using the ID should return the correct value
	val, ok := tab.fetch(id1)
	require.True(t, ok)
	require.Equal(t, 100, val, "Fetch should return the correct value")

	// Insert another value with same hash (same bucket)
	id2 := tab.insert(200, bucketHash)
	require.NotEqual(t, id1, id2, "Different values should have different reference IDs")

	// Both values should be accessible via their reference IDs
	val1, ok1 := tab.fetch(id1)
	val2, ok2 := tab.fetch(id2)
	require.True(t, ok1)
	require.True(t, ok2)
	require.Equal(t, 100, val1)
	require.Equal(t, 200, val2)
}

func TestLRUTableQuick(t *testing.T) {
	cfg := &quick.Config{MaxCount: 5000}

	// Test function that verifies LRU behavior with random operations
	f := func(operations []uint32) bool {
		var tab lruTable[uint32]

		// Keep track of entries inserted per bucket to verify LRU eviction
		bucketValues := make(map[uint16][]uint32)
		bucketIds := make(map[uint16][]lruTableReferenceID)

		// Process each operation
		for _, op := range operations {
			// Use lower bits for the bucket hash to ensure collisions
			h := uint16(op & 0x3ff)
			// Insert the value and save it in our tracking maps
			id := tab.insert(op, uint64(h))
			// Track values and IDs per bucket
			values := bucketValues[h]
			ids := bucketIds[h]

			// If we already have 2 values in this bucket, one will be evicted
			// But we need to know which one is LRU to determine which gets evicted
			if len(values) == 2 {
				// Check if either value has been evicted
				_, firstExists := tab.lookup(values[0], uint64(h))
				_, secondExists := tab.lookup(values[1], uint64(h))

				// One but not both should be evicted
				if firstExists && secondExists {
					return false // Neither was evicted
				}
				if !firstExists && !secondExists {
					return false // Both were evicted
				}

				// One was evicted, keep the one that wasn't
				if firstExists {
					// First entry still exists, second was evicted
					values = []uint32{values[0]}
					ids = []lruTableReferenceID{ids[0]}
				} else {
					// Second entry still exists, first was evicted
					values = []uint32{values[1]}
					ids = []lruTableReferenceID{ids[1]}
				}
			}

			// Verify lookup returns correct ID
			lookupId, ok := tab.lookup(op, uint64(h))
			if !ok || lookupId != id {
				return false
			}
			// Verify fetch returns correct value
			fetchedVal, ok := tab.fetch(id)
			if !ok || fetchedVal != op {
				return false
			}
			// Update our tracking maps
			values = append(values, op)
			ids = append(ids, id)
			if len(values) > 2 {
				values = values[len(values)-2:]
				ids = ids[len(ids)-2:]
			}
			bucketValues[h] = values
			bucketIds[h] = ids

			// Ocasionally access a previous value to change MRU state
			if len(values) == 2 && (op&0x3 == 0) { // ~25% probability
				// Access the first value to make it MRU
				_, _ = tab.lookup(values[0], uint64(h))
			}
		}
		return true
	}

	if err := quick.Check(f, cfg); err != nil {
		t.Fatalf("quick-check failed: %v", err)
	}
}
