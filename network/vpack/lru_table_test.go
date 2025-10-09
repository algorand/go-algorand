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
	"encoding/binary"
	"hash/fnv"
	"testing"
	"testing/quick"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestLRUTableSizeValidation(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Test invalid size (not power of 2)
	_, err := NewStatefulEncoder(100)
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be a power of 2")

	// Test invalid size (too small)
	_, err = NewStatefulEncoder(8)
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least 16")

	// Test valid sizes
	for _, size := range []uint{16, 32, 64, 128, 256, 512, 1024, 2048} {
		enc, err := NewStatefulEncoder(size)
		require.NoError(t, err)
		require.NotNil(t, enc)

		dec, err := NewStatefulDecoder(size)
		require.NoError(t, err)
		require.NotNil(t, dec)
	}
}

// TestLRUTableInvalidID tests the fetch function with an invalid ID
func TestLRUTableInvalidID(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Test fetch with invalid ID (greater than table size)
	table, err := newLRUTable[pkSigPair](1024)
	require.NoError(t, err)
	var invalidID lruTableReferenceID = 1024 // greater than numBuckets (512)
	result, ok := table.fetch(invalidID)
	require.False(t, ok)
	require.Equal(t, pkSigPair{}, result)
}

func TestLRUTableInsertLookupFetch(t *testing.T) {
	partitiontest.PartitionTest(t)
	tab, err := newLRUTable[int](1024)
	require.NoError(t, err)

	const bucketHash = 42          // deterministic hash for test
	const baseID = bucketHash << 1 // slot-bit is OR-ed below

	// first insert on empty table sees MRU bit 0, so slot 1 is LRU
	id1 := tab.insert(100, bucketHash)
	// id1 is baseID | 1 (value was stored in slot 1)
	require.EqualValues(t, baseID|1, id1)
	// on insert, our slot 1 is now the MRU, so LRU is slot 0
	require.Equal(t, lruSlotIndex(0), tab.getLRUSlot(lruBucketIndex(bucketHash)))

	// lookup for same value and bucketHash returns the same ID
	id, ok := tab.lookup(100, bucketHash)
	require.True(t, ok)
	require.EqualValues(t, id1, id)
	// MRU/LRU is unchanged
	require.Equal(t, lruSlotIndex(0), tab.getLRUSlot(lruBucketIndex(bucketHash)))

	// second insert with new value for same hash sees MRU bit 1, so slot 0 is LRU
	id2 := tab.insert(200, bucketHash)
	require.EqualValues(t, baseID, id2)
	// MRU/LRU is flipped
	require.Equal(t, lruSlotIndex(1), tab.getLRUSlot(lruBucketIndex(bucketHash)))

	// old key (100) is still in slot 1
	_, ok = tab.lookup(100, bucketHash)
	require.True(t, ok)
	// the act of lookup 100 flips the MRU bit to 1
	require.Equal(t, lruSlotIndex(0), tab.getLRUSlot(lruBucketIndex(bucketHash)))

	// lookup for 200 (slot 0) → MRU bit flips to 0
	_, ok = tab.lookup(200, bucketHash)
	require.True(t, ok)
	require.Equal(t, lruSlotIndex(1), tab.getLRUSlot(lruBucketIndex(bucketHash)))

	// third insert: evicts and replaces slot 1, and now MRU is slot 1
	id3 := tab.insert(300, bucketHash)
	require.EqualValues(t, baseID|1, id3)
	require.Equal(t, lruSlotIndex(0), tab.getLRUSlot(lruBucketIndex(bucketHash)))

	// fetch(id3) returns the value 300 and keeps the MRU bit at slot 1
	val, ok := tab.fetch(id3)
	require.True(t, ok)
	require.Equal(t, 300, val)
	require.Equal(t, lruSlotIndex(0), tab.getLRUSlot(lruBucketIndex(bucketHash)))

	// after insert for a new value, slot 0 is evicted and assigned
	id4 := tab.insert(400, bucketHash)
	require.EqualValues(t, baseID, id4)
	// now slot 1 is LRU
	require.Equal(t, lruSlotIndex(1), tab.getLRUSlot(lruBucketIndex(bucketHash)))

	// fetch of 300 (slot 1) makes it the new MRU
	val, ok = tab.fetch(id3)
	require.True(t, ok)
	require.Equal(t, 300, val)
	require.Equal(t, lruSlotIndex(0), tab.getLRUSlot(lruBucketIndex(bucketHash)))

	// fetch of 400 (slot 0) makes it the new MRU
	val, ok = tab.fetch(id4)
	require.True(t, ok)
	require.Equal(t, 400, val)
	require.Equal(t, lruSlotIndex(1), tab.getLRUSlot(lruBucketIndex(bucketHash)))
}

// TestLRUEvictionOrder verifies that the LRU table correctly evicts the least recently used item
// when inserting into a full bucket. This test will fail if the lruSlot implementation is incorrect.
func TestLRUEvictionOrder(t *testing.T) {
	partitiontest.PartitionTest(t)
	tab, err := newLRUTable[int](1024)
	require.NoError(t, err)
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
	refID, ok := tab.lookup(100, bucketHash)
	require.True(t, ok, "First inserted value should still exist")
	require.EqualValues(t, id1, refID, "Reference ID for first value should match")

	refID, ok = tab.lookup(200, bucketHash)
	require.True(t, ok, "Second inserted value should exist")
	require.EqualValues(t, id2, refID, "Reference ID for second value should match")

	// Access the first value to make it MRU
	refID, ok = tab.lookup(100, bucketHash)
	require.True(t, ok)
	require.EqualValues(t, id1, refID)

	// Now the second value (200) should be LRU
	// Insert a third value - it should evict the second value (200)
	id3 := tab.insert(300, bucketHash)
	val3, ok := tab.fetch(id3)
	require.True(t, ok)
	require.Equal(t, 300, val3)

	// First value should still be accessible
	refID, ok = tab.lookup(100, bucketHash)
	require.True(t, ok, "First value should still exist after third insert")
	require.EqualValues(t, id1, refID)

	// Second value should have been evicted
	refID, ok = tab.lookup(200, bucketHash)
	require.False(t, ok, "Second value should be evicted as it was LRU")
	require.EqualValues(t, 0, refID)

	// But the third value should be accessible
	refID, ok = tab.lookup(300, bucketHash)
	require.True(t, ok, "Third value should exist")
	require.EqualValues(t, id3, refID)

	// Now make the third value MRU
	refID, ok = tab.lookup(300, bucketHash)
	require.True(t, ok)
	require.EqualValues(t, id3, refID)

	// Insert a fourth value - it should evict the first value (100)
	id4 := tab.insert(400, bucketHash)
	val4, ok := tab.fetch(id4)
	require.True(t, ok)
	require.Equal(t, 400, val4)

	// First value should now be evicted
	refID, ok = tab.lookup(100, bucketHash)
	require.False(t, ok, "First value should now be evicted as it became LRU")
	require.EqualValues(t, 0, refID)

	// Third and fourth values should be accessible
	refID, ok = tab.lookup(300, bucketHash)
	require.True(t, ok, "Third value should still exist")
	require.EqualValues(t, id3, refID)
	refID, ok = tab.lookup(400, bucketHash)
	require.True(t, ok, "Fourth value should exist")
	require.EqualValues(t, id4, refID)
}

// TestLRURefIDConsistency verifies that reference IDs remain consistent
// and that fetch/lookup operations correctly mark items as MRU
func TestLRURefIDConsistency(t *testing.T) {
	partitiontest.PartitionTest(t)
	tab, err := newLRUTable[int](1024)
	require.NoError(t, err)
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

// TestLRUErrorPaths tests the error paths in fetch operations to ensure 100% coverage
func TestLRUErrorPaths(t *testing.T) {
	partitiontest.PartitionTest(t)

	// The lruTableSize in lru_table.go is 512, so we need to create an ID
	// where the bucket index (id >> 1) exceeds this value
	// If bucket index >= 512, fetch should return false
	invalidBucketID := lruTableReferenceID(1024 << 1) // (1024 is > 512)

	// Create a decoder with an empty LRU table
	dec, err := NewStatefulDecoder(1024)
	require.NoError(t, err)

	// Attempt to access references with invalid bucket IDs
	_, ok := dec.sndTable.fetch(invalidBucketID)
	require.False(t, ok)
	_, ok = dec.pkTable.fetch(invalidBucketID)
	require.False(t, ok)
	_, ok = dec.pk2Table.fetch(invalidBucketID)
	require.False(t, ok)

	// Attempt to access an invalid proposal reference by looking up a proposal that doesn't exist
	prop := proposalEntry{dig: crypto.Digest{1}, encdig: crypto.Digest{2}}
	index := dec.proposalWindow.lookup(prop)
	require.Equal(t, 0, index)
}

func TestLRUTableQuick(t *testing.T) {
	partitiontest.PartitionTest(t)
	cfg := &quick.Config{MaxCount: 50000}

	hashfn := func(v uint32) uint64 {
		// use FNV-1 for hashing test values
		h64 := fnv.New64()
		h64.Write([]byte(binary.LittleEndian.AppendUint32(nil, v)))
		return h64.Sum64()
	}

	// Property: when a third distinct value is inserted into a bucket, the
	// previously least-recently-used (LRU) value must be evicted, while the
	// previously most-recently-used (MRU) value survives.
	prop := func(seq []uint32) bool {
		tab, err := newLRUTable[uint32](1024)
		require.NoError(t, err)

		// Per-bucket ordered list of values, index 0 == MRU, len<=2.
		type order []uint32
		expectedState := make(map[lruBucketIndex]order)

		for _, v := range seq {
			h := hashfn(v)
			b := tab.hashToBucketIndex(h)
			expectedBucket := expectedState[b]

			// First, try lookup.
			if id, ok := tab.lookup(v, h); ok {
				// Move found value to MRU position in state.
				if len(expectedBucket) == 2 {
					if expectedBucket[0] != v {
						expectedBucket[0], expectedBucket[1] = v, expectedBucket[0]
					}
				} else if len(expectedBucket) == 1 {
					expectedBucket[0] = v // already MRU
				}

				// Round-trip fetch check.
				fetched, okF := tab.fetch(id)
				if !okF || fetched != v {
					return false
				}
				expectedState[b] = expectedBucket
				continue
			}

			// Insert new distinct value.
			_ = tab.insert(v, h)
			// Update expected state.
			switch len(expectedBucket) {
			case 0: // Bucket was empty
				expectedState[b] = order{v}
				continue
			case 1: // Bucket had one value
				expectedState[b] = order{v, expectedBucket[0]}
				continue
			case 2: // Bucket was full, expect eviction of state[1]
				lruVal := expectedBucket[1]

				// After insert: MRU is v, survivor should be previous MRU (state[0])
				expectedState[b] = order{v, expectedBucket[0]}

				// Check LRU really went away
				if _, ok := tab.lookup(lruVal, h); ok {
					return false
				}
				// The previous MRU MUST still be present
				if _, ok := tab.lookup(expectedBucket[0], h); !ok {
					return false
				}
				// The newly inserted value must be present
				if _, ok := tab.lookup(v, h); !ok {
					return false
				}
			default: // Should not happen
				return false
			}
		}
		return true
	}

	if err := quick.Check(prop, cfg); err != nil {
		t.Fatalf("quick-check failed: %v", err)
	}
}
