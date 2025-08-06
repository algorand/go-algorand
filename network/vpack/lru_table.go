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
	"errors"
)

// lruTable is a fixed-size, 2-way set-associative hash table with 512 buckets.
// Each bucket contains exactly two entries, with LRU eviction on collision.
// The implementation is O(1) and zero-allocation during lookups and inserts.
//
// Each bucket has a MRU bit that encodes which of the two slots is MRU. The
// bit is set to 0 if the first slot is MRU, and 1 if the second slot is MRU.
//
// Reference IDs are encoded as (bucket << 1) | slot, where bucket is the index
// of the bucket and slot is the index of the slot within the bucket (0 or 1).
type lruTable[K comparable] struct {
	numBuckets uint32
	buckets    []twoSlotBucket[K]
	mru        []byte // 1 bit per bucket
}

// newLRUTable creates a new LRU table with the given size N.
// The size N is the total number of entries in the table.
// The number of buckets is N/2, and each bucket contains 2 slots.
func newLRUTable[K comparable](N uint32) (*lruTable[K], error) {
	// enforce size is a power of 2 and at least 16
	if N < 16 || N&(N-1) != 0 {
		return nil, errors.New("lruTable size must be a power of 2 and at least 16")
	}
	numBuckets := N / 2
	return &lruTable[K]{
		numBuckets: numBuckets,
		buckets:    make([]twoSlotBucket[K], numBuckets),
		mru:        make([]byte, numBuckets/8),
	}, nil
}

// twoSlotBucket is a 2-way set-associative bucket that contains two slots.
type twoSlotBucket[K comparable] struct{ slots [2]K }

// lruBucketIndex is the index of a bucket in the LRU table.
type lruBucketIndex uint32

// lruSlotIndex is the index of a slot in a bucket, either 0 or 1.
type lruSlotIndex uint8

// lruTableReferenceID is the reference ID for a key in the LRU table.
type lruTableReferenceID uint16

// pkSigPair is a 32-byte public key + 64-byte signature
// used for the LRU tables for p+p1s and p2+p2s.
type pkSigPair struct {
	pk  [pkSize]byte
	sig [sigSize]byte
}

func (p *pkSigPair) hash() uint64 {
	// Since pk and sig should already be uniformly distributed, we can use a
	// simple XOR of the first 8 bytes of each to get a good hash.
	// Any invalid votes intentionally designed to cause collisions will only
	// affect the sending peer's own per-peer compression state, and cause
	// agreement to disconnect the peer.
	return binary.LittleEndian.Uint64(p.pk[:8]) ^ binary.LittleEndian.Uint64(p.sig[:8])
}

// addressValue is a 32-byte address used for the LRU table for snd.
type addressValue [digestSize]byte

func (v *addressValue) hash() uint64 {
	// addresses are fairly uniformly distributed, so we can use a simple XOR
	return binary.LittleEndian.Uint64(v[:8]) ^ binary.LittleEndian.Uint64(v[8:16]) ^
		binary.LittleEndian.Uint64(v[16:24]) ^ binary.LittleEndian.Uint64(v[24:])
}

// mruBitmask returns the byte index and bit mask for the MRU bit of bucket b.
func (t *lruTable[K]) mruBitmask(b lruBucketIndex) (byteIdx uint32, mask byte) {
	byteIdx = uint32(b) >> 3
	bitIdx := b & 7
	mask = 1 << bitIdx
	return byteIdx, mask
}

// getLRUSlot returns the index of the LRU slot in bucket b
func (t *lruTable[K]) getLRUSlot(b lruBucketIndex) lruSlotIndex {
	byteIdx, mask := t.mruBitmask(b)
	if (t.mru[byteIdx] & mask) == 0 {
		return 1 // this bucket's bit is 0, meaning slot 1 is LRU
	}
	return 0 // this bucket's bit is 1, meaning slot 0 is LRU
}

// setMRUSlot marks the given bucket and slot index as MRU
func (t *lruTable[K]) setMRUSlot(b lruBucketIndex, slot lruSlotIndex) {
	byteIdx, mask := t.mruBitmask(b)
	if slot == 0 { // want to set slot 0 to be MRU, so bucket bit should be 0
		t.mru[byteIdx] &^= mask
	} else { // want to set slot 1 to be MRU, so bucket bit should be 1
		t.mru[byteIdx] |= mask
	}
}

func (t *lruTable[K]) hashToBucketIndex(h uint64) lruBucketIndex {
	// Use the lower bits of the hash to determine the bucket index.
	return lruBucketIndex(h & uint64(t.numBuckets-1))
}

// lookup returns the reference ID of the given key, if it exists. The hash is
// used to determine the bucket, and the key is used to determine the slot.
// A lookup marks the found key as MRU.
func (t *lruTable[K]) lookup(k K, h uint64) (id lruTableReferenceID, ok bool) {
	b := t.hashToBucketIndex(h)
	bk := &t.buckets[b]
	if bk.slots[0] == k {
		t.setMRUSlot(b, 0)
		return lruTableReferenceID(b << 1), true
	}
	if bk.slots[1] == k {
		t.setMRUSlot(b, 1)
		return lruTableReferenceID(b<<1 | 1), true
	}
	return 0, false
}

// insert inserts the given key into the table and returns its reference ID.
// The hash is used to determine the bucket, and the LRU slot is used to
// determine the slot. The inserted key is marked as MRU.
func (t *lruTable[K]) insert(k K, h uint64) lruTableReferenceID {
	b := t.hashToBucketIndex(h)
	evict := t.getLRUSlot(b) // LRU slot
	t.buckets[b].slots[evict] = k
	t.setMRUSlot(b, evict) // new key -> MRU
	return lruTableReferenceID((lruTableReferenceID(b) << 1) | lruTableReferenceID(evict))
}

// fetch returns the key by id and marks it as MRU. If the id is invalid, it
// returns false (leading to a decoder error). The key is marked as MRU.
func (t *lruTable[K]) fetch(id lruTableReferenceID) (K, bool) {
	b := lruBucketIndex(id >> 1)
	slot := lruSlotIndex(id & 1)
	if b >= lruBucketIndex(t.numBuckets) { // invalid id
		var zero K
		return zero, false
	}
	// touch MRU bit
	t.setMRUSlot(b, slot)
	return t.buckets[b].slots[slot], true
}
