package vpack

import (
	"math/rand"
	"testing"
	"testing/quick"
	"time"

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

func TestLRUTableQuick(t *testing.T) {
	cfg := &quick.Config{MaxCount: 5_000, Rand: rand.New(rand.NewSource(time.Now().UnixNano()))}
	f := func(keys []uint32) bool {
		var tab lruTable[uint32]
		for _, k := range keys {
			h := uint16(k & 0x3ff) // confine to existing bucket range
			tab.insert(k, uint64(h))
			id, ok := tab.lookup(k, uint64(h))
			if !ok {
				return false
			}
			if k2, ok := tab.key(id); !ok || k2 != k {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, cfg); err != nil {
		t.Fatalf("quick-check failed: %v", err)
	}
}

func (t *lruTable[K]) key(id lruTableReferenceID) (K, bool) {
	b := id >> 1
	slot := id & 1
	if b >= lruTableSize {
		var zero K
		return zero, false
	}
	return t.bkt[b].key[slot], true
}

func makeTestPropBundle(seed byte) proposalEntry {
	var p proposalEntry
	for i := range p.dig {
		p.dig[i] = seed
	}
	p.operLen = 1
	p.operEnc[0] = seed
	p.mask = bitDig | bitOper
	return p
}

func (w *propWindow) setSlot(pos int, s physicalSlotIndex) {
	shift := pos * 3
	w.order &^= 7 << shift
	w.order |= uint32(s) << shift
}

func TestPropWindowOrderAndLRU(t *testing.T) {
	var w propWindow

	// fill with 8 unique entries
	for i := 0; i < 8; i++ {
		p := makeTestPropBundle(byte(i))
		w.pushFront(p, physicalSlotIndex(i)) // physical == seed for ease
		if w.size != i+1 {
			t.Fatalf("size incorrect after pushFront")
		}
		// newest should be accessible at logical 0
		if idx, ok := w.indexOf(p); !ok || idx != 0 {
			t.Fatalf("indexOf failed just after insertion")
		}
	}

	// Check logical -> physical mapping
	got := make([]physicalSlotIndex, 8)
	for i := 0; i < 8; i++ {
		got[i] = w.slotAt(i)
	}
	want := []physicalSlotIndex{7, 6, 5, 4, 3, 2, 1, 0}
	require.Equal(t, got, want)

	// LRU should be physical slot of oldest (seed 0)
	if lru := w.lruSlot(); lru != 0 {
		t.Fatalf("lruSlot=%d want 0", lru)
	}

	// insert duplicate of existing entry (seed 3) – should move to front
	p3 := makeTestPropBundle(3)
	if idx, ok := w.indexOf(p3); !ok || idx == 0 {
		t.Fatalf("pre-condition failed; dup not found")
	} else {
		prevPhys := w.slotAt(idx)
		w.pushFront(p3, prevPhys)
	}

	if idx, ok := w.indexOf(p3); !ok || idx != 0 {
		t.Fatalf("duplicate insert did not promote to front")
	}
}
