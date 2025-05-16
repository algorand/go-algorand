package vpack

import (
	"github.com/cespare/xxhash/v2"
)

type dynamicTableState struct {
	// 2-way tables
	sndTable lruTable[addressValue]
	pkTable  lruTable[pkSigPair]
	pk2Table lruTable[pkSigPair]

	// proposal 8-slot window
	proposalWindow propWindow

	// last round number
	lastRnd uint64
}

// pkSigPair is a 32-byte public key + 64-byte signature
// used for the LRU tables for p+p1s and p2+p2s.
type pkSigPair struct {
	pk  [32]byte
	sig [64]byte
}

// addressValue is a 32-byte address used for the LRU table for snd.
type addressValue [32]byte

func (b *addressValue) hash() uint64 {
	return xxhash.Sum64(b[:])
}

func (pb *pkSigPair) hash() uint64 {
	var buf [96]byte
	copy(buf[:32], pb.pk[:])
	copy(buf[32:], pb.sig[:])
	return xxhash.Sum64(buf[:])
}

// lruTable is a fixed-size, 2-way set-associative hash table with 1024 buckets.
// Each bucket contains exactly two entries, with LRU eviction on collision.
// The implementation is O(1) and zero-allocation during lookups and inserts.
//
// Each bucket has a MRU bit that encodes which of the two slots is MRU. The
// bit is set to 0 if the first slot is MRU, and 1 if the second slot is MRU.
//
// Reference IDs are encoded as (bucket << 1) | slot, where bucket is the index
// of the bucket and slot is the index of the slot within the bucket (0 or 1).
type lruTable[K lruKey] struct {
	bkt [lruTableSize]twoSlotBucket[K]
	mru [lruTableSize / 8]byte // 1 bit per bucket
}

const lruTableSize = 1024
const lruTableBucketMask = lruTableSize - 1

type lruKey interface {
	comparable
	//hash() uint64
}

type twoSlotBucket[K lruKey] struct{ key [2]K }
type lruBucketIndex uint32
type lruSlotIndex uint8
type lruTableReferenceID uint16

// lruSlot returns the index of the LRU slot in bucket b
func (t *lruTable[K]) lruSlot(b lruBucketIndex) lruSlotIndex {
	byteIdx := b >> 3
	bitIdx := b & 7
	if (t.mru[byteIdx]>>(bitIdx))&1 == 0 {
		return 1 // this bucket's bit is 0, meaning slot 1 is LRU
	}
	return 0 // this bucket's bit is 1, meaning slot 0 is LRU
}

// setMRU marks the given bucket and slot index as MRU
func (t *lruTable[K]) setMRU(b lruBucketIndex, slot lruSlotIndex) {
	byteIdx := b >> 3
	bitIdx := b & 7
	mask := byte(1 << bitIdx)
	if slot == 0 {
		t.mru[byteIdx] &^= mask
	} else {
		t.mru[byteIdx] |= mask
	}
}

// lookup returns the reference ID of the given key, if it exists. The hash is
// used to determine the bucket, and the key is used to determine the slot.
func (t *lruTable[K]) lookup(k K, h uint64) (id lruTableReferenceID, ok bool) {
	b := lruBucketIndex(h & lruTableBucketMask)
	bk := &t.bkt[b]
	if bk.key[0] == k {
		t.setMRU(b, 0)
		return lruTableReferenceID(b << 1), true
	}
	if bk.key[1] == k {
		t.setMRU(b, 1)
		return lruTableReferenceID(b<<1 | 1), true
	}
	return 0, false
}

// insert inserts the given key into the table and returns its reference ID.
// The hash is used to determine the bucket, and the LRU slot is used to
// determine the slot.
func (t *lruTable[K]) insert(k K, h uint64) lruTableReferenceID {
	b := lruBucketIndex(h & lruTableBucketMask)
	evict := t.lruSlot(b) // LRU slot
	t.bkt[b].key[evict] = k
	t.setMRU(b, evict) // new key -> MRU
	return lruTableReferenceID((lruTableReferenceID(b) << 1) | lruTableReferenceID(evict))
}

// fetch returns the key by id and marks it as MRU. If the id is invalid, it
// returns false (leading to a decoder error).
func (t *lruTable[K]) fetch(id lruTableReferenceID) (K, bool) {
	b := lruBucketIndex(id >> 1)
	slot := lruSlotIndex(id & 1)
	if b >= lruTableSize { // invalid id
		var zero K
		return zero, false
	}
	// touch MRU bit
	t.setMRU(b, slot)
	return t.bkt[b].key[slot], true
}

// proposalEntry contains all the values inside the r.prop map in a vote.
// Some fields may be omitted, so a mask is used to indicate which fields
// are present (bitDig, bitEncDig, bitOper, bitOprop).
type proposalEntry struct {
	dig, encdig, oprop [32]byte
	operEnc            [maxMsgpVaruintSize]byte // msgp varuint encoding of oper
	operLen            uint8                    // length of operEnc
	mask               uint8                    // which fields were present
}

// propWindow is an 8-slot MRU window for proposal values. Instead of
// rewriting the values on every insertion, the order of the slots
// is stored in a 24-bit number, where every 3 bits encode the index
// of each slot in the window (7 = LRU, 0 = MRU). This allows for O(1)
// lookups and insertions.
type propWindow struct {
	order uint32 // 24 bits: [lsb] slot0 slot1 ... slot7 [msb]
	size  int
	slots [8]proposalEntry
}

// physicalSlotIndex is an index into the propWindow.slots array.
// It is a separate type to prevent confusion with logical slot indices.
type physicalSlotIndex uint8

// getAt returns the proposal entry at logical position pos,
// and its physical slot index (for use in pushFront).
func (w *propWindow) getAt(pos int) (proposalEntry, physicalSlotIndex) {
	phys := w.slotAt(pos)
	return w.slots[phys], phys
}

// slotAt returns the physical slot index of the logical slot at pos.
func (w *propWindow) slotAt(pos int) physicalSlotIndex {
	return physicalSlotIndex(w.order >> (pos * 3) & 7)
}

// indexOf returns the logical position of pb in the window, if it exists.
func (w *propWindow) indexOf(pb proposalEntry) (int, bool) {
	for i := 0; i < w.size; i++ {
		if w.slots[w.slotAt(i)] == pb {
			return i, true
		}
	}
	return -1, false
}

// pushFront inserts a new proposal entry at the front of the window.
// phys is the physical slot index of the new entry.
func (w *propWindow) pushFront(pb proposalEntry, phys physicalSlotIndex) {
	if w.size < 8 {
		w.size++
	}
	// shift logical order right by 3 bits (slot7 <- slot6 <- ... <- slot0)
	w.order <<= 3
	w.order |= uint32(phys)
	w.slots[phys] = pb
}

// lruSlot returns the physical slot index of the LRU entry (logical 7)
func (w *propWindow) lruSlot() physicalSlotIndex { return w.slotAt(7) }
