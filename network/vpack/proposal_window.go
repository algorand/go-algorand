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

// proposalEntry contains all the values inside the r.prop map in a vote.
// Some fields may be omitted, so a mask is used to indicate which fields
// are present (bitDig, bitEncDig, bitOper, bitOprop).
type proposalEntry struct {
	dig, encdig, oprop [32]byte
	operEnc            [maxMsgpVaruintSize]byte // msgp varuint encoding of oper
	operLen            uint8                    // length of operEnc
	mask               uint8                    // which fields were present
}

// windowSize is fixed because hdr[1] holds only 3 bits for the reference code
// (0 = literal, 1-7 = index).
const windowSize = 7

// propWindow implements a small sliding window for vote proposal bundles.
// It behaves like the dynamic table defined in RFC 7541 (HPACK), but is limited
// to 7 entries, encoded using 3 bits in the header byte. This is enough to
// provide effective compression, since usually almost all the votes in a round
// are for the same proposal value.
type propWindow struct {
	entries [windowSize]proposalEntry // circular buffer
	head    int                       // slot of the oldest entry
	size    int                       // number of live entries (0 ... windowSize)
}

// lookup returns the 1-based HPACK index of pv.  It walks from the oldest entry
// to the newest; worst-case is seven comparisons, which is fine for such a
// small table. Returns 0 if not found.
func (w *propWindow) lookup(pv proposalEntry) int {
	for i := range w.size {
		slot := (w.head + i) % windowSize // oldest first
		if w.entries[slot] == pv {
			// Convert position to HPACK index.
			// Example: size == 7
			//   i == 0 (oldest) -> index 7
			//   i == 1          -> index 6
			//   i == 2          -> index 5
			//   ...
			//   i == 6 (newest) -> index 1
			return w.size - i
		}
	}
	return 0
}

// byRef returns the proposalEntry stored at HPACK index idx (1 ... w.size).
// ok == false if idx is out of range.
func (w *propWindow) byRef(idx int) (prop proposalEntry, ok bool) {
	if idx < 1 || idx > w.size {
		return proposalEntry{}, false
	}
	// convert HPACK index (1 == newest, w.size == oldest) to physical slot
	// newest slot is (head + size - 1) % windowSize
	// logical slot idx is (idx - 1) positions from newest
	physical := (w.head + w.size - idx) % windowSize
	// Example: size == 7, head == 3
	//   logical idx == 1 (newest) -> slot (3 + 7 - 1) % 7 == slot 2
	//   logical idx == 2          -> slot (3 + 7 - 2) % 7 == slot 1
	//   logical idx == 3          -> slot (3 + 7 - 3) % 7 == slot 0
	//   logical idx == 4          -> slot (3 + 7 - 4) % 7 == slot 6
	//   logical idx == 5          -> slot (3 + 7 - 5) % 7 == slot 5
	//   logical idx == 6          -> slot (3 + 7 - 6) % 7 == slot 4
	//   logical idx == 7 (oldest) -> slot (3 + 7 - 7) % 7 == slot 3
	return w.entries[physical], true
}

// insertNew puts pv into the table as the newest entry (HPACK index 1).
// When the table is full, the oldest one is overwritten.
func (w *propWindow) insertNew(pv proposalEntry) {
	if w.size == windowSize {
		// Evict the oldest element at w.head, then advance head.
		w.entries[w.head] = pv
		w.head = (w.head + 1) % windowSize
	} else {
		// Store at the slot just after the current newest.
		pos := (w.head + w.size) % windowSize
		w.entries[pos] = pv
		w.size++
	}
}
