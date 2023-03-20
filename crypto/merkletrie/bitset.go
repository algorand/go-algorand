// Copyright (C) 2019-2023 Algorand, Inc.
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

package merkletrie

// bitset is used as a 256 bits bitmask storage. The simplistic implementation is designed
// explicitly to reduce memory utilization to the minimum required.
type bitset struct {
	d [4]uint64
}

// SetBit sets the given bit in the bitset.
func (b *bitset) SetBit(bit byte) {
	b.d[bit/64] |= 1 << (bit & 63)
}

// ClearBit clears the given bit in the bitset.
func (b *bitset) ClearBit(bit byte) {
	// the &^ is the go and-not operator
	b.d[bit/64] &^= 1 << (bit & 63)
}

// Bit tests the given bit in the bitset.
func (b *bitset) Bit(bit byte) bool {
	return (b.d[bit/64] & (1 << (bit & 63))) != 0
}

// IsZero tests to see if all the bits in the bitset are set to zero.
func (b *bitset) IsZero() bool {
	return b.d[0] == 0 && b.d[1] == 0 && b.d[2] == 0 && b.d[3] == 0
}
