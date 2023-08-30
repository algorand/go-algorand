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

package statetrie

import (
	"bytes"
	"errors"
)

// Nibbles are 4-bit values stored in an 8-bit byte arrays
type Nibbles []byte

// MakeNibbles returns a nibble array from the byte array.  If half is true, the
// last 4 bits of the last byte of the array are ignored.
func MakeNibbles(data []byte, half bool) Nibbles {
	return unpack(data, half)
}

// Unpack the byte array into a nibble array.  If half is true, the last 4
// bits of the last byte of the array are ignored.
//
// [0x11, 0x30], true -> [0x1, 0x2, 0x3]
// [0x12, 0x34], false -> [0x1, 0x2, 0x3, 0x4]
// [0x12, 0x34], true -> [0x1, 0x2, 0x3]  <-- last byte last 4 bits ignored
// [], false -> []
// never to be called with [], true
func unpack(data []byte, half bool) Nibbles {
	length := len(data) * 2
	if half {
		length = length - 1
	}
	ns := make([]byte, length)

	halfWidth := false
	j := 0
	for i := 0; i < length; i++ {
		halfWidth = !halfWidth
		if halfWidth {
			ns[i] = data[j] >> 4
		} else {
			ns[i] = data[j] & 15
			j++
		}
	}
	return ns
}

// pack the nibble array into a byte array.
// Return the byte array and a bool indicating if the last byte is a full byte or
// only the high 4 bits are part of the encoding
// the last four bits of a half byte encoding will always be zero
//
// [0x1, 0x2, 0x3] -> [0x12, 0x30], true
// [0x1, 0x2, 0x3, 0x4] -> [0x12, 0x34], false
// [0x1] -> [0x10], true
// [] -> [], false
func (ns *Nibbles) pack() ([]byte, bool) {
	length := len(*ns)
	data := make([]byte, length/2+length%2)
	for i := 0; i < length; i++ {
		if i%2 == 0 {
			data[i/2] = (*ns)[i] << 4
		} else {
			data[i/2] = data[i/2] | (*ns)[i]
		}
	}

	return data, length%2 != 0
}

// equalNibbles returns true if the two nibble arrays are equal
// [0x1, 0x2, 0x3], [0x1, 0x2, 0x3] -> true
// [0x1, 0x2, 0x3], [0x1, 0x2, 0x4] -> false
// [0x1, 0x2, 0x3], [0x1] -> false
// [0x1, 0x2, 0x3], [0x1, 0x2, 0x3, 0x4] -> false
// [], [] -> true
// [], [0x1] -> false
func equalNibbles(nyb1 Nibbles, nyb2 Nibbles) bool {
	return bytes.Equal(nyb1, nyb2)
}

// shiftNibbles returns a slice of nyb1 that contains the Nibbles after the first
// numNibbles
func shiftNibbles(nyb1 Nibbles, numNibbles int) Nibbles {
	if numNibbles <= 0 {
		return nyb1
	}
	if numNibbles > len(nyb1) {
		return nyb1[:0]
	}

	return nyb1[numNibbles:]
}

// sharedNibbles returns a slice from nyb1 that contains the shared Nibbles
// between nyb1 and nyb2
func sharedNibbles(nyb1 Nibbles, nyb2 Nibbles) Nibbles {
	minLength := len(nyb1)
	if len(nyb2) < minLength {
		minLength = len(nyb2)
	}
	for i := 0; i < minLength; i++ {
		if nyb1[i] != nyb2[i] {
			return nyb1[:i]
		}
	}
	return nyb1[:minLength]
}

// serialize returns a byte array that represents the Nibbles
// an empty nibble array is serialized as a single byte with value 0x3
// as the empty nibble is considered to be full width
//
// [0x1, 0x2, 0x3] -> [0x12, 0x30, 0x01]
// [0x1, 0x2, 0x3, 0x4] -> [0x12, 0x34, 0x03]
// [] -> [0x03]
func (ns Nibbles) serialize() (data []byte) {
	var buf bytes.Buffer
	p, h := ns.pack()
	buf.Write(p)
	if h {
		// 0x1 is the arbitrary half width indicator
		buf.WriteByte(1)
	} else {
		// 0x3 is the arbitrary full width indicator
		buf.WriteByte(3)
	}

	return buf.Bytes()
}

// deserializeNibbles returns a nibble array from the byte array.
func deserializeNibbles(encoding []byte) (Nibbles, error) {
	var ns Nibbles
	if len(encoding) == 0 {
		return nil, errors.New("invalid encoding")
	}
	if encoding[len(encoding)-1] == 1 {
		ns = unpack(encoding[:len(encoding)-1], true)
	} else if encoding[len(encoding)-1] == 3 {
		ns = unpack(encoding[:len(encoding)-1], false)
	} else {
		return nil, errors.New("invalid encoding")
	}
	return ns, nil
}
