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

package nibbles

import (
	"bytes"
	"errors"
)

// Nibbles are 4-bit values stored in an 8-bit byte arrays
type Nibbles []byte

// MakeNibbles returns a nibble array from the byte array.  If oddLength is true, the
// last 4 bits of the last byte of the array are ignored.
func MakeNibbles(data []byte, oddLength bool) Nibbles {
	return Unpack(data, oddLength)
}

// Unpack the byte array into a nibble array.  If oddLength is true, the last 4
// bits of the last byte of the array are ignored.  Allocates a new byte
// slice.
//
// [0x12, 0x30], true -> [0x1, 0x2, 0x3]
// [0x12, 0x34], false -> [0x1, 0x2, 0x3, 0x4]
// [0x12, 0x34], true -> [0x1, 0x2, 0x3]  <-- last byte last 4 bits ignored
// [], false -> []
// never to be called with [], true
func Unpack(data []byte, oddLength bool) Nibbles {
	length := len(data) * 2
	if oddLength {
		length = length - 1
	}
	ns := make([]byte, length)

	j := 0
	for i := 0; i < length; i++ {
		if i%2 == 0 {
			ns[i] = data[j] >> 4
		} else {
			ns[i] = data[j] & 0x0f
			j++
		}
	}
	return ns
}

// Pack the nibble array into a byte array.
// Return the byte array and a bool indicating if the last byte is a full byte or
// only the high 4 bits are part of the encoding
// the last four bits of a oddLength byte encoding will always be zero.
// Allocates a new byte slice.
//
// [0x1, 0x2, 0x3] -> [0x12, 0x30], true
// [0x1, 0x2, 0x3, 0x4] -> [0x12, 0x34], false
// [0x1] -> [0x10], true
// [] -> [], false
func Pack(nyb Nibbles) ([]byte, bool) {
	length := len(nyb)
	data := make([]byte, length/2+length%2)
	for i := 0; i < length; i++ {
		if i%2 == 0 {
			data[i/2] = nyb[i] << 4
		} else {
			data[i/2] = data[i/2] | nyb[i]
		}
	}

	return data, length%2 != 0
}

// Equal returns true if the two nibble arrays are equal
// [0x1, 0x2, 0x3], [0x1, 0x2, 0x3] -> true
// [0x1, 0x2, 0x3], [0x1, 0x2, 0x4] -> false
// [0x1, 0x2, 0x3], [0x1] -> false
// [0x1, 0x2, 0x3], [0x1, 0x2, 0x3, 0x4] -> false
// [], [] -> true
// [], [0x1] -> false
func Equal(nyb1 Nibbles, nyb2 Nibbles) bool {
	return bytes.Equal(nyb1, nyb2)
}

// ShiftLeft returns a slice of nyb1 that contains the Nibbles after the first
// numNibbles
func ShiftLeft(nyb1 Nibbles, numNibbles int) Nibbles {
	if numNibbles <= 0 {
		return nyb1
	}
	if numNibbles > len(nyb1) {
		return nyb1[:0]
	}

	return nyb1[numNibbles:]
}

// SharedPrefix returns a slice from nyb1 that contains the shared prefix
// between nyb1 and nyb2
func SharedPrefix(nyb1 Nibbles, nyb2 Nibbles) Nibbles {
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

// Serialize returns a byte array that represents the Nibbles
// an empty nibble array is serialized as a single byte with value 0x3
// as the empty nibble is considered to be full width
//
// [0x1, 0x2, 0x3] -> [0x12, 0x30, 0x01]
// [0x1, 0x2, 0x3, 0x4] -> [0x12, 0x34, 0x03]
// [] -> [0x03]
func Serialize(nyb Nibbles) (data []byte) {
	p, h := Pack(nyb)
	length := len(p)
	output := make([]byte, length+1)
	copy(output, p)
	if h {
		// 0x1 is the arbitrary odd length indicator
		output[length] = 0x1
	} else {
		// 0x3 is the arbitrary even length indicator
		output[length] = 0x3
	}

	return output
}

// DeserializeNibbles returns a nibble array from the byte array.
func DeserializeNibbles(encoding []byte) (Nibbles, error) {
	var ns Nibbles
	length := len(encoding)
	if length == 0 {
		return nil, errors.New("invalid encoding")
	}
	if encoding[length-1] == 1 {
		ns = Unpack(encoding[:length-1], true)
	} else if encoding[length-1] == 3 {
		ns = Unpack(encoding[:length-1], false)
	} else {
		return nil, errors.New("invalid encoding")
	}
	return ns, nil
}
