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

const (
	// 0x00 - 0x7f reserved for dynamic table entries

	// Binary types: 64-byte, 80-byte literals and 32-byte dynamic binary values
	markerLiteralBin64 = 0xc8 // signatures
	markerLiteralBin80 = 0xc9 // pf
	markerDynamicBin32 = 0xca // digests, addresses, pubkeys

	markerDynamicFixuint = 0xcb // msgpack fixuint
	markerDynamicUint8   = 0xcc // msgpack uint8
	markerDynamicUint16  = 0xcd // msgpack uint16
	markerDynamicUint32  = 0xce // msgpack uint32
	markerDynamicUint64  = 0xcf // msgpack uint64
)

func isStaticIdx(idx uint8) bool {
	return idx >= 0xc1 && idx <= 0xe6
}

const (
	// Msgpack snippets used for decompression
	msgpBin8Len32 = "\xc4\x20" // bin8 marker with 32 items
	msgpBin8Len64 = "\xc4\x40" // bin8 marker with 64 items
	msgpBin8Len80 = "\xc4\x50" // bin8 marker with 80 items
)
