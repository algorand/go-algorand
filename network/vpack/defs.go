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

// generates static_table.go and parse.go
//go:generate go run gen.go

const (
	// vpack marker byte values:
	// 0x00 - 0xbf reserved for dynamic table entries
	// 0xc0 - 0xef reserved for static table entries
	// 0xf0 - 0xff reserved for markers

	// Binary types: 64-byte, 80-byte literals and 32-byte dynamic binary values
	markerLiteralBin64 = 0xf0 // signatures
	markerLiteralBin80 = 0xf1 // pf
	markerDynamicBin32 = 0xf2 // digests, addresses, pubkeys
	// Uint types: fixuint, uint8, uint16, uint32, uint64
	markerDynamicFixuint = 0xf3 // msgpack fixuint
	markerDynamicUint8   = 0xf4 // msgpack uint8
	markerDynamicUint16  = 0xf5 // msgpack uint16
	markerDynamicUint32  = 0xf6 // msgpack uint32
	markerDynamicUint64  = 0xf7 // msgpack uint64
)

func isStaticIdx(idx uint8) bool {
	return idx >= staticIdxStart && idx <= staticIdxEnd
}

const (
	// Msgpack snippets used for decompression
	msgpBin8Len32 = "\xc4\x20" // bin8 marker with 32 items
	msgpBin8Len64 = "\xc4\x40" // bin8 marker with 64 items
	msgpBin8Len80 = "\xc4\x50" // bin8 marker with 80 items
)
