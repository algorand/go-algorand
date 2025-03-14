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
	// 0x00 - 0x7f available for dynamic table bits

	// Binary types: 64-byte, 80-byte literals and 32-byte dynamic binary values

	MarkerLiteralBin64 = 0xc8 // signatures
	MarkerLiteralBin80 = 0xc9 // pf
	MarkerDynamicBin32 = 0xca // digests, addresses, pubkeys

	MarkerDynamicFixuint = 0xcb // msgpack fixuint
	MarkerDynamicUint8   = 0xcc // msgpack uint8
	MarkerDynamicUint16  = 0xcd // msgpack uint16
	MarkerDynamicUint32  = 0xce // msgpack uint32
	MarkerDynamicUint64  = 0xcf // msgpack uint64

	// Constants for commonly used static fields in votes

	// Map markers (re-use msgpack markers)
	StaticIdxMapMarker1 uint8 = 0x81 // Map with 1 item (0x81)
	StaticIdxMapMarker2 uint8 = 0x82 // Map with 2 items (0x82)
	StaticIdxMapMarker3 uint8 = 0x83 // Map with 3 items (0x83)
	StaticIdxMapMarker4 uint8 = 0x84 // Map with 4 items (0x84)
	StaticIdxMapMarker5 uint8 = 0x85 // Map with 5 items (0x85)
	StaticIdxMapMarker6 uint8 = 0x86 // Map with 6 items (0x86)

	// Field names start from 0x90
	StaticIdxCredField   uint8 = 0x90 // "cred" field name with fixstr prefix
	StaticIdxPfField     uint8 = 0x91 // "pf" field name with fixstr prefix
	StaticIdxRField      uint8 = 0x92 // "r" field name with fixstr prefix
	StaticIdxPropField   uint8 = 0x93 // "prop" field name with fixstr prefix
	StaticIdxDigField    uint8 = 0x94 // "dig" field name with fixstr prefix
	StaticIdxEncdigField uint8 = 0x95 // "encdig" field name with fixstr prefix
	StaticIdxOperField   uint8 = 0x96 // "oper" field name with fixstr prefix
	StaticIdxOpropField  uint8 = 0x97 // "oprop" field name with fixstr prefix
	StaticIdxRndField    uint8 = 0x98 // "rnd" field name with fixstr prefix
	StaticIdxPerField    uint8 = 0x99 // "per" field name with fixstr prefix
	StaticIdxStepField   uint8 = 0x9a // "step" field name with fixstr prefix
	StaticIdxSndField    uint8 = 0x9b // "snd" field name with fixstr prefix
	StaticIdxSigField    uint8 = 0x9c // "sig" field name with fixstr prefix
	StaticIdxPField      uint8 = 0x9d // "p" field name with fixstr prefix
	StaticIdxP1sField    uint8 = 0x9e // "p1s" field name with fixstr prefix
	StaticIdxP2Field     uint8 = 0x9f // "p2" field name with fixstr prefix
	StaticIdxP2sField    uint8 = 0xa0 // "p2s" field name with fixstr prefix
	StaticIdxPsField     uint8 = 0xa1 // "ps" field name with fixstr prefix
	StaticIdxSField      uint8 = 0xa2 // "s" field name with fixstr prefix

	// Binary markers
	StaticIdxBin8Marker32 uint8 = 0xa3 // bin8 marker for 32 bytes (0xc4, 0x20)
	StaticIdxBin8Marker64 uint8 = 0xa4 // bin8 marker for 64 bytes (0xc4, 0x40)
	StaticIdxBin8Marker80 uint8 = 0xa5 // bin8 marker for 80 bytes (0xc4, 0x50)

	// Special patterns
	StaticIdxAllZeroPsField uint8 = 0xa6 // Complete zero-filled "ps" field with marker
	StaticIdxStep1Field     uint8 = 0xa7 // "step" field with value 0x01
	StaticIdxStep2Field     uint8 = 0xa8 // "step" field with value 0x02
	StaticIdxStep3Field     uint8 = 0xa9 // "step" field with value 0x03

	// 0xb0 - 0xff also available for dynamic table bits
)

var staticTable = createDefaultStaticTable()

func isStaticIdx(idx uint8) bool {
	return idx >= 0x81 && idx <= 0xa9
}

// createDefaultStaticTable creates a default static table with common msgpack patterns
func createDefaultStaticTable() [][]byte {
	t := make([][]byte, 256) // enough for all possible 1-byte values

	// Map markers
	t[StaticIdxMapMarker1] = []byte{0x81}
	t[StaticIdxMapMarker2] = []byte{0x82}
	t[StaticIdxMapMarker3] = []byte{0x83}
	t[StaticIdxMapMarker4] = []byte{0x84}
	t[StaticIdxMapMarker5] = []byte{0x85}
	t[StaticIdxMapMarker6] = []byte{0x86}

	// Field names with fixstr prefix
	t[StaticIdxCredField] = []byte{0xa4, 'c', 'r', 'e', 'd'}             // "cred"
	t[StaticIdxPfField] = []byte{0xa2, 'p', 'f'}                         // "pf"
	t[StaticIdxRField] = []byte{0xa1, 'r'}                               // "r"
	t[StaticIdxPropField] = []byte{0xa4, 'p', 'r', 'o', 'p'}             // "prop"
	t[StaticIdxDigField] = []byte{0xa3, 'd', 'i', 'g'}                   // "dig"
	t[StaticIdxEncdigField] = []byte{0xa6, 'e', 'n', 'c', 'd', 'i', 'g'} // "encdig"
	t[StaticIdxOpropField] = []byte{0xa5, 'o', 'p', 'r', 'o', 'p'}       // "oprop"
	t[StaticIdxOperField] = []byte{0xa4, 'o', 'p', 'e', 'r'}             // "oper"
	t[StaticIdxRndField] = []byte{0xa3, 'r', 'n', 'd'}                   // "rnd"
	t[StaticIdxSndField] = []byte{0xa3, 's', 'n', 'd'}                   // "snd"
	t[StaticIdxSigField] = []byte{0xa3, 's', 'i', 'g'}                   // "sig"
	t[StaticIdxPField] = []byte{0xa1, 'p'}                               // "p"
	t[StaticIdxP1sField] = []byte{0xa3, 'p', '1', 's'}                   // "p1s"
	t[StaticIdxP2Field] = []byte{0xa2, 'p', '2'}                         // "p2"
	t[StaticIdxP2sField] = []byte{0xa3, 'p', '2', 's'}                   // "p2s"
	t[StaticIdxPsField] = []byte{0xa2, 'p', 's'}                         // "ps"
	t[StaticIdxSField] = []byte{0xa1, 's'}                               // "s"
	t[StaticIdxPerField] = []byte{0xa3, 'p', 'e', 'r'}                   // "per"
	t[StaticIdxStepField] = []byte{0xa4, 's', 't', 'e', 'p'}             // "step"

	// Binary markers
	t[StaticIdxBin8Marker32] = []byte{0xc4, 0x20} // bin8 marker with 32 items
	t[StaticIdxBin8Marker64] = []byte{0xc4, 0x40} // bin8 marker with 64 items
	t[StaticIdxBin8Marker80] = []byte{0xc4, 0x50} // bin8 marker with 80 items

	// Special patterns
	// Create the all-zero ps + value field (with name, marker, length, and 64 zero bytes)
	psZeroField := append(t[StaticIdxPsField], t[StaticIdxBin8Marker64]...)
	psZeroField = append(psZeroField, make([]byte, 64)...)
	t[StaticIdxAllZeroPsField] = psZeroField
	// Create the step fields with values 0x01, 0x02, and 0x03
	t[StaticIdxStep1Field] = append(t[StaticIdxStepField], []byte{0x01}...)
	t[StaticIdxStep2Field] = append(t[StaticIdxStepField], []byte{0x02}...)
	t[StaticIdxStep3Field] = append(t[StaticIdxStepField], []byte{0x03}...)
	return t
}
