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

package stateproof

import (
	"sort"
	"testing"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/msgp/msgp"
	"github.com/stretchr/testify/require"
)

type marshalMode int

const (
	canonical marshalMode = iota
	wrongStructOrder
	wrongMapOrder
)

// TestDecodeCanonicalMsg ensures that DecodeValidate detects non-canonical encodings
// this is tested here because StateProof contains an example of a map and is itself contained within
// Transaction message which is a relevant message to check canonical encoding for.
func TestDecodeCanonicalMsg(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// z.Reveals has out of order keys
	z := StateProof{
		SignedWeight:               56,
		MerkleSignatureSaltVersion: 5,
		Reveals:                    map[uint64]Reveal{20: {}, 10: {}},
	}

	b := protocol.Encode(&z)
	var zDecode, zDecodeValidate StateProof
	require.NoError(t, protocol.Decode(b, &zDecode))
	require.NoError(t, protocol.DecodeCanonicalMsg(b, &zDecodeValidate))

	zDecode = StateProof{}
	zDecodeValidate = StateProof{}
	bCorrect := z.marshalWrongOrder(nil, canonical)
	require.NoError(t, protocol.Decode(bCorrect, &zDecode))
	require.NoError(t, protocol.DecodeCanonicalMsg(bCorrect, &zDecodeValidate))

	zDecode = StateProof{}
	zDecodeValidate = StateProof{}
	bWrongMapOrder := z.marshalWrongOrder(nil, wrongMapOrder)
	require.NoError(t, protocol.Decode(bWrongMapOrder, &zDecode))
	require.ErrorContains(t, protocol.DecodeCanonicalMsg(bWrongMapOrder, &zDecodeValidate), "msgp: non-canonical encoding detected")

	zDecode = StateProof{}
	zDecodeValidate = StateProof{}
	bWrongStructOrder := z.marshalWrongOrder(nil, wrongStructOrder)
	require.NoError(t, protocol.Decode(bWrongStructOrder, &zDecode))
	require.ErrorContains(t, protocol.DecodeCanonicalMsg(bWrongStructOrder, &zDecodeValidate), "msgp: non-canonical encoding detected")

}

// marshalWrongOrder is a helper function copied from msgp_gen.go file but modified to
// 1. encode correctly
// 2. encode struct fields of out of order
// 3. encode map keys out of order
// depending on the marshalMode passed in.
func (z *StateProof) marshalWrongOrder(b []byte, mode marshalMode) (o []byte) {
	o = msgp.Require(b, z.Msgsize())
	// omitempty: check for empty values
	zb0004Len := uint32(7)
	var zb0004Mask uint8 /* 8 bits */
	if (*z).PartProofs.MsgIsZero() {
		zb0004Len--
		zb0004Mask |= 0x1
	}
	if (*z).SigProofs.MsgIsZero() {
		zb0004Len--
		zb0004Mask |= 0x2
	}
	if (*z).SigCommit.MsgIsZero() {
		zb0004Len--
		zb0004Mask |= 0x8
	}
	if len((*z).PositionsToReveal) == 0 {
		zb0004Len--
		zb0004Mask |= 0x10
	}
	if len((*z).Reveals) == 0 {
		zb0004Len--
		zb0004Mask |= 0x20
	}
	if (*z).MerkleSignatureSaltVersion == 0 {
		zb0004Len--
		zb0004Mask |= 0x40
	}
	if (*z).SignedWeight == 0 {
		zb0004Len--
		zb0004Mask |= 0x80
	}
	// variable map header, size zb0004Len
	o = append(o, 0x80|uint8(zb0004Len))
	if zb0004Len != 0 {
		if mode == wrongStructOrder { // manually added to produce wrong sort
			if (zb0004Mask & 0x40) == 0 { // if not empty
				// string "v"
				o = append(o, 0xa1, 0x76)
				o = msgp.AppendByte(o, (*z).MerkleSignatureSaltVersion)
			}
		}
		if (zb0004Mask & 0x1) == 0 { // if not empty
			// string "P"
			o = append(o, 0xa1, 0x50)
			o = (*z).PartProofs.MarshalMsg(o)
		}
		if (zb0004Mask & 0x2) == 0 { // if not empty
			// string "S"
			o = append(o, 0xa1, 0x53)
			o = (*z).SigProofs.MarshalMsg(o)
		}
		if (zb0004Mask & 0x8) == 0 { // if not empty
			// string "c"
			o = append(o, 0xa1, 0x63)
			o = (*z).SigCommit.MarshalMsg(o)
		}
		if (zb0004Mask & 0x10) == 0 { // if not empty
			// string "pr"
			o = append(o, 0xa2, 0x70, 0x72)
			if (*z).PositionsToReveal == nil {
				o = msgp.AppendNil(o)
			} else {
				o = msgp.AppendArrayHeader(o, uint32(len((*z).PositionsToReveal)))
			}
			for zb0003 := range (*z).PositionsToReveal {
				o = msgp.AppendUint64(o, (*z).PositionsToReveal[zb0003])
			}
		}
		if (zb0004Mask & 0x20) == 0 { // if not empty
			// string "r"
			o = append(o, 0xa1, 0x72)
			if (*z).Reveals == nil {
				o = msgp.AppendNil(o)
			} else {
				o = msgp.AppendMapHeader(o, uint32(len((*z).Reveals)))
			}
			zb0001Keys := make([]uint64, 0, len((*z).Reveals))
			for zb0001 := range (*z).Reveals {
				zb0001Keys = append(zb0001Keys, zb0001)
			}
			if mode != wrongMapOrder { // manually added to produce wrong sort
				sort.Sort(SortUint64(zb0001Keys))
			}
			for _, zb0001 := range zb0001Keys {
				zb0002 := (*z).Reveals[zb0001]
				_ = zb0002
				o = msgp.AppendUint64(o, zb0001)
				o = zb0002.MarshalMsg(o)
			}
		}

		if mode != wrongStructOrder { // manually added to produce wrong sort
			if (zb0004Mask & 0x40) == 0 { // if not empty
				// string "v"
				o = append(o, 0xa1, 0x76)
				o = msgp.AppendByte(o, (*z).MerkleSignatureSaltVersion)
			}
		}
		if (zb0004Mask & 0x80) == 0 { // if not empty
			// string "w"
			o = append(o, 0xa1, 0x77)
			o = msgp.AppendUint64(o, (*z).SignedWeight)
		}
	}
	return
}
