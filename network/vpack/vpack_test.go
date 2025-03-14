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

import (
	"testing"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/msgp/msgp"
	"github.com/stretchr/testify/require"
)

// based on RunEncodingTest from protocol/codec_tester.go
func TestEncodingTest(t *testing.T) {
	partitiontest.PartitionTest(t)

	for i := 0; i < 10000; i++ {
		v0, err := protocol.RandomizeObject(&agreement.UnauthenticatedVote{}, protocol.RandomizeObjectWithZeroesEveryN(10))
		require.NoError(t, err)

		v0vote := v0.(*agreement.UnauthenticatedVote)
		if *v0vote == (agreement.UnauthenticatedVote{}) {
			continue // don't try to encode or compress empty votes (a single byte, 0x80)
		}
		expectFailMissing := false
		// top-level should have 3 fields, all of which are required
		if v0vote.R.MsgIsZero() || v0vote.Cred.MsgIsZero() || v0vote.Sig.MsgIsZero() {
			expectFailMissing = true
		}
		// Cred must be non-zero
		if v0vote.Cred.Proof.MsgIsZero() {
			expectFailMissing = true
		}

		msgpBuf := protocol.EncodeMsgp(v0.(msgp.Marshaler))
		enc := NewStaticEncoder()
		encBuf, err := enc.CompressVote(nil, msgpBuf)
		if expectFailMissing {
			// We are strict, and won't process votes with missing fields (where vpack_size is set)
			require.ErrorContains(t, err, "expected fixed map size")
			continue
		} else {
			require.NoError(t, err)
		}

		dec := NewStaticDecoder()
		decMsgpBuf, err := dec.DecompressVote(nil, encBuf)
		require.NoError(t, err)

		require.Equal(t, msgpBuf, decMsgpBuf)
		var v1 agreement.UnauthenticatedVote
		protocol.Decode(decMsgpBuf, &v1)

		require.Equal(t, *v0vote, v1)
	}
}
