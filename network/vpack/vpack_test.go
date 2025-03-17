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
	"github.com/stretchr/testify/require"
)

// based on RunEncodingTest from protocol/codec_tester.go
func TestEncodingTest(t *testing.T) {
	partitiontest.PartitionTest(t)

	var errorCount int
	const iters = 10000
	for range iters {
		v0obj, err := protocol.RandomizeObject(&agreement.UnauthenticatedVote{},
			protocol.RandomizeObjectWithZeroesEveryN(10),
			protocol.RandomizeObjectWithAllUintSizes(),
		)
		require.NoError(t, err)

		v0 := v0obj.(*agreement.UnauthenticatedVote)
		if *v0 == (agreement.UnauthenticatedVote{}) {
			continue // don't try to encode or compress empty votes (a single byte, 0x80)
		}
		var expectError string
		// Expect errors when random vote doesn't match vpack_assert_size
		if v0.Cred.Proof.MsgIsZero() {
			expectError = "expected fixed map size 1 for UnauthenticatedCredential"
		}
		if v0.R.MsgIsZero() || v0.Cred.MsgIsZero() || v0.Sig.MsgIsZero() {
			expectError = "expected fixed map size 3 for unauthenticatedVote"
		}

		msgpBuf := protocol.EncodeMsgp(v0)
		enc := NewStaticEncoder()
		encBuf, err := enc.CompressVote(nil, msgpBuf)
		if expectError != "" {
			// skip expected errors
			require.ErrorContains(t, err, expectError)
			require.Nil(t, encBuf)
			errorCount++
			continue
		}
		require.NoError(t, err)

		// decompress and compare to original
		dec := NewStaticDecoder()
		decMsgpBuf, err := dec.DecompressVote(nil, encBuf)
		require.NoError(t, err)
		require.Equal(t, msgpBuf, decMsgpBuf) // msgp encoding matches
		var v1 agreement.UnauthenticatedVote
		err = protocol.Decode(decMsgpBuf, &v1)
		require.NoError(t, err)
		require.Equal(t, *v0, v1) // vote objects match
	}
	t.Logf("TestEncodingTest: %d expected errors out of %d iterations", errorCount, iters)
}

// TestEncodeStaticSteps asserts that table entries for step:1, step:2, step:3 are encoded
func TestEncodeStaticSteps(t *testing.T) {
	partitiontest.PartitionTest(t)
	v := agreement.UnauthenticatedVote{}
	v.Cred.Proof[0] = 1 // not empty
	v.R.Round = 1
	v.Sig.PK[0] = 1 // not empty

	for i := 1; i <= 3; i++ {
		var expectedStaticIdx uint8
		switch i {
		case 1:
			v.R.Step = 1
			expectedStaticIdx = staticIdxStepVal1Field
		case 2:
			v.R.Step = 2
			expectedStaticIdx = staticIdxStepVal2Field
		case 3:
			v.R.Step = 3
			expectedStaticIdx = staticIdxStepVal3Field
		}

		msgpbuf := protocol.Encode(&v)
		w := &mockCompressWriter{}
		err := parseVote(msgpbuf, w)
		require.NoError(t, err)
		require.Contains(t, w.writes, expectedStaticIdx)
	}
}
