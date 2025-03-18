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
	"reflect"
	"testing"
	"unsafe"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
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

// FuzzMsgpVote is a fuzz test for parseVote, CompressVote and DecompressVote.
// It generates random msgp-encoded votes, then compresses & decompresses them.
func FuzzMsgpVote(f *testing.F) {
	addVote := func(obj any) {
		var buf []byte
		if v, ok := obj.(*agreement.UnauthenticatedVote); ok {
			buf = protocol.Encode(v)
		} else {
			buf = protocol.EncodeReflect(obj)
		}
		f.Add(buf)
	}
	// error cases (weird msgp bufs)
	for _, tc := range parseVoteTestCases {
		addVote(tc.obj)
	}
	for range 100 { // random valid votes
		v, err := protocol.RandomizeObject(&agreement.UnauthenticatedVote{},
			protocol.RandomizeObjectWithZeroesEveryN(10),
			protocol.RandomizeObjectWithAllUintSizes())
		require.NoError(f, err)
		addVote(v)
	}

	f.Fuzz(func(t *testing.T, buf []byte) {
		enc := NewStaticEncoder()
		encBuf, err := enc.CompressVote(nil, buf)
		if err != nil {
			// invalid msgpbuf, skip
			return
		}
		dec := NewStaticDecoder()
		decBuf, err := dec.DecompressVote(nil, encBuf)
		require.NoError(t, err)
		require.Equal(t, buf, decBuf)
	})
}

func FuzzVoteFields(f *testing.F) {
	f.Fuzz(func(t *testing.T, snd []byte, rnd, per, step uint64,
		oper uint64, oprop, dig, encdig []byte,
		pf []byte, s, p, ps, p2, p1s, p2s []byte) {
		var v0 agreement.UnauthenticatedVote
		copy(v0.R.Sender[:], snd)
		v0.R.Round = basics.Round(rnd)
		// Use reflection to set the unexported period field
		rPeriodField := reflect.ValueOf(&v0.R).Elem().FieldByName("Period")
		rPeriodField = reflect.NewAt(rPeriodField.Type(), unsafe.Pointer(rPeriodField.UnsafeAddr())).Elem()
		rPeriodField.SetUint(per)
		require.EqualValues(t, per, v0.R.Period)
		// Use reflection to set the unexported step field
		rStepField := reflect.ValueOf(&v0.R).Elem().FieldByName("Step")
		rStepField = reflect.NewAt(rStepField.Type(), unsafe.Pointer(rStepField.UnsafeAddr())).Elem()
		rStepField.SetUint(step)
		require.EqualValues(t, step, v0.R.Step)
		// Use reflection to set the OriginalPeriod field in the proposal
		propVal := reflect.ValueOf(&v0.R.Proposal).Elem()
		origPeriodField := propVal.FieldByName("OriginalPeriod")
		origPeriodField = reflect.NewAt(origPeriodField.Type(), unsafe.Pointer(origPeriodField.UnsafeAddr())).Elem()
		origPeriodField.SetUint(oper)
		require.EqualValues(t, oper, v0.R.Proposal.OriginalPeriod)

		copy(v0.R.Proposal.OriginalProposer[:], oprop)
		copy(v0.R.Proposal.BlockDigest[:], dig)
		copy(v0.R.Proposal.EncodingDigest[:], encdig)
		copy(v0.Cred.Proof[:], pf)
		copy(v0.Sig.Sig[:], s)
		copy(v0.Sig.PK[:], p)
		copy(v0.Sig.PKSigOld[:], ps)
		copy(v0.Sig.PK2[:], p2)
		copy(v0.Sig.PK1Sig[:], p1s)
		copy(v0.Sig.PK2Sig[:], p2s)

		var expectError string
		if v0.Cred.Proof.MsgIsZero() {
			expectError = "expected fixed map size 1 for UnauthenticatedCredential"
		}
		if v0.R.MsgIsZero() || v0.Cred.MsgIsZero() || v0.Sig.MsgIsZero() {
			expectError = "expected fixed map size 3 for unauthenticatedVote"
		}

		msgpBuf := protocol.Encode(&v0)
		enc := NewStaticEncoder()
		encBuf, err := enc.CompressVote(nil, msgpBuf)
		if expectError != "" {
			// skip expected errors
			require.ErrorContains(t, err, expectError)
			require.Nil(t, encBuf)
			return
		}
		require.NoError(t, err)
		dec := NewStaticDecoder()
		decBuf, err := dec.DecompressVote(nil, encBuf)
		require.NoError(t, err)
		require.Equal(t, msgpBuf, decBuf)
		var v1 agreement.UnauthenticatedVote
		err = protocol.Decode(decBuf, &v1)
		require.NoError(t, err)
		require.Equal(t, v0, v1)
	})
}
