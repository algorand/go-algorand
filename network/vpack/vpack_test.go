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
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"testing"
	"unsafe"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// checkVoteValid analyzes a vote to determine if it would cause compression errors and what kind.
// These errors result from vpack_assert_size not matching the input.
// Returns (true, expectedError) if an error is expected during compression, (false, "") otherwise.
func checkVoteValid(vote *agreement.UnauthenticatedVote) (ok bool, expectedError string) {
	if vote.R.MsgIsZero() || vote.Cred.MsgIsZero() || vote.Sig.MsgIsZero() {
		return false, "expected fixed map size 3 for unauthenticatedVote"
	}
	if vote.Cred.Proof.MsgIsZero() {
		return false, "expected fixed map size 1 for UnauthenticatedCredential"
	}
	if !vote.Sig.PKSigOld.MsgIsZero() {
		return false, "expected empty array for ps"
	}
	return true, ""
}

// based on RunEncodingTest from protocol/codec_tester.go
func TestEncodingTest(t *testing.T) {
	partitiontest.PartitionTest(t)

	var errorCount int
	const iters = 10000 //10000
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
		if ok, errorMsg := checkVoteValid(v0); !ok {
			expectError = errorMsg
		}

		msgpBuf := protocol.EncodeMsgp(v0)
		enc := NewBitmaskEncoder()
		encBuf, err := enc.CompressVote(nil, msgpBuf)
		if expectError != "" {
			// skip expected errors
			require.ErrorContains(t, err, expectError, "expected error: %s", expectError)
			require.Nil(t, encBuf)
			errorCount++
			continue
		}
		require.NoError(t, err)

		// decompress and compare to original
		dec := NewBitmaskDecoder()
		decMsgpBuf, err := dec.DecompressVote(nil, encBuf)
		jsonBuf, _ := json.MarshalIndent(v0, "", "  ")
		require.NoError(t, err, "got vote %s", jsonBuf)
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
	f.Skip()
	addVote := func(obj any) []byte {
		var buf []byte
		if v, ok := obj.(*agreement.UnauthenticatedVote); ok {
			buf = protocol.Encode(v)
		} else {
			buf = protocol.EncodeReflect(obj)
		}
		f.Add(buf)
		f.Add(append([]byte{0x80}, buf...)) // add a prefix
		f.Add(append([]byte{0x00}, buf...)) // add a prefix
		f.Add(append(buf, 0x80))            // add a suffix
		f.Add(append(buf, 0x00))            // add a suffix
		return buf
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
		msgpbuf := addVote(v)
		for i := range len(msgpbuf) {
			f.Add(msgpbuf[:i])
		}
	}

	f.Fuzz(func(t *testing.T, buf []byte) {
		enc := NewBitmaskEncoder()
		encBuf, err := enc.CompressVote(nil, buf)
		if err != nil {
			// invalid msgpbuf, skip
			return
		}
		dec := NewBitmaskDecoder()
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
		if ok, errorMsg := checkVoteValid(&v0); !ok {
			expectError = errorMsg
		}

		msgpBuf := protocol.Encode(&v0)
		enc := NewBitmaskEncoder()
		encBuf, err := enc.CompressVote(nil, msgpBuf)
		if expectError != "" {
			// skip expected errors
			require.ErrorContains(t, err, expectError)
			require.Nil(t, encBuf)
			return
		}
		require.NoError(t, err)
		dec := NewBitmaskDecoder()
		decBuf, err := dec.DecompressVote(nil, encBuf)
		require.NoError(t, err)
		require.Equal(t, msgpBuf, decBuf)
		var v1 agreement.UnauthenticatedVote
		err = protocol.Decode(decBuf, &v1)
		require.NoError(t, err)
		require.Equal(t, v0, v1)
	})
}

var decompressVoteTestCases = []struct {
	name        string
	input       []byte
	errExpected error
}{
	{
		name:        "Empty input",
		input:       []byte{},
		errExpected: nil, // Empty inputs are valid and return empty outputs
	},
	{
		name:        "Insufficient bytes for markerDynamicFixuint",
		input:       []byte{markerDynamicFixuint},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Insufficient bytes for markerDynamicUint8",
		input:       []byte{markerDynamicUint8},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Insufficient bytes for markerDynamicUint16",
		input:       []byte{markerDynamicUint16},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Partial bytes for markerDynamicUint16",
		input:       []byte{markerDynamicUint16, 0x01},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Insufficient bytes for markerDynamicUint32",
		input:       []byte{markerDynamicUint32},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Partial bytes for markerDynamicUint32",
		input:       []byte{markerDynamicUint32, 0x01, 0x02, 0x03},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Insufficient bytes for markerDynamicUint64",
		input:       []byte{markerDynamicUint64},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Partial bytes for markerDynamicUint64",
		input:       []byte{markerDynamicUint64, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Insufficient bytes for markerLiteralBin64",
		input:       []byte{markerLiteralBin64},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Partial bytes for markerLiteralBin64",
		input:       []byte{markerLiteralBin64, 0x01, 0x02, 0x03},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Insufficient bytes for markerLiteralBin80",
		input:       []byte{markerLiteralBin80},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Partial bytes for markerLiteralBin80",
		input:       []byte{markerLiteralBin80, 0x01, 0x02, 0x03},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Insufficient bytes for markerDynamicBin32",
		input:       []byte{markerDynamicBin32},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Partial bytes for markerDynamicBin32",
		input:       []byte{markerDynamicBin32, 0x01, 0x02, 0x03},
		errExpected: io.ErrUnexpectedEOF,
	},
	{
		name:        "Invalid static marker outside static range",
		input:       []byte{0x10}, // This is outside the valid static index range
		errExpected: fmt.Errorf("unexpected marker: 0x%02x", 0x10),
	},
	{
		name:        "Valid static index but nil entry in table",
		input:       []byte{0xc7}, // This is within the valid static index range but has no entry
		errExpected: fmt.Errorf("unexpected static marker: 0x%02x", 0xc7),
	},
	{
		name:        "Unexpected marker outside valid range",
		input:       []byte{0xFF}, // Marker outside of any valid range
		errExpected: fmt.Errorf("unexpected marker: 0x%02x", 0xFF),
	},
}

// TestDecompressVoteErrors tests error cases of the decompressStatic function
func TestDecompressVoteErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, tc := range decompressVoteTestCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decompressStatic(nil, tc.input)
			if tc.errExpected == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				if customErr, ok := tc.errExpected.(fmt.Formatter); ok {
					require.Contains(t, err.Error(), fmt.Sprintf("%v", customErr))
				} else {
					require.Equal(t, tc.errExpected, err)
				}
			}
		})
	}
}

// FuzzDecompressStatic is a fuzz test for decompressStatic.
// It tests error cases from decompressVoteTestCases and also valid compressed votes.
func FuzzDecompressStatic(f *testing.F) {
	for _, tc := range decompressVoteTestCases {
		f.Add(tc.input)
	}
	// Generate random votes, compress them, and add the compressed votes to the fuzzer
	for range 100 {
		v, err := protocol.RandomizeObject(&agreement.UnauthenticatedVote{},
			protocol.RandomizeObjectWithZeroesEveryN(10),
			protocol.RandomizeObjectWithAllUintSizes())
		require.NoError(f, err)
		vote := v.(*agreement.UnauthenticatedVote)
		if ok, _ := checkVoteValid(vote); !ok {
			continue
		}
		msgpBuf := protocol.EncodeMsgp(vote)
		enc := NewBitmaskEncoder()
		compressedVote, err := enc.CompressVote(nil, msgpBuf)
		require.NoError(f, err)
		f.Add(compressedVote)
	}
	for i := range staticTable {
		f.Add(staticTable[i])
	}

	// The actual fuzzing function
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = decompressStatic(nil, input)
	})
}
