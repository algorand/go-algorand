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
	"reflect"
	"slices"
	"testing"
	"unsafe"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// checkVoteValid analyzes a vote to determine if it would cause compression errors and what kind.
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
	if vote.R.Round == 0 {
		return false, "missing required fields"
	}
	if vote.R.Sender.IsZero() {
		return false, "missing required fields"
	}

	return true, ""
}

// based on RunEncodingTest from protocol/codec_tester.go
func TestEncodingTest(t *testing.T) {
	partitiontest.PartitionTest(t)

	var errorCount int
	const iters = 20000
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
		// zero out ps, always empty
		v0.Sig.PKSigOld = [64]byte{}

		var expectError string
		if ok, errorMsg := checkVoteValid(v0); !ok {
			expectError = errorMsg
		}

		msgpBuf := protocol.EncodeMsgp(v0)
		enc := NewStatelessEncoder()
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
		dec := NewStatelessDecoder()
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

// Test error cases for StatelessDecoder
func TestStatelessDecoderErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	type testcases struct {
		input []byte
		err   string
	}

	for _, tc := range []testcases{
		{input: []byte{}, err: "header missing"},
		{input: []byte{0x01}, err: "header missing"},
		{
			input: []byte{0x00, 0x00, 0x01},
			err:   fmt.Sprintf("not enough data to read value for field %s", msgpFixstrPf),
		},
		{
			input: slices.Concat([]byte{0x00, 0x00}, make([]byte, 80)), // Add 80 bytes for pfField
			err:   fmt.Sprintf("not enough data to read varuint marker for field %s", msgpFixstrRnd),
		},
		{
			input: slices.Concat([]byte{0x00, 0x00}, make([]byte, 80), []byte{0xff}),
			err:   fmt.Sprintf("not a fixint for field %s, got 255", msgpFixstrRnd)},
		{
			input: func() []byte {
				vote := generateRandomVote().Example(0)
				msgpBuf := protocol.EncodeMsgp(vote)
				enc := NewStatelessEncoder()
				compressed, err := enc.CompressVote(nil, msgpBuf)
				require.NoError(t, err)
				return append(compressed, 0xFF, 0xFF, 0xFF)
			}(),
			err: "unexpected trailing data",
		},
	} {
		t.Run(tc.err, func(t *testing.T) {
			dec := NewStatelessDecoder()
			_, err := dec.DecompressVote(nil, tc.input)
			require.ErrorContains(t, err, tc.err)
		})
	}

	// Test cases for varuint method
	t.Run("varuint errors", func(t *testing.T) {
		testField := msgpFixstrRnd
		for _, tc := range []testcases{
			{
				input: []byte{},
				err:   fmt.Sprintf("not enough data to read varuint marker for field %s", testField),
			},
			{
				input: []byte{0xFF},
				err:   fmt.Sprintf("not a fixint for field %s", testField),
			},
			{
				input: []byte{msgpUint8},
				err:   fmt.Sprintf("not enough data for varuint (need 1 bytes) for field %s", testField),
			},
			{
				input: []byte{msgpUint16, 0x01},
				err:   fmt.Sprintf("not enough data for varuint (need 2 bytes) for field %s", testField),
			},
			{
				input: []byte{msgpUint32, 0x01, 0x02, 0x03},
				err:   fmt.Sprintf("not enough data for varuint (need 4 bytes) for field %s", testField),
			},
			{
				input: []byte{msgpUint64, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
				err:   fmt.Sprintf("not enough data for varuint (need 8 bytes) for field %s", testField),
			},
		} {
			t.Run(tc.err, func(t *testing.T) {
				dec := NewStatelessDecoder()
				dec.src = tc.input
				err := dec.varuint(testField)
				require.ErrorContains(t, err, tc.err)
			})
		}
	})

	t.Run("bin32 errors", func(t *testing.T) {
		testField := msgpFixstrSnd
		for _, tc := range []testcases{
			{
				input: []byte{},
				err:   fmt.Sprintf("not enough data to read value for field %s", testField),
			},
			{
				input: []byte{0x01, 0x02},
				err:   fmt.Sprintf("not enough data to read value for field %s", testField),
			},
		} {
			t.Run(tc.err, func(t *testing.T) {
				dec := NewStatelessDecoder()
				dec.src = tc.input
				err := dec.bin32(testField)
				require.ErrorContains(t, err, tc.err)
			})
		}
	})

	t.Run("bin64 errors", func(t *testing.T) {
		testField := msgpFixstrP1s
		for _, tc := range []testcases{
			{
				input: []byte{},
				err:   fmt.Sprintf("not enough data to read value for field %s", testField),
			},
			{
				input: []byte{0x01, 0x02},
				err:   fmt.Sprintf("not enough data to read value for field %s", testField),
			},
		} {
			t.Run(tc.err, func(t *testing.T) {
				dec := NewStatelessDecoder()
				dec.src = tc.input
				err := dec.bin64(testField)
				require.ErrorContains(t, err, tc.err)
			})
		}
	})
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
		enc := NewStatelessEncoder()
		encBuf, err := enc.CompressVote(nil, buf)
		if err != nil {
			// invalid msgpbuf, skip
			return
		}
		dec := NewStatelessDecoder()
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
		enc := NewStatelessEncoder()
		encBuf, err := enc.CompressVote(nil, msgpBuf)
		if expectError != "" {
			// skip expected errors
			require.ErrorContains(t, err, expectError)
			require.Nil(t, encBuf)
			return
		}
		require.NoError(t, err)
		dec := NewStatelessDecoder()
		decBuf, err := dec.DecompressVote(nil, encBuf)
		require.NoError(t, err)
		require.Equal(t, msgpBuf, decBuf)
		var v1 agreement.UnauthenticatedVote
		err = protocol.Decode(decBuf, &v1)
		require.NoError(t, err)
		require.Equal(t, v0, v1)
	})
}

// TestEncoderReuse specifically tests the reuse of a StatelessEncoder instance across
// multiple compression operations. This test would have caught the bug where
// the encoder's position wasn't being reset between calls.
func TestEncoderReuse(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Create several random votes
	const numVotes = 10
	msgpBufs := make([][]byte, 0, numVotes)
	voteGen := generateRandomVote()

	// Generate random votes and encode them
	for i := 0; i < numVotes; i++ {
		msgpBufs = append(msgpBufs, protocol.EncodeMsgp(voteGen.Example(i)))
	}

	// Test reusing the same encoder multiple times
	enc := NewStatelessEncoder()
	var compressedBufs [][]byte

	// First case: Create a new buffer for each compression
	for i, msgpBuf := range msgpBufs {
		compressedBuf, err := enc.CompressVote(nil, msgpBuf)
		require.NoError(t, err, "Vote %d failed to compress with new buffer", i)
		compressedBufs = append(compressedBufs, compressedBuf)
	}

	// Verify all compressed buffers can be decompressed correctly
	dec := NewStatelessDecoder()
	for i, compressedBuf := range compressedBufs {
		decompressedBuf, err := dec.DecompressVote(nil, compressedBuf)
		require.NoError(t, err, "Vote %d failed to decompress", i)
		require.Equal(t, msgpBufs[i], decompressedBuf, "Vote %d decompressed incorrectly", i)
	}

	// Second case: Reuse a single pre-allocated buffer
	compressedBufs = compressedBufs[:0] // Clear
	reusedBuffer := make([]byte, 0, 4096)

	for i, msgpBuf := range msgpBufs {
		// Save the compressed result and create a new copy
		// to avoid the buffer being modified by subsequent operations
		compressed, err := enc.CompressVote(reusedBuffer[:0], msgpBuf)
		require.NoError(t, err, "Vote %d failed to compress with reused buffer", i)
		compressedCopy := make([]byte, len(compressed))
		copy(compressedCopy, compressed)
		compressedBufs = append(compressedBufs, compressedCopy)
	}

	// Verify all compressed buffers with reused buffer can be decompressed correctly
	for i, compressedBuf := range compressedBufs {
		decompressedBuf, err := dec.DecompressVote(nil, compressedBuf)
		require.NoError(t, err, "Vote %d failed to decompress (reused buffer)", i)
		require.Equal(t, msgpBufs[i], decompressedBuf, "Vote %d decompressed incorrectly (reused buffer)", i)
	}

	// Third case: Test with varying buffer sizes to ensure we handle capacity changes correctly
	compressedBufs = compressedBufs[:0]  // Clear
	varyingBuffer := make([]byte, 0, 10) // Start with a small buffer

	for i, msgpBuf := range msgpBufs {
		// This will cause the buffer to be reallocated sometimes
		compressed, err := enc.CompressVote(varyingBuffer[:0], msgpBuf)
		require.NoError(t, err, "Vote %d failed to compress with varying buffer", i)
		compressedCopy := make([]byte, len(compressed))
		copy(compressedCopy, compressed)
		compressedBufs = append(compressedBufs, compressedCopy)

		// Update the buffer for next iteration - it might have grown
		varyingBuffer = compressed
	}

	// Verify all compressed buffers with varying buffer can be decompressed correctly
	for i, compressedBuf := range compressedBufs {
		decompressedBuf, err := dec.DecompressVote(nil, compressedBuf)
		require.NoError(t, err, "Vote %d failed to decompress (varying buffer)", i)
		require.Equal(t, msgpBufs[i], decompressedBuf, "Vote %d decompressed incorrectly (varying buffer)", i)
	}
}
