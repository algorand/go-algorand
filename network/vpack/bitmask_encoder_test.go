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
	"bytes"
	"fmt"
	"math"
	"reflect"
	"slices"
	"testing"
	"unsafe"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestStatelessEncoder tests the StatelessEncoder/Decoder using randomly generated votes
// This replaces both TestStatelessEncoder and TestStatelessEncoderMultiple with a more
// comprehensive property-based test using rapid
func TestStatelessEncoder(t *testing.T) {
	partitiontest.PartitionTest(t)
	rapid.Check(t, checkStatelessEncoder)
}

func checkStatelessEncoder(t *rapid.T) {
	// Generate a random vote
	v0 := generateRandomVote().Draw(t, "vote")

	// Convert to msgpack
	msgpBuf := protocol.EncodeMsgp(v0)

	// Try to compress with StatelessEncoder
	encBM := NewStatelessEncoder()
	encBufBM, err := encBM.CompressVote(nil, msgpBuf)
	require.NoError(t, err)

	// Verify the bitmask is at the beginning
	require.GreaterOrEqual(t, len(encBufBM), 2, "Compressed data should have at least 2 bytes for header")
	// Decompress with StatelessDecoder
	decBM := NewStatelessDecoder()
	decBufBM, err := decBM.DecompressVote(nil, encBufBM)
	require.NoError(t, err)

	// Ensure the decompressed data matches the original msgpack data
	require.Equal(t, msgpBuf, decBufBM)

	// Decode the decompressed data and verify it matches the original vote
	var v1 agreement.UnauthenticatedVote
	err = protocol.Decode(decBufBM, &v1)
	require.NoError(t, err)
	require.Equal(t, *v0, v1)
	t.Logf("Vote OK")
}

// createMask is a helper function that creates a byte slice representing a bitmask
// with the requiredFieldsMask and any additional bits provided
func createMask(additionalBits ...uint8) []byte {
	// Start with 0
	mask := uint8(0)

	// Add any additional bits
	for _, bit := range additionalBits {
		mask |= bit
	}
	return []byte{mask, 0}
}

// Test error cases for StatelessDecoder
func TestStatelessDecoderErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	testCases := []struct {
		name        string
		input       []byte
		errExpected error
	}{
		{
			name:        "Empty input",
			input:       []byte{},
			errExpected: fmt.Errorf("header missing"),
		},
		{
			name:        "Too short for header",
			input:       []byte{0x01},
			errExpected: fmt.Errorf("header missing"),
		},
		{
			name:        "Not enough data for pf",
			input:       []byte{0x00, 0x00, 0x01},
			errExpected: fmt.Errorf("not enough data to read value for field %s", msgpFixstrPf),
		},
		{
			name: "Error in varuint for rnd field",
			input: slices.Concat(createMask(),
				// Add required fields and append just the marker causing an error
				make([]byte, 80), // Add 80 bytes for pfField
			),
			errExpected: fmt.Errorf("not enough data to read varuint marker for field %s", msgpFixstrRnd),
		},
		{
			name: "Error reading varuint for rnd field",
			input: slices.Concat(createMask(),
				// Add required fields and append just the marker causing an error
				make([]byte, 80), // Add 80 bytes for pfField
				[]byte{0xff},     // Invalid marker
			),
			errExpected: fmt.Errorf("not a fixint for field %s, got 255", msgpFixstrRnd)},
		{
			name: "Trailing data error",
			input: func() []byte {
				// Use a real compressed vote and add trailing data
				voteGen := generateRandomVote()
				vote := voteGen.Example(0)
				// Encode and compress it
				msgpBuf := protocol.EncodeMsgp(vote)
				enc := NewStatelessEncoder()
				compressed, err := enc.CompressVote(nil, msgpBuf)
				if err != nil {
					panic(fmt.Sprintf("Failed to compress valid vote: %v", err))
				}
				// Add trailing data
				return append(compressed, 0xFF, 0xFF, 0xFF)
			}(),
			errExpected: fmt.Errorf("unexpected trailing data"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dec := NewStatelessDecoder()
			_, err := dec.DecompressVote(nil, tc.input)
			require.ErrorContains(t, err, tc.errExpected.Error())
		})
	}
}

// TestStatelessHelperMethods tests the helper methods in StatelessDecoder for various error cases
func TestStatelessHelperMethods(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Test cases for varuint method
	t.Run("varuint errors", func(t *testing.T) {
		testField := msgpFixstrRnd // The field we'll test with

		tests := []struct {
			name          string
			input         []byte
			errMsgPattern string
		}{
			{
				name:          "Empty input",
				input:         []byte{},
				errMsgPattern: fmt.Sprintf("not enough data to read varuint marker for field %s", testField),
			},
			{
				name:          "Invalid marker",
				input:         []byte{0xFF},
				errMsgPattern: fmt.Sprintf("not a fixint for field %s", testField),
			},
			{
				name:          "uint8tag without data",
				input:         []byte{uint8tag},
				errMsgPattern: fmt.Sprintf("not enough data for varuint (need 1 bytes) for field %s", testField),
			},
			{
				name:          "uint16tag with insufficient data",
				input:         []byte{uint16tag, 0x01},
				errMsgPattern: fmt.Sprintf("not enough data for varuint (need 2 bytes) for field %s", testField),
			},
			{
				name:          "uint32tag with insufficient data",
				input:         []byte{uint32tag, 0x01, 0x02, 0x03},
				errMsgPattern: fmt.Sprintf("not enough data for varuint (need 4 bytes) for field %s", testField),
			},
			{
				name:          "uint64tag with insufficient data",
				input:         []byte{uint64tag, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
				errMsgPattern: fmt.Sprintf("not enough data for varuint (need 8 bytes) for field %s", testField),
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				dec := NewStatelessDecoder()
				dec.src = tc.input
				err := dec.varuint(testField)
				require.ErrorContains(t, err, tc.errMsgPattern)
			})
		}
	})

	// Test cases for bin32 method
	t.Run("bin32 errors", func(t *testing.T) {
		testField := msgpFixstrSnd // The field we'll test with

		tests := []struct {
			name          string
			input         []byte
			errMsgPattern string
		}{
			{
				name:          "Empty input",
				input:         []byte{},
				errMsgPattern: fmt.Sprintf("not enough data to read value for field %s", testField),
			},
			{
				name:          "Insufficient data",
				input:         []byte{0x01, 0x02},
				errMsgPattern: fmt.Sprintf("not enough data to read value for field %s", testField),
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				dec := NewStatelessDecoder()
				dec.src = tc.input
				err := dec.bin32(testField)
				require.ErrorContains(t, err, tc.errMsgPattern)
			})
		}
	})

	// Test cases for bin64 method
	t.Run("bin64 errors", func(t *testing.T) {
		testField := msgpFixstrP1s // The field we'll test with

		tests := []struct {
			name          string
			input         []byte
			errMsgPattern string
		}{
			{
				name:          "Empty input",
				input:         []byte{},
				errMsgPattern: fmt.Sprintf("not enough data to read value for field %s", testField),
			},
			{
				name:          "Insufficient data",
				input:         []byte{0x01, 0x02},
				errMsgPattern: fmt.Sprintf("not enough data to read value for field %s", testField),
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				dec := NewStatelessDecoder()
				dec.src = tc.input
				err := dec.bin64(testField)
				require.ErrorContains(t, err, tc.errMsgPattern)
			})
		}
	})
}

// generateRandomVote creates a random vote generator using rapid
func generateRandomVote() *rapid.Generator[*agreement.UnauthenticatedVote] {
	return rapid.Custom(func(t *rapid.T) *agreement.UnauthenticatedVote {
		v := &agreement.UnauthenticatedVote{}

		filterZeroBytes := func(b []byte) bool {
			for _, v := range b {
				if v != 0 {
					return true
				}
			}
			return false
		}

		// Generate random sender address (32 bytes)
		addressBytes := rapid.SliceOfN(rapid.Byte(), 32, 32).Filter(filterZeroBytes).Draw(t, "sender")
		copy(v.R.Sender[:], addressBytes)

		// Create an equal distribution generator for different integer ranges
		// This will test different MessagePack varuint encodings (uint8, uint16, uint32, uint64)
		integerRangeGen := rapid.OneOf(
			rapid.Uint64Range(0, 255),                     // uint8 range
			rapid.Uint64Range(256, 65535),                 // uint16 range
			rapid.Uint64Range(65536, 4294967295),          // uint32 range
			rapid.Uint64Range(4294967296, math.MaxUint64), // uint64 range
		)

		// Generate non-zero round using the range generator
		roundNum := integerRangeGen.Filter(func(n uint64) bool {
			return n > 0 // Ensure non-zero round
		}).Draw(t, "round")
		v.R.Round = basics.Round(roundNum)

		// Use reflection to set the unexported period field with the range generator
		rPeriodField := reflect.ValueOf(&v.R).Elem().FieldByName("Period")
		rPeriodField = reflect.NewAt(rPeriodField.Type(), unsafe.Pointer(rPeriodField.UnsafeAddr())).Elem()
		rPeriodField.SetUint(integerRangeGen.Draw(t, "period"))

		// Create a biased generator for steps to emphasize early steps (0, 1, 2, 3)
		stepGen := rapid.OneOf(
			rapid.Just(uint64(0)), // Explicitly test step 0
			rapid.Just(uint64(1)), // Explicitly test step 1
			rapid.Just(uint64(2)), // Explicitly test step 2
			rapid.Just(uint64(3)), // Explicitly test step 3
			integerRangeGen,       // Test other steps with less probability
		)

		// Use reflection to set the unexported step field
		rStepField := reflect.ValueOf(&v.R).Elem().FieldByName("Step")
		rStepField = reflect.NewAt(rStepField.Type(), unsafe.Pointer(rStepField.UnsafeAddr())).Elem()
		rStepField.SetUint(stepGen.Draw(t, "step"))

		// Decide whether to include a proposal or leave it empty
		includeProposal := rapid.Bool().Draw(t, "includeProposal")
		if includeProposal {
			// Use reflection to set the OriginalPeriod field in the proposal
			propVal := reflect.ValueOf(&v.R.Proposal).Elem()
			origPeriodField := propVal.FieldByName("OriginalPeriod")
			origPeriodField = reflect.NewAt(origPeriodField.Type(), unsafe.Pointer(origPeriodField.UnsafeAddr())).Elem()
			origPeriodField.SetUint(integerRangeGen.Draw(t, "originalPeriod"))
			// Generate random OpropField, BlockDigest, and EncodingDigest bytes (32 bytes each)
			// But sometimes make them empty to test edge cases
			makeBytesFn := func(name string) []byte {
				generator := rapid.OneOf(
					rapid.Just([]byte{}),                 // Empty case
					rapid.SliceOfN(rapid.Byte(), 32, 32), // Full case
				)
				return generator.Draw(t, name)
			}
			opropBytes := makeBytesFn("oprop")
			digestBytes := makeBytesFn("digest")
			encDigestBytes := makeBytesFn("encDigest")

			copy(v.R.Proposal.OriginalProposer[:], opropBytes)
			copy(v.R.Proposal.BlockDigest[:], digestBytes)
			copy(v.R.Proposal.EncodingDigest[:], encDigestBytes)

		} else {
			// Leave the proposal empty
			// The default zero values will be used
		}

		// Generate random proof bytes (80 bytes)
		pfBytes := rapid.SliceOfN(rapid.Byte(), 80, 80).Filter(filterZeroBytes).Draw(t, "proof")
		copy(v.Cred.Proof[:], pfBytes)

		// Generate signature fields (variable sizes)
		sigBytes := rapid.SliceOfN(rapid.Byte(), 64, 64).Filter(filterZeroBytes).Draw(t, "sig")
		pkBytes := rapid.SliceOfN(rapid.Byte(), 32, 32).Filter(filterZeroBytes).Draw(t, "pk")
		p2Bytes := rapid.SliceOfN(rapid.Byte(), 32, 32).Filter(filterZeroBytes).Draw(t, "pk2")
		p1sBytes := rapid.SliceOfN(rapid.Byte(), 64, 64).Filter(filterZeroBytes).Draw(t, "pk1sig")
		p2sBytes := rapid.SliceOfN(rapid.Byte(), 64, 64).Filter(filterZeroBytes).Draw(t, "pk2sig")
		copy(v.Sig.Sig[:], sigBytes)
		copy(v.Sig.PK[:], pkBytes)
		copy(v.Sig.PK2[:], p2Bytes)
		copy(v.Sig.PK1Sig[:], p1sBytes)
		copy(v.Sig.PK2Sig[:], p2sBytes)

		// PKSigOld is deprecated and always zero when encoded with StatelessEncoder
		v.Sig.PKSigOld = [64]byte{}

		return v
	})
}

func FuzzRapidCheck(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(checkStatelessEncoder))
}

// FuzzStatelessEncoder is a fuzz test that generates random votes,
// compresses them with StatelessEncoder and decompresses them with StatelessDecoder.
func FuzzStatelessEncoder(f *testing.F) {
	//	f.Skip()
	// Add seed corpus examples
	voteGen := generateRandomVote()
	for i := 0; i < 5; i++ {
		vote := voteGen.Example(i)
		f.Logf("Vote %d: %+v", i, vote)
		msgpBuf := protocol.EncodeMsgp(vote)
		f.Add(msgpBuf) // Add seed corpus for the fuzzer
	}

	// Use a separate function that properly utilizes the fuzzer input
	f.Fuzz(func(t *testing.T, msgpBuf []byte) {
		// Try to compress the input
		t.Logf("Input: %v", msgpBuf)
		enc := NewStatelessEncoder()
		compressed, err := enc.CompressVote(nil, msgpBuf)
		if err != nil {
			// Not valid msgpack data for a vote, skip
			return
		}

		// Then decompress it
		dec := NewStatelessDecoder()
		decompressed, err := dec.DecompressVote(nil, compressed)
		if err != nil {
			t.Fatalf("Failed to decompress valid compressed data: %v", err)
		}

		// Verify the decompressed data matches the original
		if !bytes.Equal(msgpBuf, decompressed) {
			t.Fatalf("Decompressed data does not match original")
		}
	})
}

// FuzzStatelessDecoder is a fuzz test specifically targeting the StatelessDecoder
// with potentially malformed input.
func FuzzStatelessDecoder(f *testing.F) {
	// Add valid compressed votes from our random vote generator
	voteGen := generateRandomVote()
	for i := 0; i < 100; i++ {
		vote := voteGen.Example(i) // Use deterministic seeds
		msgpBuf := protocol.EncodeMsgp(vote)
		enc := NewStatelessEncoder()
		compressedVote, err := enc.CompressVote(nil, msgpBuf)
		if err != nil {
			continue
		}
		f.Add(compressedVote)
	}

	// Add various error test cases as seed corpus
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, 0x02})
	f.Add([]byte{0xFF, 0xFF})
	// Add additional error test cases for specific bitmasks with required fields
	f.Add(createMask())
	f.Add(append(createMask(), 0xFF))

	f.Fuzz(func(t *testing.T, data []byte) {
		dec := NewStatelessDecoder()
		_, _ = dec.DecompressVote(nil, data) // Ensure it doesn't crash
	})
}
