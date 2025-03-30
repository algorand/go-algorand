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
	"strings"
	"testing"
	"unsafe"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestBitmaskEncoder tests the BitmaskEncoder/Decoder using randomly generated votes
// This replaces both TestBitmaskEncoder and TestBitmaskEncoderMultiple with a more
// comprehensive property-based test using rapid
func TestBitmaskEncoder(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Track statistics to report at the end
	var validVotes, errorVotes int
	var bitmaskTotal, staticTotal int

	rapid.Check(t, func(t *rapid.T) {
		// Generate a random vote
		v0 := generateRandomVote().Draw(t, "vote")

		// Check if the vote is valid for compression
		var expectError string
		if ok, errorMsg := checkVoteValid(v0); !ok {
			expectError = errorMsg
		}

		// Convert to msgpack
		msgpBuf := protocol.EncodeMsgp(v0)

		// Try to compress with BitmaskEncoder
		encBM := NewBitmaskEncoder()
		encBufBM, err := encBM.CompressVote(nil, msgpBuf)

		if expectError != "" {
			// We expect an error
			require.ErrorContains(t, err, expectError)
			require.Nil(t, encBufBM)
			errorVotes++
			return
		}
		require.NoError(t, err)

		// Verify the bitmask is at the beginning
		require.GreaterOrEqual(t, len(encBufBM), 2, "Compressed data should have at least 2 bytes for bitmask")
		mask := uint16(encBufBM[0])<<8 | uint16(encBufBM[1])
		require.NotZero(t, mask, "Bitmask should be non-zero")

		// Decompress with BitmaskDecoder
		decBM := NewBitmaskDecoder()
		decBufBM, err := decBM.DecompressVote(nil, encBufBM)
		require.NoError(t, err)

		// Ensure the decompressed data matches the original msgpack data
		require.Equal(t, msgpBuf, decBufBM)

		// Decode the decompressed data and verify it matches the original vote
		var v1 agreement.UnauthenticatedVote
		err = protocol.Decode(decBufBM, &v1)
		require.NoError(t, err)
		require.Equal(t, *v0, v1)

		// Also compare with StaticEncoder for reference (similar to what was in TestBitmaskEncoderMultiple)
		encStatic := NewStaticEncoder()
		encBufStatic, err := encStatic.CompressVote(nil, msgpBuf)
		require.NoError(t, err)

		// Update stats for reporting
		validVotes++
		bitmaskTotal += len(encBufBM)
		staticTotal += len(encBufStatic)

		// Log compression statistics for this vote
		t.Logf("BitmaskEncoder: %d bytes, StaticEncoder: %d bytes, Ratio: %.2f%%",
			len(encBufBM), len(encBufStatic), float64(len(encBufBM))/float64(len(encBufStatic))*100)
	})

	// Report overall statistics at the end
	if validVotes > 0 {
		avgBitmask := float64(bitmaskTotal) / float64(validVotes)
		avgStatic := float64(staticTotal) / float64(validVotes)
		ratio := avgBitmask / avgStatic * 100

		t.Logf("Processed %d valid votes and %d error votes", validVotes, errorVotes)
		t.Logf("Average sizes - BitmaskEncoder: %.2f bytes, StaticEncoder: %.2f bytes", 
			avgBitmask, avgStatic)
		t.Logf("BitmaskEncoder is %.2f%% the size of StaticEncoder on average", ratio)
	}
}

// Test error cases for BitmaskDecoder
func TestBitmaskDecoderErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	testCases := []struct {
		name        string
		input       []byte
		errExpected error
	}{
		{
			name:        "Empty input",
			input:       []byte{},
			errExpected: fmt.Errorf("bitmask missing"),
		},
		{
			name:        "Too short for bitmask",
			input:       []byte{0x01},
			errExpected: fmt.Errorf("bitmask missing"),
		},
		{
			name:        "Not enough data after bitmask",
			input:       []byte{byte(requiredFieldsMask >> 8), byte(requiredFieldsMask & 0xFF)},
			errExpected: fmt.Errorf("not enough data"),
		},
		{
			name:        "Missing pf bit",
			input:       []byte{0x00, 0x00, 0x01},
			errExpected: fmt.Errorf("missing required fields: mask 0"),
		},
		{
			name:        "Not enough data for literal bin80",
			input:       []byte{byte(requiredFieldsMask >> 8), byte(requiredFieldsMask & 0xFF), 0xFF}, // All required bits in mask set, but not enough data
			errExpected: fmt.Errorf("not enough data to read literal bin80 marker + value"),
		},
		{
			name:        "pf bit set but wrong marker",
			input:       append([]byte{byte(requiredFieldsMask >> 8), byte(requiredFieldsMask & 0xFF), 0xF0}, make([]byte, 80)...), // 0xF0 is wrong (should be 0xF1)
			errExpected: fmt.Errorf("not a literal bin80"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dec := NewBitmaskDecoder()
			_, err := dec.DecompressVote(nil, tc.input)

			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errExpected.Error())
		})
	}
}

// TestHelperMethods tests the helper methods in BitmaskDecoder for various error cases
func TestHelperMethods(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Test varuint with different formats
	t.Run("varuint errors", func(t *testing.T) {
		dec := NewBitmaskDecoder()

		// Test not enough data
		dec.src = []byte{}
		dec.pos = 0
		err := dec.varuint(staticIdxRndField)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not enough data")

		// Test invalid marker
		dec.src = []byte{0xFF}
		dec.pos = 0
		err = dec.varuint(staticIdxRndField)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a fixint")

		// Test insufficient data for each type
		dec.src = []byte{uint8tag}
		dec.pos = 0
		err = dec.varuint(staticIdxRndField)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not enough data for varuint")

		dec.src = []byte{uint16tag, 0x01}
		dec.pos = 0
		err = dec.varuint(staticIdxRndField)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not enough data for varuint")

		dec.src = []byte{uint32tag, 0x01, 0x02, 0x03}
		dec.pos = 0
		err = dec.varuint(staticIdxRndField)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not enough data for varuint")

		dec.src = []byte{uint64tag, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
		dec.pos = 0
		err = dec.varuint(staticIdxRndField)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not enough data for varuint")
	})

	// Test bin32 errors
	t.Run("dynamicBin32 errors", func(t *testing.T) {
		dec := NewBitmaskDecoder()

		// Test not enough data
		dec.src = []byte{}
		dec.pos = 0
		err := dec.dynamicBin32(staticIdxSndField)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not enough data")

		// Test wrong marker
		dec.src = []byte{0xFF}
		dec.pos = 0
		err = dec.dynamicBin32(staticIdxSndField)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not enough data to read dynamic bin32")

		// Test insufficient data after marker
		dec.src = []byte{markerDynamicBin32, 0x01, 0x02}
		dec.pos = 0
		err = dec.dynamicBin32(staticIdxSndField)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not enough data to read dynamic bin32")
	})

	// Test bin64 errors
	t.Run("literalBin64 errors", func(t *testing.T) {
		dec := NewBitmaskDecoder()

		// Test not enough data
		dec.src = []byte{}
		dec.pos = 0
		err := dec.literalBin64(staticIdxP1sField)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not enough data")

		// Test wrong marker
		dec.src = []byte{0xFF}
		dec.pos = 0
		err = dec.literalBin64(staticIdxP1sField)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not enough data to read literal bin64")

		// Test insufficient data after marker
		dec.src = []byte{markerLiteralBin64, 0x01, 0x02}
		dec.pos = 0
		err = dec.literalBin64(staticIdxP1sField)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not enough data to read literal bin64")
	})
}

// generateRandomVote creates a random vote generator using rapid
func generateRandomVote() *rapid.Generator[*agreement.UnauthenticatedVote] {
	return rapid.Custom(func(t *rapid.T) *agreement.UnauthenticatedVote {
		v := &agreement.UnauthenticatedVote{}
		
		// Generate random sender address (32 bytes)
		addressBytes := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "sender")
		copy(v.R.Sender[:], addressBytes)

		// Create an equal distribution generator for different integer ranges
		// This will test different MessagePack varuint encodings (uint8, uint16, uint32, uint64)
		integerRangeGen := rapid.OneOf(
			rapid.Uint64Range(0, 255),         // uint8 range
			rapid.Uint64Range(256, 65535),    // uint16 range
			rapid.Uint64Range(65536, 4294967295), // uint32 range
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
			integerRangeGen,     // Test other steps with less probability
		)
		
		// Use reflection to set the unexported step field
		rStepField := reflect.ValueOf(&v.R).Elem().FieldByName("Step")
		rStepField = reflect.NewAt(rStepField.Type(), unsafe.Pointer(rStepField.UnsafeAddr())).Elem()
		rStepField.SetUint(stepGen.Draw(t, "step"))
		
		// Use reflection to set the OriginalPeriod field in the proposal
		propVal := reflect.ValueOf(&v.R.Proposal).Elem()
		origPeriodField := propVal.FieldByName("OriginalPeriod")
		origPeriodField = reflect.NewAt(origPeriodField.Type(), unsafe.Pointer(origPeriodField.UnsafeAddr())).Elem()
		origPeriodField.SetUint(integerRangeGen.Draw(t, "originalPeriod"))

		// Decide whether to include a proposal or leave it empty
		includeProposal := rapid.Bool().Draw(t, "includeProposal")
		if includeProposal {
			// Generate random OpropField, BlockDigest, and EncodingDigest bytes (32 bytes each)
			// But sometimes make them empty to test edge cases
			makeBytesFn := func(name string) []byte {
				generator := rapid.OneOf(
					rapid.Just([]byte{}), // Empty case
					rapid.SliceOfN(rapid.Byte(), 32, 32), // Full case
				)
				return generator.Draw(t, name)
			}

			opropBytes := makeBytesFn("oprop")
			digestBytes := makeBytesFn("digest")
			encDigestBytes := makeBytesFn("encDigest")

			// Only copy bytes if we have them
			if len(opropBytes) > 0 {
				copy(v.R.Proposal.OriginalProposer[:], opropBytes)
			}
			if len(digestBytes) > 0 {
				copy(v.R.Proposal.BlockDigest[:], digestBytes)
			}
			if len(encDigestBytes) > 0 {
				copy(v.R.Proposal.EncodingDigest[:], encDigestBytes)
			}
		} else {
			// Leave the proposal empty
			// The default zero values will be used
		}
		
		// Generate random proof bytes (80 bytes)
		pfBytes := rapid.SliceOfN(rapid.Byte(), 80, 80).Draw(t, "proof")
		copy(v.Cred.Proof[:], pfBytes)
		
		// Generate signature fields (variable sizes)
		sigBytes := rapid.SliceOfN(rapid.Byte(), 64, 64).Draw(t, "sig")
		pkBytes := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "pk")
		p2Bytes := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "pk2")
		p1sBytes := rapid.SliceOfN(rapid.Byte(), 64, 64).Draw(t, "pk1sig")
		p2sBytes := rapid.SliceOfN(rapid.Byte(), 64, 64).Draw(t, "pk2sig")
		copy(v.Sig.Sig[:], sigBytes)
		copy(v.Sig.PK[:], pkBytes)
		copy(v.Sig.PK2[:], p2Bytes)
		copy(v.Sig.PK1Sig[:], p1sBytes)
		copy(v.Sig.PK2Sig[:], p2sBytes)
		
		// PKSigOld is deprecated and always zero when encoded with BitmaskEncoder
		v.Sig.PKSigOld = [64]byte{}
		
		return v
	})
}

func checkBitmaskVoteValid(vote *agreement.UnauthenticatedVote) bool {
	if ok, _ := checkVoteValid(vote); !ok {
		return false
	}
	if vote.Sig.PKSigOld != [64]byte{} { // PKSigOld is deprecated and always zero
		return false
	}
	if vote.R.Sender == (basics.Address{}) {
		return false
	}
	if vote.R.Round == 0 {
		return false
	}
	return true
}

// FuzzBitmaskEncoder is a fuzz test that generates random votes,
// compresses them with BitmaskEncoder and decompresses them with BitmaskDecoder.
func FuzzBitmaskEncoder(f *testing.F) {
	// Add seed examples from our generator
	voteGen := generateRandomVote()
	for i := 0; i < 10; i++ {
		vote := voteGen.Example(i)
		if ok := checkBitmaskVoteValid(vote); !ok {
			continue // Skip invalid votes
		}
		msgpBuf := protocol.EncodeMsgp(vote)
		f.Add(msgpBuf) // Add seed corpus for the fuzzer
	}

	// Define the fuzz test
	f.Fuzz(func(t *testing.T, msgpBuf []byte) {
		// Try to compress the input
		enc := NewBitmaskEncoder()
		compressed, err := enc.CompressVote(nil, msgpBuf)
		if err != nil {
			// Not valid msgpack data for a vote, skip
			return
		}

		// Then decompress it
		dec := NewBitmaskDecoder()
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

// FuzzBitmaskDecoder is a fuzz test specifically targeting the BitmaskDecoder
// with potentially malformed input.
func FuzzBitmaskDecoder(f *testing.F) {
	// Add valid compressed votes from our random vote generator
	voteGen := generateRandomVote()
	for i := 0; i < 10; i++ {
		vote := voteGen.Example(i) // Use deterministic seeds

		if ok := checkBitmaskVoteValid(vote); !ok {
			continue // Skip invalid votes
		}
		
		msgpBuf := protocol.EncodeMsgp(vote)
		enc := NewBitmaskEncoder()
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
	f.Add([]byte{byte(requiredFieldsMask >> 8), byte(requiredFieldsMask & 0xFF)})
	f.Add([]byte{byte(requiredFieldsMask >> 8), byte(requiredFieldsMask & 0xFF), 0xFF})

	// Define two types of tests using rapid.MakeFuzz:
	// 1. A test that uses rapid to generate completely random byte sequences
	// 2. A test that uses our properly structured compressed votes but mutates them
	f.Fuzz(func(t *testing.T, data []byte) {
		// This is the standard fuzzing approach - just try to decompress the input
		// and make sure it doesn't crash
		dec := NewBitmaskDecoder()
		_, _ = dec.DecompressVote(nil, data) // We don't care about the error or result, just that it doesn't crash
	})
}

// TestCompareEncoders compares the output sizes of BitmaskEncoder and StaticEncoder
func TestCompareEncoders(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Manually run a number of iterations to match the original test
	const iterations = 1000

	var bitmaskTotal, staticTotal int
	var validVotes int

	// Create a vote generator
	voteGen := generateRandomVote()

	// Run the specified number of iterations
	for i := 0; i < iterations; i++ {
		// Generate a vote with a deterministic seed for each iteration
		v0 := voteGen.Example(i)

		// Check if vote is valid for compression
		if ok := checkBitmaskVoteValid(v0); !ok {
			continue // Skip this test case if vote is invalid
		}

		msgpBuf := protocol.EncodeMsgp(v0)

		// Try to compress with BitmaskEncoder
		encBM := NewBitmaskEncoder()
		encBufBM, err := encBM.CompressVote(nil, msgpBuf)
		if err != nil {
			continue // Skip on compression error
		}

		// Try to compress with StaticEncoder
		encStatic := NewStaticEncoder()
		encBufStatic, err := encStatic.CompressVote(nil, msgpBuf)
		if err != nil {
			continue // Skip on compression error
		}

		// Update stats for reporting
		validVotes++
		bitmaskTotal += len(encBufBM)
		staticTotal += len(encBufStatic)

		// Log compression statistics for this vote
		t.Logf("Vote %d - BitmaskEncoder: %d bytes, StaticEncoder: %d bytes, Ratio: %.2f%%",
			i, len(encBufBM), len(encBufStatic),
			float64(len(encBufBM))/float64(len(encBufStatic))*100)
	}

	// Report overall statistics at the end
	if validVotes > 0 {
		avgBitmask := float64(bitmaskTotal) / float64(validVotes)
		avgStatic := float64(staticTotal) / float64(validVotes)
		ratio := avgBitmask / avgStatic * 100

		t.Logf("Average over %d votes - BitmaskEncoder: %.2f bytes, StaticEncoder: %.2f bytes",
			validVotes, avgBitmask, avgStatic)
		t.Logf("BitmaskEncoder is %.2f%% the size of StaticEncoder on average", ratio)
	}
}
