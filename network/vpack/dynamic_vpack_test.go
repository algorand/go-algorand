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
)

// TestStatefulEncoderDecoderSequence verifies that a StatefulEncoder/StatefulDecoder
// pair can be reused across multiple votes while preserving correctness.
func TestStatefulEncoderDecoderSequence(t *testing.T) {
	partitiontest.PartitionTest(t)

	const numVotes = 30

	// Stateless encoder/decoder used as front/back before Stateful layer
	stEnc := NewStatelessEncoder()
	stDec := NewStatelessDecoder()

	enc, err := NewStatefulEncoder(1024)
	require.NoError(t, err)
	dec, err := NewStatefulDecoder(1024)
	require.NoError(t, err)

	voteGen := generateRandomVote()

	for i := 0; i < numVotes; i++ {
		v0 := voteGen.Example(i)

		// Ensure PKSigOld is zero to satisfy encoder expectations
		v0.Sig.PKSigOld = [64]byte{}

		// Encode to msgpack and bounds-check size
		msgpackBuf := protocol.EncodeMsgp(v0)
		require.LessOrEqual(t, len(msgpackBuf), MaxMsgpackVoteSize)

		// First layer: stateless compression
		statelessBuf, err := stEnc.CompressVote(nil, msgpackBuf)
		require.NoError(t, err)

		// Second layer: stateful compression
		encBuf, err := enc.Compress(nil, statelessBuf)
		require.NoError(t, err, "Vote %d failed to compress", i)
		// size sanity: compressed should not exceed stateless size
		require.LessOrEqual(t, len(encBuf), len(statelessBuf))

		// Reverse: stateful decompress → stateless
		statelessOut, err := dec.Decompress(nil, encBuf)
		require.NoError(t, err, "Vote %d failed to decompress", i)

		// Reverse: stateless decompress → msgpack
		msgpackOut, err := stDec.DecompressVote(nil, statelessOut)
		require.NoError(t, err)

		// Decode and compare objects for round-trip integrity
		var v1 agreement.UnauthenticatedVote
		err = protocol.Decode(msgpackOut, &v1)
		require.NoError(t, err)
		require.Equal(t, *v0, v1, "Vote %d round-trip mismatch", i)
	}
}

// TestStatefulEncoderReuse mirrors TestEncoderReuse in vpack_test.go but targets
// StatefulEncoder to guarantee that buffer reuse does not corrupt internal state.
func TestStatefulEncoderReuse(t *testing.T) {
	partitiontest.PartitionTest(t)

	const numVotes = 10
	voteGen := generateRandomVote()
	msgpackBufs := make([][]byte, 0, numVotes)

	// Generate and encode votes
	for i := 0; i < numVotes; i++ {
		buf := protocol.EncodeMsgp(voteGen.Example(i))
		require.LessOrEqual(t, len(buf), MaxMsgpackVoteSize)
		msgpackBufs = append(msgpackBufs, buf)
	}

	stEnc := NewStatelessEncoder()
	stDec := NewStatelessDecoder()
	enc, err := NewStatefulEncoder(1024)
	require.NoError(t, err)
	dec, err := NewStatefulDecoder(1024)
	require.NoError(t, err)

	// 1) Compress into new buffers each time
	var compressed [][]byte
	for i, msgp := range msgpackBufs {
		stateless, err := stEnc.CompressVote(nil, msgp)
		require.NoError(t, err)
		c, err := enc.Compress(nil, stateless)
		require.NoError(t, err, "vote %d compress failed", i)
		compressed = append(compressed, append([]byte(nil), c...))
	}

	for i, c := range compressed {
		statelessOut, err := dec.Decompress(nil, c)
		require.NoError(t, err, "vote %d decompress failed", i)
		msgpackOut, err := stDec.DecompressVote(nil, statelessOut)
		require.NoError(t, err)
		var v agreement.UnauthenticatedVote
		require.NoError(t, protocol.Decode(msgpackOut, &v))
		var orig agreement.UnauthenticatedVote
		require.NoError(t, protocol.Decode(msgpackBufs[i], &orig))
		require.Equal(t, orig, v)
	}

	// 2) Reuse a single destination slice
	compressed = compressed[:0]
	reused := make([]byte, 0, 4096)
	for i, msgp := range msgpackBufs {
		st, err := stEnc.CompressVote(nil, msgp)
		require.NoError(t, err)
		c, err := enc.Compress(reused[:0], st)
		require.NoError(t, err, "vote %d compress failed (reuse)", i)
		compressed = append(compressed, append([]byte(nil), c...))
	}
	for i, c := range compressed {
		stOut, err := dec.Decompress(nil, c)
		require.NoError(t, err, "vote %d decompress failed (reuse)", i)
		mpOut, err := stDec.DecompressVote(nil, stOut)
		require.NoError(t, err)
		var v agreement.UnauthenticatedVote
		require.NoError(t, protocol.Decode(mpOut, &v))
		var orig agreement.UnauthenticatedVote
		require.NoError(t, protocol.Decode(msgpackBufs[i], &orig))
		require.Equal(t, orig, v)
	}

	// 3) Reuse a slice that grows over iterations
	compressed = compressed[:0]
	growing := make([]byte, 0, 8)
	for i, msgp := range msgpackBufs {
		st, err := stEnc.CompressVote(nil, msgp)
		require.NoError(t, err)
		c, err := enc.Compress(growing[:0], st)
		require.NoError(t, err, "vote %d compress failed (growing)", i)
		compressed = append(compressed, append([]byte(nil), c...))
		growing = c
	}
	for i, c := range compressed {
		stOut, err := dec.Decompress(nil, c)
		require.NoError(t, err, "vote %d decompress failed (growing)", i)
		mpOut, err := stDec.DecompressVote(nil, stOut)
		require.NoError(t, err)
		var v agreement.UnauthenticatedVote
		require.NoError(t, protocol.Decode(mpOut, &v))
		var orig agreement.UnauthenticatedVote
		require.NoError(t, protocol.Decode(msgpackBufs[i], &orig))
		require.Equal(t, orig, v)
	}
}

func TestStatefulRndDelta(t *testing.T) {
	partitiontest.PartitionTest(t)

	rounds := []uint64{10, 10, 11, 10, 11, 11, 20}
	expected := []byte{hdr1RndLiteral, hdr1RndDeltaSame, hdr1RndDeltaPlus1, hdr1RndDeltaMinus1, hdr1RndDeltaPlus1, hdr1RndDeltaSame, hdr1RndLiteral}

	enc, err := NewStatefulEncoder(1024)
	require.NoError(t, err)
	dec, err := NewStatefulDecoder(1024)
	require.NoError(t, err)
	stEnc := NewStatelessEncoder()
	stDec := NewStatelessDecoder()
	voteGen := generateRandomVote()

	// Test both encoding and decoding in the same loop
	for i, rnd := range rounds {
		v := voteGen.Example(i)
		v.R.Round = basics.Round(rnd)

		msgp := protocol.EncodeMsgp(v)
		statelessBuf, err := stEnc.CompressVote(nil, msgp)
		require.NoError(t, err)

		// Compress with stateful encoder
		compressedBuf, err := enc.Compress(nil, statelessBuf)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(compressedBuf), 2)

		// Verify the round delta encoding in the header matches expectations
		got := compressedBuf[1] & hdr1RndMask
		require.Equal(t, expected[i], got)

		// Decompress with the stateful decoder
		decompressedBuf, err := dec.Decompress(nil, compressedBuf)
		require.NoError(t, err)
		require.Equal(t, statelessBuf, decompressedBuf)

		// Decompress with the stateless decoder
		decompressedStatelessBuf, err := stDec.DecompressVote(nil, statelessBuf)
		require.NoError(t, err)
		require.Equal(t, msgp, decompressedStatelessBuf)

	}
}

func TestStatefulEncodeRef(t *testing.T) {
	// ensure lruTableReferenceID can fit in uint16 encoding used in appendDynamicRef
	partitiontest.PartitionTest(t)
	var id lruTableReferenceID
	require.Equal(t, uintptr(2), unsafe.Sizeof(id), "lruTableReferenceID should occupy 2 bytes (uint16)")
	require.Equal(t, reflect.Uint16, reflect.TypeFor[lruTableReferenceID]().Kind(), "lruTableReferenceID underlying kind should be uint16")
	// Maximum table size we support is 2048 (1024 buckets, 2 slots each)
	// Last bucket would be 1023, last slot would be 1, so maxID = (1023<<1)|1 = 2047
	maxTableSize := uint32(2048)
	maxBucketIndex := (maxTableSize / 2) - 1
	maxID := lruTableReferenceID((maxBucketIndex << 1) | 1) // last bucket, last slot
	require.LessOrEqual(t, uint32(maxID), uint32(math.MaxUint16))
}

func TestStatefulDecoderErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	fullVote := slices.Concat(
		// Header with all hdr0 optional bits set, but no hdr1 bits
		[]byte{byte(bitPer | bitDig | bitStep | bitEncDig | bitOper | bitOprop), 0x00},
		make([]byte, pfSize),           // Credential prefix (80 bytes)
		[]byte{msgpUint32},             // Per field marker
		[]byte{0x01, 0x02, 0x03, 0x04}, // Per value (4 bytes)
		make([]byte, digestSize),       // Digest (32 bytes)
		make([]byte, digestSize),       // EncDig (32 bytes)
		[]byte{msgpUint32},             // Oper field marker
		[]byte{0x01, 0x02, 0x03, 0x04}, // Oper value (4 bytes)
		make([]byte, digestSize),       // Oprop (32 bytes)
		[]byte{msgpUint32},             // Round marker (msgpack marker)
		[]byte{0x01, 0x02, 0x03, 0x04}, // Round value (4 bytes)
		make([]byte, digestSize),       // Sender (32 bytes)
		[]byte{msgpUint32},             // Step field marker
		[]byte{0x01, 0x02, 0x03, 0x04}, // Step value (4 bytes)
		make([]byte, pkSize+sigSize),   // pk + p1s (96 bytes: 32 for pk, 64 for p1s)
		make([]byte, pkSize+sigSize),   // pk2 + p2s (96 bytes: 32 for pk2, 64 for p2s)
		make([]byte, sigSize),          // sig.s (64 bytes)
	)

	refVote := slices.Concat(
		// Header with all hdr1 reference bits set, but no hdr0 bits
		[]byte{0x00, byte(hdr1SndRef | hdr1PkRef | hdr1Pk2Ref | hdr1RndLiteral)},
		make([]byte, pfSize),  // Credential prefix
		[]byte{0x07},          // Round literal (fixint 7)
		[]byte{0x01, 0x02},    // Sender ref ID
		[]byte{0x03, 0x04},    // pk ref ID
		[]byte{0x05, 0x06},    // pk2 ref ID
		make([]byte, sigSize), // sig.s
	)

	for _, tc := range []struct {
		want string
		buf  []byte
	}{
		// Truncation errors
		{"input shorter than header", fullVote[:1]},
		{"truncated pf", fullVote[:2]},
		{"truncated per marker", fullVote[:82]},
		{"truncated per", fullVote[:83]},
		{"truncated digest", fullVote[:87]},
		{"truncated encdig", fullVote[:119]},
		{"truncated oper marker", fullVote[:151]},
		{"truncated oper", fullVote[:152]},
		{"truncated oprop", fullVote[:160]},
		{"truncated rnd marker", fullVote[:188]},
		{"truncated rnd", fullVote[:189]},
		{"truncated sender", fullVote[:193]},
		{"truncated step marker", fullVote[:225]},
		{"truncated step", fullVote[:226]},
		{"truncated pk bundle", fullVote[:234]},
		{"truncated pk2 bundle", fullVote[:334]},
		{"truncated sig.s", fullVote[:422]},
		// Reference ID decoding errors
		{"truncated snd ref", refVote[:84]},
		{"truncated pk ref", refVote[:86]},
		{"truncated pk2 ref", refVote[:88]},
		{"bad sender ref", slices.Concat(refVote[:83], []byte{0xFF, 0xFF})},
		{"bad pk ref", slices.Concat(refVote[:85], []byte{0xFF, 0xFF})},
		{"bad pk2 ref", slices.Concat(refVote[:87], []byte{0xFF, 0xFF})},
		{"bad proposal ref", slices.Concat(
			[]byte{0x00, byte(3 << hdr1PropShift)}, // proposal reference ID 3 (invalid, StatefulDecoder is empty)
			make([]byte, pfSize),                   // pf
			[]byte{0x01},                           // round (fixint 1)
		)},
		{"length mismatch: expected", slices.Concat(fullVote, []byte{0xFF, 0xFF})},
	} {
		t.Run(tc.want, func(t *testing.T) {
			dec, err := NewStatefulDecoder(1024)
			require.NoError(t, err)
			_, err = dec.Decompress(nil, tc.buf)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestStatefulEncoderErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	enc, err := NewStatefulEncoder(1024)
	require.NoError(t, err)

	// Source too short error
	_, err = enc.Compress(nil, []byte{0x00})
	require.ErrorContains(t, err, "src too short")

	// Length mismatch error
	vote := generateRandomVote().Example(0)
	stEnc := NewStatelessEncoder()
	statelessBuf, err := stEnc.CompressVote(nil, protocol.EncodeMsgp(vote))
	require.NoError(t, err)

	badBuf := append(statelessBuf, 0xFF) // append spurious byte
	_, err = enc.Compress(nil, badBuf)
	require.ErrorContains(t, err, "length mismatch")

	// Test nil dst
	compressedBuf, err := enc.Compress(nil, statelessBuf)
	require.NoError(t, err)
	require.Greater(t, len(compressedBuf), 0)

	// Test bounds checking errors
	testCases := []struct {
		name string
		buf  []byte
		want string
	}{
		{
			name: "truncated pf",
			buf:  []byte{0x00, 0x00}, // header only, no pf
			want: "truncated pf",
		},
		{
			name: "truncated r.per marker",
			buf:  append([]byte{byte(bitPer), 0x00}, make([]byte, pfSize)...), // header + pf, no per marker
			want: "truncated r.per marker",
		},
		{
			name: "truncated r.per",
			buf:  append([]byte{byte(bitPer), 0x00}, append(make([]byte, pfSize), msgpUint32)...), // header + pf + per marker, no per data
			want: "truncated r.per",
		},
		{
			name: "truncated dig",
			buf:  append([]byte{byte(bitDig), 0x00}, make([]byte, pfSize)...), // header + pf, no dig
			want: "truncated dig",
		},
		{
			name: "truncated encdig",
			// When bitDig is not set but bitEncDig is set, we expect encdig directly after pf
			buf:  append([]byte{byte(bitEncDig), 0x00}, make([]byte, pfSize)...), // header + pf, no encdig
			want: "truncated encdig",
		},
		{
			name: "truncated oper marker",
			buf:  append([]byte{byte(bitOper), 0x00}, make([]byte, pfSize)...), // header + pf, no oper marker
			want: "truncated oper marker",
		},
		{
			name: "truncated oper",
			buf:  append([]byte{byte(bitOper), 0x00}, append(make([]byte, pfSize), msgpUint32)...), // header + pf + oper marker, no oper data
			want: "truncated oper",
		},
		{
			name: "truncated oprop",
			buf:  append([]byte{byte(bitOprop), 0x00}, make([]byte, pfSize)...), // header + pf, no oprop
			want: "truncated oprop",
		},
		{
			name: "truncated rnd marker",
			buf:  append([]byte{0x00, 0x00}, make([]byte, pfSize)...), // header + pf, no rnd marker
			want: "truncated rnd marker",
		},
		{
			name: "truncated rnd",
			buf:  append([]byte{0x00, 0x00}, append(make([]byte, pfSize), msgpUint32)...), // header + pf + rnd marker, no rnd data
			want: "truncated rnd",
		},
		{
			name: "truncated sender",
			buf:  append([]byte{0x00, 0x00}, append(make([]byte, pfSize), 0x07)...), // header + pf + rnd (fixint), no sender
			want: "truncated sender",
		},
		{
			name: "truncated step marker",
			buf:  append([]byte{byte(bitStep), 0x00}, append(make([]byte, pfSize), append([]byte{0x07}, make([]byte, digestSize)...)...)...), // header + pf + rnd + sender, no step marker
			want: "truncated step marker",
		},
		{
			name: "truncated step",
			buf:  append([]byte{byte(bitStep), 0x00}, append(make([]byte, pfSize), append([]byte{0x07}, append(make([]byte, digestSize), msgpUint32)...)...)...), // header + pf + rnd + sender + step marker, no step data
			want: "truncated step",
		},
		{
			name: "truncated pk bundle",
			buf:  append([]byte{0x00, 0x00}, append(make([]byte, pfSize), append([]byte{0x07}, make([]byte, digestSize)...)...)...), // header + pf + rnd + sender, no pk bundle
			want: "truncated pk bundle",
		},
		{
			name: "truncated pk2 bundle",
			buf:  append([]byte{0x00, 0x00}, append(make([]byte, pfSize), append([]byte{0x07}, append(make([]byte, digestSize), make([]byte, pkSize+sigSize)...)...)...)...), // header + pf + rnd + sender + pk bundle, no pk2 bundle
			want: "truncated pk2 bundle",
		},
		{
			name: "truncated sig.s",
			buf:  append([]byte{0x00, 0x00}, append(make([]byte, pfSize), append([]byte{0x07}, append(make([]byte, digestSize), append(make([]byte, pkSize+sigSize), make([]byte, pkSize+sigSize)...)...)...)...)...), // everything except sig.s
			want: "truncated sig.s",
		},
		{
			name: "invalid r.per marker",
			buf:  append([]byte{byte(bitPer), 0x00}, append(make([]byte, pfSize), 0xFF)...), // header + pf + invalid per marker
			want: "invalid r.per marker",
		},
		{
			name: "invalid oper marker",
			buf:  append([]byte{byte(bitOper), 0x00}, append(make([]byte, pfSize), 0xFF)...), // header + pf + invalid oper marker
			want: "invalid oper marker",
		},
		{
			name: "invalid rnd marker",
			buf:  append([]byte{0x00, 0x00}, append(make([]byte, pfSize), 0xFF)...), // header + pf + invalid rnd marker
			want: "invalid rnd marker",
		},
		{
			name: "invalid step marker",
			buf:  append([]byte{byte(bitStep), 0x00}, append(make([]byte, pfSize), append([]byte{0x07}, append(make([]byte, digestSize), 0xFF)...)...)...), // header + pf + rnd + sender + invalid step marker
			want: "invalid step marker",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := enc.Compress(nil, tc.buf)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestStatefulEncoderHeaderBits(t *testing.T) {
	partitiontest.PartitionTest(t)
	// Ensure that the three bits allocated in hdr1 for proposal references
	// matches the size of the proposal window.
	got := int(hdr1PropMask >> hdr1PropShift)
	require.Equal(t, proposalWindowSize, got,
		"hdr1PropMask (%d) and proposalWindowSize (%d) must stay in sync", got, proposalWindowSize)

	// Ensure that the header encoding of hdr1RndLiteral is zero
	require.Equal(t, hdr1RndLiteral, 0)
}
