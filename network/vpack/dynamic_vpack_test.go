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
	"slices"
	"testing"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/crypto"
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

	enc := &StatefulEncoder{}
	dec := &StatefulDecoder{}

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
	enc := &StatefulEncoder{}
	dec := &StatefulDecoder{}

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

	enc := &StatefulEncoder{}
	dec := &StatefulDecoder{}
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

func TestStatefulDecoderErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	pf := make([]byte, 80)
	crypto.RandBytes(pf)

	cases := []struct {
		name string
		want string
		buf  []byte
	}{
		{
			name: "input-short", want: "input shorter than header",
			buf: []byte{0x01},
		},
		{
			name: "pf-trunc", want: "truncated pf",
			buf: []byte{0x00, 0x00},
		},
		{
			name: "per-marker-trunc", want: "truncated rnd marker",
			buf: slices.Concat([]byte{bitPer, 0x00}, pf),
		},
		{
			name: "per-value-trunc", want: "truncated per",
			buf: slices.Concat([]byte{bitPer, 0x00}, pf, []byte{msgpUint32, 0x00}),
		},
		{
			name: "dig-trunc", want: "truncated digest",
			buf: slices.Concat([]byte{bitDig, 0x00}, pf, make([]byte, 10)),
		},
		{
			name: "encdig-trunc", want: "truncated encdig",
			buf: slices.Concat([]byte{bitEncDig, 0x00}, pf, make([]byte, 10)),
		},
		{
			name: "oper-marker-trunc", want: "truncated rnd marker",
			buf: slices.Concat([]byte{bitOper, 0x00}, pf, []byte{0x00}),
		},
		{
			name: "oper-marker-trunc-2", want: "truncated rnd marker",
			buf: slices.Concat([]byte{bitOper, 0x00}, pf),
		},
		{
			name: "oper-value-trunc", want: "truncated oper",
			buf: slices.Concat([]byte{bitOper, 0x00}, pf, []byte{msgpUint32, 0x01}),
		},
		{
			name: "oprop-trunc", want: "truncated oprop",
			buf: slices.Concat([]byte{bitOprop, 0x00}, pf, make([]byte, 10)),
		},
		{
			name: "bad-prop-ref", want: "bad proposal ref",
			buf: slices.Concat([]byte{0x00, byte(1 << hdr1PropShift)}, pf, []byte{0x00}),
		},
		{
			name: "snd-ref-trunc", want: "truncated ref id",
			buf: slices.Concat([]byte{0x00, byte(hdr1SndRef)}, pf, []byte{0x00}),
		},
		{
			name: "bad-sender-ref", want: "bad sender ref",
			buf: slices.Concat(
				[]byte{0x00, byte(hdr1SndRef | hdr1RndLiteral)},
				pf,
				[]byte{0x07},       // Round literal value (fixint 7)
				[]byte{0xFF, 0xFF}, // Invalid sender reference ID (255)
			),
		},
		{
			name: "snd-literal-trunc", want: "truncated sender",
			buf: slices.Concat([]byte{0x00, 0x00}, pf, []byte{0x00}),
		},
		{
			name: "step-marker-trunc", want: "truncated rnd marker",
			buf: slices.Concat([]byte{bitStep, 0x00}, pf, []byte{0x00}, make([]byte, 32)),
		},
		{
			name: "step-value-trunc", want: "truncated step",
			buf: slices.Concat([]byte{bitStep, 0x00}, pf, []byte{0x00}, make([]byte, 32), []byte{msgpUint32}),
		},
		{
			name: "pk-ref-trunc", want: "truncated ref id",
			buf: slices.Concat([]byte{0x00, byte(hdr1PkRef)}, pf, []byte{0x00}, make([]byte, 32)),
		},
		{
			name: "bad-pk-ref", want: "bad pk ref",
			buf: slices.Concat(
				[]byte{0x00, byte(hdr1RndLiteral | hdr1PkRef)},
				pf,
				[]byte{0x08},       // Round literal value (fixint 8)
				make([]byte, 32),   // Sender (32 bytes)
				[]byte{0xFF, 0xFF}, // Invalid pk reference ID (255)
			),
		},
		{
			name: "pk-literal-trunc", want: "truncated pk bundle",
			buf: slices.Concat([]byte{0x00, 0x00}, pf, []byte{0x00}, make([]byte, 32)),
		},
		{
			name: "pk2-ref-trunc", want: "truncated ref id",
			buf: slices.Concat([]byte{0x00, byte(hdr1Pk2Ref)}, pf, []byte{0x00}, make([]byte, 32), make([]byte, 96)),
		},
		{
			name: "bad-pk2-ref", want: "bad pk2 ref",
			buf: slices.Concat(
				[]byte{0x00, byte(hdr1RndLiteral | hdr1Pk2Ref)},
				pf,
				[]byte{0x09},       // Round literal value (fixint 9)
				make([]byte, 32),   // Sender (32 bytes)
				make([]byte, 96),   // pk (32 bytes) + p1s (64 bytes)
				[]byte{0xFF, 0xFF}, // Invalid pk2 reference ID (255)
			),
		},
		{
			name: "pk2-literal-trunc", want: "truncated pk2 bundle",
			buf: slices.Concat([]byte{0x00, 0x00}, pf, []byte{0x00}, make([]byte, 32), make([]byte, 96)),
		},
		{
			name: "rnd-literal-trunc", want: "truncated rnd",
			buf: slices.Concat(
				[]byte{0x00, byte(hdr1RndLiteral)},
				pf,
				[]byte{0xCE}, // high value for round (CE requires multiple bytes, but we only provide one)
			),
		},
		{
			name: "sig-s-trunc", want: "truncated sig.s",
			buf: slices.Concat([]byte{0x00, 0x00}, pf, []byte{0x00}, make([]byte, 32), make([]byte, 96), make([]byte, 96)),
		},
		{
			name: "length-mismatch", want: "length mismatch",
			buf: slices.Concat([]byte{0x00, 0x00}, pf, []byte{0x00}, make([]byte, 32), make([]byte, 96), make([]byte, 96), make([]byte, 64), []byte{0x01}),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dec := &StatefulDecoder{}
			_, err := dec.Decompress(nil, c.buf)
			require.ErrorContains(t, err, c.want)
		})
	}
}

// TestStatefulEncoderErrors verifies that encoder detects obvious malformed inputs.
func TestStatefulEncoderErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	enc := &StatefulEncoder{}

	// 1) Source too short
	_, err := enc.Compress(nil, []byte{0x00})
	require.ErrorContains(t, err, "src too short")

	// 2) Length mismatch: valid stateless buffer with an extra byte at the end
	vote := generateRandomVote().Example(0)
	vote.Sig.PKSigOld = [64]byte{}

	// Set deterministic round so delta tests are predictable below
	vote.R.Round = basics.Round(10)

	stEnc := NewStatelessEncoder()
	statelessBuf, err := stEnc.CompressVote(nil, protocol.EncodeMsgp(vote))
	require.NoError(t, err)

	badBuf := append(statelessBuf, 0xFF) // append spurious byte
	_, err = enc.Compress(nil, badBuf)
	require.ErrorContains(t, err, "length mismatch")

	// 3) Buffer overflow behavior test
	// First get a valid compressed vote with nil dst to determine needed size
	compressedBuf, err := enc.Compress(nil, statelessBuf)
	require.NoError(t, err)
	// Verify we got a result with some length
	require.Greater(t, len(compressedBuf), 0)
}
