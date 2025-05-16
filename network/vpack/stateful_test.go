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

//go:build !race

package vpack

import (
	"testing"

	"github.com/algorand/go-algorand/agreement"
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
