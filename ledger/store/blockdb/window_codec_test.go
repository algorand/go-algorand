// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package blockdb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/DataDog/zstd"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// makePayload returns a deterministic-but-varied byte slice that has both a
// random prefix (incompressible) and a repeating tail (highly compressible
// across rows), mimicking the structure of a real block where the body
// changes per round but the header has many repeated fields.
func makePayload(round int, size int) []byte {
	out := make([]byte, size)
	if size >= 64 {
		_, _ = rand.Read(out[:64])
	}
	if size > 0 {
		out[0] = 0x80 | byte(round%16)
	}
	for i := 64; i < size; i++ {
		out[i] = byte('A' + (i+round)%16)
	}
	return out
}

func TestWindowCodec_Disabled(t *testing.T) {
	partitiontest.PartitionTest(t)
	// With BlockDBCompressionWindow=0 the encoder is a no-op pass-through:
	// the chunk must be byte-identical to the payload so on-disk rows
	// remain readable by older binaries and by tools that expect raw msgp.
	enc := NewEncoder(WindowCodec{N: 0})
	for r := 100; r < 110; r++ {
		p := makePayload(r, 200)
		chunk, anchor, err := enc.EncodeRow(basics.Round(r), p)
		require.NoError(t, err)
		require.Equal(t, p, chunk)
		require.Equal(t, basics.Round(0), anchor)
	}
}

func TestWindowCodec_Roundtrip(t *testing.T) {
	partitiontest.PartitionTest(t)

	const N = 8
	const size = 4 * 1024
	enc := NewEncoder(WindowCodec{N: N, Level: 11})
	startRound := basics.Round(N * 1000)
	const total = N * 3

	payloads := make([][]byte, total)
	chunks := make([][]byte, total)
	for i := range total {
		r := startRound + basics.Round(i)
		payloads[i] = makePayload(int(r), size)
		c, anchor, err := enc.EncodeRow(r, payloads[i])
		require.NoError(t, err)
		// Every Nth row should open a fresh frame; the rest are
		// continuations of the prior anchor.
		expectedAnchor := basics.Round((int(r) / N) * N)
		require.Equal(t, expectedAnchor, anchor, "row %d", i)
		chunks[i] = c
	}

	// Each row should decode to the original payload when given the slice
	// of chunks from its window's anchor through that row.
	for i := range total {
		windowStart := (i / N) * N
		got, err := decodeWindow(chunks[windowStart : i+1])
		require.NoError(t, err, "row %d", i)
		require.Equal(t, payloads[i], got, "row %d", i)
	}
}

func TestWindowCodec_RestartMidWindow(t *testing.T) {
	partitiontest.PartitionTest(t)

	const N = 8
	const size = 2 * 1024
	enc := NewEncoder(WindowCodec{N: N, Level: 11})

	// Write rounds [0..4] with one encoder, then "crash" by constructing a
	// fresh encoder. The next round we write (5) is mid-window; the new
	// encoder must start a fresh frame at 5 and the decoder must be able to
	// recover round 5 by treating 5 as its own anchor.
	chunks := make([][]byte, 0, 10)
	payloads := make([][]byte, 0, 10)
	anchors := make([]basics.Round, 0, 10)
	for r := 0; r < 5; r++ {
		p := makePayload(r, size)
		c, anchor, err := enc.EncodeRow(basics.Round(r), p)
		require.NoError(t, err)
		chunks = append(chunks, c)
		payloads = append(payloads, p)
		anchors = append(anchors, anchor)
	}

	enc2 := NewEncoder(WindowCodec{N: N, Level: 11})
	for r := 5; r < 10; r++ {
		p := makePayload(r, size)
		c, anchor, err := enc2.EncodeRow(basics.Round(r), p)
		require.NoError(t, err)
		chunks = append(chunks, c)
		payloads = append(payloads, p)
		anchors = append(anchors, anchor)
	}

	// Rows [0..4] form one window with anchor at 0.
	for r := 0; r < 5; r++ {
		require.Equal(t, basics.Round(0), anchors[r], "row %d", r)
		got, err := decodeWindow(chunks[0 : r+1])
		require.NoError(t, err, "row %d", r)
		require.Equal(t, payloads[r], got, "row %d", r)
	}

	// Rows [5..7] form a window that started at 5 (a forced anchor due to
	// the restart). Each row's anchor must report 5, not 0.
	for r := 5; r < 8; r++ {
		require.Equal(t, basics.Round(5), anchors[r], "row %d", r)
		got, err := decodeWindow(chunks[5 : r+1])
		require.NoError(t, err, "row %d", r)
		require.Equal(t, payloads[r], got, "row %d", r)
	}

	// Round 8 starts a regular new window aligned at the configured boundary.
	require.Equal(t, basics.Round(8), anchors[8])
	got, err := decodeWindow(chunks[8:9])
	require.NoError(t, err)
	require.Equal(t, payloads[8], got)
}

func TestWindowCodec_OutOfOrder(t *testing.T) {
	partitiontest.PartitionTest(t)
	enc := NewEncoder(WindowCodec{N: 8, Level: 1})
	_, _, err := enc.EncodeRow(100, makePayload(100, 64))
	require.NoError(t, err)
	_, _, err = enc.EncodeRow(102, makePayload(102, 64))
	require.Error(t, err)
}

// TestMaxWindowConstantsInSync guards against the documented duplication
// between MaxCompressionWindow here and config.MaxBlockDBCompressionWindow
// (the latter exists so the startup validator does not have to import this
// package). If they drift, the ledger writer will silently clamp larger settings
// while config validation lets them through.
func TestMaxWindowConstantsInSync(t *testing.T) {
	partitiontest.PartitionTest(t)
	require.Equal(t, uint64(MaxCompressionWindow), uint64(config.MaxBlockDBCompressionWindow))
}

// TestNewBlockWriterNormalizesWindow guards the retention invariant: every
// codec N must divide MaxCompressionWindow so the round-down by 32 in
// RoundDownRetention always lands on an anchor. NewBlockWriter clamps any
// out-of-set input down to the next valid value so a stray caller (a test,
// a misconfigured tool) cannot produce a DB with a stranded anchor.
func TestNewBlockWriterNormalizesWindow(t *testing.T) {
	partitiontest.PartitionTest(t)
	cases := []struct {
		in   uint64
		want int
	}{
		{0, 0}, {1, 1}, {2, 2}, {4, 4}, {8, 8}, {16, 16}, {32, 32},
		{3, 2}, {7, 4}, {10, 8}, {17, 16}, {31, 16},
		{33, 32}, {1 << 20, 32}, {^uint64(0), 32},
	}
	for _, tc := range cases {
		w := NewBlockWriter(tc.in)
		require.Equal(t, tc.want, w.Codec().N, "window %d", tc.in)
	}
}

func TestRoundDownRetention(t *testing.T) {
	partitiontest.PartitionTest(t)

	tests := []struct {
		in   basics.Round
		want basics.Round
	}{
		{0, 0},
		{1, 0},
		{31, 0},
		{32, 32},
		{33, 32},
		{63, 32},
		{64, 64},
		{basics.Round(1 << 40), basics.Round(1 << 40)},
		{basics.Round(1<<40 + 31), basics.Round(1 << 40)},
	}
	for _, tc := range tests {
		require.Equal(t, tc.want, RoundDownRetention(tc.in), "round %d", tc.in)
	}
}

// TestEncoderPair_CloseLeavesReusable ensures Close leaves the encoders in a
// fresh state rather than just freeing the writer pointer.
func TestEncoderPair_CloseLeavesReusable(t *testing.T) {
	partitiontest.PartitionTest(t)

	ep := NewEncoderPair(WindowCodec{N: 4, Level: 1})
	for r := 0; r < 4; r++ {
		_, _, err := ep.Blk.EncodeRow(basics.Round(r), makePayload(r, 256))
		require.NoError(t, err)
		_, _, err = ep.Cert.EncodeRow(basics.Round(r), makePayload(r+100, 256))
		require.NoError(t, err)
	}

	ep.Close()

	// After Close the next EncodeRow should succeed and produce a fresh
	// frame anchored at whatever round comes next, even one that is not a
	// multiple of N. If Close left started=true / a stale writer ptr, the
	// internal "skip writer init" branch would crash on the nil writer.
	// Both rounds belong to the post-Close frame, anchored at 4.
	for _, r := range []basics.Round{4, 5} {
		_, anchor, err := ep.Blk.EncodeRow(r, makePayload(int(r), 256))
		require.NoError(t, err)
		require.Equal(t, basics.Round(4), anchor)
	}
	ep.Close()
}

// TestWindowCodec_RejectsHugeUvarint ensures that a corrupt or tampered
// row whose decoded uvarint length exceeds maxDecodedPayloadBytes is
// rejected with an error rather than triggering an out-of-memory panic.
func TestWindowCodec_RejectsHugeUvarint(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Construct a single-chunk window whose decompressed contents start
	// with a uvarint length well above maxDecodedPayloadBytes.
	var huge bytes.Buffer
	w := zstd.NewWriterLevel(&huge, 1)
	var lb [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lb[:], uint64(maxDecodedPayloadBytes()+1))
	_, err := w.Write(lb[:n])
	require.NoError(t, err)
	require.NoError(t, w.Close())

	_, err = decodeWindow([][]byte{huge.Bytes()})
	require.ErrorContains(t, err, "exceeds maxDecodedPayloadBytes")
}
