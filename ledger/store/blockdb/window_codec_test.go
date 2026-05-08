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
	// With BlockDBCompressionWindow=1 the codec is a no-op pass-through:
	// the chunk must be byte-identical to the payload so on-disk rows
	// remain readable by older binaries and by tools that expect raw msgp.
	enc := NewEncoder(WindowCodec{N: 1})
	for r := 100; r < 110; r++ {
		p := makePayload(r, 200)
		chunk, err := enc.EncodeRow(basics.Round(r), p)
		require.NoError(t, err)
		require.Equal(t, p, chunk)
		// DecodeRaw still strips a legacy formatRaw prefix if it ever
		// shows up in old DBs, but for fresh disabled-codec rows the
		// chunk has no prefix at all.
		require.Equal(t, p, DecodeRaw(chunk))
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
		c, err := enc.EncodeRow(r, payloads[i])
		require.NoError(t, err)
		// Every Nth row should be a fresh frame anchor; the rest are
		// continuations of the prior anchor.
		expectedPrefix := formatWindowedContinuation
		if i%N == 0 {
			expectedPrefix = formatWindowedAnchor
		}
		require.Equal(t, expectedPrefix, c[0], "row %d", i)
		chunks[i] = c
	}

	// Each row should decode to the original payload when given the slice
	// of chunks from its window's anchor through that row.
	for i := range total {
		windowStart := (i / N) * N
		got, err := DecodeWindow(chunks[windowStart : i+1])
		require.NoError(t, err, "row %d", i)
		require.Equal(t, payloads[i], got, "row %d", i)
	}

	// Anchors are exactly the rows at multiples of N within a window slice.
	require.Equal(t, 0, FindAnchorOffset(chunks[0:1]))
	require.Equal(t, 0, FindAnchorOffset(chunks[0:N]))
	require.Equal(t, 0, FindAnchorOffset(chunks[N:2*N]))
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
	for r := 0; r < 5; r++ {
		p := makePayload(r, size)
		c, err := enc.EncodeRow(basics.Round(r), p)
		require.NoError(t, err)
		chunks = append(chunks, c)
		payloads = append(payloads, p)
	}

	enc2 := NewEncoder(WindowCodec{N: N, Level: 11})
	for r := 5; r < 10; r++ {
		p := makePayload(r, size)
		c, err := enc2.EncodeRow(basics.Round(r), p)
		require.NoError(t, err)
		chunks = append(chunks, c)
		payloads = append(payloads, p)
	}

	// Helper that mimics what blockGetEncoded does at read time: slice the
	// nominal window down to the latest anchor and feed the result to
	// DecodeWindow.
	decodeUpTo := func(r int) ([]byte, error) {
		win := chunks[0 : r+1]
		idx := FindAnchorOffset(win)
		require.GreaterOrEqual(t, idx, 0)
		return DecodeWindow(win[idx:])
	}

	// Rows [0..4] form one window with anchor at 0.
	for r := range 5 {
		got, err := decodeUpTo(r)
		require.NoError(t, err, "row %d", r)
		require.Equal(t, payloads[r], got, "row %d", r)
	}

	// Rows [5..7] form a window that started at 5 (a forced anchor due to
	// the restart). FindAnchorOffset must pick 5, not 0.
	for r := 5; r < 8; r++ {
		got, err := decodeUpTo(r)
		require.NoError(t, err, "row %d", r)
		require.Equal(t, payloads[r], got, "row %d", r)
	}

	// Round 8 starts a regular new window aligned at the configured boundary.
	got, err := DecodeWindow(chunks[8:9])
	require.NoError(t, err)
	require.Equal(t, payloads[8], got)
}

func TestWindowCodec_OutOfOrder(t *testing.T) {
	partitiontest.PartitionTest(t)
	enc := NewEncoder(WindowCodec{N: 8, Level: 1})
	_, err := enc.EncodeRow(100, makePayload(100, 64))
	require.NoError(t, err)
	_, err = enc.EncodeRow(102, makePayload(102, 64))
	require.Error(t, err)
}

func TestWindowCodec_LegacyDetection(t *testing.T) {
	partitiontest.PartitionTest(t)
	require.True(t, IsLegacyRaw([]byte{0x83, 0xa3, 'a', 'b', 'c'})) // fixmap header
	require.False(t, IsLegacyRaw([]byte{formatRaw, 0xff}))
	require.False(t, IsLegacyRaw([]byte{formatWindowedAnchor, 0x28, 0xb5, 0x2f, 0xfd}))
	require.False(t, IsLegacyRaw([]byte{formatWindowedContinuation, 0x00, 0x01}))
	require.False(t, IsLegacyRaw(nil))
}

// TestWindowCodec_AnchorByPrefixNotMagic guards against the precise
// review finding that motivated the formatWindowedAnchor /
// formatWindowedContinuation split: a continuation chunk whose
// compressed delta happens to begin with the zstd magic must NOT be
// mistaken for an anchor. We construct the chunk by hand because real
// zstd output rarely produces the magic mid-frame; the contract that
// anchor detection is purely format-prefix-driven is what the test
// pins down.
func TestWindowCodec_AnchorByPrefixNotMagic(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Synthetic continuation chunk whose payload starts with the zstd
	// frame magic. Under the old "scan for magic" heuristic this would
	// have been picked as an anchor; under the new format-prefix scheme
	// it must be ignored.
	bogusContinuation := append([]byte{formatWindowedContinuation}, zstdMagic...)
	bogusContinuation = append(bogusContinuation, 0x00, 0x01, 0x02)

	realAnchor := append([]byte{formatWindowedAnchor}, zstdMagic...)
	realAnchor = append(realAnchor, 0xff, 0xff)

	chunks := [][]byte{realAnchor, bogusContinuation, bogusContinuation}
	require.Equal(t, 0, FindAnchorOffset(chunks))

	chunks = [][]byte{bogusContinuation, bogusContinuation}
	require.Equal(t, -1, FindAnchorOffset(chunks))
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
		_, err := ep.Blk.EncodeRow(basics.Round(r), makePayload(r, 256))
		require.NoError(t, err)
		_, err = ep.Cert.EncodeRow(basics.Round(r), makePayload(r+100, 256))
		require.NoError(t, err)
	}

	ep.Close()

	// After Close the next EncodeRow should succeed and produce a fresh
	// frame anchored at whatever round comes next, even one that is not a
	// multiple of N. If Close left started=true / a stale writer ptr, the
	// internal "skip writer init" branch would crash on the nil writer.
	for i, r := range []basics.Round{4, 5} {
		chunk, err := ep.Blk.EncodeRow(r, makePayload(int(r), 256))
		require.NoError(t, err)
		// The first post-Close write opens a new frame (anchor); the
		// next continues it.
		expected := formatWindowedContinuation
		if i == 0 {
			expected = formatWindowedAnchor
		}
		require.Equal(t, expected, chunk[0])
	}
	ep.Close()
}

// TestWindowCodec_RejectsHugeUvarint ensures that a corrupt or tampered
// row whose decoded uvarint length exceeds MaxDecodedPayloadBytes is
// rejected with an error rather than triggering an out-of-memory panic.
func TestWindowCodec_RejectsHugeUvarint(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Encode a single legitimate row with the codec, then craft a
	// continuation chunk whose decompressed uvarint length is well above
	// MaxDecodedPayloadBytes. We do this by manually constructing a zstd
	// frame whose decompressed contents start with a >32 MiB uvarint.
	var huge bytes.Buffer
	w := zstd.NewWriterLevel(&huge, 1)
	var lb [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lb[:], MaxDecodedPayloadBytes+1)
	_, err := w.Write(lb[:n])
	require.NoError(t, err)
	require.NoError(t, w.Close())

	chunk := append([]byte{formatWindowedAnchor}, huge.Bytes()...)
	_, err = DecodeWindow([][]byte{chunk})
	require.ErrorContains(t, err, "exceeds MaxDecodedPayloadBytes")
}
