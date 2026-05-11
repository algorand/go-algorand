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
	"encoding/binary"
	"fmt"
	"io"
	"slices"

	"github.com/DataDog/zstd"

	"github.com/algorand/go-algorand/config/bounds"
	"github.com/algorand/go-algorand/data/basics"
)

// MaxCompressionWindow is the largest BlockDBCompressionWindow value the
// codec will accept. The implementation is bounded by the maximum number of
// prior rows a read may have to load to decode a single round. The mirror
// constant in package config (config.MaxBlockDBCompressionWindow) MUST stay
// in sync; the duplication exists so the startup config validator does not
// have to import this package.
const MaxCompressionWindow = 32

// defaultCompressionLevel is the zstd level used for blkdata/certdata
// compression. The vpackblocks experiments showed level 11 was strongly
// preferable on this data even at high N: faster levels gave back several
// percentage points of ratio without measurable encode-cost relief.
const defaultCompressionLevel = 11

// WindowCodec holds the configuration for the per-column windowed-zstd
// codec. A value of N == 0 means compression is disabled and EncodeRow
// returns the payload verbatim, byte-identical to the pre-codec on-disk
// layout. When N >= 1, rows are stored as raw streaming-zstd chunks and the
// encoder is reset every N rounds. N == 1 produces a fresh frame per row.
type WindowCodec struct {
	N     int
	Level int
}

// Disabled reports whether this codec writes uncompressed rows.
func (c WindowCodec) Disabled() bool { return c.N == 0 }

// Encoder is the per-column streaming encoder. Two Encoders are typically
// used in parallel (one for blkdata, one for certdata). Rounds must be
// supplied in strictly ascending order via EncodeRow.
type Encoder struct {
	c        WindowCodec
	w        *zstd.Writer
	buf      bytes.Buffer
	consumed int

	started      bool
	expectedNext basics.Round
	anchorRound  basics.Round
}

// NewEncoder returns an Encoder configured by c.
func NewEncoder(c WindowCodec) *Encoder { return &Encoder{c: c} }

// EncoderPair groups two parallel Encoders, one for blkdata and one for
// certdata. Both columns share the same WindowCodec settings and reset at
// the same round boundaries.
type EncoderPair struct {
	Blk  *Encoder
	Cert *Encoder
}

// NewEncoderPair constructs an EncoderPair where both columns use the same
// codec settings.
func NewEncoderPair(c WindowCodec) *EncoderPair {
	return &EncoderPair{Blk: NewEncoder(c), Cert: NewEncoder(c)}
}

// Reset clears in-flight window state on both columns.
func (ep *EncoderPair) Reset() {
	ep.Blk.Reset()
	ep.Cert.Reset()
}

// Close releases the C-allocated zstd writer state held by both encoders
// and leaves them in the same state as a fresh encoder, so the pair is
// safe to reuse. Always call this when an EncoderPair is no longer needed;
// DataDog/zstd's Writer has no finalizer, so a missed Close leaks native
// memory. BlockWriter.Close relies on this to support blockQueue stop/start
// cycles during ledger reload.
func (ep *EncoderPair) Close() {
	if ep == nil {
		return
	}
	ep.Blk.Reset()
	ep.Cert.Reset()
}

// BlockWriter owns the streaming encoder state needed to append compressed
// blkdata/certdata rows. The state must be preserved across consecutive
// successful writes for good compression, and reset whenever a transaction
// containing encoded rows is retried or abandoned. NewBlockWriter constructs
// a writer that honors the configured compression window.
type BlockWriter struct {
	codec   WindowCodec
	encPair *EncoderPair
}

// NewBlockWriter constructs a writer for normal block-table appends.
func NewBlockWriter(window uint64) *BlockWriter {
	n := min(max(int(window), 0), MaxCompressionWindow)
	c := WindowCodec{N: n, Level: defaultCompressionLevel}
	return &BlockWriter{codec: c, encPair: NewEncoderPair(c)}
}

// Codec returns the WindowCodec configured for this writer. The caller
// only uses this to decide whether to bind a real window_start anchor
// or NULL when inserting a row.
func (w *BlockWriter) Codec() WindowCodec { return w.codec }

func (w *BlockWriter) pair() *EncoderPair { return w.encPair }

// Reset drops any in-flight compression window. The next write will start a
// fresh frame anchor at whatever round it receives.
func (w *BlockWriter) Reset() {
	if w == nil || w.encPair == nil {
		return
	}
	w.encPair.Reset()
}

// Close releases native zstd writer state held by this writer and leaves it
// reusable in the same state as a fresh writer. The blockQueue syncer stops
// and restarts the same writer across ledger reloads, so Close must not make
// future BlockPut calls invalid.
func (w *BlockWriter) Close() {
	if w == nil || w.encPair == nil {
		return
	}
	w.encPair.Close()
}

// Reset drops any in-flight window state. The next EncodeRow call will
// start a new zstd frame regardless of r % N. Use this on startup when the
// previous encoder state was not preserved across a restart, and after a
// failed BlockPut so the next attempt does not see an inconsistent encoder.
func (e *Encoder) Reset() {
	e.closeWriter()
	e.buf.Reset()
	e.consumed = 0
	e.started = false
	e.expectedNext = 0
	e.anchorRound = 0
}

// closeWriter shuts down the current zstd writer, if any. DataDog/zstd's
// Writer holds a C-allocated stream that is only freed by Close, so every
// path that drops e.w must come through here. The trailer bytes that
// Close writes to e.buf are never persisted: callers always Reset the
// buffer (or discard the encoder entirely) immediately after.
func (e *Encoder) closeWriter() {
	if e.w == nil {
		return
	}
	_ = e.w.Close()
	e.w = nil
}

// EncodeRow encodes payload for round r and returns the per-row chunk plus
// the round that opened the chunk's zstd frame (the anchor). When the codec
// is disabled the chunk is a fresh copy of payload, byte-identical to the
// pre-codec on-disk layout, and the returned anchor is 0 (the caller will
// bind window_start to NULL in that case). When the codec is active the
// chunk holds the streaming-zstd delta for r; rows that begin a new frame
// (the first encode after construction or Reset, and every r where r%N==0)
// return anchorRound = r, and subsequent continuation rows return the
// anchor round of the frame they belong to.
func (e *Encoder) EncodeRow(r basics.Round, payload []byte) ([]byte, basics.Round, error) {
	if e.c.Disabled() {
		return slices.Clone(payload), 0, nil
	}

	if e.started && r != e.expectedNext {
		return nil, 0, fmt.Errorf("blockdb codec: out-of-order encode r=%d expected=%d", r, e.expectedNext)
	}

	startNewFrame := !e.started || uint64(r)%uint64(e.c.N) == 0
	if startNewFrame {
		e.closeWriter()
		e.buf.Reset()
		e.consumed = 0
		e.w = zstd.NewWriterLevel(&e.buf, e.c.Level)
		e.anchorRound = r
	}

	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(payload)))
	if _, err := e.w.Write(lenBuf[:n]); err != nil {
		return nil, 0, fmt.Errorf("blockdb codec: zstd write len: %w", err)
	}
	if _, err := e.w.Write(payload); err != nil {
		return nil, 0, fmt.Errorf("blockdb codec: zstd write payload: %w", err)
	}
	if err := e.w.Flush(); err != nil {
		return nil, 0, fmt.Errorf("blockdb codec: zstd flush: %w", err)
	}

	delta := slices.Clone(e.buf.Bytes()[e.consumed:])
	e.consumed = e.buf.Len()
	e.started = true
	e.expectedNext = r + 1
	return delta, e.anchorRound, nil
}

// maxDecodedPayloadBytes caps the per-row decompressed payload size that
// decodeWindow will allocate for. A corrupt or tampered DB row could
// otherwise encode a uvarint length close to 2^64 and cause an
// out-of-memory panic before any error is returned. The bound covers both
// block bytes (dominated by MaxTxnBytesPerBlock) and certificates (well
// below the floor); MaxTxnBytesPerBlock is a process-level config var, so
// fall back to an 8 MiB floor in the unusual case where it has not been
// initialized yet (the standalone codec tests, for instance).
func maxDecodedPayloadBytes() int {
	n := max(bounds.MaxTxnBytesPerBlock+1<<20, 8<<20)
	return n
}

// decodeWindow decodes the per-row chunks for an in-order range of rounds
// in the same window (all sharing one zstd frame) and returns the payload
// for the highest round (the last entry in chunks). The first chunk is
// expected to be a frame anchor; every subsequent chunk is a continuation
// of that frame. The unified read path in blockGetEncoded passes exactly
// this slice (the SELECT range starts at window_start), so callers do not
// need to do any anchor detection themselves.
func decodeWindow(chunks [][]byte) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("blockdb codec: empty window")
	}
	var concat bytes.Buffer
	for i, c := range chunks {
		if len(c) == 0 {
			return nil, fmt.Errorf("blockdb codec: empty chunk at index %d", i)
		}
		concat.Write(c)
	}
	r := zstd.NewReader(&concat)
	defer r.Close()

	br := newByteReader(r)
	max := maxDecodedPayloadBytes()
	var last []byte
	for i := 0; i < len(chunks); i++ {
		plen, err := binary.ReadUvarint(br)
		if err != nil {
			return nil, fmt.Errorf("blockdb codec: read uvarint #%d: %w", i, err)
		}
		if plen > uint64(max) {
			return nil, fmt.Errorf("blockdb codec: payload #%d length %d exceeds maxDecodedPayloadBytes=%d (corrupt row?)",
				i, plen, max)
		}
		buf := make([]byte, plen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("blockdb codec: read payload #%d (%d bytes): %w", i, plen, err)
		}
		last = buf
	}
	return last, nil
}

// byteReader adapts an io.Reader to io.ByteReader for binary.ReadUvarint
// without buffering. zstd.Reader does not implement ReadByte directly.
type byteReader struct {
	r   io.Reader
	one [1]byte
}

func newByteReader(r io.Reader) *byteReader { return &byteReader{r: r} }

func (b *byteReader) ReadByte() (byte, error) {
	if _, err := io.ReadFull(b.r, b.one[:]); err != nil {
		return 0, err
	}
	return b.one[0], nil
}
