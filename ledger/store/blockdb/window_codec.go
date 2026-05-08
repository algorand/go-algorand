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

	"github.com/DataDog/zstd"

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

// Per-row format prefix bytes for windowed rows.
//
// formatRaw (0x00) historically marked an uncompressed-but-prefixed row;
// no shipping code writes it any more (disabled-codec rows are stored
// verbatim, byte-identical to pre-codec msgp), but DecodeRaw still strips
// it on read so any rows from an in-development build that emitted it
// remain decodable.
//
// formatWindowedAnchor (0x01) marks a streaming-zstd chunk that begins a
// new frame; its compressed payload starts with the zstd magic number.
// formatWindowedContinuation (0x02) marks a chunk that continues the
// previous anchor's frame. The two are kept distinct so FindAnchorOffset
// never confuses a continuation chunk that coincidentally begins with the
// zstd magic for a real anchor (a 1-in-2^32 collision per row that becomes
// real on long-lived block DBs).
//
// Any chunk whose first byte is none of these three is treated as legacy
// raw msgp: msgp-encoded blocks and certificates always start with a
// fixmap header byte (0x80-0x8f), so the prefix bytes chosen here do not
// collide with the legacy on-disk format.
const (
	formatRaw                  byte = 0x00
	formatWindowedAnchor       byte = 0x01
	formatWindowedContinuation byte = 0x02
)

// zstdMagic is the 4-byte magic number that begins every zstd frame. We
// only use it as a sanity check on anchor chunks; the formatWindowedAnchor
// byte is the load-bearing signal and we never rely on the magic to
// disambiguate anchors from continuations.
var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

// WindowCodec holds the configuration for the per-column windowed-zstd
// codec. A value of N <= 1 means compression is disabled and EncodeRow
// returns the payload verbatim, byte-identical to the pre-codec on-disk
// layout. When N > 1, rows are stored with a formatWindowed prefix and a
// streaming-zstd encoder is reset every N rounds.
type WindowCodec struct {
	N     int
	Level int
}

// Disabled reports whether this codec writes uncompressed rows.
func (c WindowCodec) Disabled() bool { return c.N <= 1 }

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
// containing encoded rows is retried or abandoned. The zero value is usable
// as an uncompressed writer; NewBlockWriter should be used when compression
// is configured.
type BlockWriter struct {
	encPair *EncoderPair
}

// NewBlockWriter constructs a writer for normal block-table appends.
func NewBlockWriter(window uint64) *BlockWriter {
	n := int(window)
	if n < 1 {
		n = 1
	}
	if n > MaxCompressionWindow {
		n = MaxCompressionWindow
	}
	return &BlockWriter{encPair: NewEncoderPair(WindowCodec{N: n, Level: defaultCompressionLevel})}
}

func (w *BlockWriter) pair() *EncoderPair {
	if w.encPair == nil {
		w.encPair = NewEncoderPair(WindowCodec{})
	}
	return w.encPair
}

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

// EncodeRow encodes payload for round r and returns the per-row chunk.
// When the codec is disabled the chunk is the payload bytes verbatim so
// BlockDBCompressionWindow=1 (the default) leaves the on-disk layout
// indistinguishable from the pre-codec format. When the codec is active
// the chunk carries either formatWindowedAnchor or
// formatWindowedContinuation as its first byte (the former for the row
// that opens a new zstd frame, the latter for every subsequent row in
// the same window). The returned slice is freshly allocated and safe for
// the caller to retain.
func (e *Encoder) EncodeRow(r basics.Round, payload []byte) ([]byte, error) {
	if e.c.Disabled() {
		out := make([]byte, len(payload))
		copy(out, payload)
		return out, nil
	}

	if e.started && r != e.expectedNext {
		return nil, fmt.Errorf("blockdb codec: out-of-order encode r=%d expected=%d", r, e.expectedNext)
	}

	// Start a fresh frame at the configured anchor boundary, or the first
	// time EncodeRow is called after construction/Reset.
	startNewFrame := !e.started || uint64(r)%uint64(e.c.N) == 0
	if startNewFrame {
		e.closeWriter()
		e.buf.Reset()
		e.consumed = 0
		e.w = zstd.NewWriterLevel(&e.buf, e.c.Level)
	}

	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(payload)))
	if _, err := e.w.Write(lenBuf[:n]); err != nil {
		return nil, fmt.Errorf("blockdb codec: zstd write len: %w", err)
	}
	if _, err := e.w.Write(payload); err != nil {
		return nil, fmt.Errorf("blockdb codec: zstd write payload: %w", err)
	}
	if err := e.w.Flush(); err != nil {
		return nil, fmt.Errorf("blockdb codec: zstd flush: %w", err)
	}

	delta := e.buf.Bytes()[e.consumed:]
	e.consumed = e.buf.Len()
	e.started = true
	e.expectedNext = r + 1

	prefix := formatWindowedContinuation
	if startNewFrame {
		prefix = formatWindowedAnchor
	}
	out := make([]byte, 1+len(delta))
	out[0] = prefix
	copy(out[1:], delta)
	return out, nil
}

// IsLegacyRaw reports whether chunk is in the pre-codec raw-msgp format.
// Legacy rows have no format prefix; the test simply checks for the
// absence of any of the format bytes the codec emits, taking advantage of
// the fact that msgp-encoded blocks/certs always start with a fixmap
// (0x80-0x8f) header.
func IsLegacyRaw(chunk []byte) bool {
	if len(chunk) == 0 {
		return false
	}
	switch chunk[0] {
	case formatRaw, formatWindowedAnchor, formatWindowedContinuation:
		return false
	}
	return true
}

// DecodeRaw returns the payload of a chunk that does not require windowed
// decoding (legacy or formatRaw prefix).
func DecodeRaw(chunk []byte) []byte {
	if len(chunk) > 0 && chunk[0] == formatRaw {
		return chunk[1:]
	}
	return chunk
}

// MaxDecodedPayloadBytes caps the per-row decompressed payload size that
// DecodeWindow will allocate for. A corrupt or tampered DB row could
// otherwise encode a uvarint length close to 2^64 and cause an
// out-of-memory panic before any error is returned. The value here is
// generous (well above the protocol's MaxTxnBytesPerBlock and any
// realistic certificate size) but small enough that an allocation request
// can never lock up the process.
const MaxDecodedPayloadBytes = 32 * 1024 * 1024 // 32 MiB

// DecodeWindow decodes the per-row chunks for an in-order range of rounds
// in the same window and returns the payload for the highest round (the
// last entry in chunks). The first chunk must be a formatWindowedAnchor
// (i.e. it begins a new zstd frame) and every subsequent chunk must be a
// formatWindowedContinuation. Callers that supply a wider window should
// use FindAnchorOffset to slice down to a starting anchor first.
func DecodeWindow(chunks [][]byte) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("blockdb codec: empty window")
	}
	if len(chunks[0]) < 1+len(zstdMagic) || chunks[0][0] != formatWindowedAnchor {
		return nil, fmt.Errorf("blockdb codec: first chunk is not a zstd frame anchor")
	}
	if !bytes.HasPrefix(chunks[0][1:], zstdMagic) {
		return nil, fmt.Errorf("blockdb codec: anchor chunk does not begin with zstd magic")
	}
	var concat bytes.Buffer
	for i, c := range chunks {
		if len(c) == 0 {
			return nil, fmt.Errorf("blockdb codec: empty chunk at index %d", i)
		}
		expected := formatWindowedContinuation
		if i == 0 {
			expected = formatWindowedAnchor
		}
		if c[0] != expected {
			return nil, fmt.Errorf("blockdb codec: chunk #%d has prefix %#x, expected %#x", i, c[0], expected)
		}
		concat.Write(c[1:])
	}
	r := zstd.NewReader(&concat)
	defer r.Close()

	br := newByteReader(r)
	wantPayloads := len(chunks)
	var last []byte
	for i := 0; i < wantPayloads; i++ {
		plen, err := binary.ReadUvarint(br)
		if err != nil {
			return nil, fmt.Errorf("blockdb codec: read uvarint #%d: %w", i, err)
		}
		if plen > MaxDecodedPayloadBytes {
			return nil, fmt.Errorf("blockdb codec: payload #%d length %d exceeds MaxDecodedPayloadBytes=%d (corrupt row?)",
				i, plen, MaxDecodedPayloadBytes)
		}
		buf := make([]byte, plen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("blockdb codec: read payload #%d (%d bytes): %w", i, plen, err)
		}
		last = buf
	}
	return last, nil
}

// FindAnchorOffset returns the index within chunks of the latest
// formatWindowedAnchor chunk, or -1 if none is present. Chunks are
// expected to be in ascending round order. Recognition is based purely on
// the explicit format prefix; we do not rely on the zstd magic bytes
// because any continuation chunk's compressed payload could begin with
// the same 4-byte sequence.
func FindAnchorOffset(chunks [][]byte) int {
	for i := len(chunks) - 1; i >= 0; i-- {
		c := chunks[i]
		if len(c) >= 1 && c[0] == formatWindowedAnchor {
			return i
		}
	}
	return -1
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
