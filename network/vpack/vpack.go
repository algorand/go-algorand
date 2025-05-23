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
	"fmt"
	"math/bits"
)

// A vote is made up of 14 values, some of which are optional.
// The required values are: cred.pf, r.rnd, r.snd, sig.p, sig.p1s, sig.p2,
// sig.p2s, sig.s (sig.ps is always zero).
// The remaining 6 optional values are either present or omitted, and their
// presence is indicated in a 1-byte bitmask in the header.
const (
	bitPer    uint8 = 1 << iota // r.per
	bitDig                      // r.prop.dig
	bitEncDig                   // r.prop.encdig
	bitOper                     // r.prop.oper
	bitOprop                    // r.prop.oprop
	bitStep                     // r.step

	propFieldsMask      uint8 = bitDig | bitEncDig | bitOper | bitOprop
	totalRequiredFields       = 8
)

const (
	headerSize = 2 // 1 byte for StatelessEncoder, 1 byte for StatefulEncoder

	maxMsgpVaruintSize   = 9 // max size of a varuint is 8 bytes + 1 byte for the marker
	msgpBin8Len32Size    = len(msgpBin8Len32) + 32
	msgpBin8Len64Size    = len(msgpBin8Len64) + 64
	msgpBin8Len80Size    = len(msgpBin8Len80) + 80
	msgpFixMapMarkerSize = 1

	// MaxMsgpackVoteSize is the maximum size of a vote, including msgpack control characters
	// and all required and optional data fields.
	MaxMsgpackVoteSize = msgpFixMapMarkerSize + // top-level fixmap
		len(msgpFixstrCred) + msgpFixMapMarkerSize + // cred: fixmap
		len(msgpFixstrPf) + msgpBin8Len80Size + // cred.pf: bin8(80)
		len(msgpFixstrR) + msgpFixMapMarkerSize + // r: fixmap
		len(msgpFixstrPer) + maxMsgpVaruintSize + // r.per: varuint
		len(msgpFixstrProp) + msgpFixMapMarkerSize + // r.prop: fixmap
		len(msgpFixstrDig) + msgpBin8Len32Size + // r.prop.dig: bin8(32)
		len(msgpFixstrEncdig) + msgpBin8Len32Size + // r.prop.encdig: bin8(32)
		len(msgpFixstrOper) + maxMsgpVaruintSize + // r.prop.oper: varuint
		len(msgpFixstrOprop) + msgpBin8Len32Size + // r.prop.oprop: bin8(32)
		len(msgpFixstrRnd) + maxMsgpVaruintSize + // r.rnd: varuint
		len(msgpFixstrSnd) + msgpBin8Len32Size + // r.snd: bin8(32)
		len(msgpFixstrStep) + maxMsgpVaruintSize + // r.step: varuint
		len(msgpFixstrSig) + msgpFixMapMarkerSize + // sig: fixmap
		len(msgpFixstrP) + msgpBin8Len32Size + // sig.p: bin8(32)
		len(msgpFixstrP1s) + msgpBin8Len64Size + // sig.p1s: bin8(64)
		len(msgpFixstrP2) + msgpBin8Len32Size + // sig.p2: bin8(32)
		len(msgpFixstrP2s) + msgpBin8Len64Size + // sig.p2s: bin8(64)
		len(msgpFixstrPs) + msgpBin8Len64Size + // sig.ps: bin8(64)
		len(msgpFixstrS) + msgpBin8Len64Size // sig.s: bin8(64)

	// MaxCompressedVoteSize is the maximum size of a compressed vote using StatelessEncoder,
	// including all required and optional fields.
	MaxCompressedVoteSize = headerSize +
		80 + // cred.pf
		maxMsgpVaruintSize*4 + // r.rnd, r.per, r.step, r.prop.oper
		32*6 + // r.prop.dig, r.prop.encdig, r.prop.oprop, r.snd, sig.p, sig.p2
		64*3 // sig.p1s, sig.p2s, sig.s (sig.ps is omitted)
)

// StatelessEncoder compresses a msgpack-encoded vote by stripping all msgpack
// formatting and field names, replacing them with a bitmask indicating which
// fields are present. It is not thread-safe.
type StatelessEncoder struct {
	cur  []byte
	pos  int
	mask uint8

	requiredFields uint8
}

// NewStatelessEncoder returns a new StatelessEncoder.
func NewStatelessEncoder() *StatelessEncoder {
	return &StatelessEncoder{}
}

// ErrBufferTooSmall is returned when the destination buffer is too small
var ErrBufferTooSmall = fmt.Errorf("destination buffer too small")

// CompressVote compresses a vote in src and writes it to dst.
// If the provided buffer dst is nil or too small, a new slice is allocated.
// The returned slice may be the same as dst.
// To re-use dst, run like: dst = enc.CompressVote(dst[:0], src)
func (e *StatelessEncoder) CompressVote(dst, src []byte) ([]byte, error) {
	bound := MaxCompressedVoteSize
	// Reuse dst if it's big enough, otherwise allocate a new buffer
	if cap(dst) >= bound {
		dst = dst[0:bound] // Reuse dst buffer with its full capacity
	} else {
		dst = make([]byte, bound)
	}

	// Reset our position to the beginning
	e.cur = dst
	e.mask = 0
	e.requiredFields = 0
	// put empty header at beginning, to fill in later
	e.pos = headerSize
	err := parseMsgpVote(src, e)
	if err != nil {
		return nil, err
	}

	// Check if we overflowed the buffer
	if e.pos > len(dst) {
		return nil, ErrBufferTooSmall
	}

	if e.requiredFields != totalRequiredFields {
		return nil, fmt.Errorf("missing required fields")
	}
	// fill in header's first byte with mask
	e.cur[0] = e.mask

	// Return only the portion that was used
	return dst[:e.pos], nil

}

// writeBytes writes multiple bytes to the current buffer
// This is optimized to avoid per-byte bounds checking when possible
func (e *StatelessEncoder) writeBytes(bytes []byte) {
	// If we have enough room in the buffer, use direct copy
	if e.pos+len(bytes) <= len(e.cur) {
		copy(e.cur[e.pos:], bytes)
	}
	// Always increment pos, so CompressVote will return ErrBufferTooSmall
	e.pos += len(bytes)
}

func (e *StatelessEncoder) updateMask(field voteValueType) {
	switch field {
	case rPerVoteValue:
		e.mask |= bitPer
	case rPropDigVoteValue:
		e.mask |= bitDig
	case rPropEncdigVoteValue:
		e.mask |= bitEncDig
	case rPropOperVoteValue:
		e.mask |= bitOper
	case rPropOpropVoteValue:
		e.mask |= bitOprop
	case rStepVoteValue:
		e.mask |= bitStep
	default:
		// all other fields are required
		e.requiredFields++
	}
}

func (e *StatelessEncoder) writeVaruint(field voteValueType, b []byte) {
	e.updateMask(field)
	e.writeBytes(b)
}

func (e *StatelessEncoder) writeBin32(field voteValueType, b [32]byte) {
	e.updateMask(field)
	e.writeBytes(b[:])
}

func (e *StatelessEncoder) writeBin64(field voteValueType, b [64]byte) {
	e.updateMask(field)
	e.writeBytes(b[:])
}

func (e *StatelessEncoder) writeBin80(field voteValueType, b [80]byte) {
	e.updateMask(field)
	e.writeBytes(b[:])
}

// StatelessDecoder decompresses votes that were compressed by StatelessEncoder.
type StatelessDecoder struct {
	dst, src []byte
	pos      int
}

// NewStatelessDecoder returns a new StatelessDecoder.
func NewStatelessDecoder() *StatelessDecoder {
	return &StatelessDecoder{}
}

func (d *StatelessDecoder) rawVoteMapSize(mask uint8) (cnt uint8) {
	// Count how many of per, step are set (rnd & snd must be present)
	cnt = 2 + uint8(bits.OnesCount8(mask&(bitPer|bitStep)))
	// Add 1 if any prop bits are set
	if mask&propFieldsMask != 0 {
		cnt++
	}
	return
}

func (d *StatelessDecoder) proposalValueMapSize(mask uint8) uint8 {
	// Count how many of dig, encdig, oper, oprop are set
	return uint8(bits.OnesCount8(mask & (bitDig | bitEncDig | bitOper | bitOprop)))
}

// DecompressVote decodes a compressed vote in src and appends it to dst.
// To re-use dst, run like: dst = dec.DecompressVote(dst[:0], src)
func (d *StatelessDecoder) DecompressVote(dst, src []byte) ([]byte, error) {
	if len(src) < 2 {
		return nil, fmt.Errorf("header missing")
	}
	mask := uint8(src[0])
	d.pos = 2
	d.src = src
	d.dst = dst
	if d.dst == nil { // allocate a new buffer if dst is nil
		d.dst = make([]byte, 0, MaxMsgpackVoteSize)
	}

	// top-level UnauthenticatedVote: fixmap(3) { cred, rawVote, sig }
	d.dst = append(d.dst, msgpFixMapMask|3)

	// cred: fixmap(1) { pf: bin8(80) }
	d.dst = append(d.dst, msgpFixstrCred...)
	d.dst = append(d.dst, msgpFixMapMask|1)

	// cred.pf is always present
	if err := d.bin80(msgpFixstrPf); err != nil {
		return nil, err
	}

	// rawVote: fixmap { per, prop, rnd, snd, step }
	d.dst = append(d.dst, msgpFixstrR...)
	d.dst = append(d.dst, msgpFixMapMask|d.rawVoteMapSize(mask))

	// rawVote.per
	if (mask & bitPer) != 0 {
		if err := d.varuint(msgpFixstrPer); err != nil {
			return nil, err
		}
	}

	// rawVote.prop could be zero (bottom vote is empty value)
	if (mask & propFieldsMask) != 0 {
		// proposalValue: fixmap { dig, encdig, oper, oprop }
		d.dst = append(d.dst, msgpFixstrProp...)
		d.dst = append(d.dst, msgpFixMapMask|d.proposalValueMapSize(mask))
		// prop.dig
		if (mask & bitDig) != 0 {
			if err := d.bin32(msgpFixstrDig); err != nil {
				return nil, err
			}
		}
		// prop.encdig
		if (mask & bitEncDig) != 0 {
			if err := d.bin32(msgpFixstrEncdig); err != nil {
				return nil, err
			}
		}
		// prop.oper
		if (mask & bitOper) != 0 {
			if err := d.varuint(msgpFixstrOper); err != nil {
				return nil, err
			}
		}
		// prop.oprop
		if (mask & bitOprop) != 0 {
			if err := d.bin32(msgpFixstrOprop); err != nil {
				return nil, err
			}
		}
	}

	// rawVote.rnd is always present
	if err := d.varuint(msgpFixstrRnd); err != nil {
		return nil, err
	}

	// rawVote.snd is always present
	if err := d.bin32(msgpFixstrSnd); err != nil {
		return nil, err
	}

	// rawVote.step
	if (mask & bitStep) != 0 {
		if err := d.varuint(msgpFixstrStep); err != nil {
			return nil, err
		}
	}

	// crypto.OneTimeSignature does not use omitempty; all fields are required
	// and always present.

	// sig: fixmap(6) { p, p1s, p2, p2s, ps, s }
	d.dst = append(d.dst, msgpFixstrSig...)
	d.dst = append(d.dst, msgpFixMapMask|6)
	// sig.p
	if err := d.bin32(msgpFixstrP); err != nil {
		return nil, err
	}
	// sig.p1s
	if err := d.bin64(msgpFixstrP1s); err != nil {
		return nil, err
	}
	// sig.p2
	if err := d.bin32(msgpFixstrP2); err != nil {
		return nil, err
	}
	// sig.p2s
	if err := d.bin64(msgpFixstrP2s); err != nil {
		return nil, err
	}
	// sig.ps is always zero
	d.dst = append(d.dst, msgpFixstrPs...)
	d.dst = append(d.dst, msgpBin8Len64...)
	d.dst = append(d.dst, make([]byte, 64)...)
	// sig.s
	if err := d.bin64(msgpFixstrS); err != nil {
		return nil, err
	}

	if d.pos < len(d.src) {
		return nil, fmt.Errorf("unexpected trailing data: %d bytes remain", len(d.src)-d.pos)
	}

	return d.dst, nil
}

func (d *StatelessDecoder) bin64(fieldStr string) error {
	if d.pos+64 > len(d.src) {
		return fmt.Errorf("not enough data to read value for field %s", fieldStr)
	}
	d.dst = append(d.dst, fieldStr...)
	d.dst = append(d.dst, msgpBin8Len64...)
	d.dst = append(d.dst, d.src[d.pos:d.pos+64]...)
	d.pos += 64
	return nil
}

func (d *StatelessDecoder) bin32(fieldStr string) error {
	if d.pos+32 > len(d.src) {
		return fmt.Errorf("not enough data to read value for field %s", fieldStr)
	}
	d.dst = append(d.dst, fieldStr...)
	d.dst = append(d.dst, msgpBin8Len32...)
	d.dst = append(d.dst, d.src[d.pos:d.pos+32]...)
	d.pos += 32
	return nil
}

func (d *StatelessDecoder) bin80(fieldStr string) error {
	if d.pos+80 > len(d.src) {
		return fmt.Errorf("not enough data to read value for field %s,  d.pos=%d, len(src)=%d", fieldStr, d.pos, len(d.src))
	}
	d.dst = append(d.dst, fieldStr...)
	d.dst = append(d.dst, msgpBin8Len80...)
	d.dst = append(d.dst, d.src[d.pos:d.pos+80]...)
	d.pos += 80
	return nil
}

func (d *StatelessDecoder) varuint(fieldName string) error {
	if d.pos+1 > len(d.src) {
		return fmt.Errorf("not enough data to read varuint marker for field %s", fieldName)
	}
	marker := d.src[d.pos] // read msgpack varuint marker
	moreBytes := 0
	switch marker {
	case msgpUint8:
		moreBytes = 1
	case msgpUint16:
		moreBytes = 2
	case msgpUint32:
		moreBytes = 4
	case msgpUint64:
		moreBytes = 8
	default: // fixint uses a single byte for marker+value
		if !isMsgpFixint(marker) {
			return fmt.Errorf("not a fixint for field %s, got %d", fieldName, marker)
		}
		moreBytes = 0
	}

	if d.pos+1+moreBytes > len(d.src) {
		return fmt.Errorf("not enough data for varuint (need %d bytes) for field %s", moreBytes, fieldName)
	}
	d.dst = append(d.dst, fieldName...)
	d.dst = append(d.dst, marker)
	if moreBytes > 0 {
		d.dst = append(d.dst, d.src[d.pos+1:d.pos+moreBytes+1]...)
	}
	d.pos += moreBytes + 1 // account for marker byte + value bytes

	return nil
}
