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
	"encoding/binary"
	"errors"
	"fmt"
)

// The second byte in the header is used by StatefulEncoder and
// StatefulDecoder to signal which values have been replaced
// by references.
// For r.prop, 3 bits are used to encode the reference directly.
// For r.rnd, a 2-bit delta encoding is used.
//
//	7 6 5 4 3 2 1 0
//	| | | \___/ \_/-- rnd encoding (00=literal, 01=+1, 10=-1, 11=same as last rnd)
//	| | |   `-------- prop window reference (000=literal, 001...111=window index)
//	| | +------------ snd table reference (0=literal, 1=table)
//	| +-------------- (sig.p,sig.p1s) table reference appears (0=literal, 1=table)
//	+---------------- (sig.p2, sig.p2s) table reference (0=literal, 1=table)
const (
	// bits 0-1: rnd delta encoding
	hdr1RndMask        = 0b00000011
	hdr1RndDeltaSame   = 0b11
	hdr1RndDeltaPlus1  = 0b01
	hdr1RndDeltaMinus1 = 0b10
	hdr1RndLiteral     = 0b00

	// bits 2-4: proposal-bundle reference (value<<2)
	hdr1PropShift = 2
	hdr1PropMask  = 0b00011100

	// bits 5-7: whether snd, pk, pk2 are dynamic table references
	hdr1SndRef = 1 << 5
	hdr1PkRef  = 1 << 6
	hdr1Pk2Ref = 1 << 7
)

// StatefulEncoder compresses votes by using references to previously seen values
// from earlier votes.
type StatefulEncoder struct{ dynamicTableState }

// StatefulDecoder decompresses votes by using references to previously seen values
// from earlier votes.
type StatefulDecoder struct{ dynamicTableState }

// dynamicTableState is shared by StatefulEncoder and StatefulDecoder. It contains
// the necessary state for tracking references to previously seen values.
type dynamicTableState struct {
	// LRU hash tables for snd, p+p1s, and p2+p2s
	sndTable lruTable[addressValue] // 512 * 2 * 32 = 32KB
	pkTable  lruTable[pkSigPair]    // 512 * 2 * 96 = 96KB
	pk2Table lruTable[pkSigPair]    // 512 * 2 * 96 = 96KB

	// 8-slot window of recent proposal values
	proposalWindow propWindow

	// last round number seen in previous vote
	lastRnd uint64
}

func encodeDynamicRef(id lruTableReferenceID, dst *[]byte) {
	*dst = binary.BigEndian.AppendUint16(*dst, uint16(id))
}

func decodeDynamicRef(src []byte, pos *int) (lruTableReferenceID, error) {
	if *pos+2 > len(src) {
		return 0, errors.New("truncated ref id")
	}
	id := binary.BigEndian.Uint16(src[*pos : *pos+2])
	*pos += 2
	return lruTableReferenceID(id), nil
}

// Compress takes a vote compressed by StatelessEncoder, and additionally
// compresses it using dynamic references to previously seen values.
func (e *StatefulEncoder) Compress(dst, src []byte) ([]byte, error) {
	if len(src) < 2 {
		return nil, errors.New("src too short")
	}
	hdr0 := src[0] // from StatelessEncoder
	var hdr1 byte  // StatefulEncoder header
	pos := 2       // position in src

	// prepare output, leave room for 2-byte header
	out := dst[:0]
	out = append(out, hdr0, 0) // will fill in with hdr1 later

	// cred.pf: pass through
	out = append(out, src[pos:pos+80]...)
	pos += 80

	// r.per: pass through, if present
	if (hdr0 & bitPer) != 0 {
		n := msgpVaruintLen(src[pos])
		out = append(out, src[pos:pos+n]...)
		pos += n
	}

	// r.prop: check LRU window
	// copy proposal fields for table lookup
	var prop proposalEntry
	if (hdr0 & bitDig) != 0 {
		copy(prop.dig[:], src[pos:pos+32])
		pos += 32
	}
	if (hdr0 & bitEncDig) != 0 {
		copy(prop.encdig[:], src[pos:pos+32])
		pos += 32
	}
	if (hdr0 & bitOper) != 0 {
		n := msgpVaruintLen(src[pos])
		copy(prop.operEnc[:], src[pos:pos+n])
		prop.operLen = uint8(n)
		pos += n
	}
	if (hdr0 & bitOprop) != 0 {
		copy(prop.oprop[:], src[pos:pos+32])
		pos += 32
	}
	prop.mask = hdr0 & propFieldsMask

	if idx := e.proposalWindow.lookup(prop); idx != 0 {
		hdr1 |= byte(idx) << hdr1PropShift // set 001..111
	} else {
		// not found: send literal and add to window
		hdr1 |= 0 << hdr1PropShift // set 000
		e.proposalWindow.insertNew(prop)
		// write proposal bytes as StatelessEncoder would
		if (hdr0 & bitDig) != 0 {
			out = append(out, prop.dig[:]...)
		}
		if (hdr0 & bitEncDig) != 0 {
			out = append(out, prop.encdig[:]...)
		}
		if (hdr0 & bitOper) != 0 {
			out = append(out, prop.operEnc[:prop.operLen]...)
		}
		if (hdr0 & bitOprop) != 0 {
			out = append(out, prop.oprop[:]...)
		}
	}

	// r.rnd: perform delta encoding
	n := msgpVaruintLen(src[pos])
	rnd := decodeMsgpVaruint(src[pos : pos+n])

	switch { // delta encoding
	case rnd == e.lastRnd:
		hdr1 |= hdr1RndDeltaSame
	case rnd == e.lastRnd+1:
		hdr1 |= hdr1RndDeltaPlus1
	case rnd == e.lastRnd-1:
		hdr1 |= hdr1RndDeltaMinus1
	default:
		// pass through literal bytes
		hdr1 |= hdr1RndLiteral // set 00
		out = append(out, src[pos:pos+n]...)
	}
	pos += n
	e.lastRnd = rnd

	// r.snd: check LRU table
	var snd addressValue
	copy(snd[:], src[pos:pos+32])
	pos += 32
	sndH := snd.hash()
	if id, ok := e.sndTable.lookup(snd, sndH); ok {
		// found in table, use reference
		hdr1 |= hdr1SndRef
		encodeDynamicRef(id, &out)
	} else { // not found, add to table and use literal
		out = append(out, snd[:]...)
		e.sndTable.insert(snd, sndH)
	}

	// r.step: pass through, if present
	if (hdr0 & bitStep) != 0 {
		n := msgpVaruintLen(src[pos])
		out = append(out, src[pos:pos+n]...)
		pos += n
	}

	// sig.p + sig.p1s: check LRU table
	var pk pkSigPair
	copy(pk.pk[:], src[pos:pos+32])
	pos += 32
	copy(pk.sig[:], src[pos:pos+64])
	pos += 64

	pkH := pk.hash()
	if id, ok := e.pkTable.lookup(pk, pkH); ok {
		// found in table, use reference
		hdr1 |= hdr1PkRef
		encodeDynamicRef(id, &out)
	} else { // not found, add to table and use literal
		out = append(out, pk.pk[:]...)
		out = append(out, pk.sig[:]...)
		_ = e.pkTable.insert(pk, pkH)
	}

	// sig.p2 + sig.p2s: check LRU table
	var pk2 pkSigPair
	copy(pk2.pk[:], src[pos:pos+32])
	pos += 32
	copy(pk2.sig[:], src[pos:pos+64])
	pos += 64

	pk2H := pk2.hash()
	if id, ok := e.pk2Table.lookup(pk2, pk2H); ok {
		// found in table, use reference
		hdr1 |= hdr1Pk2Ref
		encodeDynamicRef(id, &out)
	} else { // not found, add to table and use literal
		out = append(out, pk2.pk[:]...)
		out = append(out, pk2.sig[:]...)
		_ = e.pk2Table.insert(pk2, pk2H)
	}

	// sig.s: pass through
	out = append(out, src[pos:pos+64]...)
	pos += 64

	if pos != len(src) {
		return nil, fmt.Errorf("length mismatch: expected %d, got %d", len(src), pos)
	}

	// fill in stateful header (hdr0 is unchanged)
	out[1] = hdr1
	return out, nil
}

// Decompress reverses StatefulEncoder, and writes a valid stateless vpack
// format buffer into dst. Caller must then pass it to StatelessDecoder.
func (d *StatefulDecoder) Decompress(dst, src []byte) ([]byte, error) {
	if len(src) < 2 {
		return nil, errors.New("input shorter than header")
	}
	hdr0 := src[0] // from StatelessEncoder
	hdr1 := src[1] // from StatefulEncoder
	pos := 2       // position in src

	// prepare out; stateless size <= original
	out := dst[:0]
	out = append(out, hdr0, 0) // StatelessDecoder-compatible header

	// cred.pf: pass through
	if pos+80 > len(src) {
		return nil, errors.New("truncated pf")
	}
	out = append(out, src[pos:pos+80]...)
	pos += 80

	// r.per: pass through, if present
	if (hdr0 & bitPer) != 0 {
		if pos+1 > len(src) {
			return nil, errors.New("truncated rnd marker")
		}
		n := msgpVaruintLen(src[pos])
		if pos+n > len(src) {
			return nil, errors.New("truncated per")
		}
		out = append(out, src[pos:pos+n]...)
		pos += n
	}

	// r.prop: check for reference to LRU window
	var prop proposalEntry
	propRef := (hdr1 & hdr1PropMask) >> hdr1PropShift // index in range [0, 7]
	if propRef == 0 {                                 // literal follows
		if (hdr0 & bitDig) != 0 {
			if pos+32 > len(src) {
				return nil, errors.New("truncated digest")
			}
			copy(prop.dig[:], src[pos:pos+32])
			pos += 32
		}
		if (hdr0 & bitEncDig) != 0 {
			if pos+32 > len(src) {
				return nil, errors.New("truncated encdig")
			}
			copy(prop.encdig[:], src[pos:pos+32])
			pos += 32
		}
		if (hdr0 & bitOper) != 0 {
			if pos+1 > len(src) {
				return nil, errors.New("truncated rnd marker")
			}
			n := msgpVaruintLen(src[pos])
			if pos+n > len(src) {
				return nil, errors.New("truncated oper")
			}
			copy(prop.operEnc[:], src[pos:pos+n])
			prop.operLen = uint8(n)
			pos += n
		}
		if (hdr0 & bitOprop) != 0 {
			if pos+32 > len(src) {
				return nil, errors.New("truncated oprop")
			}
			copy(prop.oprop[:], src[pos:pos+32])
			pos += 32
		}
		prop.mask = hdr0 & propFieldsMask
		// add literal to the proposal window
		d.proposalWindow.insertNew(prop)
	} else { // reference index 1-7
		var ok bool
		prop, ok = d.proposalWindow.byRef(int(propRef))
		if !ok {
			return nil, errors.New("bad proposal ref")
		}
	}

	// write proposal bytes (from either literal or reference)
	if (prop.mask & bitDig) != 0 {
		out = append(out, prop.dig[:]...)
	}
	if (prop.mask & bitEncDig) != 0 {
		out = append(out, prop.encdig[:]...)
	}
	if (prop.mask & bitOper) != 0 {
		out = append(out, prop.operEnc[:prop.operLen]...)
	}
	if (prop.mask & bitOprop) != 0 {
		out = append(out, prop.oprop[:]...)
	}

	// r.rnd: perform delta decoding
	var rnd uint64
	switch hdr1 & hdr1RndMask {
	case hdr1RndDeltaSame:
		rnd = d.lastRnd
		out = appendMsgpVaruint(out, rnd)
	case hdr1RndDeltaPlus1:
		rnd = d.lastRnd + 1
		out = appendMsgpVaruint(out, rnd)
	case hdr1RndDeltaMinus1:
		rnd = d.lastRnd - 1
		out = appendMsgpVaruint(out, rnd)
	case hdr1RndLiteral:
		if pos+1 > len(src) {
			return nil, errors.New("truncated rnd marker")
		}
		n := msgpVaruintLen(src[pos])
		if pos+n > len(src) {
			return nil, errors.New("truncated rnd")
		}
		rnd = decodeMsgpVaruint(src[pos : pos+n])
		out = append(out, src[pos:pos+n]...)
		pos += n
	}
	d.lastRnd = rnd

	// r.snd: check for reference to LRU table
	if (hdr1 & hdr1SndRef) != 0 { // reference
		id, err := decodeDynamicRef(src, &pos)
		if err != nil {
			return nil, err
		}
		addr, ok := d.sndTable.fetch(id)
		if !ok {
			return nil, errors.New("bad sender ref")
		}
		out = append(out, addr[:]...)
	} else { // literal
		if pos+32 > len(src) {
			return nil, errors.New("truncated sender")
		}
		var addr addressValue
		copy(addr[:], src[pos:pos+32])
		out = append(out, addr[:]...)
		_ = d.sndTable.insert(addr, addr.hash())
		pos += 32
	}

	// r.step: pass through, if present
	if (hdr0 & bitStep) != 0 {
		if pos+1 > len(src) {
			return nil, errors.New("truncated rnd marker")
		}
		n := msgpVaruintLen(src[pos])
		if pos+n > len(src) {
			return nil, errors.New("truncated step")
		}
		out = append(out, src[pos:pos+n]...)
		pos += n
	}

	// sig.p + p1s: check for reference to LRU table
	if (hdr1 & hdr1PkRef) != 0 { // reference
		id, err := decodeDynamicRef(src, &pos)
		if err != nil {
			return nil, err
		}
		pkb, ok := d.pkTable.fetch(id)
		if !ok {
			return nil, errors.New("bad pk ref")
		}
		out = append(out, pkb.pk[:]...)
		out = append(out, pkb.sig[:]...)
	} else { // literal
		if pos+96 > len(src) {
			return nil, errors.New("truncated pk bundle")
		}
		var pkb pkSigPair
		copy(pkb.pk[:], src[pos:pos+32])
		copy(pkb.sig[:], src[pos+32:pos+96])
		out = append(out, pkb.pk[:]...)
		out = append(out, pkb.sig[:]...)
		_ = d.pkTable.insert(pkb, pkb.hash())
		pos += 96
	}

	// sig.p2 + p2s: check for reference to LRU table
	if (hdr1 & hdr1Pk2Ref) != 0 { // reference
		id, err := decodeDynamicRef(src, &pos)
		if err != nil {
			return nil, err
		}
		pk2b, ok := d.pk2Table.fetch(id)
		if !ok {
			return nil, errors.New("bad pk2 ref")
		}
		out = append(out, pk2b.pk[:]...)
		out = append(out, pk2b.sig[:]...)
	} else { // literal
		if pos+96 > len(src) {
			return nil, errors.New("truncated pk2 bundle")
		}
		var pk2b pkSigPair
		copy(pk2b.pk[:], src[pos:pos+32])
		copy(pk2b.sig[:], src[pos+32:pos+96])
		out = append(out, pk2b.pk[:]...)
		out = append(out, pk2b.sig[:]...)
		_ = d.pk2Table.insert(pk2b, pk2b.hash())
		pos += 96
	}

	// sig.s: pass through
	if pos+64 > len(src) {
		return nil, errors.New("truncated sig.s")
	}
	out = append(out, src[pos:pos+64]...)
	pos += 64

	if pos != len(src) {
		return nil, fmt.Errorf("length mismatch: expected %d, got %d", len(src), pos)
	}
	return out, nil
}
