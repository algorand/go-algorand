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
	"math"

	"github.com/algorand/msgp/msgp"
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
//	| +-------------- (sig.p, sig.p1s) table reference (0=literal, 1=table)
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

	// sizes used below
	pfSize     = 80 // committee.VrfProof
	digestSize = 32 // crypto.Digest (and basics.Address)
	sigSize    = 64 // crypto.Signature
	pkSize     = 32 // crypto.PublicKey
)

// StatefulEncoder compresses votes by using references to previously seen values
// from earlier votes.
type StatefulEncoder struct{ dynamicTableState }

// StatefulDecoder decompresses votes by using references to previously seen values
// from earlier votes.
type StatefulDecoder struct{ dynamicTableState }

// NewStatefulEncoder creates a new StatefulEncoder with initialized LRU tables of the specified size
func NewStatefulEncoder(tableSize uint) (*StatefulEncoder, error) {
	e := &StatefulEncoder{}
	if err := e.initTables(tableSize); err != nil {
		return nil, err
	}
	return e, nil
}

// NewStatefulDecoder creates a new StatefulDecoder with initialized LRU tables of the specified size
func NewStatefulDecoder(tableSize uint) (*StatefulDecoder, error) {
	d := &StatefulDecoder{}
	if err := d.initTables(tableSize); err != nil {
		return nil, err
	}
	return d, nil
}

// dynamicTableState is shared by StatefulEncoder and StatefulDecoder. It contains
// the necessary state for tracking references to previously seen values.
type dynamicTableState struct {
	// LRU hash tables for snd, p+p1s, and p2+p2s
	sndTable *lruTable[addressValue] // 512 * 2 * 32 = 32KB
	pkTable  *lruTable[pkSigPair]    // 512 * 2 * 96 = 96KB
	pk2Table *lruTable[pkSigPair]    // 512 * 2 * 96 = 96KB

	// 8-slot window of recent proposal values
	proposalWindow propWindow

	// last round number seen in previous vote
	lastRnd uint64
}

// pkSigPair is a 32-byte public key + 64-byte signature
// used for the LRU tables for p+p1s and p2+p2s.
type pkSigPair struct {
	pk  [pkSize]byte
	sig [sigSize]byte
}

func (p *pkSigPair) hash() uint64 {
	// Since pk and sig should already be uniformly distributed, we can use a
	// simple XOR of the first 8 bytes of each to get a good hash.
	// Any invalid votes intentionally designed to cause collisions will only
	// affect the sending peer's own per-peer compression state, and cause
	// agreement to disconnect the peer.
	return binary.LittleEndian.Uint64(p.pk[:8]) ^ binary.LittleEndian.Uint64(p.sig[:8])
}

// addressValue is a 32-byte address used for the LRU table for snd.
type addressValue [digestSize]byte

func (v *addressValue) hash() uint64 {
	// addresses are fairly uniformly distributed, so we can use a simple XOR
	return binary.LittleEndian.Uint64(v[:8]) ^ binary.LittleEndian.Uint64(v[8:16]) ^
		binary.LittleEndian.Uint64(v[16:24]) ^ binary.LittleEndian.Uint64(v[24:])
}

// initTables initializes the LRU tables with the specified size for all tables
func (s *dynamicTableState) initTables(tableSize uint) error {
	var err error
	if s.sndTable, err = newLRUTable[addressValue](tableSize); err != nil {
		return err
	}
	if s.pkTable, err = newLRUTable[pkSigPair](tableSize); err != nil {
		return err
	}
	if s.pk2Table, err = newLRUTable[pkSigPair](tableSize); err != nil {
		return err
	}
	return nil
}

// statefulReader helps StatefulEncoder and StatefulDecoder to read from a
// source buffer with bounds checking.
type statefulReader struct {
	src []byte
	pos int
}

func (r *statefulReader) readFixed(n int, field string) ([]byte, error) {
	if r.pos+n > len(r.src) {
		return nil, fmt.Errorf("truncated %s", field)
	}
	data := r.src[r.pos : r.pos+n]
	r.pos += n
	return data, nil
}

func (r *statefulReader) readVaruintBytes(field string) ([]byte, error) {
	if r.pos+1 > len(r.src) {
		return nil, fmt.Errorf("truncated %s marker", field)
	}
	more, err := msgpVaruintRemaining(r.src[r.pos])
	if err != nil {
		return nil, fmt.Errorf("invalid %s marker: %w", field, err)
	}
	total := 1 + more
	if r.pos+total > len(r.src) {
		return nil, fmt.Errorf("truncated %s", field)
	}
	data := r.src[r.pos : r.pos+total]
	r.pos += total
	return data, nil
}

func (r *statefulReader) readVaruint(field string) ([]byte, uint64, error) {
	data, err := r.readVaruintBytes(field)
	if err != nil {
		return nil, 0, err
	}
	// decode: readVaruintBytes has already validated the marker
	var value uint64
	switch len(data) {
	case 1: // fixint (values 0-127)
		value = uint64(data[0])
	case 2: // uint8 (marker + uint8)
		value = uint64(data[1])
	case 3: // uint16 (marker + uint16)
		value = uint64(binary.BigEndian.Uint16(data[1:]))
	case 5: // uint32 (marker + uint32)
		value = uint64(binary.BigEndian.Uint32(data[1:]))
	case 9: // uint64 (marker + uint64)
		value = binary.BigEndian.Uint64(data[1:])
	default:
		return nil, 0, fmt.Errorf("readVaruint: %s unexpected length %d", field, len(data))
	}

	return data, value, nil
}

// readDynamicRef reads an LRU table reference ID from the statefulReader.
func (r *statefulReader) readDynamicRef(field string) (lruTableReferenceID, error) {
	if r.pos+2 > len(r.src) {
		return 0, fmt.Errorf("truncated %s", field)
	}
	id := binary.BigEndian.Uint16(r.src[r.pos : r.pos+2])
	r.pos += 2
	return lruTableReferenceID(id), nil
}

// appendDynamicRef encodes an LRU table reference ID and appends it to dst.
func appendDynamicRef(dst []byte, id lruTableReferenceID) []byte {
	return binary.BigEndian.AppendUint16(dst, uint16(id))
}

// Compress takes a vote compressed by StatelessEncoder, and additionally
// compresses it using dynamic references to previously seen values.
func (e *StatefulEncoder) Compress(dst, src []byte) ([]byte, error) {
	r := statefulReader{src: src, pos: 0}

	// Read header
	header, err := r.readFixed(2, "header")
	if err != nil {
		return nil, errors.New("src too short")
	}
	hdr0 := header[0] // from StatelessEncoder
	var hdr1 byte     // StatefulEncoder header

	// prepare output, leave room for 2-byte header
	out := dst[:0]
	out = append(out, hdr0, 0) // will fill in with hdr1 later

	// cred.pf: pass through
	pf, err := r.readFixed(pfSize, "pf")
	if err != nil {
		return nil, err
	}
	out = append(out, pf...)

	// r.per: pass through, if present
	if (hdr0 & bitPer) != 0 {
		perData, err1 := r.readVaruintBytes("r.per")
		if err1 != nil {
			return nil, err1
		}
		out = append(out, perData...)
	}

	// r.prop: check LRU window
	// copy proposal fields for table lookup
	var prop proposalEntry
	if (hdr0 & bitDig) != 0 {
		dig, err1 := r.readFixed(digestSize, "dig")
		if err1 != nil {
			return nil, err1
		}
		copy(prop.dig[:], dig)
	}
	if (hdr0 & bitEncDig) != 0 {
		encdig, err1 := r.readFixed(digestSize, "encdig")
		if err1 != nil {
			return nil, err1
		}
		copy(prop.encdig[:], encdig)
	}
	if (hdr0 & bitOper) != 0 {
		operData, err1 := r.readVaruintBytes("oper")
		if err1 != nil {
			return nil, err1
		}
		copy(prop.operEnc[:], operData)
		prop.operLen = uint8(len(operData))
	}
	if (hdr0 & bitOprop) != 0 {
		oprop, err1 := r.readFixed(digestSize, "oprop")
		if err1 != nil {
			return nil, err1
		}
		copy(prop.oprop[:], oprop)
	}
	prop.mask = hdr0 & propFieldsMask

	if idx := e.proposalWindow.lookup(prop); idx != 0 {
		hdr1 |= byte(idx) << hdr1PropShift // set 001..111
	} else {
		// not found: send literal and add to window (don't touch hdr1)
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
	rndData, rnd, err := r.readVaruint("rnd")
	if err != nil {
		return nil, err
	}

	switch { // delta encoding
	case rnd == e.lastRnd:
		hdr1 |= hdr1RndDeltaSame
	case rnd == e.lastRnd+1 && e.lastRnd < math.MaxUint64: // avoid overflow
		hdr1 |= hdr1RndDeltaPlus1
	case rnd == e.lastRnd-1 && e.lastRnd > 0: // avoid underflow
		hdr1 |= hdr1RndDeltaMinus1
	default:
		// pass through literal bytes (don't touch hdr1)
		out = append(out, rndData...)
	}
	e.lastRnd = rnd

	// r.snd: check LRU table
	sndData, err := r.readFixed(digestSize, "sender")
	if err != nil {
		return nil, err
	}
	var snd addressValue
	copy(snd[:], sndData)
	sndH := snd.hash()
	if id, ok := e.sndTable.lookup(snd, sndH); ok {
		// found in table, use reference
		hdr1 |= hdr1SndRef
		out = appendDynamicRef(out, id)
	} else { // not found, add to table and use literal
		out = append(out, snd[:]...)
		e.sndTable.insert(snd, sndH)
	}

	// r.step: pass through, if present
	if (hdr0 & bitStep) != 0 {
		stepData, err1 := r.readVaruintBytes("step")
		if err1 != nil {
			return nil, err1
		}
		out = append(out, stepData...)
	}

	// sig.p + sig.p1s: check LRU table
	pkBundle, err := r.readFixed(pkSize+sigSize, "pk bundle")
	if err != nil {
		return nil, err
	}
	var pk pkSigPair
	copy(pk.pk[:], pkBundle[:pkSize])
	copy(pk.sig[:], pkBundle[pkSize:])

	pkH := pk.hash()
	if id, ok := e.pkTable.lookup(pk, pkH); ok {
		// found in table, use reference
		hdr1 |= hdr1PkRef
		out = appendDynamicRef(out, id)
	} else { // not found, add to table and use literal
		out = append(out, pk.pk[:]...)
		out = append(out, pk.sig[:]...)
		e.pkTable.insert(pk, pkH)
	}

	// sig.p2 + sig.p2s: check LRU table
	pk2Bundle, err := r.readFixed(pkSize+sigSize, "pk2 bundle")
	if err != nil {
		return nil, err
	}
	var pk2 pkSigPair
	copy(pk2.pk[:], pk2Bundle[:pkSize])
	copy(pk2.sig[:], pk2Bundle[pkSize:])

	pk2H := pk2.hash()
	if id, ok := e.pk2Table.lookup(pk2, pk2H); ok {
		// found in table, use reference
		hdr1 |= hdr1Pk2Ref
		out = appendDynamicRef(out, id)
	} else { // not found, add to table and use literal
		out = append(out, pk2.pk[:]...)
		out = append(out, pk2.sig[:]...)
		e.pk2Table.insert(pk2, pk2H)
	}

	// sig.s: pass through
	sigs, err := r.readFixed(sigSize, "sig.s")
	if err != nil {
		return nil, err
	}
	out = append(out, sigs...)

	if r.pos != len(src) {
		return nil, fmt.Errorf("length mismatch: expected %d, got %d", len(src), r.pos)
	}

	// fill in stateful header (hdr0 is unchanged)
	out[1] = hdr1
	return out, nil
}

// Decompress reverses StatefulEncoder, and writes a valid stateless vpack
// format buffer into dst. Caller must then pass it to StatelessDecoder.
func (d *StatefulDecoder) Decompress(dst, src []byte) ([]byte, error) {
	r := statefulReader{src: src, pos: 0}

	// Read header
	header, err := r.readFixed(2, "header")
	if err != nil {
		return nil, errors.New("input shorter than header")
	}
	hdr0 := header[0] // from StatelessEncoder
	hdr1 := header[1] // from StatefulEncoder

	// prepare out; stateless size <= original
	out := dst[:0]
	out = append(out, hdr0, 0) // StatelessDecoder-compatible header

	// cred.pf: pass through
	pf, err := r.readFixed(pfSize, "pf")
	if err != nil {
		return nil, err
	}
	out = append(out, pf...)

	// r.per: pass through, if present
	if (hdr0 & bitPer) != 0 {
		perData, err1 := r.readVaruintBytes("per")
		if err1 != nil {
			return nil, err1
		}
		out = append(out, perData...)
	}

	// r.prop: check for reference to LRU window
	var prop proposalEntry
	propRef := (hdr1 & hdr1PropMask) >> hdr1PropShift // index in range [0, 7]
	if propRef == 0 {                                 // literal follows
		if (hdr0 & bitDig) != 0 {
			dig, err1 := r.readFixed(digestSize, "digest")
			if err1 != nil {
				return nil, err1
			}
			copy(prop.dig[:], dig)
		}
		if (hdr0 & bitEncDig) != 0 {
			encdig, err1 := r.readFixed(digestSize, "encdig")
			if err1 != nil {
				return nil, err1
			}
			copy(prop.encdig[:], encdig)
		}
		if (hdr0 & bitOper) != 0 {
			operData, err1 := r.readVaruintBytes("oper")
			if err1 != nil {
				return nil, err1
			}
			copy(prop.operEnc[:], operData)
			prop.operLen = uint8(len(operData))
		}
		if (hdr0 & bitOprop) != 0 {
			oprop, err1 := r.readFixed(digestSize, "oprop")
			if err1 != nil {
				return nil, err1
			}
			copy(prop.oprop[:], oprop)
		}
		prop.mask = hdr0 & propFieldsMask
		// add literal to the proposal window
		d.proposalWindow.insertNew(prop)
	} else { // reference index 1-7
		var ok bool
		prop, ok = d.proposalWindow.byRef(int(propRef))
		if !ok {
			return nil, fmt.Errorf("bad proposal ref: %v", propRef)
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
		out = msgp.AppendUint64(out, rnd)
	case hdr1RndDeltaPlus1:
		if d.lastRnd == math.MaxUint64 {
			return nil, fmt.Errorf("round overflow: lastRnd %d", d.lastRnd)
		}
		rnd = d.lastRnd + 1
		out = msgp.AppendUint64(out, rnd)
	case hdr1RndDeltaMinus1:
		if d.lastRnd == 0 {
			return nil, fmt.Errorf("round underflow: lastRnd %d", d.lastRnd)
		}
		rnd = d.lastRnd - 1
		out = msgp.AppendUint64(out, rnd)
	case hdr1RndLiteral:
		rndData, rndVal, err1 := r.readVaruint("rnd")
		if err1 != nil {
			return nil, err1
		}
		rnd = rndVal
		out = append(out, rndData...)
	}
	d.lastRnd = rnd

	// r.snd: check for reference to LRU table
	if (hdr1 & hdr1SndRef) != 0 { // reference
		id, err1 := r.readDynamicRef("snd ref")
		if err1 != nil {
			return nil, err1
		}
		addr, ok := d.sndTable.fetch(id)
		if !ok {
			return nil, fmt.Errorf("bad sender ref: %v", id)
		}
		out = append(out, addr[:]...)
	} else { // literal
		sndData, err1 := r.readFixed(digestSize, "sender")
		if err1 != nil {
			return nil, err1
		}
		var addr addressValue
		copy(addr[:], sndData)
		out = append(out, addr[:]...)
		d.sndTable.insert(addr, addr.hash())
	}

	// r.step: pass through, if present
	if (hdr0 & bitStep) != 0 {
		stepData, err1 := r.readVaruintBytes("step")
		if err1 != nil {
			return nil, err1
		}
		out = append(out, stepData...)
	}

	// sig.p + p1s: check for reference to LRU table
	if (hdr1 & hdr1PkRef) != 0 { // reference
		id, err1 := r.readDynamicRef("pk ref")
		if err1 != nil {
			return nil, err1
		}
		pkb, ok := d.pkTable.fetch(id)
		if !ok {
			return nil, fmt.Errorf("bad pk ref: %v", id)
		}
		out = append(out, pkb.pk[:]...)
		out = append(out, pkb.sig[:]...)
	} else { // literal
		pkBundle, err1 := r.readFixed(pkSize+sigSize, "pk bundle")
		if err1 != nil {
			return nil, err1
		}
		var pkb pkSigPair
		copy(pkb.pk[:], pkBundle[:pkSize])
		copy(pkb.sig[:], pkBundle[pkSize:])
		out = append(out, pkb.pk[:]...)
		out = append(out, pkb.sig[:]...)
		d.pkTable.insert(pkb, pkb.hash())
	}

	// sig.p2 + p2s: check for reference to LRU table
	if (hdr1 & hdr1Pk2Ref) != 0 { // reference
		id, err1 := r.readDynamicRef("pk2 ref")
		if err1 != nil {
			return nil, err1
		}
		pk2b, ok := d.pk2Table.fetch(id)
		if !ok {
			return nil, fmt.Errorf("bad pk2 ref: %v", id)
		}
		out = append(out, pk2b.pk[:]...)
		out = append(out, pk2b.sig[:]...)
	} else { // literal
		pk2Bundle, err1 := r.readFixed(pkSize+sigSize, "pk2 bundle")
		if err1 != nil {
			return nil, err1
		}
		var pk2b pkSigPair
		copy(pk2b.pk[:], pk2Bundle[:pkSize])
		copy(pk2b.sig[:], pk2Bundle[pkSize:])
		out = append(out, pk2b.pk[:]...)
		out = append(out, pk2b.sig[:]...)
		d.pk2Table.insert(pk2b, pk2b.hash())
	}

	// sig.s: pass through
	sigs, err := r.readFixed(sigSize, "sig.s")
	if err != nil {
		return nil, err
	}
	out = append(out, sigs...)

	if r.pos != len(src) {
		return nil, fmt.Errorf("length mismatch: expected %d, got %d", len(src), r.pos)
	}
	return out, nil
}
