// stateful_encoder.go
package vpack

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// StatefulEncoder compresses votes by using references to previously seen values
// from earlier votes.
type StatefulEncoder struct {
	dynamicTableState
}

func encodeDynamicRef(id lruTableReferenceID, dst *[]byte) {
	*dst = binary.BigEndian.AppendUint16(*dst, uint16(id))
}

// Compress takes stateless-encoded vote (canonical order) and
// returns stateful-compressed buffer.
func (e *StatefulEncoder) Compress(dst, src []byte) ([]byte, error) {
	if len(src) < 2 {
		return nil, errors.New("src too short")
	}
	maskP := src[0] // header[0] from stateless encoder
	pos := 2        // reader cursor

	// prepare output, leave room for 2-byte header
	out := dst[:0]
	out = append(out, 0, 0) // placeholder

	var hdr1 byte

	// cred.pf
	out = append(out, src[pos:pos+80]...)
	pos += 80

	// r.per
	if (maskP & bitPer) != 0 {
		n := msgpVaruintLen(src[pos])
		out = append(out, src[pos:pos+n]...)
		pos += n
	}

	// r.prop
	// copy proposal fields for table lookup
	var prop proposalEntry
	prop.mask = maskP & propFieldsMask
	if (maskP & bitDig) != 0 {
		copy(prop.dig[:], src[pos:pos+32])
		pos += 32
	}
	if (maskP & bitEncDig) != 0 {
		copy(prop.encdig[:], src[pos:pos+32])
		pos += 32
	}
	if (maskP & bitOper) != 0 {
		n := msgpVaruintLen(src[pos])
		copy(prop.operEnc[:], src[pos:pos+n])
		prop.operLen = uint8(n)
		pos += n
	}
	if (maskP & bitOprop) != 0 {
		copy(prop.oprop[:], src[pos:pos+32])
		pos += 32
	}

	// look up in sliding window
	if idx, ok := e.proposalWindow.indexOf(prop); ok {
		// reference
		hdr1 |= byte(idx+1) << 2 // 001..111  (000 will mean literal)
		e.proposalWindow.pushFront(prop, e.proposalWindow.slotAt(idx))
	} else {
		// literal
		hdr1 |= 0 << 2 // 000
		phys := e.proposalWindow.lruSlot()
		e.proposalWindow.pushFront(prop, phys)

		// write the literal bytes exactly as in stateless stream
		if (maskP & bitDig) != 0 {
			out = append(out, prop.dig[:]...)
		}
		if (maskP & bitEncDig) != 0 {
			out = append(out, prop.encdig[:]...)
		}
		if (maskP & bitOper) != 0 {
			out = append(out, prop.operEnc[:prop.operLen]...)
		}
		if (maskP & bitOprop) != 0 {
			out = append(out, prop.oprop[:]...)
		}
	}

	// r.rnd
	rndStart := pos
	n := msgpVaruintLen(src[pos])
	rnd := decodeMsgpVaruint(src[pos : pos+n])
	pos += n

	switch {
	case rnd == e.lastRnd:
		hdr1 |= 0b11 // rndOp = same
	case rnd == e.lastRnd+1:
		hdr1 |= 0b01
	case rnd == e.lastRnd-1:
		hdr1 |= 0b10
	default:
		// literal
		hdr1 |= 0b00
		out = append(out, src[rndStart:pos]...)
	}
	e.lastRnd = rnd

	// r.snd
	var snd addressValue
	copy(snd[:], src[pos:pos+32])
	pos += 32
	if id, ok := e.sndTable.lookup(snd, snd.hash()); ok {
		hdr1 |= 1 << 5 // sndRef
		encodeDynamicRef(id, &out)
	} else {
		out = append(out, snd[:]...)
		e.sndTable.insert(snd, snd.hash())
	}

	// r.step
	if (maskP & bitStep) != 0 {
		n := msgpVaruintLen(src[pos])
		out = append(out, src[pos:pos+n]...)
		pos += n
	}

	// sig.p + sig.p1s
	var pk pkSigPair
	copy(pk.pk[:], src[pos:pos+32])
	pos += 32
	copy(pk.sig[:], src[pos:pos+64])
	pos += 64

	if id, ok := e.pkTable.lookup(pk, pk.hash()); ok {
		hdr1 |= 1 << 6 // pkRef
		encodeDynamicRef(id, &out)
	} else {
		out = append(out, pk.pk[:]...)
		out = append(out, pk.sig[:]...)
		_ = e.pkTable.insert(pk, pk.hash())
	}

	// sig.p2 + sig.p2s
	var pk2 pkSigPair
	copy(pk2.pk[:], src[pos:pos+32])
	pos += 32
	copy(pk2.sig[:], src[pos:pos+64])
	pos += 64

	if id, ok := e.pk2Table.lookup(pk2, pk2.hash()); ok {
		hdr1 |= 1 << 7 // pk2Ref
		encodeDynamicRef(id, &out)
	} else {
		out = append(out, pk2.pk[:]...)
		out = append(out, pk2.sig[:]...)
		_ = e.pk2Table.insert(pk2, pk2.hash())
	}

	// sig.s
	out = append(out, src[pos:pos+64]...)
	pos += 64

	if pos != len(src) {
		return nil, fmt.Errorf("length mismatch: expected %d, got %d", len(src), pos)
	}

	// fill in headers
	out[0] = maskP
	out[1] = hdr1
	return out, nil
}
