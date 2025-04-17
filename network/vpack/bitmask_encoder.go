package vpack

import (
	"fmt"
	"math/bits"
)

// A vote is made up of 14 values, some of which are optional.  The required
// values are cred.pf, r.rnd, sig.p, sig.p1s, sig.p2, sig.p2s, and sig.s (sig.ps
// is always zero).  The remaining 7 optional values are either present or
// omitted, and their presence is indicated in a 1-byte bitmask header.
const (
	bitPer    uint8 = 1 << iota // r.per
	bitDig                      // r.prop.dig
	bitEncDig                   // r.prop.encdig
	bitOper                     // r.prop.oper
	bitOprop                    // r.prop.oprop
	bitSnd                      // r.snd
	bitStep                     // r.step
)

const (
	propFieldsMask    uint8 = bitDig | bitEncDig | bitOper | bitOprop
	rawVoteFieldsMask uint8 = bitPer | propFieldsMask | bitSnd | bitStep
)

// BitmaskEncoder is a VPack encoder that encodes data using a header bitmask followed
// by each enabled field, in msgpack canonical order.
type BitmaskEncoder struct {
	buf  []byte
	mask uint8
}

// NewBitmaskEncoder returns a new BitmaskEncoder.
func NewBitmaskEncoder() *BitmaskEncoder {
	return &BitmaskEncoder{}
}

// CompressVote compresses a vote using a header bitmask followed by each enabled
// field, in msgpack canonical order.
func (e *BitmaskEncoder) CompressVote(dst, src []byte) ([]byte, error) {
	if dst == nil {
		dst = make([]byte, 0, defaultCompressCapacity)
	}
	e.buf = dst[:0]
	// put empty 2-byte header at beginning, to fill in later
	e.buf = append(e.buf, byte(0), byte(0))
	e.mask = 0
	err := parseVote(src, e)
	if err != nil {
		return nil, err
	}
	// fill in header's first byte with mask
	e.buf[0] = e.mask
	return e.buf, nil
}

func (e *BitmaskEncoder) updateMask(staticIdx uint8) {
	switch staticIdx {
	case staticIdxPerField:
		e.mask |= bitPer
	case staticIdxDigField:
		e.mask |= bitDig
	case staticIdxEncdigField:
		e.mask |= bitEncDig
	case staticIdxOperField:
		e.mask |= bitOper
	case staticIdxOpropField:
		e.mask |= bitOprop
	case staticIdxSndField:
		e.mask |= bitSnd
	case staticIdxStepField:
		e.mask |= bitStep
	}
}

// writeStatic implements the compressWriter interface.
func (e *BitmaskEncoder) writeStatic(staticIdx uint8) {
	// ignore all static indexes
}

// writeVaruint implements the compressWriter interface, but never returns error.
// It passes the msgpack-encoded varuint bytes through as-is.
func (e *BitmaskEncoder) writeVaruint(fieldNameIdx uint8, b []byte) error {
	e.updateMask(fieldNameIdx)
	e.buf = append(e.buf, b...)
	return nil
}

func (e *BitmaskEncoder) writeBin32(idx uint8, b [32]byte) {
	e.updateMask(idx)
	e.buf = append(e.buf, b[:]...)
}

func (e *BitmaskEncoder) writeBin64(idx uint8, b [64]byte) {
	e.updateMask(idx)
	e.buf = append(e.buf, b[:]...)
}

func (e *BitmaskEncoder) writeBin80(idx uint8, b [80]byte) {
	e.updateMask(idx)
	e.buf = append(e.buf, b[:]...)
}

type BitmaskDecoder struct {
	dst, src []byte
	pos      int
}

func NewBitmaskDecoder() *BitmaskDecoder {
	return &BitmaskDecoder{}
}

func (d *BitmaskDecoder) rawVoteMapSize(mask uint8) (cnt uint8) {
	// Count how many of per, snd, step are set (rnd must be present)
	cnt = 1 + uint8(bits.OnesCount8(mask&(bitPer|bitSnd|bitStep)))
	// Add 1 if any prop bits are set
	if mask&propFieldsMask != 0 {
		cnt++
	}
	return
}

func (d *BitmaskDecoder) proposalValueMapSize(mask uint8) uint8 {
	// Count how many of dig, encdig, oper, oprop are set
	return uint8(bits.OnesCount8(mask & (bitDig | bitEncDig | bitOper | bitOprop)))
}

func (d *BitmaskDecoder) DecompressVote(dst, src []byte) ([]byte, error) {
	if len(src) < 2 {
		return nil, fmt.Errorf("bitmask missing")
	}
	mask := uint8(src[0])
	d.pos = 2
	d.src = src
	d.dst = dst
	if d.dst == nil {
		d.dst = make([]byte, 0, len(d.src)*4/3)
	}

	// top-level UnauthenticatedVote: fixmap(3) { cred, rawVote, sig }
	d.dst = append(d.dst, staticTable[staticIdxMapMarker3]...)

	// cred: fixmap(1) { pf: bin8(80) }
	d.dst = append(d.dst, staticTable[staticIdxCredField]...)
	d.dst = append(d.dst, staticTable[staticIdxMapMarker1]...)

	// cred.pf is always present
	if err := d.literalBin80(staticIdxPfField); err != nil {
		return nil, err
	}

	// rawVote: fixmap { per, prop, rnd, snd, step }
	d.dst = append(d.dst, staticTable[staticIdxRField]...)
	d.dst = append(d.dst, fixMapMask|d.rawVoteMapSize(mask))

	// rawVote.per
	if (mask & bitPer) != 0 {
		if err := d.varuint(staticIdxPerField); err != nil {
			return nil, err
		}
	}

	// rawVote.prop could be zero (bottom vote is empty value)
	if (mask & propFieldsMask) != 0 {
		// proposalValue: fixmap { dig, encdig, oper, oprop }
		d.dst = append(d.dst, staticTable[staticIdxPropField]...)
		d.dst = append(d.dst, fixMapMask|d.proposalValueMapSize(mask))
		// prop.dig
		if (mask & bitDig) != 0 {
			if err := d.dynamicBin32(staticIdxDigField); err != nil {
				return nil, err
			}
		}
		// prop.encdig
		if (mask & bitEncDig) != 0 {
			if err := d.dynamicBin32(staticIdxEncdigField); err != nil {
				return nil, err
			}
		}
		// prop.oper
		if (mask & bitOper) != 0 {
			if err := d.varuint(staticIdxOperField); err != nil {
				return nil, err
			}
		}
		// prop.oprop
		if (mask & bitOprop) != 0 {
			if err := d.dynamicBin32(staticIdxOpropField); err != nil {
				return nil, err
			}
		}
	}

	// rawVote.rnd is always present
	if err := d.varuint(staticIdxRndField); err != nil {
		return nil, err
	}

	// rawVote.snd
	if (mask & bitSnd) != 0 {
		if err := d.dynamicBin32(staticIdxSndField); err != nil {
			return nil, err
		}
	}
	// rawVote.step
	if (mask & bitStep) != 0 {
		if err := d.varuint(staticIdxStepField); err != nil {
			return nil, err
		}
	}

	// crypto.OneTimeSignature does not use omitempty; all fields are required
	// and always present.

	// sig: fixmap(6) { p, p1s, p2, p2s, ps, s }
	d.dst = append(d.dst, staticTable[staticIdxSigField]...)
	d.dst = append(d.dst, staticTable[staticIdxMapMarker6]...)
	// sig.p
	if err := d.dynamicBin32(staticIdxPField); err != nil {
		return nil, err
	}
	// sig.p1s
	if err := d.literalBin64(staticIdxP1sField); err != nil {
		return nil, err
	}
	// sig.p2
	if err := d.dynamicBin32(staticIdxP2Field); err != nil {
		return nil, err
	}
	// sig.p2s
	if err := d.literalBin64(staticIdxP2sField); err != nil {
		return nil, err
	}
	// sig.ps is always zero
	d.dst = append(d.dst, staticTable[staticIdxPsField]...)
	d.dst = append(d.dst, msgpBin8Len64...)
	d.dst = append(d.dst, make([]byte, 64)...)
	// sig.s
	if err := d.literalBin64(staticIdxSField); err != nil {
		return nil, err
	}

	if d.pos < len(d.src) {
		return nil, fmt.Errorf("unexpected trailing data: %d bytes remain", len(d.src)-d.pos)
	}

	return d.dst, nil
}

func (d *BitmaskDecoder) literalBin64(staticIdxField uint8) error {
	if d.pos+64 > len(d.src) {
		return fmt.Errorf("not enough data to read literal bin64 marker + value for field %d", staticIdxField)
	}
	d.dst = append(d.dst, staticTable[staticIdxField]...)
	d.dst = append(d.dst, msgpBin8Len64...)
	d.dst = append(d.dst, d.src[d.pos:d.pos+64]...)
	d.pos += 64
	return nil
}

func (d *BitmaskDecoder) dynamicBin32(staticIdxField uint8) error {
	if d.pos+32 > len(d.src) {
		return fmt.Errorf("not enough data to read dynamic bin32 marker + value for field %d", staticIdxField)
	}
	d.dst = append(d.dst, staticTable[staticIdxField]...)
	d.dst = append(d.dst, msgpBin8Len32...)
	d.dst = append(d.dst, d.src[d.pos:d.pos+32]...)
	d.pos += 32
	return nil
}

func (d *BitmaskDecoder) literalBin80(staticIdxField uint8) error {
	if d.pos+80 > len(d.src) {
		return fmt.Errorf("not enough data to read literal bin80 marker + value for field %d", staticIdxField)
	}
	d.dst = append(d.dst, staticTable[staticIdxField]...)
	d.dst = append(d.dst, msgpBin8Len80...)
	d.dst = append(d.dst, d.src[d.pos:d.pos+80]...)
	d.pos += 80
	return nil
}

func (d *BitmaskDecoder) varuint(staticIdxField uint8) error {
	if d.pos+1 > len(d.src) {
		return fmt.Errorf("not enough data to read varuint marker for field %d", staticIdxField)
	}
	marker := d.src[d.pos] // read msgpack varuint marker
	moreBytes := 0
	switch marker {
	case uint8tag:
		moreBytes = 1
	case uint16tag:
		moreBytes = 2
	case uint32tag:
		moreBytes = 4
	case uint64tag:
		moreBytes = 8
	default: // fixint uses a single byte for marker+value
		if !isfixint(marker) {
			return fmt.Errorf("not a fixint for field %d, got %d", staticIdxField, marker)
		}
		moreBytes = 0
	}

	if d.pos+1+moreBytes > len(d.src) {
		return fmt.Errorf("not enough data for varuint (need %d bytes) for field %d", moreBytes, staticIdxField)
	}
	d.dst = append(d.dst, staticTable[staticIdxField]...)
	d.dst = append(d.dst, marker)
	if moreBytes > 0 {
		d.dst = append(d.dst, d.src[d.pos+1:d.pos+moreBytes+1]...)
	}
	d.pos += moreBytes + 1 // account for marker byte + value bytes

	return nil
}
