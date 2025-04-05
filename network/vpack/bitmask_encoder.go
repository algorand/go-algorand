package vpack

import (
	"fmt"
	"math/bits"
)

// A vote is made up of 14 values, some of which are optional.
// This bitmask is used for 2-byte header for each compressed vote.
// The bitmask bits & following data appear in msgpack canonical order.
const (
	bitPf     uint16 = 1 << iota // cred.pf
	bitPer                       // r.per
	bitDig                       // r.prop.dig
	bitEncDig                    // r.prop.encdig
	bitOper                      // r.prop.oper
	bitOprop                     // r.prop.oprop
	bitRnd                       // r.rnd
	bitSnd                       // r.snd
	bitStep                      // r.step
	bitP                         // sig.p
	bitP1s                       // sig.p1s
	bitP2                        // sig.p2
	bitP2s                       // sig.p2s
	bitS                         // sig.s
)

const (
	sigFieldsMask     uint16 = bitP | bitP1s | bitP2 | bitP2s | bitS
	propFieldsMask    uint16 = bitDig | bitEncDig | bitOper | bitOprop
	rawVoteFieldsMask uint16 = bitPer | propFieldsMask | bitRnd | bitSnd | bitStep
)

// BitmaskEncoder is a VPack encoder that encodes data using a header bitmask followed
// by each enabled field, in msgpack canonical order.
type BitmaskEncoder struct {
	buf  []byte
	mask uint16
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
	// put empty 2-byte mask at beginning, to fill in later
	e.buf = append(e.buf, 0, 0)
	e.mask = 0
	err := parseVote(src, e)
	if err != nil {
		return nil, err
	}
	// fill in mask
	e.buf[0] = byte(e.mask >> 8)
	e.buf[1] = byte(e.mask)
	return e.buf, nil
}

func (e *BitmaskEncoder) updateMask(staticIdx uint8) {
	switch staticIdx {
	case staticIdxPfField:
		e.mask |= bitPf
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
	case staticIdxRndField:
		e.mask |= bitRnd
	case staticIdxSndField:
		e.mask |= bitSnd
	case staticIdxStepField:
		e.mask |= bitStep
	case staticIdxPField:
		e.mask |= bitP
	case staticIdxP1sField:
		e.mask |= bitP1s
	case staticIdxP2Field:
		e.mask |= bitP2
	case staticIdxP2sField:
		e.mask |= bitP2s
	case staticIdxSField:
		e.mask |= bitS
	}
}

// writeStatic implements the compressWriter interface.
func (e *BitmaskEncoder) writeStatic(staticIdx uint8) {
	// ignore all static indexes
}

// writeDynamicVaruint implements the compressWriter interface, but never returns error.
// It passes the msgpack-encoded varuint bytes through as-is.
func (e *BitmaskEncoder) writeDynamicVaruint(fieldNameIdx uint8, b []byte) error {
	e.updateMask(fieldNameIdx)
	e.buf = append(e.buf, b...)
	return nil
}

func (e *BitmaskEncoder) writeDynamicBin32(idx uint8, b [32]byte) {
	e.updateMask(idx)
	e.buf = append(e.buf, b[:]...)
}

func (e *BitmaskEncoder) writeLiteralBin64(idx uint8, b [64]byte) {
	e.updateMask(idx)
	e.buf = append(e.buf, b[:]...)
}

func (e *BitmaskEncoder) writeLiteralBin80(idx uint8, b [80]byte) {
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

func (d *BitmaskDecoder) unauthenticatedVoteMapSize(mask uint16) (cnt uint8) {
	// Count how many of cred, rawVote, sig are set
	if mask&bitPf != 0 {
		cnt++
	}
	if mask&rawVoteFieldsMask != 0 {
		cnt++
	}
	if mask&sigFieldsMask != 0 {
		cnt++
	}
	return
}

func (d *BitmaskDecoder) rawVoteMapSize(mask uint16) (cnt uint8) {
	// Count how many of per, rnd, snd, step are set
	cnt = uint8(bits.OnesCount16(mask & (bitPer | bitRnd | bitSnd | bitStep)))
	// Add 1 if any prop bits are set
	if mask&propFieldsMask != 0 {
		cnt++
	}
	return
}

func (d *BitmaskDecoder) proposalValueMapSize(mask uint16) uint8 {
	// Count how many of dig, encdig, oper, oprop are set
	return uint8(bits.OnesCount16(mask & (bitDig | bitEncDig | bitOper | bitOprop)))
}

func (d *BitmaskDecoder) DecompressVote(dst, src []byte) ([]byte, error) {
	if len(src) < 2 {
		return nil, fmt.Errorf("bitmask missing")
	}
	mask := uint16(src[0])<<8 | uint16(src[1])
	d.pos = 2
	d.src = src
	d.dst = dst
	if d.dst == nil {
		d.dst = make([]byte, 0, len(d.src)*4/3)
	}

	if mask == 0 {
		return nil, fmt.Errorf("empty bitmask")
	}

	// top-level UnauthenticatedVote: fixmap { cred, rawVote, sig }
	d.dst = append(d.dst, fixMapMask|d.unauthenticatedVoteMapSize(mask))

	if (mask & bitPf) != 0 {
		// cred: fixmap(1) { pf: bin8(80) }
		d.dst = append(d.dst, staticTable[staticIdxCredField]...)
		d.dst = append(d.dst, staticTable[staticIdxMapMarker1]...)
		// cred.pf
		if err := d.literalBin80(staticIdxPfField); err != nil {
			return nil, err
		}
	}

	if (mask & rawVoteFieldsMask) != 0 {
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

		// rawVote.rnd
		if (mask & bitRnd) != 0 {
			if err := d.varuint(staticIdxRndField); err != nil {
				return nil, err
			}
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
	}

	// crypto.OneTimeSignature does not use omitempty, so all fields must be written
	if (mask & sigFieldsMask) == sigFieldsMask {
		// sig: fixmap(6)
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
	} else {
		return nil, fmt.Errorf("bitmask does not contain all sig fields: %b", mask)
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
			return fmt.Errorf("not a fixint for field %d", staticIdxField)
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
