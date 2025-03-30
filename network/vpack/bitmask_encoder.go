package vpack

import (
	"fmt"
	"math/bits"
	"strings"
)

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
	sigFieldsMask      uint16 = bitP | bitP1s | bitP2 | bitP2s | bitS
	propFieldsMask     uint16 = bitDig | bitEncDig | bitOper | bitOprop
	requiredFieldsMask uint16 = bitPf | bitRnd | bitSnd | sigFieldsMask
)

func printMask(mask uint16) string {
	if mask == 0 {
		return "0"
	}
	var bitNames []string
	if mask&bitPf != 0 {
		bitNames = append(bitNames, "bitPf")
	}
	if mask&bitPer != 0 {
		bitNames = append(bitNames, "bitPer")
	}
	if mask&bitDig != 0 {
		bitNames = append(bitNames, "bitDig")
	}
	if mask&bitEncDig != 0 {
		bitNames = append(bitNames, "bitEncDig")
	}
	if mask&bitOper != 0 {
		bitNames = append(bitNames, "bitOper")
	}
	if mask&bitOprop != 0 {
		bitNames = append(bitNames, "bitOprop")
	}
	if mask&bitRnd != 0 {
		bitNames = append(bitNames, "bitRnd")
	}
	if mask&bitSnd != 0 {
		bitNames = append(bitNames, "bitSnd")
	}
	if mask&bitStep != 0 {
		bitNames = append(bitNames, "bitStep")
	}
	if mask&bitP != 0 {
		bitNames = append(bitNames, "bitP")
	}
	if mask&bitP1s != 0 {
		bitNames = append(bitNames, "bitP1s")
	}
	if mask&bitP2 != 0 {
		bitNames = append(bitNames, "bitP2")
	}
	if mask&bitP2s != 0 {
		bitNames = append(bitNames, "bitP2s")
	}
	if mask&bitS != 0 {
		bitNames = append(bitNames, "bitS")
	}
	return strings.Join(bitNames, ",")
}

// BitmaskEncoder is a VPack encoder that encodes a bitmask of fields.
type BitmaskEncoder struct {
	buf  []byte
	mask uint16
}

// NewBitmaskEncoder returns a new BitmaskEncoder.
func NewBitmaskEncoder() *BitmaskEncoder {
	return &BitmaskEncoder{}
}

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

// writeStatic does nothing
func (e *BitmaskEncoder) writeStatic(staticIdx uint8) {
	switch staticIdx {
	case staticIdxStepVal1Field:
		_ = e.writeDynamicVaruint(staticIdxStepField, []byte{0x01})
	case staticIdxStepVal2Field:
		_ = e.writeDynamicVaruint(staticIdxStepField, []byte{0x02})
	case staticIdxStepVal3Field:
		_ = e.writeDynamicVaruint(staticIdxStepField, []byte{0x03})
	}
	// ignore all other static indexes
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
	e.buf = append(e.buf, markerDynamicBin32)
	e.buf = append(e.buf, b[:]...)
}

func (e *BitmaskEncoder) writeLiteralBin64(idx uint8, b [64]byte) {
	e.updateMask(idx)
	e.buf = append(e.buf, markerLiteralBin64)
	e.buf = append(e.buf, b[:]...)
}

func (e *BitmaskEncoder) writeLiteralBin80(idx uint8, b [80]byte) {
	e.updateMask(idx)
	e.buf = append(e.buf, markerLiteralBin80)
	e.buf = append(e.buf, b[:]...)
}

type BitmaskDecoder struct {
	dst, src []byte
	pos      int
}

func NewBitmaskDecoder() *BitmaskDecoder {
	return &BitmaskDecoder{}
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

	if mask&requiredFieldsMask != requiredFieldsMask {
		return nil, fmt.Errorf("missing required fields: mask %s", printMask(mask))
	}

	// top-level UnauthenticatedVote: fixmap(3)
	d.dst = append(d.dst, staticTable[staticIdxMapMarker3]...)
	// cred: fixmap(1) { pf: bin8(80) }
	d.dst = append(d.dst, staticTable[staticIdxCredField]...)
	d.dst = append(d.dst, staticTable[staticIdxMapMarker1]...)

	// cred.pf should always appear (checked in requiredFieldsMask)
	if err := d.literalBin80(staticIdxPfField); err != nil {
		return nil, err
	}

	// rawVote: write fixMap(sz)
	d.dst = append(d.dst, staticTable[staticIdxRField]...)
	d.dst = append(d.dst, fixMapMask|d.rawVoteMapSize(mask))

	// rawVote.per is optional
	if (mask & bitPer) != 0 {
		if err := d.varuint(staticIdxPerField); err != nil {
			return nil, err
		}
	}

	// rawVote.prop is optional (bottom vote is empty)
	if (mask & propFieldsMask) != 0 {
		// write prop: fixmap(sz)
		d.dst = append(d.dst, staticTable[staticIdxPropField]...)
		d.dst = append(d.dst, fixMapMask|d.proposalValueMapSize(mask))

		if (mask & bitDig) != 0 {
			if err := d.dynamicBin32(staticIdxDigField); err != nil {
				return nil, err
			}
		}
		if (mask & bitEncDig) != 0 {
			if err := d.dynamicBin32(staticIdxEncdigField); err != nil {
				return nil, err
			}
		}
		if (mask & bitOper) != 0 {
			if err := d.varuint(staticIdxOperField); err != nil {
				return nil, err
			}
		}
		if (mask & bitOprop) != 0 {
			if err := d.dynamicBin32(staticIdxOpropField); err != nil {
				return nil, err
			}
		}
	}

	// rawVote.rnd should always appear (checked in requiredFieldsMask)
	if err := d.varuint(staticIdxRndField); err != nil {
		return nil, err
	}

	// rawVote.snd should always appear (checked in requiredFieldsMask)
	if err := d.dynamicBin32(staticIdxSndField); err != nil {
		return nil, err
	}

	// rawVote.step is optional
	if (mask & bitStep) != 0 {
		if err := d.varuint(staticIdxStepField); err != nil {
			return nil, err
		}
	}

	// sig: fixmap(6)
	// all sig fields are required (checked in requiredFieldsMask)
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
	if d.pos+1+64 > len(d.src) {
		return fmt.Errorf("not enough data to read literal bin64 marker + value for field %d", staticIdxField)
	}
	marker := d.src[d.pos] // read custom marker
	d.pos++
	if marker != markerLiteralBin64 {
		return fmt.Errorf("not a literal bin64 for field %d", staticIdxField)
	}
	d.dst = append(d.dst, staticTable[staticIdxField]...)
	d.dst = append(d.dst, msgpBin8Len64...)
	d.dst = append(d.dst, d.src[d.pos:d.pos+64]...)
	d.pos += 64
	return nil
}

func (d *BitmaskDecoder) dynamicBin32(staticIdxField uint8) error {
	if d.pos+1+32 > len(d.src) {
		return fmt.Errorf("not enough data to read dynamic bin32 marker + value for field %d", staticIdxField)
	}
	marker := d.src[d.pos] // read custom marker
	d.pos++
	if marker != markerDynamicBin32 {
		return fmt.Errorf("not a dynamic bin32 for field %d", staticIdxField)
	}
	d.dst = append(d.dst, staticTable[staticIdxField]...)
	d.dst = append(d.dst, msgpBin8Len32...)
	d.dst = append(d.dst, d.src[d.pos:d.pos+32]...)
	d.pos += 32
	return nil
}

func (d *BitmaskDecoder) literalBin80(staticIdxField uint8) error {
	if d.pos+1+80 > len(d.src) {
		return fmt.Errorf("not enough data to read literal bin80 marker + value for field %d", staticIdxField)
	}
	marker := d.src[d.pos] // read custom marker
	d.pos++
	if marker != markerLiteralBin80 {
		return fmt.Errorf("not a literal bin80 for field %d", staticIdxField)
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
	d.pos++
	switch marker {
	case uint8tag:
		if d.pos+1 > len(d.src) { // Needs one more byte
			return fmt.Errorf("not enough data for varuint uint8 for field %d", staticIdxField)
		}
		d.dst = append(d.dst, staticTable[staticIdxField]...)
		d.dst = append(d.dst, marker, d.src[d.pos])
		d.pos++
	case uint16tag:
		if d.pos+2 > len(d.src) { // Needs two more bytes
			return fmt.Errorf("not enough data for varuint uint16 for field %d", staticIdxField)
		}
		d.dst = append(d.dst, staticTable[staticIdxField]...)
		d.dst = append(d.dst, marker, d.src[d.pos], d.src[d.pos+1])
		d.pos += 2
	case uint32tag:
		if d.pos+4 > len(d.src) { // Needs four more bytes
			return fmt.Errorf("not enough data for varuint uint32 for field %d", staticIdxField)
		}
		d.dst = append(d.dst, staticTable[staticIdxField]...)
		d.dst = append(d.dst, marker, d.src[d.pos], d.src[d.pos+1], d.src[d.pos+2], d.src[d.pos+3])
		d.pos += 4
	case uint64tag:
		if d.pos+8 > len(d.src) { // Needs eight more bytes
			return fmt.Errorf("not enough data for varuint uint64 for field %d", staticIdxField)
		}
		d.dst = append(d.dst, staticTable[staticIdxField]...)
		d.dst = append(d.dst, marker, d.src[d.pos], d.src[d.pos+1], d.src[d.pos+2], d.src[d.pos+3], d.src[d.pos+4], d.src[d.pos+5], d.src[d.pos+6], d.src[d.pos+7])
		d.pos += 8
	default: // fixint uses a single byte for marker+value
		if !isfixint(marker) {
			return fmt.Errorf("not a fixint for field %d", staticIdxField)
		}
		d.dst = append(d.dst, staticTable[staticIdxField]...)
		d.dst = append(d.dst, marker)
	}

	return nil
}
