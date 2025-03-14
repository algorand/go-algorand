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
)

// Minimal msgpack constants used here
const (
	fixMapMask = 0x80
	fixMapMax  = 0x8f
	fixStrMask = 0xa0
	fixStrMax  = 0xbf
	bin8       = 0xc4
	bin16      = 0xc5
	bin32      = 0xc6
	uint8tag   = 0xcc
	uint16tag  = 0xcd
	uint32tag  = 0xce
	uint64tag  = 0xcf
)

// parseVoteMsgpack reads a single vote message (top-level map with keys "cred","r","sig"),
// calling the compressor with static/dynamic/literal data.
func parseVoteMsgpack(data []byte, c compressWriter) error {
	p := newParser(data)

	// 1) Expect a top-level map with 3 items: { "cred":..., "r":..., "sig":... }
	err := p.expectFixMap(3)
	if err != nil {
		return fmt.Errorf("top-level map: %w", err)
	}
	c.writeStatic(StaticIdxMapMarker3)

	// For each of the 3 entries:
	for range 3 {
		key, err := p.readString()
		if err != nil {
			return fmt.Errorf("reading top-level key: %w", err)
		}

		switch string(key) {
		case "cred":
			c.writeStatic(StaticIdxCredField)
			// cred => fixmap of size 1 => { "pf": <80-byte VRF> }
			err = p.expectFixMap(1)
			if err != nil {
				return fmt.Errorf("cred map: %w", err)
			}
			c.writeStatic(StaticIdxMapMarker1)

			err := p.expectString("pf")
			if err != nil {
				return fmt.Errorf("reading pf key: %w", err)
			}
			c.writeStatic(StaticIdxPfField)

			pfVal, err := p.readBin80()
			if err != nil {
				return fmt.Errorf("reading pf bin: %w", err)
			}
			c.writeLiteralBin80(pfVal)

		case "r":
			c.writeStatic(StaticIdxRField)
			// rawVote => fixmap of size 3 => { "prop","rnd","snd" } with optional per, step
			keyCount, err := expectWriteMapMarker(5, p, c)
			if err != nil {
				return fmt.Errorf("r map: %w", err)
			}

			for range keyCount {
				subKey, err := p.readString()
				if err != nil {
					return fmt.Errorf("reading r subkey: %w", err)
				}

				switch string(subKey) {
				case "prop":
					c.writeStatic(StaticIdxPropField)
					// prop => { "dig","encdig","oprop","oper" }
					propKeyCount, err := expectWriteMapMarker(4, p, c)
					if err != nil {
						return fmt.Errorf("prop map: %w", err)
					}
					for range propKeyCount {
						propKey, err := p.readString()
						if err != nil {
							return fmt.Errorf("reading prop key: %w", err)
						}
						switch string(propKey) {
						case "dig":
							c.writeStatic(StaticIdxDigField)
						case "encdig":
							c.writeStatic(StaticIdxEncdigField)
						case "oprop":
							c.writeStatic(StaticIdxOpropField)
						case "oper":
							c.writeStatic(StaticIdxOperField)
							operBytes, err := p.readUintBytes()
							if err != nil {
								return fmt.Errorf("reading oper: %w", err)
							}
							c.writeDynamicVaruint(operBytes)
							continue
						default:
							return fmt.Errorf("unexpected prop key: %q", propKey)
						}
						propVal, err := p.readBin32()
						if err != nil {
							return fmt.Errorf("reading prop val: %w", err)
						}
						c.writeDynamicBin32(propVal)
					}

				case "rnd":
					// rnd, per, and step values will be re-used across multiple votes
					c.writeStatic(StaticIdxRndField)
					roundBytes, err := p.readUintBytes()
					if err != nil {
						return fmt.Errorf("reading round: %w", err)
					}
					c.writeDynamicVaruint(roundBytes)
				case "per":
					c.writeStatic(StaticIdxPerField)
					perBytes, err := p.readUintBytes()
					if err != nil {
						return fmt.Errorf("reading per: %w", err)
					}
					c.writeDynamicVaruint(perBytes)
				case "step":
					stepBytes, err := p.readUintBytes()
					if err != nil {
						return fmt.Errorf("reading step: %w", err)
					}
					// use hard-coded static for "step" + 1, 2, or 3
					if len(stepBytes) == 1 {
						switch stepBytes[0] {
						case 1: // soft vote
							c.writeStatic(StaticIdxStep1Field)
							continue
						case 2: // cert vote
							c.writeStatic(StaticIdxStep2Field)
							continue
						case 3: // next vote
							c.writeStatic(StaticIdxStep3Field)
							continue
						}
					}
					// otherwise, write "step" key + varuint
					c.writeStatic(StaticIdxStepField)
					c.writeDynamicVaruint(stepBytes)
				case "snd":
					c.writeStatic(StaticIdxSndField)
					addrVal, err := p.readBin32()
					if err != nil {
						return fmt.Errorf("reading snd address: %w", err)
					}
					c.writeDynamicBin32(addrVal)
				default:
					return fmt.Errorf("unexpected r subkey: %q", subKey)
				}
			}

		case "sig":
			c.writeStatic(StaticIdxSigField)
			// sig => fixmap of size 6 => { "p","p1s","p2","p2s","ps","s" }
			err = p.expectFixMap(6)
			if err != nil {
				return fmt.Errorf("sig map: %w", err)
			}
			c.writeStatic(StaticIdxMapMarker6)

			for range 6 {
				sigKey, err := p.readString()
				if err != nil {
					return fmt.Errorf("reading sig key: %w", err)
				}
				switch string(sigKey) {
				case "p": // pubkey for round (could reappear in this round)
					c.writeStatic(StaticIdxPField)
					pVal, err := p.readBin32()
					if err != nil {
						return fmt.Errorf("reading p val: %w", err)
					}
					c.writeDynamicBin32(pVal)
				case "p1s": // signature
					c.writeStatic(StaticIdxP1sField)
					p1sVal, err := p.readBin64()
					if err != nil {
						return fmt.Errorf("reading p1s val: %w", err)
					}
					c.writeLiteralBin64(p1sVal) // write 64-byte literal
				case "p2": // pubkey for batch (could reappear in many rounds)
					c.writeStatic(StaticIdxP2Field)
					p2Val, err := p.readBin32()
					if err != nil {
						return fmt.Errorf("reading p2 val: %w", err)
					}
					c.writeDynamicBin32(p2Val)
				case "p2s": // signature
					c.writeStatic(StaticIdxP2sField)
					p2sVal, err := p.readBin64()
					if err != nil {
						return fmt.Errorf("reading p2s val: %w", err)
					}
					c.writeLiteralBin64(p2sVal) // write 64-byte literal
				case "ps": // signature
					psVal, err := p.readBin64()
					if err != nil {
						return fmt.Errorf("reading ps val: %w", err)
					}
					// All-zero "ps" field is common case
					if [64]byte(psVal) == [64]byte{} {
						c.writeStatic(StaticIdxAllZeroPsField)
					} else {
						// Would only occur for historical votes
						c.writeStatic(StaticIdxPsField)
						c.writeLiteralBin64(psVal) // write 64-byte literal
					}
				case "s": // signature
					c.writeStatic(StaticIdxSField)
					sVal, err := p.readBin64()
					if err != nil {
						return fmt.Errorf("reading s val: %w", err)
					}
					c.writeLiteralBin64(sVal) // write 64-byte literal
				default:
					return fmt.Errorf("unexpected sig key: %q", sigKey)
				}
			}

		default:
			return fmt.Errorf("unexpected top-level key: %q", key)
		}
	}
	return nil
}

func expectWriteMapMarker(maxSz int, p *parser, c compressWriter) (int, error) {
	cnt, err := p.readFixMap()
	if err != nil {
		return 0, err
	}
	if cnt < 1 || cnt > maxSz {
		return 0, fmt.Errorf("expected fixmap size %d <= cnt <= %d, got %d", 1, maxSz, cnt)
	}
	switch cnt {
	case 1:
		c.writeStatic(StaticIdxMapMarker1)
	case 2:
		c.writeStatic(StaticIdxMapMarker2)
	case 3:
		c.writeStatic(StaticIdxMapMarker3)
	case 4:
		c.writeStatic(StaticIdxMapMarker4)
	case 5:
		c.writeStatic(StaticIdxMapMarker5)
	case 6:
		c.writeStatic(StaticIdxMapMarker6)
	default:
		return 0, fmt.Errorf("unexpected fixmap size: %d", cnt)
	}
	return cnt, nil
}

// parser provides a zero-allocation parser for vote messages.
type parser struct {
	data []byte
	pos  int
}

func newParser(data []byte) *parser {
	return &parser{data: data}
}

// Error if we need more bytes than available
func (p *parser) ensureBytes(n int) error {
	if p.pos+n > len(p.data) {
		return fmt.Errorf("unexpected EOF: need %d bytes, have %d", n, len(p.data)-p.pos)
	}
	return nil
}

// Read a single byte
func (p *parser) readByte() (byte, error) {
	if err := p.ensureBytes(1); err != nil {
		return 0, err
	}
	b := p.data[p.pos]
	p.pos++
	return b, nil
}

// Read a fixmap header and return the count
func (p *parser) readFixMap() (int, error) {
	b, err := p.readByte()
	if err != nil {
		return 0, err
	}

	if b < fixMapMask || b > fixMapMax {
		return 0, fmt.Errorf("expected fixmap, got 0x%02x", b)
	}

	return int(b & 0x0f), nil
}

// Expect a fixmap of specific size
func (p *parser) expectFixMap(expectedCount int) error {
	count, err := p.readFixMap()
	if err != nil {
		return err
	}
	if count != expectedCount {
		return fmt.Errorf("expected fixmap size %d, got %d", expectedCount, count)
	}
	return nil
}

// Zero-allocation string reading that returns a slice of the original data
func (p *parser) readString() ([]byte, error) {
	b, err := p.readByte()
	if err != nil {
		return nil, err
	}
	if b < fixStrMask || b > fixStrMax {
		return nil, fmt.Errorf("readString: expected fixstr, got 0x%02x", b)
	}
	length := int(b & 0x1f)
	if err := p.ensureBytes(length); err != nil {
		return nil, err
	}
	s := p.data[p.pos : p.pos+length]
	p.pos += length
	return s, nil
}

func (p *parser) expectString(expected string) error {
	s, err := p.readString()
	if err != nil {
		return err
	}
	if string(s) != expected { // zero-alloc conversion
		return fmt.Errorf("expected string %s, got %s", string(expected), string(s))
	}
	return nil
}

func (p *parser) readBin80() ([80]byte, error) {
	var data [80]byte
	if err := p.ensureBytes(2); err != nil {
		return data, err
	}
	if p.data[p.pos] != bin8 || p.data[p.pos+1] != 80 {
		return data, fmt.Errorf("expected bin8 length 80, got %d", int(p.data[p.pos+1]))
	}
	p.pos += 2

	if err := p.ensureBytes(80); err != nil {
		return data, err
	}
	copy(data[:], p.data[p.pos:p.pos+80])
	p.pos += 80
	return data, nil
}

func (p *parser) readBin32() ([32]byte, error) {
	var data [32]byte
	if err := p.ensureBytes(2); err != nil {
		return data, err
	}
	if p.data[p.pos] != bin8 || p.data[p.pos+1] != 32 {
		return data, fmt.Errorf("expected bin8 length 32, got %d", int(p.data[p.pos+1]))
	}
	p.pos += 2

	if err := p.ensureBytes(32); err != nil {
		return data, err
	}
	copy(data[:], p.data[p.pos:p.pos+32])
	p.pos += 32
	return data, nil
}

func (p *parser) readBin64() ([64]byte, error) {
	var data [64]byte
	if err := p.ensureBytes(2); err != nil {
		return data, err
	}
	if p.data[p.pos] != bin8 || p.data[p.pos+1] != 64 {
		return data, fmt.Errorf("expected bin8 length 64, got %d", int(p.data[p.pos+1]))
	}
	p.pos += 2

	if err := p.ensureBytes(64); err != nil {
		return data, err
	}
	copy(data[:], p.data[p.pos:p.pos+64])
	p.pos += 64
	return data, nil
}

func isfixint(b byte) bool {
	return b>>7 == 0
}

// readUintBytes reads a variable-length msgpack unsigned integer from the reader.
// It will return a zero-length/nil slice iff err != nil.
func (p *parser) readUintBytes() ([]byte, error) {
	startPos := p.pos

	b, err := p.readByte()
	if err != nil {
		return nil, err
	}
	if isfixint(b) { // 1-byte unsigned int encoding
		return p.data[startPos : startPos+1], nil
	}
	var dataSize int
	switch b {
	case uint8tag:
		dataSize = 1
	case uint16tag:
		dataSize = 2
	case uint32tag:
		dataSize = 4
	case uint64tag:
		dataSize = 8
	default:
		return nil, fmt.Errorf("expected uint tag, got 0x%02x", b)
	}
	if err := p.ensureBytes(dataSize); err != nil {
		return nil, err
	}
	p.pos += dataSize
	return p.data[startPos : startPos+dataSize+1], nil
}
