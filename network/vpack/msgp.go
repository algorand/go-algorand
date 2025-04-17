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

	msgpMapMarker0 = "\x80" // Map with 0 items
	msgpMapMarker1 = "\x81" // Map with 1 items
	msgpMapMarker2 = "\x82" // Map with 2 items
	msgpMapMarker3 = "\x83" // Map with 3 items
	msgpMapMarker4 = "\x84" // Map with 4 items
	msgpMapMarker5 = "\x85" // Map with 5 items
	msgpMapMarker6 = "\x86" // Map with 6 items
)

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
func (p *parser) readFixMap() (uint8, error) {
	b, err := p.readByte()
	if err != nil {
		return 0, err
	}

	if b < fixMapMask || b > fixMapMax {
		return 0, fmt.Errorf("expected fixmap, got 0x%02x", b)
	}

	return b & 0x0f, nil
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
	if string(s) != expected {
		return fmt.Errorf("expected string %q, got %q", expected, s)
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
	// read marker byte
	b, err := p.readByte()
	if err != nil {
		return nil, err
	}
	// fixint is a single byte containing marker and value
	if isfixint(b) {
		return p.data[startPos : startPos+1], nil
	}
	// otherwise, we expect a tag byte followed by the value
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
