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
	msgpFixMapMask = 0x80
	msgpFixMapMax  = 0x8f
	msgpFixStrMask = 0xa0
	msgpFixStrMax  = 0xbf
	msgpBin8       = 0xc4
	msgpBin8Len32  = "\xc4\x20" // bin8 marker with 32 items
	msgpBin8Len64  = "\xc4\x40" // bin8 marker with 64 items
	msgpBin8Len80  = "\xc4\x50" // bin8 marker with 80 items
	msgpUint8      = 0xcc
	msgpUint16     = 0xcd
	msgpUint32     = 0xce
	msgpUint64     = 0xcf

	msgpFixstrCred   = "\xa4cred"
	msgpFixstrDig    = "\xa3dig"
	msgpFixstrEncdig = "\xa6encdig"
	msgpFixstrOper   = "\xa4oper"
	msgpFixstrOprop  = "\xa5oprop"
	msgpFixstrP      = "\xa1p"
	msgpFixstrP1s    = "\xa3p1s"
	msgpFixstrP2     = "\xa2p2"
	msgpFixstrP2s    = "\xa3p2s"
	msgpFixstrPer    = "\xa3per"
	msgpFixstrPf     = "\xa2pf"
	msgpFixstrProp   = "\xa4prop"
	msgpFixstrPs     = "\xa2ps"
	msgpFixstrR      = "\xa1r"
	msgpFixstrRnd    = "\xa3rnd"
	msgpFixstrS      = "\xa1s"
	msgpFixstrSig    = "\xa3sig"
	msgpFixstrSnd    = "\xa3snd"
	msgpFixstrStep   = "\xa4step"
)

func isMsgpFixint(b byte) bool {
	return b>>7 == 0
}

// msgpVaruintRemaining looks at the first byte of a msgpack-encoded variable-length unsigned integer,
// and returns the number of bytes remaining in the encoded value (not including the first byte).
func msgpVaruintRemaining(first byte) (int, error) {
	switch first {
	case msgpUint8:
		return 1, nil
	case msgpUint16:
		return 2, nil
	case msgpUint32:
		return 4, nil
	case msgpUint64:
		return 8, nil
	default:
		if !isMsgpFixint(first) {
			return 0, fmt.Errorf("msgpVaruintRemaining: expected fixint or varuint tag, got 0x%02x", first)
		}
		return 0, nil
	}
}

// msgpVoteParser provides a zero-allocation msgpVoteParser for vote messages.
type msgpVoteParser struct {
	data []byte
	pos  int
}

func newMsgpVoteParser(data []byte) *msgpVoteParser {
	return &msgpVoteParser{data: data}
}

// Error if we need more bytes than available
func (p *msgpVoteParser) ensureBytes(n int) error {
	if p.pos+n > len(p.data) {
		return fmt.Errorf("unexpected EOF: need %d bytes, have %d", n, len(p.data)-p.pos)
	}
	return nil
}

// Read a single byte
func (p *msgpVoteParser) readByte() (byte, error) {
	if err := p.ensureBytes(1); err != nil {
		return 0, err
	}
	b := p.data[p.pos]
	p.pos++
	return b, nil
}

// Read a fixmap header and return the count
func (p *msgpVoteParser) readFixMap() (uint8, error) {
	b, err := p.readByte()
	if err != nil {
		return 0, err
	}

	if b < msgpFixMapMask || b > msgpFixMapMax {
		return 0, fmt.Errorf("expected fixmap, got 0x%02x", b)
	}

	return b & 0x0f, nil
}

// Zero-allocation string reading that returns a slice of the original data
func (p *msgpVoteParser) readString() ([]byte, error) {
	b, err := p.readByte()
	if err != nil {
		return nil, err
	}
	if b < msgpFixStrMask || b > msgpFixStrMax {
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

func (p *msgpVoteParser) readBin80() ([80]byte, error) {
	const sz = 80
	var data [sz]byte
	if err := p.ensureBytes(sz + 2); err != nil {
		return data, err
	}
	if p.data[p.pos] != msgpBin8 || p.data[p.pos+1] != sz {
		return data, fmt.Errorf("expected bin8 length %d, got %d", sz, int(p.data[p.pos+1]))
	}
	copy(data[:], p.data[p.pos+2:p.pos+sz+2])
	p.pos += sz + 2
	return data, nil
}

func (p *msgpVoteParser) readBin32() ([32]byte, error) {
	const sz = 32
	var data [sz]byte
	if err := p.ensureBytes(sz + 2); err != nil {
		return data, err
	}
	if p.data[p.pos] != msgpBin8 || p.data[p.pos+1] != sz {
		return data, fmt.Errorf("expected bin8 length %d, got %d", sz, int(p.data[p.pos+1]))
	}
	copy(data[:], p.data[p.pos+2:p.pos+sz+2])
	p.pos += sz + 2
	return data, nil
}

func (p *msgpVoteParser) readBin64() ([64]byte, error) {
	const sz = 64
	var data [sz]byte
	if err := p.ensureBytes(sz + 2); err != nil {
		return data, err
	}
	if p.data[p.pos] != msgpBin8 || p.data[p.pos+1] != sz {
		return data, fmt.Errorf("expected bin8 length %d, got %d", sz, int(p.data[p.pos+1]))
	}
	copy(data[:], p.data[p.pos+2:p.pos+sz+2])
	p.pos += sz + 2
	return data, nil
}

// readUintBytes reads a variable-length msgpack unsigned integer from the reader.
// It will return a zero-length/nil slice iff err != nil.
func (p *msgpVoteParser) readUintBytes() ([]byte, error) {
	startPos := p.pos
	// read marker byte
	b, err := p.readByte()
	if err != nil {
		return nil, err
	}
	dataSize, err := msgpVaruintRemaining(b)
	if err != nil {
		return nil, err
	}
	// fixint is a single byte containing marker and value
	if dataSize == 0 {
		return p.data[startPos : startPos+1], nil
	}
	if err := p.ensureBytes(dataSize); err != nil {
		return nil, err
	}
	p.pos += dataSize
	return p.data[startPos : startPos+dataSize+1], nil
}
