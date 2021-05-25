// Copyright (C) 2019-2021 Algorand, Inc.
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

package bloom

import (
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/algorand/xorfilter"
)

// XorBuilder is a local alias for xorfilter.Builder
type XorBuilder = xorfilter.Builder

// XorFilter is a faster more efficient alternative to a Bloom filter
// An XorFilter object can be used as is or with optional adittional setup.
type XorFilter struct {
	xor     *xorfilter.Xor32
	holding map[uint64]bool

	b *XorBuilder
}

// NewXor returns an XorFilter with an internal map created with a size hint and an optional *XorBuilder (may be nil)
// The Builder is not thread safe and should only be used by one thread at a time.
func NewXor(hint int, builder *XorBuilder) *XorFilter {
	return &XorFilter{
		holding: make(map[uint64]bool, hint),
		b:       builder,
	}
}

// Set adds the value to the filter.
func (xf *XorFilter) Set(x []byte) {
	if xf.holding == nil {
		xf.holding = make(map[uint64]bool)
	}
	k := binary.BigEndian.Uint64(x)
	xf.holding[k] = true
}

// Test checks whether x is present in the filter.
// May return (rare) erroneous true values, but false is precise.
func (xf *XorFilter) Test(x []byte) bool {
	k := binary.BigEndian.Uint64(x)
	if xf.holding != nil {
		return xf.holding[k]
	}
	if xf.xor != nil {
		return xf.xor.Contains(k)
	}
	return false
}

// MarshalBinary implements encoding.BinaryMarshaller interface
func (xf *XorFilter) MarshalBinary() ([]byte, error) {
	if len(xf.holding) != 0 {
		keys := make([]uint64, len(xf.holding))
		pos := 0
		for k := range xf.holding {
			keys[pos] = k
			pos++
		}
		var err error
		if xf.b != nil {
			xf.xor, err = xf.b.Populate32(keys)
		} else {
			xf.xor, err = xorfilter.Populate32(keys)
		}
		if err != nil {
			return nil, err
		}
	}
	if xf.xor == nil || (len(xf.xor.Fingerprints) == 0) {
		// TODO: some other encoding for empty set?
		return nil, nil
	}
	out := make([]byte, binary.MaxVarintLen64+binary.MaxVarintLen32+binary.MaxVarintLen32+(len(xf.xor.Fingerprints)*4))
	pos := 0
	pos += binary.PutUvarint(out[pos:], xf.xor.Seed)
	pos += binary.PutUvarint(out[pos:], uint64(xf.xor.BlockLength))
	pos += binary.PutUvarint(out[pos:], uint64(len(xf.xor.Fingerprints)))
	for _, v := range xf.xor.Fingerprints {
		binary.LittleEndian.PutUint32(out[pos:], v)
		pos += 4
	}
	out = out[:pos]
	return out, nil
}

// ErrBadBinary is returned when UnmarshalBinary fails
var ErrBadBinary = errors.New("bad XorFilter binary")

// UnmarshalBinary implements encoding.BinaryUnmarshaller interface
func (xf *XorFilter) UnmarshalBinary(data []byte) error {
	pos := 0
	var dp int
	xor := new(xorfilter.Xor32)
	xor.Seed, dp = binary.Uvarint(data[pos:])
	if dp < 0 {
		return ErrBadBinary
	}
	pos += dp
	blockLength, dp := binary.Uvarint(data[pos:])
	if dp < 0 {
		return ErrBadBinary
	}
	xor.BlockLength = uint32(blockLength)
	pos += dp
	lenFingerprints, dp := binary.Uvarint(data[pos:])
	if dp < 0 {
		return ErrBadBinary
	}
	pos += dp
	if lenFingerprints > 0 {
		xor.Fingerprints = make([]uint32, lenFingerprints)
		for i := 0; i < int(lenFingerprints); i++ {
			xor.Fingerprints[i] = binary.LittleEndian.Uint32(data[pos:])
			pos += 4
		}
		xf.xor = xor
	} else {
		xf.xor = nil
	}
	return nil
}

// MarshalJSON implements encoding/json.Marshaller interface
func (xf *XorFilter) MarshalJSON() ([]byte, error) {
	data, err := xf.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

// UnmarshalJSON implements encoding/json.Unmarshaler interface
func (xf *XorFilter) UnmarshalJSON(data []byte) error {
	var blob []byte
	err := json.Unmarshal(data, &blob)
	if err != nil {
		return err
	}
	return xf.UnmarshalBinary(blob)
}

// XorFilter8 is a faster more efficient alternative to a Bloom filter
// An XorFilter8 object can be used as is or with optional adittional setup.
// XorFilter8 uses 1/4 the space of XorFilter (32 bit)
type XorFilter8 struct {
	xor     *xorfilter.Xor8
	holding map[uint64]bool

	b *XorBuilder
}

// NewXor8 returns an XorFilter8 with an internal map created with a size hint and an optional *XorBuilder (may be nil)
// The Builder is not thread safe and should only be used by one thread at a time.
func NewXor8(hint int, builder *XorBuilder) *XorFilter8 {
	return &XorFilter8{
		holding: make(map[uint64]bool, hint),
		b:       builder,
	}
}

// Set adds the value to the filter.
func (xf *XorFilter8) Set(x []byte) {
	if xf.holding == nil {
		xf.holding = make(map[uint64]bool)
	}
	k := binary.BigEndian.Uint64(x)
	xf.holding[k] = true
}

// Test checks whether x is present in the filter.
// May return (rare) erroneous true values, but false is precise.
func (xf *XorFilter8) Test(x []byte) bool {
	k := binary.BigEndian.Uint64(x)
	if xf.holding != nil {
		return xf.holding[k]
	}
	if xf.xor != nil {
		return xf.xor.Contains(k)
	}
	return false
}

// MarshalBinary implements encoding.BinaryMarshaller interface
func (xf *XorFilter8) MarshalBinary() ([]byte, error) {
	if len(xf.holding) != 0 {
		keys := make([]uint64, len(xf.holding))
		pos := 0
		for k := range xf.holding {
			keys[pos] = k
			pos++
		}
		var err error
		if xf.b != nil {
			xf.xor, err = xf.b.Populate(keys)
		} else {
			xf.xor, err = xorfilter.Populate(keys)
		}
		if err != nil {
			return nil, err
		}
	}
	if xf.xor == nil || (len(xf.xor.Fingerprints) == 0) {
		// TODO: some other encoding for empty set?
		return nil, nil
	}
	out := make([]byte, binary.MaxVarintLen64+binary.MaxVarintLen32+binary.MaxVarintLen32+(len(xf.xor.Fingerprints)))
	pos := 0
	pos += binary.PutUvarint(out[pos:], xf.xor.Seed)
	pos += binary.PutUvarint(out[pos:], uint64(xf.xor.BlockLength))
	pos += binary.PutUvarint(out[pos:], uint64(len(xf.xor.Fingerprints)))
	copy(out[pos:], xf.xor.Fingerprints)
	pos += len(xf.xor.Fingerprints)
	out = out[:pos]
	return out, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaller interface
func (xf *XorFilter8) UnmarshalBinary(data []byte) error {
	pos := 0
	var dp int
	xor := new(xorfilter.Xor8)
	xor.Seed, dp = binary.Uvarint(data[pos:])
	if dp < 0 {
		return ErrBadBinary
	}
	pos += dp
	blockLength, dp := binary.Uvarint(data[pos:])
	if dp < 0 {
		return ErrBadBinary
	}
	xor.BlockLength = uint32(blockLength)
	pos += dp
	lenFingerprints, dp := binary.Uvarint(data[pos:])
	if dp < 0 {
		return ErrBadBinary
	}
	pos += dp
	if lenFingerprints > 0 {
		xor.Fingerprints = make([]byte, lenFingerprints)
		copy(xor.Fingerprints, data[pos:])
		xf.xor = xor
	} else {
		xf.xor = nil
	}
	return nil
}

// MarshalJSON implements encoding/json.Marshaller interface
func (xf *XorFilter8) MarshalJSON() ([]byte, error) {
	data, err := xf.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

// UnmarshalJSON implements encoding/json.Unmarshaler interface
func (xf *XorFilter8) UnmarshalJSON(data []byte) error {
	var blob []byte
	err := json.Unmarshal(data, &blob)
	if err != nil {
		return err
	}
	return xf.UnmarshalBinary(blob)
}
