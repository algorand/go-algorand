// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bloom implements Bloom filters.
package bloom

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"

	"github.com/dchest/siphash"
)

const maxHashes = uint32(32)

// Filter represents the state of the Bloom filter
type Filter struct {
	numHashes             uint32
	data                  []byte
	prefix                [4]byte
	hashStagingBuffer     []uint32
	preimageStagingBuffer []byte
}

// New creates a new Bloom filter
func New(sizeBits int, numHashes uint32, prefix uint32) *Filter {
	m := (sizeBits + 7) / 8
	filter := Filter{
		numHashes:             numHashes,
		data:                  make([]byte, m),
		preimageStagingBuffer: make([]byte, 0, 4+32),
		hashStagingBuffer:     make([]uint32, numHashes+3),
	}
	binary.BigEndian.PutUint32(filter.prefix[:], prefix)
	copy(filter.preimageStagingBuffer, filter.prefix[:])
	filter.preimageStagingBuffer = filter.preimageStagingBuffer[:len(filter.prefix)]
	return &filter
}

// Optimal computes optimal Bloom filter parameters.
// These parameters are optimal for small bloom filters as
// described in section 4.1 of this paper:
//
//   https://web.stanford.edu/~ashishg/papers/inverted.pdf
func Optimal(numElements int, falsePositiveRate float64) (sizeBits int, numHashes uint32) {
	n := float64(numElements)
	p := falsePositiveRate
	m := -(n+0.5)*math.Log(p)/math.Pow(math.Log(2), 2) + 1
	k := -math.Log(p) / math.Log(2)

	numHashes = uint32(math.Ceil(k))
	if numHashes > maxHashes {
		numHashes = maxHashes
	}

	return int(math.Ceil(m)), numHashes
}

// makePreimage creates the preimage we use for a byte-array before hashing it.
func (f *Filter) makePreimage(x []byte) (preimage []byte) {
	preimage = f.preimageStagingBuffer
	preimage = append(preimage, x...)
	return
}

// Set marks x as present in the filter
func (f *Filter) Set(x []byte) {
	withPrefix := f.makePreimage(x)
	hs := f.hash(withPrefix)
	f.preimageStagingBuffer = withPrefix[:len(f.prefix)]
	n := uint32(len(f.data) * 8)
	for _, h := range hs {
		f.set(h % n)
	}
}

// Test checks whether x is present in the filter
func (f *Filter) Test(x []byte) bool {
	withPrefix := f.makePreimage(x)
	hs := f.hash(withPrefix)
	f.preimageStagingBuffer = withPrefix[:len(f.prefix)]
	n := uint32(len(f.data) * 8)
	for _, h := range hs {
		if !f.test(h % n) {
			return false
		}
	}
	return true
}

// Len returns the size of the filter in bytes
func (f *Filter) Len() int {
	return len(f.data)
}

// NumHashes returns the number of hash functions used in the filter
func (f *Filter) NumHashes() uint32 {
	return f.numHashes
}

// MarshalBinary defines how this filter should be encoded to binary
func (f *Filter) MarshalBinary() ([]byte, error) {
	data := make([]byte, len(f.data)+8)
	n := uint32(f.numHashes)
	binary.BigEndian.PutUint32(data[0:4], n)
	copy(data[4:8], f.prefix[:])
	copy(data[8:], f.data)
	return data, nil
}

// BinaryMarshalLength returns the length of a binary marshaled filter ( in bytes ) using the
// optimal configuration for the given number of elements with the desired false positive rate.
func BinaryMarshalLength(numElements int, falsePositiveRate float64) int64 {
	sizeBits, _ := Optimal(numElements, falsePositiveRate)
	filterBytes := int64((sizeBits + 7) / 8) // convert bits -> bytes.
	return filterBytes + 8                   // adding 8 to match 4 prefix array, plus 4 bytes for the numHashes uint32
}

// UnmarshalBinary restores the state of the filter from raw data
func UnmarshalBinary(data []byte) (*Filter, error) {
	f := &Filter{}
	if len(data) <= 8 {
		return nil, errors.New("short data")
	}
	f.numHashes = binary.BigEndian.Uint32(data[0:4])
	if f.numHashes > maxHashes {
		return nil, errors.New("too many hashes")
	}
	copy(f.prefix[:], data[4:8])
	f.data = data[8:]
	return f, nil
}

// MarshalJSON defines how this filter should be encoded to JSON
func (f *Filter) MarshalJSON() ([]byte, error) {
	data, err := f.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

// UnmarshalJSON defines how this filter should be decoded from JSON
func UnmarshalJSON(data []byte) (*Filter, error) {
	var bs []byte
	if err := json.Unmarshal(data, &bs); err != nil {
		return nil, err
	}
	return UnmarshalBinary(bs)
}

// Previously, we used the hashing method described in this paper:
// http://www.eecs.harvard.edu/~michaelm/postscripts/rsa2008.pdf
// but this gave us bad false positive rates for small bloom filters.
func (f *Filter) hash(x []byte) []uint32 {
	res := f.hashStagingBuffer

	for i := uint32(0); i < (f.numHashes+3)/4; i++ {
		h1, h2 := siphash.Hash128(uint64(i), 666666, x)

		res[i*4] = uint32(h1)
		res[i*4+1] = uint32(h1 >> 32)
		res[i*4+2] = uint32(h2)
		res[i*4+3] = uint32(h2 >> 32)
	}

	return res[:f.numHashes]
}

func (f *Filter) test(bit uint32) bool {
	i := bit / 8
	return f.data[i]&(1<<(bit%8)) != 0
}

func (f *Filter) set(bit uint32) {
	i := bit / 8
	f.data[i] |= 1 << (bit % 8)
}
