// Copyright (C) 2019-2023 Algorand, Inc.
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

package crypto

import (
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/algorand/go-algorand/protocol"
)

// Hashable is an interface implemented by an object that can be represented
// with a sequence of bytes to be hashed or signed, together with a type ID
// to distinguish different types of objects.
type Hashable interface {
	ToBeHashed() (protocol.HashID, []byte)
}

// HashRep appends the correct hashid before the message to be hashed.
func HashRep(h Hashable) []byte {
	hashid, data := h.ToBeHashed()
	return append([]byte(hashid), data...)
}

// DigestSize is the number of bytes in the preferred hash Digest used here.
const DigestSize = sha512.Size256

// Digest represents a 32-byte value holding the 256-bit Hash digest.
type Digest [DigestSize]byte

// ToSlice converts Digest to slice, is used by bookkeeping.PaysetCommit
func (d Digest) ToSlice() []byte {
	return d[:]
}

// String returns the digest in a human-readable Base32 string
func (d Digest) String() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(d[:])
}

// TrimUint64 returns the top 64 bits of the digest and converts to uint64
func (d Digest) TrimUint64() uint64 {
	return binary.LittleEndian.Uint64(d[:8])
}

// IsZero return true if the digest contains only zeros, false otherwise
func (d Digest) IsZero() bool {
	return d == Digest{}
}

// DigestFromString converts a string to a Digest
func DigestFromString(str string) (d Digest, err error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(str)
	if err != nil {
		return d, err
	}
	if len(decoded) != len(d) {
		msg := fmt.Sprintf(`Attempted to decode a string which was not a Digest: "%v"`, str)
		return d, errors.New(msg)
	}
	copy(d[:], decoded[:])
	return d, err
}

// Hash computes the SHASum512_256 hash of an array of bytes
func Hash(data []byte) Digest {
	return sha512.Sum512_256(data)
}

// HashObj computes a hash of a Hashable object and its type
func HashObj(h Hashable) Digest {
	return Hash(HashRep(h))
}

// NewHash returns a sha512-256 object to do the same operation as Hash()
func NewHash() hash.Hash {
	return sha512.New512_256()
}

// EncodeAndHash returns both the packed representation of the object and its hash.
func EncodeAndHash(h Hashable) (Digest, []byte) {
	hashid, encodedData := h.ToBeHashed()
	hashrep := append([]byte(hashid), encodedData...)
	return Hash(hashrep), encodedData
}
