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
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-sumhash"
)

// HashType represents different hash functions
type HashType uint16

// Validate verifies that the hash type is in a valid range.
func (h HashType) Validate() error {
	if h >= MaxHashType {
		return protocol.ErrInvalidObject
	}
	return nil
}

// types of hashes
const (
	Sha512_256 HashType = iota
	Sumhash
	Sha256
	MaxHashType
)

// MaxHashDigestSize is used to bound the max digest size. it is important to change it if a hash with
// a longer output is introduced.
const MaxHashDigestSize = SumhashDigestSize

//size of each hash
const (
	Sha512_256Size    = sha512.Size256
	SumhashDigestSize = sumhash.Sumhash512DigestSize
	Sha256Size        = sha256.Size
)

// HashFactory is responsible for generating new hashes accordingly to the type it stores.
//msgp:postunmarshalcheck HashFactory Validate
type HashFactory struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	HashType HashType `codec:"t"`
}

var errUnknownHash = errors.New("unknown hash type")

func (h HashType) String() string {
	switch h {
	case Sha512_256:
		return "sha512_256"
	case Sumhash:
		return "sumhash"
	case Sha256:
		return "sha256"
	default:
		return ""
	}
}

// UnmarshalHashType decodes a string into the HashType enum
func UnmarshalHashType(s string) (HashType, error) {
	switch s {
	case "sha512_256":
		return Sha512_256, nil
	case "sumhash":
		return Sumhash, nil
	case "sha256":
		return Sha256, nil
	default:
		return 0, fmt.Errorf("HashType not supported: %s", s)
	}
}

// NewHash generates a new hash.Hash to use.
func (z HashFactory) NewHash() hash.Hash {
	switch z.HashType {

	case Sha512_256:
		return sha512.New512_256()
	case Sumhash:
		return sumhash.New512(nil)
	case Sha256:
		return sha256.New()
	// This shouldn't be reached, when creating a new hash, one would know the type of hash they wanted,
	// in addition to that, unmarshalling of the hashFactory verifies the HashType of the factory.
	default:
		return invalidHash{}
	}
}

// Validate states whether the HashFactory is valid, and is safe to use.
func (z *HashFactory) Validate() error {
	return z.HashType.Validate()
}

// GenericHashObj Makes it easier to sum using hash interface and Hashable interface
func GenericHashObj(hsh hash.Hash, h Hashable) []byte {
	rep := HashRep(h)
	return hashBytes(hsh, rep)
}

func hashBytes(hash hash.Hash, m []byte) []byte {
	hash.Reset()
	hash.Write(m)
	outhash := hash.Sum(nil)
	return outhash
}

// InvalidHash is used to identify errors on the factory.
// this function will return nil slice
type invalidHash struct {
}

// Write writes bytes into the hash function. this function will return an error
func (h invalidHash) Write(p []byte) (n int, err error) {
	return 0, errUnknownHash
}

// Sum returns an empty slice since this is an empty hash function
func (h invalidHash) Sum(b []byte) []byte {
	return nil
}

// Reset this function has no state so it is empty
func (h invalidHash) Reset() {
}

// Size the current size of the function is always 0
func (h invalidHash) Size() int {
	return 0
}

// BlockSize returns zero since this is an empty hash function
func (h invalidHash) BlockSize() int {
	return 0
}
