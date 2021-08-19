package crypto

import (
	"crypto/sha512"
	"errors"
	"hash"
)

// HashType enum type for signing algorithms
type HashType uint64

// types of hashes
const (
	Sha512_256 HashType = iota
	Sha512_2512
)

// HashFactory is responsible for generating new hashes accordingly to the type it stores.
type HashFactory struct {
	_struct  struct{} `codec:",omitempty,omitemptyarray"`
	HashType HashType `codec:"t"`
}

var errUnknownHash = errors.New("unknown hash type")

// NewHash generates a new hash.Hash to use.
func (h HashFactory) NewHash() (hash.Hash, error) {
	switch h.HashType {
	case Sha512_256:
		return sha512.New512_256(), nil
	default:
		return nil, errUnknownHash
	}
}
