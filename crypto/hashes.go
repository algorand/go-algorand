package crypto

import (
	"crypto/sha512"
	"errors"
	"hash"

	"github.com/algonathan/sumhash"
	"golang.org/x/crypto/sha3"
)

// HashType enum type for signing algorithms
type HashType uint64

// types of hashes
const (
	Sha512_256 HashType = iota
	Subsetsum
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
	case Subsetsum:
		C := 4
		N := 14
		shk := sha3.NewShake256()
		seed := []byte("I have nothing up my sleeve...")
		_, err := shk.Write(seed)
		if err != nil {
			return nil, err
		}
		return sumhash.New(sumhash.RandomMatrix(shk, N, C)), nil
	default:
		return nil, errUnknownHash
	}
}

// HashSum Makes it easier to sum using hash interface and Hashable interface
func HashSum(hsh hash.Hash, h Hashable) []byte {
	rep := HashRep(h)
	return HashBytes(hsh, rep)
}

// HashBytes Makes it easier to sum using hash interface.
func HashBytes(hash hash.Hash, m []byte) []byte {
	hash.Reset()
	hash.Write(m)
	outhash := hash.Sum(nil)
	return outhash
}
