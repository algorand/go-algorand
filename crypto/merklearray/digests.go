package merklearray

import "github.com/algorand/go-algorand/crypto"

// TreeDigest represents the digests the merklearray.Tree returns.
type TreeDigest interface {
	To32Byte() [32]byte
	ToSlice() []byte
}

// Proof contains the merkle path, along with the hash factory that should be used.
type Proof struct {
	path []Digest
	i    crypto.HashFactory
}

// Digest is used as the digest the tree will use.
type Digest []byte

// To32Byte is used to change the data into crypto.Digest.
func (d Digest) To32Byte() [32]byte {
	var cpy [32]byte
	copy(cpy[:], d)
	return cpy

}

// ToSlice is used inside the Tree itself when interacting with TreeDigest
func (d Digest) ToSlice() []byte { return d }
