package merklearray

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// A layer of the Merkle tree consists of a dense array of hashes at that
// level of the tree.  Hashes beyond the end of the array (e.g., if the
// number of leaves is not an exact power of 2) are implicitly zero.
type layer []crypto.Digest

// A pair represents an internal node in the Merkle tree.
type pair struct {
	l crypto.Digest
	r crypto.Digest
}

func (p *pair) ToBeHashed() (protocol.HashID, []byte) {
	var buf [2 * crypto.DigestSize]byte
	copy(buf[:crypto.DigestSize], p.l[:])
	copy(buf[crypto.DigestSize:], p.r[:])
	return protocol.MerkleArrayNode, buf[:]
}

// up takes a layer representing some level in the tree,
// and returns the next-higher level in the tree,
// represented as a layer.
func (l layer) up() layer {
	res := make(layer, (len(l)+1)/2)
	for i := 0; i < len(l); i += 2 {
		var p pair
		p.l = l[i]
		if i+1 < len(l) {
			p.r = l[i+1]
		}
		res[i/2] = crypto.HashObj(&p)
	}
	return res
}
