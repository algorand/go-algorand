package merklearray

import (
	"github.com/algorand/go-algorand/crypto"
)

// An Array represents a dense array of leaf elements that are
// combined into a Merkle tree.  Each element must be hashable.
type Array interface {
	Length() uint64
	Get(pos uint64) (crypto.Hashable, error)
}
