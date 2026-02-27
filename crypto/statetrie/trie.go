// Copyright (C) 2019-2024 Algorand, Inc.
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

package statetrie

import (
	"errors"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/statetrie/nibbles"
)

const (
	// MaxKeyLength is the maximum key length in bytes that can be added to the trie
	MaxKeyLength = 65535
)

// Trie is a hashable 16-way radix tree
type Trie struct {
	root node
}

// MakeTrie constructs a Trie
func MakeTrie() *Trie {
	mt := &Trie{}
	return mt
}

// Hash provides the root hash for this trie.
// The root hash is the secure hash for all the nodes in the trie.
func (mt *Trie) Hash() crypto.Digest {
	if mt.root == nil {
		return crypto.Digest{}
	}
	if mt.root.getHash().IsZero() {
		err := mt.root.hashing()
		if err != nil {
			panic(err)
		}
	}
	return *(mt.root.getHash())
}

// Add adds the given key/value pair to the trie.  The value stored with
// the key is immediately hashed, however parent nodes are not re-hashed
// with the new child hash until Trie.Hash() is called.
func (mt *Trie) Add(key nibbles.Nibbles, value []byte) (err error) {
	if len(key) == 0 {
		return errors.New("empty key not allowed")
	}

	if len(key) > MaxKeyLength {
		return errors.New("key too long")
	}

	if mt.root == nil {
		// If there are no nodes in the trie, make a leaf node for this
		// key/value pair and return.
		stats.cryptohashes.Add(1)
		stats.newrootnode.Add(1)
		mt.root = makeLeafNode(key, crypto.Hash(value), nibbles.Nibbles{})
		return nil
	}

	// Add the key/value pair to the trie, and replace the root node with the
	// new modified node that results from the operation.  If the root node has
	// no hash, then the key/value pair resulted in a new root hash (i.e. it was
	// not a duplicate key/value pair)
	stats.cryptohashes.Add(1)
	replacement, err := mt.root.add(mt, nibbles.Nibbles{}, key, crypto.Hash(value))
	if err != nil {
		return err
	}
	if replacement.getHash().IsZero() {
		stats.newrootnode.Add(1)
	}

	// Replace the root with the replacement node.
	mt.root = replacement
	return nil
}
