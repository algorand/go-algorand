// Copyright (C) 2019-2020 Algorand, Inc.
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

package merkletrie

import (
	"github.com/algorand/go-algorand/crypto"
)

// MerkleTrie is a merkle trie intended to efficiently calculate the merkle root of
// unordered elements
type MerkleTrie struct {
	root  storedNodeIdentifier
	cache *merkleTrieCache
}

// Stats structure is a helper for finding underlaying statistics about the trie
type Stats struct {
	nodesCount uint
	leafCount  uint
	depth      int
	size       int
}

// MakeMerkleTrie creates a merkle trie
func MakeMerkleTrie() *MerkleTrie {
	mt := &MerkleTrie{
		root:  storedNodeIdentifierNull,
		cache: &merkleTrieCache{},
	}
	mt.cache.initialize()
	return mt
}

// RootHash returns the root hash of all the elements in the trie
func (mt *MerkleTrie) RootHash() (crypto.Digest, error) {
	if mt.root == storedNodeIdentifierNull {
		return crypto.Digest{}, nil
	}
	pnode, err := mt.cache.getNode(mt.root)
	if err != nil {
		return crypto.Digest{}, err
	}
	return crypto.Hash(pnode.hash), nil
}

// Add adds the given hash to the trie.
// returns false if the item already exists.
func (mt *MerkleTrie) Add(d []byte) (bool, error) {
	if mt.root == storedNodeIdentifierNull {
		// first item added to the tree.
		var pnode *node
		pnode, mt.root = mt.cache.allocateNewNode()
		pnode.leaf = true
		pnode.hash = d
		return true, nil
	}
	pnode, err := mt.cache.getNode(mt.root)
	if err != nil {
		return false, err
	}
	found, err := pnode.find(mt.cache, d[:])
	if found || (err != nil) {
		return false, err
	}
	var updatedRoot storedNodeIdentifier
	updatedRoot, err = pnode.add(mt.cache, d[:])
	if err == nil {
		mt.root = updatedRoot
	}
	return true, err
}

// Delete deletes the given hash to the trie, if such element exists.
// if no such element exists, return false
func (mt *MerkleTrie) Delete(d []byte) (bool, error) {
	if mt.root == storedNodeIdentifierNull {
		return false, nil
	}
	pnode, err := mt.cache.getNode(mt.root)
	if err != nil {
		return false, err
	}
	found, err := pnode.find(mt.cache, d[:])
	if !found || err != nil {
		return false, err
	}
	if pnode.leaf {
		// remove the root.
		mt.cache.deleteNode(mt.root)
		mt.root = storedNodeIdentifierNull
		return true, nil
	}
	var updatedRoot storedNodeIdentifier
	updatedRoot, err = pnode.remove(mt.cache, d[:])
	if err != nil {
		return false, err
	}
	mt.root = updatedRoot
	return true, nil
}

// GetStats return statistics about the merkle trie
func (mt *MerkleTrie) GetStats() (stats Stats, err error) {
	if mt.root == storedNodeIdentifierNull {
		return Stats{}, nil
	}
	pnode, err := mt.cache.getNode(mt.root)
	if err != nil {
		return Stats{}, err
	}
	err = pnode.stats(mt.cache, &stats, 1)
	return
}

// BeginTransaction starts an atomic transaction on the markle trie.
func (mt *MerkleTrie) BeginTransaction() *Transaction {
	return makeTransaction(mt)
}
