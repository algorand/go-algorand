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
	"encoding/binary"

	"github.com/algorand/go-algorand/crypto"
)

const (
	// MerkleTreeVersion is the version of the encoded trie. If we ever want to make changes and want to have upgrade path,
	// this would give us the ability to do so.
	MerkleTreeVersion = uint64(0x1000000010000000)
	// NodePageVersion is the version of the encoded node. If we ever want to make changes and want to have upgrade path,
	// this would give us the ability to do so.
	NodePageVersion = uint64(0x1000000010000000)
)

// MerkleTrie is a merkle trie intended to efficiently calculate the merkle root of
// unordered elements
type MerkleTrie struct {
	root       storedNodeIdentifier
	nextNodeID storedNodeIdentifier
	cache      *merkleTrieCache
}

// Stats structure is a helper for finding underlaying statistics about the trie
type Stats struct {
	nodesCount uint
	leafCount  uint
	depth      int
	size       int
}

// MakeMerkleTrie creates a merkle trie
func MakeMerkleTrie(committer Committer) *MerkleTrie {
	mt := &MerkleTrie{
		root:       storedNodeIdentifierNull,
		cache:      &merkleTrieCache{},
		nextNodeID: storedNodeIdentifierBase,
	}
	if committer == nil {
		committer = &InMemoryCommitter{}
	} else {
		rootBytes, err := committer.LoadPage(storedNodeIdentifierNull)
		if err == nil {
			mt.deserialize(rootBytes)
		}
	}

	mt.cache.initialize(mt, committer)
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
		mt.cache.beginTransaction()
		pnode, mt.root = mt.cache.allocateNewNode()
		mt.cache.commitTransaction()
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
	mt.cache.beginTransaction()
	var updatedRoot storedNodeIdentifier
	updatedRoot, err = pnode.add(mt.cache, d[:], make([]byte, 0, len(d)))
	if err != nil {
		mt.cache.deleteNode(updatedRoot)
		mt.cache.rollbackTransaction()
		return false, err
	}
	mt.cache.deleteNode(mt.root)
	mt.root = updatedRoot
	mt.cache.commitTransaction()
	return true, nil
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
	mt.cache.beginTransaction()
	if pnode.leaf {
		// remove the root.
		mt.cache.deleteNode(mt.root)
		mt.root = storedNodeIdentifierNull
		mt.cache.commitTransaction()
		return true, nil
	}
	var updatedRoot storedNodeIdentifier
	updatedRoot, err = pnode.remove(mt.cache, d[:], make([]byte, 0, len(d)))
	if err != nil {
		mt.cache.deleteNode(updatedRoot)
		mt.cache.rollbackTransaction()
		return false, err
	}
	mt.cache.commitTransaction()
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

// Commit stores the existings trie using the committer.
func (mt *MerkleTrie) Commit() error {
	bytes := mt.serialize()
	mt.cache.committer.StorePage(storedNodeIdentifierNull, bytes)
	return mt.cache.commit()
}

// Evict removes elements from the cache that are no longer needed. Must not be called while the tree contains any uncommited changes.
func (mt *MerkleTrie) Evict() int {
	return mt.cache.evict(10000)
}

// serialize serializes the trie root
func (mt *MerkleTrie) serialize() []byte {
	serializedBuffer := make([]byte, 8*3)
	version := binary.PutUvarint(serializedBuffer[:], MerkleTreeVersion)
	root := binary.PutUvarint(serializedBuffer[version:], uint64(mt.root))
	next := binary.PutUvarint(serializedBuffer[version+root:], uint64(mt.nextNodeID))
	return serializedBuffer[:version+root+next]
}

// serialize serializes the trie root
func (mt *MerkleTrie) deserialize(bytes []byte) error {
	version, versionLen := binary.Uvarint(bytes[:])
	if versionLen <= 0 {
		return ErrPageDecodingFailuire
	}
	if version != MerkleTreeVersion {
		return ErrPageDecodingFailuire
	}
	root, rootLen := binary.Uvarint(bytes[versionLen:])
	if rootLen <= 0 {
		return ErrPageDecodingFailuire
	}
	nextNodeID, nextNodeIDLen := binary.Uvarint(bytes[versionLen+rootLen:])
	if nextNodeIDLen <= 0 {
		return ErrPageDecodingFailuire
	}
	mt.root = storedNodeIdentifier(root)
	mt.nextNodeID = storedNodeIdentifier(nextNodeID)
	return nil
}
