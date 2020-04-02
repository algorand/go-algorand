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

// Trie is a merkle trie intended to efficiently calculate the merkle root of
// unordered elements
type Trie struct {
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

// MakeTrie creates a merkle trie
func MakeTrie(committer Committer, cachedNodesCount int) (*Trie, error) {
	mt := &Trie{
		root:       storedNodeIdentifierNull,
		cache:      &merkleTrieCache{},
		nextNodeID: storedNodeIdentifierBase,
	}
	if committer == nil {
		committer = &InMemoryCommitter{}
	} else {
		rootBytes, err := committer.LoadPage(storedNodeIdentifierNull)
		if err == nil {
			if rootBytes != nil {
				err = mt.deserialize(rootBytes)
				if err != nil {
					return nil, err
				}
			}
		} else {
			return nil, err
		}
	}

	mt.cache.initialize(mt, committer, cachedNodesCount)
	return mt, nil
}

// SetCommitter set the provided committter as the current committer, and return the old one.
func (mt *Trie) SetCommitter(committer Committer) (prevCommitter Committer) {
	prevCommitter = mt.cache.committer
	mt.cache.committer = committer
	return
}

// RootHash returns the root hash of all the elements in the trie
func (mt *Trie) RootHash() (crypto.Digest, error) {
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
func (mt *Trie) Add(d []byte) (bool, error) {
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
func (mt *Trie) Delete(d []byte) (bool, error) {
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
func (mt *Trie) GetStats() (stats Stats, err error) {
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
func (mt *Trie) BeginTransaction(committer Committer) *Transaction {
	return makeTransaction(mt, committer)
}

// Commit stores the existings trie using the committer.
func (mt *Trie) Commit() error {
	bytes := mt.serialize()
	mt.cache.committer.StorePage(storedNodeIdentifierNull, bytes)
	return mt.cache.commit()
}

// Evict removes elements from the cache that are no longer needed. Must not be called while the tree contains any uncommited changes.
func (mt *Trie) Evict() int {
	return mt.cache.evict()
}

// serialize serializes the trie root
func (mt *Trie) serialize() []byte {
	serializedBuffer := make([]byte, (8+1)*3) // allocate the worst-case scenario for the trie header.
	version := binary.PutUvarint(serializedBuffer[:], MerkleTreeVersion)
	root := binary.PutUvarint(serializedBuffer[version:], uint64(mt.root))
	next := binary.PutUvarint(serializedBuffer[version+root:], uint64(mt.nextNodeID))
	return serializedBuffer[:version+root+next]
}

// serialize serializes the trie root
func (mt *Trie) deserialize(bytes []byte) error {
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

// reset is used to reset the trie to a given root & nextID. It's used exclusively as part of the
// transaction rollback recovery in case no persistence could be established.
func (mt *Trie) reset(root, nextID storedNodeIdentifier) {
	mt.root = root
	mt.nextNodeID = nextID
	mt.cache.initialize(mt, mt.cache.committer, mt.cache.cachedNodeCount)
}
