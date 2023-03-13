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

package merkletrie

import (
	"encoding/binary"
	"errors"

	"github.com/algorand/go-algorand/crypto"
)

const (
	// merkleTreeVersion is the version of the encoded trie. If we ever want to make changes and want to have upgrade path,
	// this would give us the ability to do so.
	merkleTreeVersion = uint64(0x1000000010000000)
	// nodePageVersion is the version of the encoded node. If we ever want to make changes and want to have upgrade path,
	// this would give us the ability to do so.
	nodePageVersion = uint64(0x1000000010000000)
)

// ErrRootPageDecodingFailure is returned if the decoding the root page has failed.
var ErrRootPageDecodingFailure = errors.New("error encountered while decoding root page")

// ErrMismatchingElementLength is returned when an element is being added/removed from the trie that doesn't align with the trie's previous elements length
var ErrMismatchingElementLength = errors.New("mismatching element length")

// ErrMismatchingPageSize is returned when you try to provide an existing trie a committer with a different page size than it was originally created with.
var ErrMismatchingPageSize = errors.New("mismatching page size")

// ErrUnableToEvictPendingCommits is returned if the tree was modified and Evict was called with commit=false
var ErrUnableToEvictPendingCommits = errors.New("unable to evict as pending commits available")

// MemoryConfig used to define the Trie object memory configuration.
type MemoryConfig struct {
	// NodesCountPerPage defines how many nodes each page would contain
	NodesCountPerPage int64
	// CachedNodesCount defines the number of nodes we want to retain in memory between consecutive Evict calls.
	CachedNodesCount int
	// PageFillFactor defines the desired fill ratio of a created page.
	PageFillFactor float32
	// MaxChildrenPagesThreshold define the maximum number of different pages that would be used for a single node's children.
	// it's being evaluated during Commit, for all the updated nodes.
	MaxChildrenPagesThreshold uint64
}

// Trie is a merkle trie intended to efficiently calculate the merkle root of
// unordered elements
type Trie struct {
	root                storedNodeIdentifier
	nextNodeID          storedNodeIdentifier
	lastCommittedNodeID storedNodeIdentifier
	cache               merkleTrieCache
	elementLength       int
}

// Stats structure is a helper for finding underlaying statistics about the trie
type Stats struct {
	NodesCount uint
	LeafCount  uint
	Depth      int
	Size       int
}

// MakeTrie creates a merkle trie
func MakeTrie(committer Committer, memoryConfig MemoryConfig) (*Trie, error) {
	mt := &Trie{
		root:                storedNodeIdentifierNull,
		cache:               merkleTrieCache{},
		nextNodeID:          storedNodeIdentifierBase,
		lastCommittedNodeID: storedNodeIdentifierBase,
	}
	if committer == nil {
		committer = &InMemoryCommitter{}
	} else {
		rootBytes, err := committer.LoadPage(storedNodeIdentifierNull)
		if err == nil {
			if rootBytes != nil {
				var pageSize int64
				pageSize, err = mt.deserialize(rootBytes)
				if err != nil {
					return nil, err
				}
				if pageSize != memoryConfig.NodesCountPerPage {
					return nil, ErrMismatchingPageSize
				}
			}
		} else {
			return nil, err
		}
	}
	mt.cache.initialize(mt, committer, memoryConfig)
	return mt, nil
}

// SetCommitter sets the provided committer as the current committer
func (mt *Trie) SetCommitter(committer Committer) {
	mt.cache.committer = committer
}

// RootHash returns the root hash of all the elements in the trie
func (mt *Trie) RootHash() (crypto.Digest, error) {
	if mt.root == storedNodeIdentifierNull {
		return crypto.Digest{}, nil
	}
	if mt.cache.modified {
		if _, err := mt.Commit(); err != nil {
			return crypto.Digest{}, err
		}
	}
	pnode, err := mt.cache.getNode(mt.root)
	if err != nil {
		return crypto.Digest{}, err
	}

	if pnode.leaf() {
		return crypto.Hash(append([]byte{0}, pnode.hash...)), nil
	}
	return crypto.Hash(append([]byte{1}, pnode.hash...)), nil
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
		pnode.hash = d
		mt.elementLength = len(d)
		return true, nil
	}
	if len(d) != mt.elementLength {
		return false, ErrMismatchingElementLength
	}
	pnode, err := mt.cache.getNode(mt.root)
	if err != nil {
		return false, err
	}
	found, err := pnode.find(&mt.cache, d[:])
	if found || (err != nil) {
		return false, err
	}
	mt.cache.beginTransaction()
	var updatedRoot storedNodeIdentifier
	updatedRoot, err = pnode.add(&mt.cache, d[:], make([]byte, 0, len(d)))
	if err != nil {
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
	if len(d) != mt.elementLength {
		return false, ErrMismatchingElementLength
	}
	pnode, err := mt.cache.getNode(mt.root)
	if err != nil {
		return false, err
	}
	found, err := pnode.find(&mt.cache, d[:])
	if !found || err != nil {
		return false, err
	}
	mt.cache.beginTransaction()
	if pnode.leaf() {
		// remove the root.
		mt.cache.deleteNode(mt.root)
		mt.root = storedNodeIdentifierNull
		mt.cache.commitTransaction()
		mt.elementLength = 0
		return true, nil
	}
	var updatedRoot storedNodeIdentifier
	updatedRoot, err = pnode.remove(&mt.cache, d[:], make([]byte, 0, len(d)))
	if err != nil {
		mt.cache.rollbackTransaction()
		return false, err
	}
	mt.cache.deleteNode(mt.root)
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
	err = pnode.stats(&mt.cache, &stats, 1)
	return
}

// Commit stores the existings trie using the committer.
func (mt *Trie) Commit() (stats CommitStats, err error) {
	stats, err = mt.cache.commit()
	if err == nil {
		mt.lastCommittedNodeID = mt.nextNodeID
		bytes := mt.serialize()
		err = mt.cache.committer.StorePage(storedNodeIdentifierNull, bytes)
	}
	return
}

// Evict removes elements from the cache that are no longer needed.
func (mt *Trie) Evict(commit bool) (int, error) {
	if commit {
		if mt.cache.modified {
			if _, err := mt.Commit(); err != nil {
				return 0, err
			}
		}
	} else {
		if mt.cache.modified {
			return 0, ErrUnableToEvictPendingCommits
		}
	}
	return mt.cache.evict(), nil
}

// serialize serializes the trie root
func (mt *Trie) serialize() []byte {
	serializedBuffer := make([]byte, 5*binary.MaxVarintLen64) // allocate the worst-case scenario for the trie header.
	version := binary.PutUvarint(serializedBuffer[:], merkleTreeVersion)
	root := binary.PutUvarint(serializedBuffer[version:], uint64(mt.root))
	next := binary.PutUvarint(serializedBuffer[version+root:], uint64(mt.nextNodeID))
	elementLength := binary.PutUvarint(serializedBuffer[version+root+next:], uint64(mt.elementLength))
	pageSizeLength := binary.PutUvarint(serializedBuffer[version+root+next+elementLength:], uint64(mt.cache.nodesPerPage))
	return serializedBuffer[:version+root+next+elementLength+pageSizeLength]
}

// deserialize deserializes the trie root
func (mt *Trie) deserialize(bytes []byte) (int64, error) {
	version, versionLen := binary.Uvarint(bytes[:])
	if versionLen <= 0 {
		return 0, ErrRootPageDecodingFailure
	}
	if version != merkleTreeVersion {
		return 0, ErrRootPageDecodingFailure
	}
	root, rootLen := binary.Uvarint(bytes[versionLen:])
	if rootLen <= 0 {
		return 0, ErrRootPageDecodingFailure
	}
	nextNodeID, nextNodeIDLen := binary.Uvarint(bytes[versionLen+rootLen:])
	if nextNodeIDLen <= 0 {
		return 0, ErrRootPageDecodingFailure
	}
	elemLength, elemLengthLength := binary.Uvarint(bytes[versionLen+rootLen+nextNodeIDLen:])
	if elemLengthLength <= 0 {
		return 0, ErrRootPageDecodingFailure
	}
	pageSize, pageSizeLength := binary.Uvarint(bytes[versionLen+rootLen+nextNodeIDLen+elemLengthLength:])
	if pageSizeLength <= 0 {
		return 0, ErrRootPageDecodingFailure
	}
	mt.root = storedNodeIdentifier(root)
	mt.nextNodeID = storedNodeIdentifier(nextNodeID)
	mt.lastCommittedNodeID = storedNodeIdentifier(nextNodeID)
	mt.elementLength = int(elemLength)
	return int64(pageSize), nil
}
