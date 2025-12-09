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
	"bytes"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/statetrie/nibbles"
)

type branchNode struct {
	children  [16]node
	valueHash crypto.Digest
	key       nibbles.Nibbles
	hash      crypto.Digest
}

// makeBranchNode creates a branch node with the provided children nodes, valueHash,
// and full key.
func makeBranchNode(children [16]node, valueHash crypto.Digest, key nibbles.Nibbles) *branchNode {
	stats.makebranches.Add(1)
	bn := &branchNode{children: children, valueHash: valueHash, key: make(nibbles.Nibbles, len(key))}
	copy(bn.key, key)
	return bn
}
func (bn *branchNode) add(mt *Trie, pathKey nibbles.Nibbles, remainingKey nibbles.Nibbles, valueHash crypto.Digest) (node, error) {
	//Three operational transitions:
	//
	//- BN.ADD.1: Store the new value in the branch node value slot. This overwrites
	//  the branch node slot value.
	//
	//- BN.ADD.2: Make a new leaf node with the new value, and point an available
	//  branch child slot at it. This stores a new leaf node in a child slot.
	//
	//- BN.ADD.3: This repoints the child node to a new/existing node resulting from
	//  performing the Add operation on the child node.
	if len(remainingKey) == 0 {
		// If we're here, then set the value hash in this node, overwriting the old one.
		if bn.valueHash == valueHash {
			// If it is the same value, do not zero the hash
			return bn, nil
		}

		bn.valueHash = valueHash
		// transition BN.ADD.1
		bn.hash = crypto.Digest{}
		return bn, nil
	}

	// Otherwise, shift out the first nibble and check the children for it.
	shifted := nibbles.ShiftLeft(remainingKey, 1)
	slot := remainingKey[0]
	if bn.children[slot] == nil {
		// nil children are available.
		lnKey := pathKey[:]
		lnKey = append(lnKey, slot)

		// transition BN.ADD.2
		bn.hash = crypto.Digest{}
		bn.children[slot] = makeLeafNode(shifted, valueHash, lnKey)
	} else {
		// Not available.  Descend down the branch.
		replacement, err := bn.children[slot].add(mt, append(pathKey, remainingKey[0]), shifted, valueHash)
		if err != nil {
			return nil, err
		}
		// If the replacement hash is zero, zero the branch node hash
		if replacement.getHash().IsZero() {
			bn.hash = crypto.Digest{}
		}
		// transition BN.ADD.3
		bn.children[slot] = replacement
	}

	return bn, nil
}

// hashing serializes the node and then hashes it, storing the hash in the node.
func (bn *branchNode) hashing() error {
	if bn.hash.IsZero() {
		for i := 0; i < 16; i++ {
			if bn.children[i] != nil && bn.children[i].getHash().IsZero() {
				err := bn.children[i].hashing()
				if err != nil {
					return err
				}
			}
		}
		bytes, err := bn.serialize()
		if err != nil {
			return err
		}
		stats.cryptohashes.Add(1)
		bn.hash = crypto.Hash(bytes)
	}
	return nil
}

// deserializeBranchNode turns a data array and its key in the trie into
// a branch node.
func deserializeBranchNode(data []byte, key nibbles.Nibbles) *branchNode {
	if data[0] != 5 {
		panic("invalid prefix for branch node")
	}
	if len(data) < (1 + 17*crypto.DigestSize) {
		panic("data too short to be a branch node")
	}

	var children [16]node
	for i := 0; i < 16; i++ {
		var hash crypto.Digest

		copy(hash[:], data[1+i*crypto.DigestSize:(1+crypto.DigestSize)+i*crypto.DigestSize])
		if !hash.IsZero() {
			chKey := key[:]
			chKey = append(chKey, byte(i))
			children[i] = makeBackingNode(hash, chKey)
		}
	}
	var valueHash crypto.Digest
	copy(valueHash[:], data[(1+16*crypto.DigestSize):(1+17*crypto.DigestSize)])
	return makeBranchNode(children, valueHash, key)
}

// setHash sets the value of the hash for the node.
func (bn *branchNode) setHash(hash crypto.Digest) {
	bn.hash = hash
}

func (bn *branchNode) serialize() ([]byte, error) {
	var buf bytes.Buffer
	var empty crypto.Digest
	prefix := byte(5)

	buf.WriteByte(prefix)
	for i := 0; i < 16; i++ {
		if bn.children[i] != nil {
			buf.Write(bn.children[i].getHash().ToSlice())
		} else {
			buf.Write(empty[:])
		}
	}
	buf.Write(bn.valueHash[:])
	return buf.Bytes(), nil
}

// getKey gets the nibbles of the full key for this node.
func (bn *branchNode) getKey() nibbles.Nibbles {
	return bn.key
}

// getHash gets the hash for this node.  If the hash has not been set by a
// hashing operation like branchNode.hashing, getHash will not calculate it
// (instead it will return the empty hash, crypto.Digest{})
func (bn *branchNode) getHash() *crypto.Digest {
	return &bn.hash
}
