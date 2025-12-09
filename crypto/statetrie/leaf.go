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

type leafNode struct {
	key       nibbles.Nibbles
	keyEnd    nibbles.Nibbles
	valueHash crypto.Digest
	hash      crypto.Digest
}

// makeLeafNode creates a leaf node with the provided valueHash, key and keyEnd.
// The full key of the value represented by the node is key + keyEnd.
func makeLeafNode(keyEnd nibbles.Nibbles, valueHash crypto.Digest, key nibbles.Nibbles) *leafNode {
	stats.makeleaves.Add(1)
	ln := &leafNode{keyEnd: make(nibbles.Nibbles, len(keyEnd)), valueHash: valueHash, key: make(nibbles.Nibbles, len(key))}
	copy(ln.key, key)
	copy(ln.keyEnd, keyEnd)
	return ln
}

// setHash sets the value of the hash for the node.
func (ln *leafNode) setHash(hash crypto.Digest) {
	ln.hash = hash
}
func (ln *leafNode) add(mt *Trie, pathKey nibbles.Nibbles, remainingKey nibbles.Nibbles, valueHash crypto.Digest) (node, error) {
	//Add operation transitions:
	//
	//- LN.ADD.0: The key and value already exist in the trie.
	//- LN.ADD.1: Store the new value in the existing leaf node, overwriting it.
	//- LN.ADD.2: Store the existing leaf value in a new branch node value space.
	//- LN.ADD.3: Store the existing leaf value in a new leaf node attached to a new branch node.
	//- LN.ADD.4: Store the new value in the new branch node value space.
	//- LN.ADD.5: Store the new value in a new leaf node attached to the new branch node.
	//- LN.ADD.6: Replace the leaf node with a new extension node in front of the new branch node.
	//- LN.ADD.7: Replace the leaf node with the branch node created earlier.
	//
	//  Codepath 0:
	//    This codepath is triggered when the added key/value already exists in the trie.
	//    The leaf node is returned as the replacement node (eg no replacement), and the
	//    hash is left unchanged.
	//  Codepath 1: LN.ADD.3 then LN.ADD.5 then LN.ADD.7
	//    This codepath is triggered when the existing leaf node keyEnd has nothing in common
	//    with the added key. This results in a new branch node, with two leaf nodes attached to
	//    it, representing the original leaf and the new key.  The branch node is returned as the
	//    replacement for this leaf node.
	//  Example:
	//  {key="AB", value="DEF"} // added to trie as a leaf node which is now the root node.
	//  {key="CD", value="GHI"} // adding this node triggers codepath 1 on the first node
	//
	//  Codepath 2: LN.ADD.1
	//    This codepath is triggered when the added key is already in the trie.  The existing
	//    leaf node is modified to change its value, and the hash is blanked, then this node is
	//    returned as the replacement (so, not really a replacement).
	//  Example:
	//  {key="A", value="DEF"} // added to trie as a leaf node which is now the root node.
	//  {key="A", value="GHI"} // adding this node triggers Codepath 2 on the first node
	//
	//  Codepath 3: LN.ADD.2 then LN.ADD.5 then LN.ADD.6
	//    This codepath is triggered when there is an existing leaf node whose key is
	//    a complete prefix of the added key.  The result is a new branch node with the
	//    existing value stored in its branch value slot and a new child leaf node hanging
	//    off of the new branch node.  The branch node is returned as the replacement node.
	//  Example:
	//  {key="A", value="DEF"}  // added to trie as a leaf node which is now the root node.
	//  {key="AB", value="GHI"} // adding this node triggers Codepath 3 on the first node
	//
	//  Codepath 4: LN.ADD.3 then LN.ADD.4 then LN.ADD.6
	//    This codepath is triggered when the added key is a prefix of the leaf node key.
	//    The result is an extension node containing the shared prefix, which points to a
	//    new branch node containing the new key in the branch node value slot and a
	//    additional leaf node attached to the branch node to contain the original leaf node.
	//    The extension node is returned as the leaf node replacement.
	//  Example:
	//  {key="AB", value="DEF"} // added to trie as a leaf node which is now the root node.
	//  {key="A", value="GHI"}  // adding this node triggers Codepath 4 on the first node
	//
	//  Codepath 5: LN.ADD.3 then LN.ADD.5 then LN.ADD.6
	//    This codepath is triggered when the added key shares a prefix with the existing
	//    leaf node, but then diverges. The leaf node is replaced with an extension node
	//    containing the shared prefix, which points to a new branch node, and both the original
	//    leaf node and the added key/value are attached to that node.  The extension node
	//    is returned as the leaf node replacement.
	//  Example:
	//  {key="AB", value="DEF"} // added to trie as a leaf node which is now the root node.
	//  {key="AC", value="GHI"} // adding this node triggers Codepath 5 on the first node
	//
	//  Codepath 6: LN.ADD.2 then LN.ADD.5 then LN.ADD.7
	//    This codepath is triggered when the existing leaf node has no more keyEnd (as the
	//    branch slot it is attached to completes the key) but the added node still has
	//    additional nibbles in it.  A new branch node is created, and the original leaf
	//    value is stored in its branch value slot, and the added key is stored in a leaf
	//    node attached to that new branch node.  The branch node is returned as the leaf
	//    node replacement.
	//  Example:
	//  {key="A", value="DEF"}  // added to trie as a leaf node which is now the root node.
	//  {key="B", value="GHI"}  // added to trie, creating a branch node via codepath 1 with
	//                          // two leaf nodes, each with no keyEnd (as they are attached to
	//                          // the A and B slots in the new branch node)
	//  {key="AB", value="JKL"} // adding this node triggers codepath 6 on the leaf node in
	//                          // the "A" slot (value DEF)
	//
	//  Codepath 7: LN.ADD.3 then LN.ADD.4 then LN.ADD.7
	//    This codepath is triggered when the added key is a prefix of the existing leaf node,
	//    but unlike codepath 4, the existing leaf node shares no nibbles with the added key.
	//    The new key is added into the value slot for a new branch node and the original key
	//    is stored in a leaf node attached to the branch.  The branch node is returned as the
	//    leaf node replacement.
	//  Example:
	//  {key="AB", value="DEF"} // added to trie as a leaf node which is now the root node.
	//  {key="B", value="GHI"}  // added to trie, creating a branch node via codepath 1, with
	//                          // two new leaf nodes, one with keyEnd {} attached to the "B" slot (value GHI)
	//                          // and one with keyEnd {"B"} attached to the "A" slot (value DEF)
	//  {key="A", value="JKL"}  // adding this node triggers codepath 7 on the node with value DEF
	//                          // from above, placing JKL in a new branch node value slot and attaching
	//                          // the DEF node to that branch node's "B" slot.
	//
	if nibbles.Equal(ln.keyEnd, remainingKey) {
		// The two keys are the same. Replace the value.
		if ln.valueHash == valueHash {
			// The two values are the same.  No change, don't clear the hash.
			return ln, nil
		}
		// LN.ADD.1
		ln.valueHash = valueHash
		ln.setHash(crypto.Digest{})
		return ln, nil
	}

	// Calculate the shared Nibbles between the leaf node we're on and the key we're inserting.
	// sharedNibbles returns the shared slice from the first argmuent, ln.keyEnd, and is read-only.
	shNibbles := nibbles.SharedPrefix(ln.keyEnd, remainingKey)
	// Shift away the common Nibbles from both the keys.
	shiftedLn1 := nibbles.ShiftLeft(ln.keyEnd, len(shNibbles))
	shiftedLn2 := nibbles.ShiftLeft(remainingKey, len(shNibbles))

	// Make a branch node.
	var children [16]node
	branchHash := crypto.Digest{}

	// If the existing leaf node has no more Nibbles, then store it in the branch node's value slot.
	if len(shiftedLn1) == 0 {
		// LN.ADD.2
		branchHash = ln.valueHash
	} else {
		// Otherwise, make a new leaf node that shifts away one nibble, and store it in that nibble's slot
		// in the branch node.
		key1 := append(append(pathKey, shNibbles...), shiftedLn1[0])
		ln1 := makeLeafNode(nibbles.ShiftLeft(shiftedLn1, 1), ln.valueHash, key1)
		// LN.ADD.3
		children[shiftedLn1[0]] = ln1
	}

	// Similarly, for our new insertion, if it has no more Nibbles, store it in the
	// branch node's value slot.
	if len(shiftedLn2) == 0 {
		// LN.ADD.4
		branchHash = valueHash
	} else {
		// Otherwise, make a new leaf node that shifts away one
		// nibble, and store it in that nibble's slot in the branch node.
		key2 := pathKey[:]
		key2 = append(key2, shNibbles...)
		key2 = append(key2, shiftedLn2[0])
		ln2 := makeLeafNode(nibbles.ShiftLeft(shiftedLn2, 1), valueHash, key2)
		// LN.ADD.5
		children[shiftedLn2[0]] = ln2
	}
	bn2key := pathKey[:]
	bn2key = append(bn2key, shNibbles...)
	bn2 := makeBranchNode(children, branchHash, bn2key)

	if len(shNibbles) >= 1 {
		// If there was more than one shared nibble, insert an extension node before the branch node.
		enKey := pathKey[:]
		en := makeExtensionNode(shNibbles, bn2, enKey)
		// LN.ADD.6
		return en, nil
	}
	// LN.ADD.7
	return bn2, nil
}

// hashing serializes the node and then hashes it, storing the hash in the node.
func (ln *leafNode) hashing() error {
	if ln.hash.IsZero() {
		bytes, err := ln.serialize()
		if err == nil {
			stats.cryptohashes.Add(1)
			ln.setHash(crypto.Hash(bytes))
		}
	}
	return nil
}

// serialize creates a byte array containing an identifier prefix
// (4 if the nibble length of the keyEnd is even, 3 if it is odd)
// as well as the keyEnd and the valueHash themselves.
func (ln *leafNode) serialize() ([]byte, error) {
	var buf bytes.Buffer

	prefix := byte(4)
	pack, half := nibbles.Pack(ln.keyEnd)
	if half {
		prefix = byte(3)
	}
	buf.WriteByte(prefix)
	buf.Write(ln.valueHash[:])
	buf.Write(pack)
	return buf.Bytes(), nil
}

// deserializeLeafNode turns a data array and its key in the trie into
// a leaf node.
func deserializeLeafNode(data []byte, key nibbles.Nibbles) *leafNode {
	if data[0] != 3 && data[0] != 4 {
		panic("invalid leaf node")
	}
	if len(data) < 1+crypto.DigestSize {
		panic("data too short to be a leaf node")
	}

	keyEnd := nibbles.MakeNibbles(data[(1+crypto.DigestSize):], data[0] == 3)
	lnKey := key[:]
	return makeLeafNode(keyEnd, crypto.Digest(data[1:(1+crypto.DigestSize)]), lnKey)
}

// getKey gets the nibbles of the full key for this node.
func (ln *leafNode) getKey() nibbles.Nibbles {
	return ln.key
}

// getHash gets the hash for this node.  If the hash has not been set by a
// hashing operation like leafNode.hashing, getHash will not calculate it
// (instead it will return the empty hash, crypto.Digest{})
func (ln *leafNode) getHash() *crypto.Digest {
	return &ln.hash
}
