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
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/statetrie/nibbles"
)

type extensionNode struct {
	key       nibbles.Nibbles
	sharedKey nibbles.Nibbles
	next      node
	hash      crypto.Digest
}

// makeExtensionNode creates a extension node with the provided shared prefix,
// next node, and full key in the trie.
func makeExtensionNode(sharedKey nibbles.Nibbles, next node, key nibbles.Nibbles) *extensionNode {
	stats.makeextensions.Add(1)
	en := &extensionNode{sharedKey: make(nibbles.Nibbles, len(sharedKey)), next: next, key: make(nibbles.Nibbles, len(key))}
	copy(en.key, key)
	copy(en.sharedKey, sharedKey)
	return en
}
func (en *extensionNode) add(mt *Trie, pathKey nibbles.Nibbles, remainingKey nibbles.Nibbles, valueHash crypto.Digest) (node, error) {
	//- EN.ADD.1: Point the existing extension node at a (possibly new or existing) node resulting
	//            from performing the Add operation on the child node.
	//- EN.ADD.2: Create an extension node for the current child and store it in a new branch node child slot.
	//- EN.ADD.3: Store the existing extension node child in a new branch node child slot.
	//- EN.ADD.4: Store the new value in a new leaf node stored in an available child slot of the new branch node.
	//- EN.ADD.5: Store the new value in the value slot of the new branch node.
	//- EN.ADD.6: Modify the existing extension node shared key and point the child at the new branch node.
	//- EN.ADD.7: Replace the extension node with the branch node created earlier.
	//
	//Codepaths:
	//
	//  * Codepath 1: EN.ADD.1
	//
	//  This redirects the extension node to a new/existing node resulting from
	//  performing the Add operation on the extension child.
	//
	//  * Codepaths 2 - 5: EN.ADD.2|EN.ADD.3 then EN.ADD.4|EN.ADD.5 then EN.ADD.6
	//
	//  This stores the current extension node child in either a new branch node
	//  child slot or by creating a new extension node at a new key pointing at the
	//  child, and attaching that to a new branch node.  Either way, the new branch
	//  node also receives a new leaf node with the new value or has its value slot
	//  assigned, and another extension node is created to replace it pointed at the
	//  branch node as its target.
	//
	//  * Codepaths 6 - 9: EN.ADD.2|EN.ADD.3 then EN.ADD.4|EN.ADD.5 then EN.ADD.7
	//
	//  Same as above, only the new branch node replaceds the existing extension node
	//  outright, without the additional extension node.
	//

	// Calculate the shared Nibbles between the key we're adding and this extension node.
	// shNibbles is a slice from en.sharedKey and is read-only
	shNibbles := nibbles.SharedPrefix(en.sharedKey, remainingKey)
	if len(shNibbles) == len(en.sharedKey) {
		// The entire extension node is shared.  descend.
		shifted := nibbles.ShiftLeft(remainingKey, len(shNibbles))
		replacement, err := en.next.add(mt, append(pathKey, shNibbles...), shifted, valueHash)
		if err != nil {
			panic(fmt.Sprintf("extensionNode.add: %v", err))
		}
		if replacement.getHash().IsZero() {
			en.setHash(crypto.Digest{})
		}
		// EN.ADD.1
		en.next = replacement
		return en, nil
	}

	// we have to upgrade part or all of this extension node into a branch node.
	var children [16]node
	branchHash := crypto.Digest{}
	// what's left of the extension node shared key after removing the shared part gets
	// attached to the new branch node.
	shifted := nibbles.ShiftLeft(en.sharedKey, len(shNibbles))
	if len(shifted) >= 2 {
		// if there's two or more Nibbles left, make another extension node.
		shifted2 := nibbles.ShiftLeft(shifted, 1)
		enKey := pathKey[:]
		enKey = append(enKey, shNibbles...)
		enKey = append(enKey, shifted[0])
		en2 := makeExtensionNode(shifted2, en.next, enKey)
		// EN.ADD.2
		children[shifted[0]] = en2
	} else {
		// if there's only one nibble left, store the child in the branch node.
		// there can't be no Nibbles left, or the earlier entire-node-shared case would have been triggered.
		// EN.ADD.3
		children[shifted[0]] = en.next
	}

	//what's left of the new remaining key gets put into the branch node bucket corresponding
	//with its first nibble, or into the valueHash if it's now empty.
	shifted = nibbles.ShiftLeft(remainingKey, len(shNibbles))
	if len(shifted) > 0 {
		shifted3 := nibbles.ShiftLeft(shifted, 1)
		// we know this slot will be empty because it's the first nibble that differed from the
		// only other occupant in the child arrays, the one that leads to the extension node's child.
		lnKey := pathKey[:]
		lnKey = append(lnKey, shNibbles...)
		lnKey = append(lnKey, shifted[0])
		ln := makeLeafNode(shifted3, valueHash, lnKey)
		// EN.ADD.4
		children[shifted[0]] = ln
	} else {
		// if the key is no more, store it in the branch node's value hash slot.
		// EN.ADD.5
		branchHash = valueHash
	}

	bnKey := pathKey[:]
	bnKey = append(bnKey, shNibbles...)
	replacement := makeBranchNode(children, branchHash, bnKey)
	// the shared bits of the extension node get smaller
	if len(shNibbles) > 0 {
		// still some shared key left, store them in an extension node
		// and point in to the new branch node
		en.sharedKey = shNibbles
		en.next = replacement
		en.setHash(crypto.Digest{})
		// EN.ADD.6
		return en, nil
	}
	// or else there there is no shared key left, and the extension node is destroyed.
	// EN.ADD.7
	return replacement, nil
}

// setHash sets the value of the hash for the node.
func (en *extensionNode) setHash(hash crypto.Digest) {
	en.hash = hash
}

// hashing serializes the node and then hashes it, storing the hash in the node.
func (en *extensionNode) hashing() error {
	if en.hash.IsZero() {
		if en.next.getHash().IsZero() {
			err := en.next.hashing()
			if err != nil {
				return err
			}
		}
		bytes, err := en.serialize()
		if err != nil {
			return err
		}

		stats.cryptohashes.Add(1)
		en.setHash(crypto.Hash(bytes))
	}
	return nil
}

// serialize creates a byte array containing an identifier prefix
// (2 if the nibble length of the keyEnd is even, 1 if it is odd)
// as well as the hash of the next node and the shared key prefix.
func (en *extensionNode) serialize() ([]byte, error) {
	pack, half := nibbles.Pack(en.sharedKey)
	data := make([]byte, 1+crypto.DigestSize+len(pack))
	if half {
		data[0] = 1
	} else {
		data[0] = 2
	}

	copy(data[1:(1+crypto.DigestSize)], en.next.getHash()[:])
	copy(data[(1+crypto.DigestSize):], pack)
	return data, nil
}

// deserializeExtensionNode turns a data array and its key in the trie into
// an extension node.
func deserializeExtensionNode(data []byte, key nibbles.Nibbles) *extensionNode {
	if data[0] != 1 && data[0] != 2 {
		panic("invalid prefix for extension node")
	}

	if len(data) < (1 + crypto.DigestSize) {
		panic("data too short to be an extension node")
	}

	sharedKey := nibbles.MakeNibbles(data[(1+crypto.DigestSize):], data[0] == 1)
	if len(sharedKey) == 0 {
		panic("sharedKey can't be empty in an extension node")
	}
	var hash crypto.Digest
	copy(hash[:], data[1:(1+crypto.DigestSize)])
	var child node
	if !hash.IsZero() {
		chKey := key[:]
		chKey = append(chKey, sharedKey...)
		child = makeBackingNode(hash, chKey)
	} else {
		panic("next node hash can't be zero in an extension node")
	}

	return makeExtensionNode(sharedKey, child, key)
}

// getKey gets the nibbles of the full key for this node.
func (en *extensionNode) getKey() nibbles.Nibbles {
	return en.key
}

// getHash gets the hash for this node.  If the hash has not been set by a
// hashing operation like extNode.hashing, getHash will not calculate it
// (instead it will return the empty hash, crypto.Digest{})
func (en *extensionNode) getHash() *crypto.Digest {
	return &en.hash
}
