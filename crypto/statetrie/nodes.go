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

// Trie nodes

type node interface {
	// add to the trie the key (represented by pathKey + remainingKey) and the value (represented
	// by valueHash) into the trie provided.
	add(mt *Trie, pathKey nibbles.Nibbles, remainingKey nibbles.Nibbles, valueHash crypto.Digest) (node, error)

	hashing() error             // calculate the hash of the node
	serialize() ([]byte, error) // serialize the node
	getHash() *crypto.Digest    // the hash of the node, if it has been hashed
	setHash(hash crypto.Digest) // set the hash of the node
	getKey() nibbles.Nibbles    // the key of the node in the trie
}

// First byte of a committed node indicates the type of node.
//
//  1 == extension, half nibble
//  2 == extension, full
//  3 == leaf, half nibble
//  4 == leaf, full
//  5 == branch
//

func deserializeNode(nbytes []byte, key nibbles.Nibbles) node {
	if len(nbytes) == 0 {
		panic("deserializeNode: zero length node")
	}
	switch nbytes[0] {
	case 1, 2:
		return deserializeExtensionNode(nbytes, key)
	case 3, 4:
		return deserializeLeafNode(nbytes, key)
	case 5:
		return deserializeBranchNode(nbytes, key)
	default:
		panic(fmt.Sprintf("deserializeNode: invalid node type %d", nbytes[0]))
	}
}
