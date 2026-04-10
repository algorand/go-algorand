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
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/statetrie/nibbles"
	"sync"
)

// Backing nodes are placeholders for nodes that have been stored in the
// backing store.  All we need is the full key of the node and its hash.
type backingNode struct {
	key  nibbles.Nibbles
	hash crypto.Digest
}

var backingNodePool = sync.Pool{
	New: func() interface{} {
		return &backingNode{
			key: make(nibbles.Nibbles, 0),
		}
	},
}

func makeBackingNode(hash crypto.Digest, key nibbles.Nibbles) *backingNode {
	stats.makebanodes.Add(1)
	ba := backingNodePool.Get().(*backingNode)
	ba.hash = hash
	ba.key = append(ba.key[:0], key...)
	return ba
}
func (ba *backingNode) setHash(hash crypto.Digest) {
	ba.hash = hash
}
func (ba *backingNode) add(mt *Trie, pathKey nibbles.Nibbles, remainingKey nibbles.Nibbles, valueHash crypto.Digest) (node, error) {
	// will be provided in the subsequent backing store PR
	return nil, nil
}
func (ba *backingNode) hashing() error {
	return nil
}
func (ba *backingNode) getKey() nibbles.Nibbles {
	return ba.key
}
func (ba *backingNode) getHash() *crypto.Digest {
	return &ba.hash
}
func (ba *backingNode) serialize() ([]byte, error) {
	panic("backingNode cannot be serialized")
}
