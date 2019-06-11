// RFC6962, soon to be modified by us (Algorand) to use SHA512-256 instead of SHA256 to avoid length extension attacks

// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package merkle

import (
	"crypto"
	_ "crypto/sha256" // XXX TODO make sha512 and update test vectors
)

// Domain separation prefixes
const (
	LeafHashPrefix = 0
	NodeHashPrefix = 1
)

// DefaultHasher is a SHA512-256 based LogHasher.
var DefaultHasher = New(crypto.SHA256) // XXX TODO make SHA512_256 and update test vectors

// Hasher implements the RFC6962 tree hashing algorithm but with SHA512-256 instead of SHA256
type Hasher struct {
	crypto.Hash
}

// New creates a new Hashers.LogHasher on the passed in hash function.
func New(h crypto.Hash) *Hasher {
	return &Hasher{Hash: h}
}

// EmptyRoot returns a special case for an empty tree.
func (t *Hasher) EmptyRoot() []byte {
	return t.New().Sum(nil)
}

// HashLeaf returns the Merkle tree leaf hash of the data passed in through leaf.
// The data in leaf is prefixed by the LeafHashPrefix.
func (t *Hasher) HashLeaf(leaf []byte) ([]byte, error) {
	h := t.New()
	h.Write([]byte{LeafHashPrefix})
	h.Write(leaf)
	return h.Sum(nil), nil
}

// HashChildren returns the inner Merkle tree node hash of the the two child nodes l and r.
// The hashed structure is NodeHashPrefix||l||r.
func (t *Hasher) HashChildren(l, r []byte) []byte {
	h := t.New()
	h.Write([]byte{NodeHashPrefix})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}
