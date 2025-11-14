// Copyright (C) 2019-2025 Algorand, Inc.
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

package statecommit

import (
	"bytes"
	"slices"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/protocol"
)

// stateUpdate represents a single insert/update or delete operation
type stateUpdate struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Key     []byte `codec:"k"`
	Value   []byte `codec:"v"`
	Deleted bool   `codec:"d"`
}

// ToBeHashed implements crypto.Hashable for stateUpdate
func (u *stateUpdate) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.StateUpdateLeaf, protocol.Encode(u)
}

// merkleArrayCommitter implements UpdateCommitter using a Merkle array
type merkleArrayCommitter struct{ updates []stateUpdate }

// newMerkleArrayCommitter creates a new Merkle array-based update committer
func newMerkleArrayCommitter() UpdateCommitter { return &merkleArrayCommitter{} }

// updateArray implements merklearray.Array for stateUpdates
type updateArray struct{ updates []stateUpdate }

func (a *updateArray) Length() uint64                              { return uint64(len(a.updates)) }
func (a *updateArray) Marshal(pos uint64) (crypto.Hashable, error) { return &a.updates[pos], nil }

// Add adds a key-value update
func (m *merkleArrayCommitter) Add(key, val []byte) error {
	m.updates = append(m.updates, stateUpdate{Key: key, Value: val, Deleted: false})
	return nil
}

// Delete adds a deletion update
func (m *merkleArrayCommitter) Delete(key []byte) error {
	m.updates = append(m.updates, stateUpdate{Key: key, Value: nil, Deleted: true})
	return nil
}

// Root returns the Merkle root commitment of all updates
func (m *merkleArrayCommitter) Root() (crypto.Sha512Digest, error) {
	if len(m.updates) == 0 {
		return crypto.Sha512Digest{}, nil
	}

	// Sort updates by key to ensure deterministic commitment (KvMods is a map)
	slices.SortFunc(m.updates, func(a, b stateUpdate) int { return bytes.Compare(a.Key, b.Key) })

	array := &updateArray{updates: m.updates}
	// not calling merklearray.BuildVectorCommitmentTree (we don't want proof of position in array)
	tree, err := merklearray.Build(array, crypto.HashFactory{HashType: crypto.Sha512})
	if err != nil {
		return crypto.Sha512Digest{}, err
	}

	rootSlice := tree.Root().ToSlice()
	var root crypto.Sha512Digest
	copy(root[:], rootSlice)
	return root, nil
}

// Reset clears the committer state
func (m *merkleArrayCommitter) Reset() {
	m.updates = nil
}
