// Copyright (C) 2019-2021 Algorand, Inc.
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

package ledgercore

import (
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
)

// ParticipantsArray implements merklearray.Array and is used to commit
// to a Merkle tree of online accounts.
//msgp:ignore ParticipantsArray
type ParticipantsArray []basics.Participant

// Length returns the ledger of the array.
func (p ParticipantsArray) Length() uint64 {
	return uint64(len(p))
}

// Marshal Returns the hash for the given position.
func (p ParticipantsArray) Marshal(pos uint64) ([]byte, error) {
	if pos >= uint64(len(p)) {
		return crypto.GenericDigest{}, fmt.Errorf("array ParticipantsArray.Get(%d) out of bounds %d", pos, len(p))
	}

	return crypto.HashRep(p[pos]), nil
}

// InitState structure defines blockchain init params
type InitState struct {
	Block       bookkeeping.Block
	Accounts    map[basics.Address]basics.AccountData
	GenesisHash crypto.Digest
}
