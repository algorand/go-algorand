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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
)

// FoundAddress is a wrapper for an address and a boolean.
type FoundAddress struct {
	Address basics.Address
	Exists  bool
}

// LedgerForCowBase represents subset of Ledger functionality needed for cow business
type LedgerForCowBase interface {
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, Txlease) error
	LookupWithoutRewards(basics.Round, basics.Address) (basics.AccountData, basics.Round, error)
	GetCreatorForRound(basics.Round, basics.CreatableIndex, basics.CreatableType) (basics.Address, bool, error)
}

// ParticipantsArray implements merklearray.Array and is used to commit
// to a Merkle tree of online accounts.
//msgp:ignore ParticipantsArray
type ParticipantsArray []basics.Participant

// Length returns the ledger of the array.
func (a ParticipantsArray) Length() uint64 {
	return uint64(len(a))
}

// GetHash returns the hash for the given position.
func (a ParticipantsArray) GetHash(pos uint64) (crypto.Digest, error) {
	if pos >= uint64(len(a)) {
		return crypto.Digest{}, fmt.Errorf("array ParticipantsArray.Get(%d) out of bounds %d", pos, len(a))
	}

	return crypto.HashObj(a[pos]), nil
}

// InitState structure defines blockchain init params
type InitState struct {
	Block       bookkeeping.Block
	Accounts    map[basics.Address]basics.AccountData
	GenesisHash crypto.Digest
}
