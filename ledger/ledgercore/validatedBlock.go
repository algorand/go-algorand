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

package ledgercore

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
)

// ValidatedBlock represents the result of a block validation.  It can
// be used to efficiently add the block to the ledger, without repeating
// the work of applying the block's changes to the ledger state.
type ValidatedBlock struct {
	blk   bookkeeping.Block
	delta StateDelta
}

// Block returns the underlying Block for a ValidatedBlock.
func (vb ValidatedBlock) Block() bookkeeping.Block {
	return vb.blk
}

// Delta returns the underlying Delta for a ValidatedBlock.
func (vb ValidatedBlock) Delta() StateDelta {
	return vb.delta
}

// MakeValidatedBlock creates a validated block.
func MakeValidatedBlock(blk bookkeeping.Block, delta StateDelta) ValidatedBlock {
	return ValidatedBlock{
		blk:   blk,
		delta: delta,
	}
}

// UnfinishedBlock represents a block that has been generated, but is
// not yet ready for proposing until FinishBlock is called.
type UnfinishedBlock struct {
	finalAccounts map[basics.Address]AccountData // status of selected accounts at end of block
	blk           bookkeeping.Block
	deltas        StateDelta
}

// MakeUnfinishedBlock creates an unfinished block.
func MakeUnfinishedBlock(blk bookkeeping.Block, deltas StateDelta, finalAccounts map[basics.Address]AccountData) UnfinishedBlock {
	return UnfinishedBlock{
		finalAccounts: finalAccounts,
		blk:           blk,
		deltas:        deltas,
	}
}

// UnfinishedBlock returns the underlying Block. It should only be used for statistics and testing purposes,
// as the block is not yet finished and ready for proposing.
func (ub UnfinishedBlock) UnfinishedBlock() bookkeeping.Block {
	return ub.blk
}

// UnfinishedDeltas returns the unfinished deltas. It should only be used for statistics and testing purposes,
// as the block is not yet finished and ready for proposing.
func (ub UnfinishedBlock) UnfinishedDeltas() StateDelta {
	return ub.deltas
}

// ContainsAddress returns true if the balance data about the given address is present in the unfinished block.
func (ub UnfinishedBlock) ContainsAddress(addr basics.Address) bool {
	_, ok := ub.finalAccounts[addr]
	return ok
}

// FinishBlock completes the block and returns a proposable block.
func (ub UnfinishedBlock) FinishBlock(s committee.Seed, proposer basics.Address, eligible bool) bookkeeping.Block {
	// Look up the given proposer's balance by the end of this block
	propData, ok := ub.finalAccounts[proposer]
	// This proposer has closed their account and is not eligible for rewards
	if !ok || propData.MicroAlgos.IsZero() {
		eligible = false
	}
	return ub.blk.WithProposer(s, proposer, eligible)
}

// Round returns the round of the block.
func (ub UnfinishedBlock) Round() basics.Round {
	return ub.blk.Round()
}
