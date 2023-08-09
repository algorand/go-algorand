// Copyright (C) 2019-2023 Algorand, Inc.
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
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
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

// WithSeed returns a copy of the ValidatedBlock with a modified seed.
func (vb ValidatedBlock) WithSeed(s committee.Seed) ValidatedBlock {
	newblock := vb.blk
	newblock.BlockHeader.Seed = s

	return ValidatedBlock{
		blk:   newblock,
		delta: vb.delta,
	}
}

// CheckDup checks whether a txn is a duplicate
func (vb ValidatedBlock) CheckDup(currentProto config.ConsensusParams, firstValid, lastValid basics.Round, txid transactions.Txid, txl Txlease) error {
	_, present := vb.delta.Txids[txid]
	if present {
		return &TransactionInLedgerError{Txid: txid}
	}

	if currentProto.SupportTransactionLeases && (txl.Lease != [32]byte{}) {
		expires, ok := vb.delta.Txleases[txl]
		if ok && vb.blk.Round() <= expires {
			return MakeLeaseInLedgerError(txid, txl, false)
		}
	}
	return nil
}

// Hash returns the hash of the block
func (vb ValidatedBlock) Hash() bookkeeping.BlockHash {
	return vb.blk.Hash()
}

// MakeValidatedBlock creates a validated block.
func MakeValidatedBlock(blk bookkeeping.Block, delta StateDelta) ValidatedBlock {
	return ValidatedBlock{
		blk:   blk,
		delta: delta,
	}
}
