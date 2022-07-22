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

package ledger

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

type LedgerForEvaluator interface {
	// Needed for cow.go
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error
	LookupWithoutRewards(basics.Round, basics.Address) (basics.AccountData, basics.Round, error)
	GetCreatorForRound(basics.Round, basics.CreatableIndex, basics.CreatableType) (basics.Address, bool, error)

	// Needed for the evaluator
	GenesisHash() crypto.Digest
	Totals(basics.Round) (ledgercore.AccountTotals, error)
	CompactCertVoters(basics.Round) (*ledgercore.VotersForRound, error)
}

// validatedBlockAsLFE presents a LedgerForEvaluator interface on top of
// a ValidatedBlock.  This makes it possible to construct a BlockEvaluator
// on top, which in turn allows speculatively constructing a subsequent
// block, before the ValidatedBlock is committed to the ledger.
//
// This is what the state looks like:
//
// previousLFE <--------- roundCowBase
//      ^           l         ^
//      |                     | lookupParent
//      |                     |
//      |               roundCowState
//      |                     ^
//      |                     | state
//      |                     |
//	|		ValidatedBlock -------> Block
//      |                     ^          blk
//      |                     | vb
//      |     l               |
//      \---------- validatedBlockAsLFE
//
// where previousLFE might be the full ledger, or might be another
// validatedBlockAsLFE.
type validatedBlockAsLFE struct {
	// l points to the underlying ledger; it might be another instance
	// of validatedBlockAsLFE if we are speculating on a chain of many
	// blocks.
	l LedgerForEvaluator

	// vb points to the ValidatedBlock that logically extends the
	// state of the ledger.
	vb *ledgercore.ValidatedBlock
}

// makeValidatedBlockAsLFE constructs a new validatedBlockAsLFE from a
// ValidatedBlock.
func makeValidatedBlockAsLFE(vb *ledgercore.ValidatedBlock, l LedgerForEvaluator) (*validatedBlockAsLFE, error) {
	return &validatedBlockAsLFE{
		l:  l,
		vb: vb,
	}, nil
}

// BlockHdr implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	if r == v.vb.Block().Round() {
		return v.vb.Block().BlockHeader, nil
	}

	return v.l.BlockHdr(r)
}

// CheckDup implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) CheckDup(currentProto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl ledgercore.Txlease) error {
	if current == v.vb.Block().Round() {
		return v.vb.CheckDup(currentProto, firstValid, lastValid, txid, txl)
	}

	return v.l.CheckDup(currentProto, current, firstValid, lastValid, txid, txl)
}

// GenesisHash implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) GenesisHash() crypto.Digest {
	return v.l.GenesisHash()
}

// GetCreatorForRound implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) GetCreatorForRound(r basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	if r == v.vb.Block().Round() {
		delta, ok := v.vb.Delta().Creatables[cidx]
		if ok {
			if delta.Created && delta.Ctype == ctype {
				return delta.Creator, true, nil
			}
			return basics.Address{}, false, nil
		}
	}

	return v.l.GetCreatorForRound(r, cidx, ctype)
}
