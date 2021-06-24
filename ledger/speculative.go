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

// validatedBlockAsLFE presents a ledgerForEvaluator interface on top of
// a ValidatedBlock.  This makes it possible to construct a BlockEvaluator
// on top, which in turn allows speculatively constructing a subsequent
// block, before the ValidatedBlock is committed to the ledger.
type validatedBlockAsLFE struct {
	// l points to the underlying ledger; it might be another instance
	// of validatedBlockAsLFE if we are speculating on a chain of many
	// blocks.
	l ledgerForEvaluator

	// vb points to the ValidatedBlock that logically extends the
	// state of the ledger.  If vb is set to nil, operations fall
	// back to the full ledger.  This is done when vb is committed
	// to the ledger.
	vb *ValidatedBlock
}

// XXX it's clunky that we need both the ValidatedBlock and the ledgerForEvaluator.
// perhaps better plan: roundCowState interface should become cowState interface,
// with round arguments everywhere.  then, validatedBlock contains cowState which
// contains the parent validatedBlock.  and the cowParent / cowState interface
// should satisfy ledgerForEvaluator.  we can build a round-specific wrapper that
// will pass in the round argument implicitly.

// BlockHdr implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	if v.vb != nil && r == v.vb.blk.Round() {
		return v.vb.blk.BlockHeader, nil
	}

	return v.l.BlockHdr(r)
}

// CheckDup implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) CheckDup(currentProto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl TxLease) error {
	// XXX more accurately handle currentProto and current, which boils down to
	// SupportTransactionLeases and FixTransactionLeases.
	if v.vb != nil {
		return v.vb.state.checkDup(firstValid, lastValid, txid, txl.Txlease)
	}

	return v.l.CheckDup(currentProto, current, firstValid, lastValid, txid, txl)
}

// CompactCertVoters implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) CompactCertVoters(r basics.Round) (*VotersForRound, error) {
	// XXX it would be quite annoying to deal with pipeline depth
	// greater than CompactCertVotersLookback..
	return v.l.CompactCertVoters(r)
}

// GenesisHash implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) GenesisHash() crypto.Digest {
	return v.l.GenesisHash()
}

// GetCreatorForRound implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) GetCreatorForRound(r basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	// XXX roundCowState does not expose round..
	if v.vb != nil {
		return v.vb.state.getCreator(cidx, ctype)
	}

	return v.l.GetCreatorForRound(r, cidx, ctype)
}

// LookupWithoutRewards implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) LookupWithoutRewards(r basics.Round, a basics.Address) (basics.AccountData, basics.Round, error) {
	// XXX lookup does not expose round..
	if v.vb != nil {
		data, err := v.vb.state.lookup(a)
		return data, r, err
	}

	return v.l.LookupWithoutRewards(r, a)
}

// Totals implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) Totals(r basics.Round) (ledgercore.AccountTotals, error) {
	// XXX roundCowState does not track changes to totals
	return v.l.Totals(r)
}

func xxStartEvaluatorVB(l *Ledger, vb *ValidatedBlock, hdr bookkeeping.BlockHeader, paysetHint int) (*BlockEvaluator, error) {
	lfe := &validatedBlockAsLFE{
		l:  l,
		vb: vb,
	}

	return startEvaluator(lfe, hdr, paysetHint, true, true)
}

// The SpeculationTracker tracks speculative blocks that have been proposed
// over the network but that have not yet been agreed upon (no certificate).
//
// The SpeculationTracker uses the tracker interface to monitor the real
// ledger for committed blocks.  The ledger's tracker rwmutex protects
// concurrent operations on the SpeculationTracker.
type SpeculationTracker struct {
	// blocks contains the set of blocks that we have received in a
	// proposal but for whose round we have not yet reached consensus.
	blocks map[bookkeeping.BlockHash]*validatedBlockAsLFE

	// committedLedger is the real ledger, storing fully committed
	// blocks.
	committedLedger ledgerForEvaluator
}

func (st *SpeculationTracker) addSpeculativeBlock(vblk ValidatedBlock, lfe ledgerForEvaluator) {
	// XXX store in db

	// XXX clunky that we need to pass in lfe here for the previous blocks in the chain
}

func (st *SpeculationTracker) loadFromDisk(ledgerForTracker) error {
	// XXX load from db
	return nil
}

func (st *SpeculationTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	for h, specblk := range st.blocks {
		if specblk.vb.blk.Round() < blk.Round() {
			// Older blocks hanging around for whatever reason.
			// Shouldn't happen, but clean them up just in case.
			delete(st.blocks, h)
		}

		if specblk.vb.blk.Round() == blk.Round() {
			// Block for the same round.  Clear it out.
			delete(st.blocks, h)

			if h == blk.Hash() {
				// Same block; we speculated correctly.
				// Clear out the block so that any ledger
				// lookups happen directly now.
				specblk.l = st.committedLedger
				specblk.vb = nil
			} else {
				// Different block for the same round.
				// Now we know this is an incorrect speculation;
				// clear out its children too.
				st.invalidateChildren(h)
			}
		}
	}
}

func (st *SpeculationTracker) invalidateChildren(branch bookkeeping.BlockHash) {
	for h, specblk := range st.blocks {
		if specblk.vb.blk.Branch == branch {
			delete(st.blocks, h)
			st.invalidateChildren(h)
		}
	}
}

func (st *SpeculationTracker) committedUpTo(r basics.Round) basics.Round {
	return r
}

func (st *SpeculationTracker) close() {
}
