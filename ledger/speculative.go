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
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/internal"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
)

type LedgerForEvaluator interface {
	// Needed for cow.go
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error
	LookupWithoutRewards(basics.Round, basics.Address) (ledgercore.AccountData, basics.Round, error)
	GetCreatorForRound(basics.Round, basics.CreatableIndex, basics.CreatableType) (basics.Address, bool, error)
	StartEvaluator(hdr bookkeeping.BlockHeader, paysetHint, maxTxnBytesPerBlock int) (*internal.BlockEvaluator, error)
	LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error)
	LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error)
	VerifiedTransactionCache() verify.VerifiedTransactionCache

	// Needed for the evaluator
	GenesisHash() crypto.Digest
	Latest() basics.Round
	CompactCertVoters(basics.Round) (*ledgercore.VotersForRound, error)
	GenesisProto() config.ConsensusParams
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
func MakeValidatedBlockAsLFE(vb *ledgercore.ValidatedBlock, l LedgerForEvaluator) (*validatedBlockAsLFE, error) {
	latestRound := l.Latest()
	if vb.Block().Round().SubSaturate(1) != latestRound {
		return nil, fmt.Errorf("MakeValidatedBlockAsLFE: Ledger round %d mismatches next block round %d", latestRound, vb.Block().Round())
	}
	hdr, err := l.BlockHdr(latestRound)
	if err != nil {
		return nil, err
	}
	if vb.Block().Branch != hdr.Hash() {
		return nil, fmt.Errorf("MakeValidatedBlockAsLFE: Ledger latest block hash %x mismatches block's prev hash %x", hdr.Hash(), vb.Block().Branch)
	}
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

// Latest implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) Latest() basics.Round {
	return v.vb.Block().Round()
}

// CompactCertVoters implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) CompactCertVoters(r basics.Round) (*ledgercore.VotersForRound, error) {
	if r >= v.vb.Block().Round() {
		// We do not support computing the compact cert voters for rounds
		// that have not been committed to the ledger yet.  This should not
		// be a problem as long as the agreement pipeline depth does not
		// exceed CompactCertVotersLookback.
		err := fmt.Errorf("validatedBlockAsLFE.CompactCertVoters(%d): validated block is for round %d, voters not available", r, v.vb.Block().Round())
		logging.Base().Warn(err.Error())
		return nil, err
	}

	return v.l.CompactCertVoters(r)
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

// Totals implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	return v.vb.Block().Round(), v.vb.Delta().Totals, nil
}

// GenesisProto returns the initial protocol for this ledger.
func (v *validatedBlockAsLFE) GenesisProto() config.ConsensusParams {
	return v.l.GenesisProto()
}

// LookupApplication loads an application resource that matches the request parameters from the ledger.
func (v *validatedBlockAsLFE) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {

	if rnd == v.vb.Block().Round() {
		// Intentionally apply (pending) rewards up to rnd.
		res, ok := v.vb.Delta().Accts.GetResource(addr, basics.CreatableIndex(aidx), basics.AppCreatable)
		if ok {
			return ledgercore.AppResource{AppParams: res.AppParams, AppLocalState: res.AppLocalState}, nil
		}
	}

	// app didn't change in last round. Subtract 1 so we can lookup the most recent change in the ledger
	rnd = rnd.SubSaturate(1)
	return v.l.LookupApplication(rnd, addr, aidx)
}

// LookupAsset loads an asset resource that matches the request parameters from the ledger.
func (v *validatedBlockAsLFE) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	if rnd == v.vb.Block().Round() {
		// Intentionally apply (pending) rewards up to rnd.
		res, ok := v.vb.Delta().Accts.GetResource(addr, basics.CreatableIndex(aidx), basics.AppCreatable)
		if ok {
			return ledgercore.AssetResource{AssetParams: res.AssetParams, AssetHolding: res.AssetHolding}, nil
		}
	}

	// asset didn't change in last round. Subtract 1 so we can lookup the most recent change in the ledger
	rnd = rnd.SubSaturate(1)
	return v.l.LookupAsset(rnd, addr, aidx)
}

// LookupWithoutRewards implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) LookupWithoutRewards(r basics.Round, a basics.Address) (ledgercore.AccountData, basics.Round, error) {
	if r == v.vb.Block().Round() {
		data, ok := v.vb.Delta().Accts.GetData(a)
		if ok {
			return data, r, nil
		}
	}

	// account didn't change in last round. Subtract 1 so we can lookup the most recent change in the ledger
	r = r.SubSaturate(1)
	return v.l.LookupWithoutRewards(r, a)
}

// VerifiedTransactionCache implements the ledgerForEvaluator interface.
// TODO(yossi) should we forward this cache?
func (v *validatedBlockAsLFE) VerifiedTransactionCache() verify.VerifiedTransactionCache {
	return v.l.VerifiedTransactionCache()
}

// StartEvaluator implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) StartEvaluator(hdr bookkeeping.BlockHeader, paysetHint, maxTxnBytesPerBlock int) (*internal.BlockEvaluator, error) {
	if hdr.Round.SubSaturate(1) != v.Latest() {
		return nil, fmt.Errorf("StartEvaluator: LFE round %d mismatches next block round %d", v.Latest(), hdr.Round)
	}

	return internal.StartEvaluator(v, hdr,
		internal.EvaluatorOptions{
			PaysetHint:          paysetHint,
			Generate:            true,
			Validate:            true,
			MaxTxnBytesPerBlock: maxTxnBytesPerBlock,
		})
}
