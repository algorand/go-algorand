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

package ledger

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
)

// LedgerForEvaluator defines the ledger interface needed by the evaluator.
type LedgerForEvaluator interface { //nolint:revive //LedgerForEvaluator is a long established but newly leaking-out name, and there really isn't a better name for it despite how lint dislikes ledger.LedgerForEvaluator
	eval.LedgerForEvaluator
	LookupKv(rnd basics.Round, key string) ([]byte, error)
	FlushCaches()

	// and a few more Ledger functions
	Block(basics.Round) (bookkeeping.Block, error)
	Latest() basics.Round
	VerifiedTransactionCache() verify.VerifiedTransactionCache
	StartEvaluator(hdr bookkeeping.BlockHeader, paysetHint, maxTxnBytesPerBlock int, tracer logic.EvalTracer) (*eval.BlockEvaluator, error)
	GetStateProofVerificationContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error)
}

// ErrRoundTooHigh "round too high" try to get ledger record in the future
var ErrRoundTooHigh = errors.New("round too high")

// validatedBlockAsLFE presents a LedgerForEvaluator interface on top of
// a ValidatedBlock.  This makes it possible to construct a BlockEvaluator
// on top, which in turn allows speculatively constructing a subsequent
// block, before the ValidatedBlock is committed to the ledger.
//
//		ledger	ValidatedBlock -------> Block
//	     |                     ^          blk
//	     |                     | vb
//	     |     l               |
//	     \---------- validatedBlockAsLFE
//
// where ledger is the full ledger.
type validatedBlockAsLFE struct {
	// l points to the underlying ledger; it might be another instance
	// of validatedBlockAsLFE if we are speculating on a chain of many
	// blocks.
	l LedgerForEvaluator

	// vb points to the ValidatedBlock that logically extends the
	// state of the ledger.
	vb *ledgercore.ValidatedBlock
}

// MakeValidatedBlockAsLFE constructs a new validatedBlockAsLFE from a ValidatedBlock.
func MakeValidatedBlockAsLFE(vb *ledgercore.ValidatedBlock, l LedgerForEvaluator) (*validatedBlockAsLFE, error) {
	latestRound := l.Latest()
	if vb.Block().Round().SubSaturate(1) != latestRound {
		return nil, fmt.Errorf("MakeBlockAsLFE: Ledger round %d mismatches next block round %d", latestRound, vb.Block().Round())
	}
	hdr, err := l.BlockHdr(latestRound)
	if err != nil {
		return nil, err
	}
	if vb.Block().Branch != hdr.Hash() {
		return nil, fmt.Errorf("MakeBlockAsLFE: Ledger latest block hash %x mismatches block's prev hash %x", hdr.Hash(), vb.Block().Branch)
	}

	return &validatedBlockAsLFE{
		l:  l,
		vb: vb,
	}, nil
}

// Block implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) Block(r basics.Round) (bookkeeping.Block, error) {
	if r == v.vb.Block().Round() {
		return v.vb.Block(), nil
	}

	return v.l.Block(r)
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

// LatestTotals returns the totals of all accounts for the most recent round, as well as the round number.
func (v *validatedBlockAsLFE) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	return v.Latest(), v.vb.Delta().Totals, nil
}

// VotersForStateProof implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) VotersForStateProof(r basics.Round) (*ledgercore.VotersForRound, error) {
	if r >= v.vb.Block().Round() {
		// We do not support computing the compact cert voters for rounds
		// that have not been committed to the ledger yet.  This should not
		// be a problem as long as the speculation depth does not
		// exceed CompactCertVotersLookback.
		err := fmt.Errorf("validatedBlockAsLFE.CompactCertVoters(%d): validated block is for round %d, voters not available", r, v.vb.Block().Round())
		logging.Base().Warn(err.Error())
		return nil, err
	}

	return v.l.VotersForStateProof(r)
}

// GetCreatorForRound implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) GetCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	vbround := v.vb.Block().Round()
	if rnd > vbround {
		return basics.Address{}, false, ErrRoundTooHigh
	}
	if rnd == vbround {
		delta, ok := v.vb.Delta().Creatables[cidx]
		if ok {
			if delta.Created && delta.Ctype == ctype {
				return delta.Creator, true, nil
			}
			return basics.Address{}, false, nil
		}

		// no change in this block, so lookup in previous
		rnd--
	}

	return v.l.GetCreatorForRound(rnd, cidx, ctype)
}

// GenesisProto returns the initial protocol for this ledger.
func (v *validatedBlockAsLFE) GenesisProto() config.ConsensusParams {
	return v.l.GenesisProto()
}

// LookupApplication loads an application resource that matches the request parameters from the ledger.
func (v *validatedBlockAsLFE) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	vbround := v.vb.Block().Round()
	if rnd > vbround {
		return ledgercore.AppResource{}, ErrRoundTooHigh
	}
	if rnd == vbround {
		// Intentionally apply (pending) rewards up to rnd.
		res, ok := v.vb.Delta().Accts.GetResource(addr, basics.CreatableIndex(aidx), basics.AppCreatable)
		if ok {
			return ledgercore.AppResource{AppParams: res.AppParams, AppLocalState: res.AppLocalState}, nil
		}

		// fall back to looking up asset in ledger, until previous block
		rnd--
	}

	return v.l.LookupApplication(rnd, addr, aidx)
}

// LookupAsset loads an asset resource that matches the request parameters from the ledger.
func (v *validatedBlockAsLFE) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	vbround := v.vb.Block().Round()
	if rnd > vbround {
		return ledgercore.AssetResource{}, ErrRoundTooHigh
	}
	if rnd == vbround {
		// Intentionally apply (pending) rewards up to rnd.
		res, ok := v.vb.Delta().Accts.GetResource(addr, basics.CreatableIndex(aidx), basics.AssetCreatable)
		if ok {
			return ledgercore.AssetResource{AssetParams: res.AssetParams, AssetHolding: res.AssetHolding}, nil
		}
		// fall back to looking up asset in ledger, until previous block
		rnd--
	}

	return v.l.LookupAsset(rnd, addr, aidx)
}

// LookupWithoutRewards implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) LookupWithoutRewards(rnd basics.Round, a basics.Address) (ledgercore.AccountData, basics.Round, error) {
	vbround := v.vb.Block().Round()
	if rnd > vbround {
		return ledgercore.AccountData{}, rnd, ErrRoundTooHigh
	}
	if rnd == vbround {
		data, ok := v.vb.Delta().Accts.GetData(a)
		if ok {
			return data, rnd, nil
		}
		// fall back to looking up account in ledger, until previous block
		rnd--
	}

	// account didn't change in last round. Subtract 1 so we can lookup the most recent change in the ledger
	acctData, fallbackrnd, err := v.l.LookupWithoutRewards(rnd, a)
	if err != nil {
		return acctData, fallbackrnd, err
	}
	return acctData, rnd, err
}

// VerifiedTransactionCache implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) VerifiedTransactionCache() verify.VerifiedTransactionCache {
	return v.l.VerifiedTransactionCache()
}

// VerifiedTransactionCache implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) BlockHdrCached(rnd basics.Round) (hdr bookkeeping.BlockHeader, err error) {
	vbround := v.vb.Block().Round()
	if rnd > vbround {
		return bookkeeping.BlockHeader{}, ErrRoundTooHigh
	}
	if rnd == vbround {
		return v.vb.Block().BlockHeader, nil
	}
	return v.l.BlockHdrCached(rnd)
}

// StartEvaluator implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) StartEvaluator(hdr bookkeeping.BlockHeader, paysetHint, maxTxnBytesPerBlock int, tracer logic.EvalTracer) (*eval.BlockEvaluator, error) {
	if hdr.Round.SubSaturate(1) != v.Latest() {
		return nil, fmt.Errorf("StartEvaluator: LFE round %d mismatches next block round %d", v.Latest(), hdr.Round)
	}

	return eval.StartEvaluator(v, hdr,
		eval.EvaluatorOptions{
			PaysetHint:          paysetHint,
			Tracer:              tracer,
			Generate:            true,
			Validate:            true,
			MaxTxnBytesPerBlock: maxTxnBytesPerBlock,
		})
}

// GetStateProofVerificationContext implements the ledgerForEvaluator interface.
func (v *validatedBlockAsLFE) GetStateProofVerificationContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	//TODO(yg): is this behavior correct? what happens if round is the last block's round?
	return v.l.GetStateProofVerificationContext(stateProofLastAttestedRound)
}

// FlushCaches is part of ledger/eval.LedgerForEvaluator interface
func (v *validatedBlockAsLFE) FlushCaches() {
}

// LookupKv implements LookupKv
func (v *validatedBlockAsLFE) LookupKv(rnd basics.Round, key string) ([]byte, error) {
	vbround := v.vb.Block().Round()
	if rnd > vbround {
		return nil, ErrRoundTooHigh
	}
	if rnd == vbround {
		data, ok := v.vb.Delta().KvMods[key]
		if ok {
			return data.Data, nil
		}
		// fall back to looking up account in ledger, until previous block
		rnd--
	}

	// account didn't change in last round. Subtract 1 so we can lookup the most recent change in the ledger
	data, err := v.l.LookupKv(rnd, key)
	if err != nil {
		return nil, err
	}
	return data, nil
}
