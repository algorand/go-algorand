// Copyright (C) 2019 Algorand, Inc.
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
	"context"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

// ErrNoSpace indicates insufficient space for transaction in block
var ErrNoSpace = errors.New("block does not have space for transaction")

// evalAux is left after removing explicit reward claims,
// in case we need this infrastructure in the future.
type evalAux struct {
}

// VerifiedTxnCache captures the interface for a cache of previously
// verified transactions.  This is expected to match the transaction
// pool object.
type VerifiedTxnCache interface {
	Verified(txn transactions.SignedTxn) bool
}

type roundCowBase struct {
	l ledgerForEvaluator

	// The round number of the previous block, for looking up prior state.
	rnd basics.Round
}

func (x *roundCowBase) lookup(addr basics.Address) (basics.AccountData, error) {
	return x.l.LookupWithoutRewards(x.rnd, addr)
}

func (x *roundCowBase) isDup(firstValid basics.Round, txid transactions.Txid) (bool, error) {
	return x.l.isDup(firstValid, x.rnd, txid)
}

// wrappers for roundCowState to satisfy the (current) transactions.Balances interface
func (cs *roundCowState) Get(addr basics.Address) (basics.BalanceRecord, error) {
	acctdata, err := cs.lookup(addr)
	if err != nil {
		return basics.BalanceRecord{}, err
	}
	acctdata = acctdata.WithUpdatedRewards(cs.proto, cs.rewardsLevel())
	return basics.BalanceRecord{Addr: addr, AccountData: acctdata}, nil
}

func (cs *roundCowState) Put(record basics.BalanceRecord) error {
	olddata, err := cs.lookup(record.Addr)
	if err != nil {
		return err
	}
	cs.put(record.Addr, olddata, record.AccountData)
	return nil
}

func (cs *roundCowState) Move(from basics.Address, to basics.Address, amt basics.MicroAlgos, fromRewards *basics.MicroAlgos, toRewards *basics.MicroAlgos) error {
	rewardlvl := cs.rewardsLevel()

	fromBal, err := cs.lookup(from)
	if err != nil {
		return err
	}
	fromBalNew := fromBal.WithUpdatedRewards(cs.proto, rewardlvl)

	if fromRewards != nil {
		var ot basics.OverflowTracker
		newFromRewards := ot.AddA(*fromRewards, ot.SubA(fromBalNew.MicroAlgos, fromBal.MicroAlgos))
		if ot.Overflowed {
			return fmt.Errorf("overflowed tracking of fromRewards for account %v: %d + (%d - %d)", from, *fromRewards, fromBalNew.MicroAlgos, fromBal.MicroAlgos)
		}
		*fromRewards = newFromRewards
	}

	var overflowed bool
	fromBalNew.MicroAlgos, overflowed = basics.OSubA(fromBalNew.MicroAlgos, amt)
	if overflowed {
		return fmt.Errorf("overspend (account %v, data %+v, tried to spend %v)", from, fromBal, amt)
	}
	cs.put(from, fromBal, fromBalNew)

	toBal, err := cs.lookup(to)
	if err != nil {
		return err
	}
	toBalNew := toBal.WithUpdatedRewards(cs.proto, rewardlvl)

	if toRewards != nil {
		var ot basics.OverflowTracker
		newToRewards := ot.AddA(*toRewards, ot.SubA(toBalNew.MicroAlgos, toBal.MicroAlgos))
		if ot.Overflowed {
			return fmt.Errorf("overflowed tracking of toRewards for account %v: %d + (%d - %d)", to, *toRewards, toBalNew.MicroAlgos, toBal.MicroAlgos)
		}
		*toRewards = newToRewards
	}

	toBalNew.MicroAlgos, overflowed = basics.OAddA(toBalNew.MicroAlgos, amt)
	if overflowed {
		return fmt.Errorf("balance overflow (account %v, data %+v, was going to receive %v)", to, toBal, amt)
	}
	cs.put(to, toBal, toBalNew)

	return nil
}

func (cs *roundCowState) ConsensusParams() config.ConsensusParams {
	return cs.proto
}

// BlockEvaluator represents an in-progress evaluation of a block
// against the ledger.
type BlockEvaluator struct {
	state    *roundCowState
	aux      *evalAux
	validate bool
	generate bool
	txcache  VerifiedTxnCache

	prevHeader  bookkeeping.BlockHeader // cached
	proto       config.ConsensusParams
	genesisHash crypto.Digest

	block        bookkeeping.Block
	totalTxBytes int

	verificationPool execpool.BacklogPool
}

type ledgerForEvaluator interface {
	GenesisHash() crypto.Digest
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	Lookup(basics.Round, basics.Address) (basics.AccountData, error)
	Totals(basics.Round) (AccountTotals, error)
	isDup(basics.Round, basics.Round, transactions.Txid) (bool, error)
	LookupWithoutRewards(basics.Round, basics.Address) (basics.AccountData, error)
}

// StartEvaluator creates a BlockEvaluator, given a ledger and a block header
// of the block that the caller is planning to evaluate.
func (l *Ledger) StartEvaluator(hdr bookkeeping.BlockHeader, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (*BlockEvaluator, error) {
	return startEvaluator(l, hdr, nil, true, true, txcache, executionPool)
}

func startEvaluator(l ledgerForEvaluator, hdr bookkeeping.BlockHeader, aux *evalAux, validate bool, generate bool, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (*BlockEvaluator, error) {
	proto, ok := config.Consensus[hdr.CurrentProtocol]
	if !ok {
		return nil, ProtocolError(hdr.CurrentProtocol)
	}

	if aux == nil {
		aux = &evalAux{}
	}

	base := &roundCowBase{
		l: l,
		// round that lookups come from is previous block.  We validate
		// the block at this round below, so underflow will be caught.
		// If we are not validating, we must have previously checked
		// an agreement.Certificate attesting that hdr is valid.
		rnd: hdr.Round - 1,
	}

	eval := &BlockEvaluator{
		aux:              aux,
		validate:         validate,
		generate:         generate,
		txcache:          txcache,
		block:            bookkeeping.Block{BlockHeader: hdr},
		proto:            proto,
		genesisHash:      l.GenesisHash(),
		verificationPool: executionPool,
	}

	if hdr.Round > 0 {
		var err error
		eval.prevHeader, err = l.BlockHdr(base.rnd)
		if err != nil {
			return nil, fmt.Errorf("can't evaluate block %v without previous header: %v", hdr.Round, err)
		}
	}

	prevTotals, err := l.Totals(eval.prevHeader.Round)
	if err != nil {
		return nil, err
	}

	poolAddr := eval.prevHeader.RewardsPool
	incentivePoolData, err := l.Lookup(eval.prevHeader.Round, poolAddr)
	if err != nil {
		return nil, err
	}

	if generate {
		if eval.proto.SupportGenesisHash {
			eval.block.BlockHeader.GenesisHash = eval.genesisHash
		}
		eval.block.BlockHeader.RewardsState = eval.prevHeader.NextRewardsState(hdr.Round, proto, incentivePoolData.MicroAlgos, prevTotals.RewardUnits())
	}
	// set the eval state with the current header
	eval.state = makeRoundCowState(base, eval.block.BlockHeader)

	if validate {
		err := eval.block.BlockHeader.PreCheck(eval.prevHeader)
		if err != nil {
			return nil, err
		}

		// Check that the rewards rate, level and residue match expected values
		expectedRewardsState := eval.prevHeader.NextRewardsState(hdr.Round, proto, incentivePoolData.MicroAlgos, prevTotals.RewardUnits())
		if eval.block.RewardsState != expectedRewardsState {
			return nil, fmt.Errorf("bad rewards state: %+v != %+v", eval.block.RewardsState, expectedRewardsState)
		}

		// For backwards compatibility: introduce Genesis Hash value
		if eval.proto.SupportGenesisHash && eval.block.BlockHeader.GenesisHash != eval.genesisHash {
			return nil, fmt.Errorf("wrong genesis hash: %s != %s", eval.block.BlockHeader.GenesisHash, eval.genesisHash)
		}
	}

	// Withdraw rewards from the incentive pool
	var ot basics.OverflowTracker
	rewardsPerUnit := ot.Sub(eval.block.BlockHeader.RewardsLevel, eval.prevHeader.RewardsLevel)
	poolOld, err := eval.state.Get(poolAddr)
	if err != nil {
		return nil, err
	}

	poolNew := poolOld
	poolNew.MicroAlgos = ot.SubA(poolOld.MicroAlgos, basics.MicroAlgos{Raw: ot.Mul(prevTotals.RewardUnits(), rewardsPerUnit)})
	err = eval.state.Put(poolNew)
	if err != nil {
		return nil, err
	}

	// ensure that we have at least MinBalance after withdrawing rewards
	ot.SubA(poolNew.MicroAlgos, basics.MicroAlgos{Raw: proto.MinBalance})
	if ot.Overflowed {
		// TODO this should never happen; should we panic here?
		return nil, fmt.Errorf("overflowed subtracting rewards for block %v", hdr.Round)
	}

	return eval, nil
}

// Round returns the round number of the block being evaluated by the BlockEvaluator.
func (eval *BlockEvaluator) Round() basics.Round {
	return eval.block.Round()
}

// ResetTxnBytes resets the number of bytes tracked by the BlockEvaluator to
// zero.  This is a specialized operation used by the transaction pool to
// simulate the effect of putting pending transactions in multiple blocks.
func (eval *BlockEvaluator) ResetTxnBytes() {
	eval.totalTxBytes = 0
}

// Transaction tentatively adds a new transaction as part of this block evaluation.
// If the transaction cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) Transaction(txn transactions.SignedTxn, ad *transactions.ApplyData) error {
	return eval.transaction(txn, ad, true)
}

// TestTransaction checks if a given transaction could be executed at this point
// in the block evaluator, but does not actually add the transaction to the block
// evaluator, or modify the block evaluator state in any other visible way.
func (eval *BlockEvaluator) TestTransaction(txn transactions.SignedTxn, ad *transactions.ApplyData) error {
	return eval.transaction(txn, ad, false)
}

// transaction tentatively executes a new transaction as part of this block evaluation.
// If the transaction cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.  If remember is true,
// the transaction is added to the block evaluator state; otherwise, the block evaluator
// is not modified and does not remember this transaction.
func (eval *BlockEvaluator) transaction(txn transactions.SignedTxn, ad *transactions.ApplyData, remember bool) error {
	var err error
	var thisTxBytes int
	cow := eval.state.child()

	spec := transactions.SpecialAddresses{
		FeeSink:     eval.block.BlockHeader.FeeSink,
		RewardsPool: eval.block.BlockHeader.RewardsPool,
	}

	if eval.validate {
		// Transaction valid (not expired)?
		err = txn.Txn.Alive(eval.block)
		if err != nil {
			return err
		}

		// Transaction already in the ledger?
		dup, err := cow.isDup(txn.Txn.First(), txn.ID())
		if err != nil {
			return err
		}
		if dup {
			return TransactionInLedgerError{txn.ID()}
		}

		// Well-formed on its own?
		err = txn.Txn.WellFormed(spec, eval.proto)
		if err != nil {
			return fmt.Errorf("transaction %v: malformed: %v", txn.ID(), err)
		}

		// Properly signed?
		if eval.txcache == nil || !eval.txcache.Verified(txn) {
			err = txn.PoolVerify(spec, eval.proto, eval.verificationPool)
			if err != nil {
				return fmt.Errorf("transaction %v: failed to verify: %v", txn.ID(), err)
			}
		}
	}

	// Apply the transaction, updating the cow balances
	applyData, err := txn.Txn.Apply(cow, spec)
	if err != nil {
		return fmt.Errorf("transaction %v: %v", txn.ID(), err)
	}

	// Validate applyData if we are validating an existing block.
	// If we are validating and generating, we have no ApplyData yet.
	if eval.validate && !eval.generate {
		if ad == nil {
			return fmt.Errorf("transaction %v: no applyData for validation", txn.ID())
		}
		if eval.proto.ApplyData {
			if *ad != applyData {
				return fmt.Errorf("transaction %v: applyData mismatch: %v != %v", txn.ID(), *ad, applyData)
			}
		} else {
			if *ad != (transactions.ApplyData{}) {
				return fmt.Errorf("transaction %v: applyData not supported", txn.ID())
			}
		}
	}

	// Check if the transaction fits in the block, now that we can encode it.
	txib, err := eval.block.EncodeSignedTxn(txn, applyData)
	if err != nil {
		return err
	}
	if eval.validate {
		thisTxBytes = len(protocol.Encode(txib))
		if eval.totalTxBytes+thisTxBytes > eval.proto.MaxTxnBytesPerBlock {
			return ErrNoSpace
		}
	}

	// Check if any affected accounts dipped below MinBalance (unless they are
	// completely zero, which means the account will be deleted.)
	rewardlvl := cow.rewardsLevel()
	for _, addr := range cow.modifiedAccounts() {
		data, err := cow.lookup(addr)
		if err != nil {
			return err
		}

		// It's always OK to have the account move to an empty state,
		// because the accounts DB can delete it.  Otherwise, we will
		// enforce MinBalance.
		if data == (basics.AccountData{}) {
			continue
		}

		// Skip FeeSink and RewardsPool MinBalance checks here.
		// There's only two accounts, so space isn't an issue, and we don't
		// expect them to have low balances, but if they do, it may cause
		// surprises for every transaction.
		if addr == spec.FeeSink || addr == spec.RewardsPool {
			continue
		}

		dataNew := data.WithUpdatedRewards(eval.proto, rewardlvl)
		if dataNew.MicroAlgos.Raw < eval.proto.MinBalance {
			return fmt.Errorf("transaction %v: account %v balance %d below min %d",
				txn.ID(), addr, dataNew.MicroAlgos.Raw, eval.proto.MinBalance)
		}
	}

	if remember {
		// Remember this TXID (to detect duplicates)
		cow.addTx(txn.ID())

		eval.block.Payset = append(eval.block.Payset, txib)
		eval.totalTxBytes += thisTxBytes
		cow.commitToParent()
	}

	return nil
}

// Call "endOfBlock" after all the block's rewards and transactions are processed. Applies any deferred balance updates.
func (eval *BlockEvaluator) endOfBlock() error {
	cow := eval.state.child()

	if eval.generate {
		eval.block.TxnRoot = eval.block.Payset.Commit(eval.proto.PaysetCommitFlat)
	}

	cow.commitToParent()
	return nil
}

// FinalValidation does the validation that must happen after the block is built and all state updates are computed
func (eval *BlockEvaluator) finalValidation() error {
	if eval.validate {
		// check commitments
		txnRoot := eval.block.Payset.Commit(eval.proto.PaysetCommitFlat)
		if txnRoot != eval.block.TxnRoot {
			return fmt.Errorf("txn root wrong: %v != %v", txnRoot, eval.block.TxnRoot)
		}
	}

	return nil
}

// GenerateBlock produces a complete block from the BlockEvaluator.  This is
// used during proposal to get an actual block that will be proposed, after
// feeding in tentative transactions into this block evaluator.
func (eval *BlockEvaluator) GenerateBlock() (*ValidatedBlock, error) {
	if !eval.generate {
		logging.Base().Panicf("GenerateBlock() called but generate is false")
	}

	err := eval.endOfBlock()
	if err != nil {
		return nil, err
	}

	err = eval.finalValidation()
	if err != nil {
		return nil, err
	}

	vb := ValidatedBlock{
		blk:   eval.block,
		delta: eval.state.mods,
		aux:   *eval.aux,
	}
	return &vb, nil
}

func (l *Ledger) eval(ctx context.Context, blk bookkeeping.Block, aux *evalAux, validate bool, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (stateDelta, evalAux, error) {
	eval, err := startEvaluator(l, blk.BlockHeader, aux, validate, false, txcache, executionPool)
	if err != nil {
		return stateDelta{}, evalAux{}, err
	}

	// TODO: batch tx sig verification: ingest blk.Payset and output a list of ValidatedTx
	// Next, transactions
	payset, err := blk.DecodePaysetWithAD()
	if err != nil {
		return stateDelta{}, evalAux{}, err
	}

	for _, txn := range payset {
		select {
		case <-ctx.Done():
			return stateDelta{}, evalAux{}, ctx.Err()
		default:
		}

		err = eval.Transaction(txn.SignedTxn, &txn.ApplyData)
		if err != nil {
			return stateDelta{}, evalAux{}, err
		}
	}

	// Finally, procees any pending end-of-block state changes
	err = eval.endOfBlock()
	if err != nil {
		return stateDelta{}, evalAux{}, err
	}

	// If validating, do final block checks that depend on our new state
	if validate {
		err = eval.finalValidation()
		if err != nil {
			return stateDelta{}, evalAux{}, err
		}
	}

	return eval.state.mods, *eval.aux, nil
}

// Validate uses the ledger to validate block blk as a candidate next block.
// It returns an error if blk is not the expected next block, or if blk is
// not a valid block (e.g., it has duplicate transactions, overspends some
// account, etc).
func (l *Ledger) Validate(ctx context.Context, blk bookkeeping.Block, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (*ValidatedBlock, error) {
	delta, aux, err := l.eval(ctx, blk, nil, true, txcache, executionPool)
	if err != nil {
		return nil, err
	}

	vb := ValidatedBlock{
		blk:   blk,
		delta: delta,
		aux:   aux,
	}
	return &vb, nil
}

// ValidatedBlock represents the result of a block validation.  It can
// be used to efficiently add the block to the ledger, without repeating
// the work of applying the block's changes to the ledger state.
type ValidatedBlock struct {
	blk   bookkeeping.Block
	delta stateDelta
	aux   evalAux
}

// Block returns the underlying Block for a ValidatedBlock.
func (vb ValidatedBlock) Block() bookkeeping.Block {
	return vb.blk
}

// WithSeed returns a copy of the ValidatedBlock with a modified seed.
func (vb ValidatedBlock) WithSeed(s committee.Seed) ValidatedBlock {
	newblock := vb.blk
	newblock.BlockHeader.Seed = s

	return ValidatedBlock{
		blk:   newblock,
		delta: vb.delta,
		aux:   vb.aux,
	}
}
