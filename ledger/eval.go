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
	"github.com/algorand/go-algorand/data/transactions/verify"
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
	Verified(txn transactions.SignedTxn, params verify.Params) bool
}

type roundCowBase struct {
	l ledgerForEvaluator

	// The round number of the previous block, for looking up prior state.
	rnd basics.Round

	// TxnCounter from previous block header.
	txnCount uint64

	// The current protocol consensus params.
	proto config.ConsensusParams
}

func (x *roundCowBase) getAssetCreator(assetIdx basics.AssetIndex) (basics.Address, error) {
	return x.l.GetAssetCreatorForRound(x.rnd, assetIdx)
}

func (x *roundCowBase) lookup(addr basics.Address) (basics.AccountData, error) {
	return x.l.LookupWithoutRewards(x.rnd, addr)
}

func (x *roundCowBase) isDup(firstValid, lastValid basics.Round, txid transactions.Txid, txl txlease) (bool, error) {
	return x.l.isDup(x.proto, x.rnd+1, firstValid, lastValid, txid, txl)
}

func (x *roundCowBase) txnCounter() uint64 {
	return x.txnCount
}

func (cs *roundCowState) GetAssetCreator(assetIdx basics.AssetIndex) (basics.Address, error) {
	return cs.getAssetCreator(assetIdx)
}

// wrappers for roundCowState to satisfy the (current) transactions.Balances interface
func (cs *roundCowState) Get(addr basics.Address, withPendingRewards bool) (basics.BalanceRecord, error) {
	acctdata, err := cs.lookup(addr)
	if err != nil {
		return basics.BalanceRecord{}, err
	}
	if withPendingRewards {
		acctdata = acctdata.WithUpdatedRewards(cs.proto, cs.rewardsLevel())
	}
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
	blockTxBytes int

	verificationPool execpool.BacklogPool

	l ledgerForEvaluator
}

type ledgerForEvaluator interface {
	GenesisHash() crypto.Digest
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	Lookup(basics.Round, basics.Address) (basics.AccountData, error)
	Totals(basics.Round) (AccountTotals, error)
	isDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, txlease) (bool, error)
	GetRoundTxIds(rnd basics.Round) (txMap map[transactions.Txid]bool)
	LookupWithoutRewards(basics.Round, basics.Address) (basics.AccountData, error)
	GetAssetCreatorForRound(basics.Round, basics.AssetIndex) (basics.Address, error)
}

// StartEvaluator creates a BlockEvaluator, given a ledger and a block header
// of the block that the caller is planning to evaluate.
func (l *Ledger) StartEvaluator(hdr bookkeeping.BlockHeader, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (*BlockEvaluator, error) {
	return startEvaluator(l, hdr, nil, true, true, txcache, executionPool)
}

func startEvaluator(l ledgerForEvaluator, hdr bookkeeping.BlockHeader, aux *evalAux, validate bool, generate bool, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (*BlockEvaluator, error) {
	proto, ok := config.Consensus[hdr.CurrentProtocol]
	if !ok {
		return nil, protocol.Error(hdr.CurrentProtocol)
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
		rnd:   hdr.Round - 1,
		proto: proto,
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
		l:                l,
	}

	if hdr.Round > 0 {
		var err error
		eval.prevHeader, err = l.BlockHdr(base.rnd)
		if err != nil {
			return nil, fmt.Errorf("can't evaluate block %v without previous header: %v", hdr.Round, err)
		}

		base.txnCount = eval.prevHeader.TxnCounter
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
	if ot.Overflowed {
		return nil, fmt.Errorf("overflowed subtracting rewards(%d, %d) levels for block %v", eval.block.BlockHeader.RewardsLevel, eval.prevHeader.RewardsLevel, hdr.Round)
	}

	poolOld, err := eval.state.Get(poolAddr, true)
	if err != nil {
		return nil, err
	}

	// hotfix for testnet stall 08/26/2019; move some algos from testnet bank to rewards pool to give it enough time until protocol upgrade occur.
	// hotfix for testnet stall 11/07/2019; the same bug again, account ran out before the protocol upgrade occurred.
	poolOld, err = eval.workaroundOverspentRewards(poolOld, hdr.Round)
	if err != nil {
		return nil, err
	}

	poolNew := poolOld
	poolNew.MicroAlgos = ot.SubA(poolOld.MicroAlgos, basics.MicroAlgos{Raw: ot.Mul(prevTotals.RewardUnits(), rewardsPerUnit)})
	if ot.Overflowed {
		return nil, fmt.Errorf("overflowed subtracting reward unit for block %v", hdr.Round)
	}

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

// hotfix for testnet stall 08/26/2019; move some algos from testnet bank to rewards pool to give it enough time until protocol upgrade occur.
// hotfix for testnet stall 11/07/2019; do the same thing
func (eval *BlockEvaluator) workaroundOverspentRewards(rewardPoolBalance basics.BalanceRecord, headerRound basics.Round) (poolOld basics.BalanceRecord, err error) {
	// verify that we patch the correct round.
	if headerRound != 1499995 && headerRound != 2926564 {
		return rewardPoolBalance, nil
	}
	// verify that we're patching the correct genesis ( i.e. testnet )
	testnetGenesisHash, _ := crypto.DigestFromString("JBR3KGFEWPEE5SAQ6IWU6EEBZMHXD4CZU6WCBXWGF57XBZIJHIRA")
	if eval.genesisHash != testnetGenesisHash {
		return rewardPoolBalance, nil
	}

	// get the testnet bank ( dispenser ) account address.
	bankAddr, _ := basics.UnmarshalChecksumAddress("GD64YIY3TWGDMCNPP553DZPPR6LDUSFQOIJVFDPPXWEG3FVOJCCDBBHU5A")
	amount := basics.MicroAlgos{Raw: 20000000000}
	err = eval.state.Move(bankAddr, eval.prevHeader.RewardsPool, amount, nil, nil)
	if err != nil {
		err = fmt.Errorf("unable to move funds from testnet bank to incentive pool: %v", err)
		return
	}
	poolOld, err = eval.state.Get(eval.prevHeader.RewardsPool, true)

	return
}

// Round returns the round number of the block being evaluated by the BlockEvaluator.
func (eval *BlockEvaluator) Round() basics.Round {
	return eval.block.Round()
}

// ResetTxnBytes resets the number of bytes tracked by the BlockEvaluator to
// zero.  This is a specialized operation used by the transaction pool to
// simulate the effect of putting pending transactions in multiple blocks.
func (eval *BlockEvaluator) ResetTxnBytes() {
	eval.blockTxBytes = 0
}

// TestTransactionGroup performs basic duplicate detection and well-formedness checks
// on a transaction group, but does not actually add the transactions to the block
// evaluator, or modify the block evaluator state in any other visible way.
func (eval *BlockEvaluator) TestTransactionGroup(txgroup []transactions.SignedTxn) error {
	// Nothing to do if there are no transactions.
	if len(txgroup) == 0 {
		return nil
	}

	if len(txgroup) > eval.proto.MaxTxGroupSize {
		return fmt.Errorf("group size %d exceeds maximum %d", len(txgroup), eval.proto.MaxTxGroupSize)
	}

	cow := eval.state.child()

	var group transactions.TxGroup
	for gi, txn := range txgroup {
		err := eval.testTransaction(txn, cow)
		if err != nil {
			return err
		}

		// Make sure all transactions in group have the same group value
		if txn.Txn.Group != txgroup[0].Txn.Group {
			return fmt.Errorf("transactionGroup: inconsistent group values: %v != %v",
				txn.Txn.Group, txgroup[0].Txn.Group)
		}

		if !txn.Txn.Group.IsZero() {
			txWithoutGroup := txn.Txn
			txWithoutGroup.Group = crypto.Digest{}
			txWithoutGroup.ResetCaches()

			group.TxGroupHashes = append(group.TxGroupHashes, crypto.HashObj(txWithoutGroup))
		} else if len(txgroup) > 1 {
			return fmt.Errorf("transactionGroup: [%d] had zero Group but was submitted in a group of %d", gi, len(txgroup))
		}
	}

	// If we had a non-zero Group value, check that all group members are present.
	if group.TxGroupHashes != nil {
		if txgroup[0].Txn.Group != crypto.HashObj(group) {
			return fmt.Errorf("transactionGroup: incomplete group: %v != %v (%v)",
				txgroup[0].Txn.Group, crypto.HashObj(group), group)
		}
	}

	return nil
}

// testTransaction performs basic duplicate detection and well-formedness checks
// on a single transaction, but does not actually add the transaction to the block
// evaluator, or modify the block evaluator state in any other visible way.
func (eval *BlockEvaluator) testTransaction(txn transactions.SignedTxn, cow *roundCowState) error {
	// Verify that groups are supported.
	if !txn.Txn.Group.IsZero() && !eval.proto.SupportTxGroups {
		return fmt.Errorf("transaction groups not supported")
	}

	// Transaction valid (not expired)?
	err := txn.Txn.Alive(eval.block)
	if err != nil {
		return err
	}

	// Well-formed on its own?
	spec := transactions.SpecialAddresses{
		FeeSink:     eval.block.BlockHeader.FeeSink,
		RewardsPool: eval.block.BlockHeader.RewardsPool,
	}
	err = txn.Txn.WellFormed(spec, eval.proto)
	if err != nil {
		return fmt.Errorf("transaction %v: malformed: %v", txn.ID(), err)
	}

	// Transaction already in the ledger?
	txid := txn.ID()
	dup, err := cow.isDup(txn.Txn.First(), txn.Txn.Last(), txid, txlease{sender: txn.Txn.Sender, lease: txn.Txn.Lease})
	if err != nil {
		return err
	}
	if dup {
		return TransactionInLedgerError{txn.ID()}
	}

	return nil
}

// Transaction tentatively adds a new transaction as part of this block evaluation.
// If the transaction cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) Transaction(txn transactions.SignedTxn, ad transactions.ApplyData) error {
	return eval.transactionGroup([]transactions.SignedTxnWithAD{
		transactions.SignedTxnWithAD{
			SignedTxn: txn,
			ApplyData: ad,
		},
	}, true)
}

// TransactionGroup tentatively adds a new transaction group as part of this block evaluation.
// If the transaction group cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) TransactionGroup(txads []transactions.SignedTxnWithAD) error {
	return eval.transactionGroup(txads, true)
}

// transactionGroup tentatively executes a group of transactions as part of this block evaluation.
// If the transaction group cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.  If remember is true,
// the transaction group is added to the block evaluator state; otherwise, the block evaluator
// is not modified and does not remember this transaction group.
func (eval *BlockEvaluator) transactionGroup(txgroup []transactions.SignedTxnWithAD, remember bool) error {
	// Nothing to do if there are no transactions.
	if len(txgroup) == 0 {
		return nil
	}

	if len(txgroup) > eval.proto.MaxTxGroupSize {
		return fmt.Errorf("group size %d exceeds maximum %d", len(txgroup), eval.proto.MaxTxGroupSize)
	}

	var txibs []transactions.SignedTxnInBlock
	var group transactions.TxGroup
	var groupTxBytes int

	cow := eval.state.child()

	groupNoAD := make([]transactions.SignedTxn, len(txgroup))
	for i := range txgroup {
		groupNoAD[i] = txgroup[i].SignedTxn
	}

	ctxs := verify.PrepareContexts(groupNoAD, eval.block.BlockHeader)

	for gi, txad := range txgroup {
		var txib transactions.SignedTxnInBlock

		err := eval.transaction(txad.SignedTxn, txad.ApplyData, groupNoAD, gi, ctxs[gi], cow, &txib)
		if err != nil {
			return err
		}

		txibs = append(txibs, txib)

		if eval.validate {
			groupTxBytes += len(protocol.Encode(txib))
			if eval.blockTxBytes+groupTxBytes > eval.proto.MaxTxnBytesPerBlock {
				return ErrNoSpace
			}
		}

		// Make sure all transactions in group have the same group value
		if txad.SignedTxn.Txn.Group != txgroup[0].SignedTxn.Txn.Group {
			return fmt.Errorf("transactionGroup: inconsistent group values: %v != %v",
				txad.SignedTxn.Txn.Group, txgroup[0].SignedTxn.Txn.Group)
		}

		if !txad.SignedTxn.Txn.Group.IsZero() {
			txWithoutGroup := txad.SignedTxn.Txn
			txWithoutGroup.Group = crypto.Digest{}
			txWithoutGroup.ResetCaches()

			group.TxGroupHashes = append(group.TxGroupHashes, crypto.HashObj(txWithoutGroup))
		} else if len(txgroup) > 1 {
			return fmt.Errorf("transactionGroup: [%d] had zero Group but was submitted in a group of %d", gi, len(txgroup))
		}
	}

	// If we had a non-zero Group value, check that all group members are present.
	if group.TxGroupHashes != nil {
		if txgroup[0].SignedTxn.Txn.Group != crypto.HashObj(group) {
			return fmt.Errorf("transactionGroup: incomplete group: %v != %v (%v)",
				txgroup[0].SignedTxn.Txn.Group, crypto.HashObj(group), group)
		}
	}

	if remember {
		eval.block.Payset = append(eval.block.Payset, txibs...)
		eval.blockTxBytes += groupTxBytes
		cow.commitToParent()
	}

	return nil
}

// transaction tentatively executes a new transaction as part of this block evaluation.
// If the transaction cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) transaction(txn transactions.SignedTxn, ad transactions.ApplyData, txgroup []transactions.SignedTxn, groupIndex int, ctx verify.Context, cow *roundCowState, txib *transactions.SignedTxnInBlock) error {
	var err error

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
		txid := txn.ID()
		dup, err := cow.isDup(txn.Txn.First(), txn.Txn.Last(), txid, txlease{sender: txn.Txn.Sender, lease: txn.Txn.Lease})
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

		if eval.txcache == nil || !eval.txcache.Verified(txn, ctx.Params) {
			err = verify.TxnPool(&txn, ctx, eval.verificationPool)
			if err != nil {
				return fmt.Errorf("transaction %v: failed to verify: %v", txn.ID(), err)
			}
		}

		// Verify that groups are supported.
		if !txn.Txn.Group.IsZero() && !eval.proto.SupportTxGroups {
			return fmt.Errorf("transaction groups not supported")
		}
	}

	// Apply the transaction, updating the cow balances
	applyData, err := txn.Txn.Apply(cow, spec, cow.txnCounter())
	if err != nil {
		return fmt.Errorf("transaction %v: %v", txn.ID(), err)
	}

	// Validate applyData if we are validating an existing block.
	// If we are validating and generating, we have no ApplyData yet.
	if eval.validate && !eval.generate {
		if eval.proto.ApplyData {
			if ad != applyData {
				return fmt.Errorf("transaction %v: applyData mismatch: %v != %v", txn.ID(), ad, applyData)
			}
		} else {
			if ad != (transactions.ApplyData{}) {
				return fmt.Errorf("transaction %v: applyData not supported", txn.ID())
			}
		}
	}

	// Check if the transaction fits in the block, now that we can encode it.
	*txib, err = eval.block.EncodeSignedTxn(txn, applyData)
	if err != nil {
		return err
	}

	// Check if any affected accounts dipped below MinBalance (unless they are
	// completely zero, which means the account will be deleted.)
	rewardlvl := cow.rewardsLevel()
	for _, addr := range cow.modifiedAccounts() {
		// Skip FeeSink and RewardsPool MinBalance checks here.
		// There's only two accounts, so space isn't an issue, and we don't
		// expect them to have low balances, but if they do, it may cause
		// surprises for every transaction.
		if addr == spec.FeeSink || addr == spec.RewardsPool {
			continue
		}

		data, err := cow.lookup(addr)
		if err != nil {
			return err
		}

		// It's always OK to have the account move to an empty state,
		// because the accounts DB can delete it.  Otherwise, we will
		// enforce MinBalance.
		if data.IsZero() {
			continue
		}

		dataNew := data.WithUpdatedRewards(eval.proto, rewardlvl)
		effectiveMinBalance := basics.MulSaturate(eval.proto.MinBalance, uint64(1+len(dataNew.Assets)))
		if dataNew.MicroAlgos.Raw < effectiveMinBalance {
			return fmt.Errorf("transaction %v: account %v balance %d below min %d (%d assets)",
				txn.ID(), addr, dataNew.MicroAlgos.Raw, effectiveMinBalance, len(dataNew.Assets))
		}
	}

	// Remember this txn
	cow.addTx(txn.Txn)

	return nil
}

// Call "endOfBlock" after all the block's rewards and transactions are processed. Applies any deferred balance updates.
func (eval *BlockEvaluator) endOfBlock() error {
	if eval.generate {
		eval.block.TxnRoot = eval.block.Payset.Commit(eval.proto.PaysetCommitFlat)
		if eval.proto.TxnCounter {
			eval.block.TxnCounter = eval.state.txnCounter()
		} else {
			eval.block.TxnCounter = 0
		}
	}

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

		var expectedTxnCount uint64
		if eval.proto.TxnCounter {
			expectedTxnCount = eval.state.txnCounter()
		}
		if eval.block.TxnCounter != expectedTxnCount {
			return fmt.Errorf("txn count wrong: %d != %d", eval.block.TxnCounter, expectedTxnCount)
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

func (l *Ledger) eval(ctx context.Context, blk bookkeeping.Block, aux *evalAux, validate bool, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (StateDelta, evalAux, error) {
	eval, err := startEvaluator(l, blk.BlockHeader, aux, validate, false, txcache, executionPool)
	if err != nil {
		return StateDelta{}, evalAux{}, err
	}

	// TODO: batch tx sig verification: ingest blk.Payset and output a list of ValidatedTx

	// Next, transactions
	paysetgroups, err := blk.DecodePaysetGroups()
	if err != nil {
		return StateDelta{}, evalAux{}, err
	}

	for _, txgroup := range paysetgroups {
		select {
		case <-ctx.Done():
			return StateDelta{}, evalAux{}, ctx.Err()
		default:
		}

		err = eval.TransactionGroup(txgroup)
		if err != nil {
			return StateDelta{}, evalAux{}, err
		}
	}

	// Finally, procees any pending end-of-block state changes
	err = eval.endOfBlock()
	if err != nil {
		return StateDelta{}, evalAux{}, err
	}

	// If validating, do final block checks that depend on our new state
	if validate {
		err = eval.finalValidation()
		if err != nil {
			return StateDelta{}, evalAux{}, err
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
	delta StateDelta
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
