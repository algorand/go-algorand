// Copyright (C) 2019-2020 Algorand, Inc.
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
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

// ErrNoSpace indicates insufficient space for transaction in block
var ErrNoSpace = errors.New("block does not have space for transaction")

// maxPaysetHint makes sure that we don't allocate too much memory up front
// in the block evaluator, since there cannot reasonably be more than this
// many transactions in a block.
const maxPaysetHint = 20000

// VerifiedTxnCache captures the interface for a cache of previously
// verified transactions.  This is expected to match the transaction
// pool object.
type VerifiedTxnCache interface {
	Verified(txn transactions.SignedTxn, params verify.Params) bool
}

type roundCowBase struct {
	l CowBaseForEvaluator

	// The round number of the previous block, for looking up prior state.
	rnd basics.Round

	// TxnCounter from previous block header.
	txnCount uint64

	// CompactCertLastRound from previous block header.
	compactCertSeen basics.Round

	// The current protocol consensus params.
	proto config.ConsensusParams
}

func (x *roundCowBase) getCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return x.l.GetCreatorForRound(x.rnd, cidx, ctype)
}

func (x *roundCowBase) lookup(addr basics.Address) (acctData basics.AccountData, err error) {
	acctData, _, err = x.l.LookupWithoutRewards(x.rnd, addr)
	return acctData, err
}

func (x *roundCowBase) checkDup(firstValid, lastValid basics.Round, txid transactions.Txid, txl txlease) error {
	return x.l.CheckDup(x.proto, x.rnd+1, firstValid, lastValid, txid, TxLease{txl})
}

func (x *roundCowBase) txnCounter() uint64 {
	return x.txnCount
}

func (x *roundCowBase) compactCertLast() basics.Round {
	return x.compactCertSeen
}

func (x *roundCowBase) blockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	return x.l.BlockHdr(r)
}

func (x *roundCowBase) allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error) {
	acct, _, err := x.l.LookupWithoutRewards(x.rnd, addr)
	if err != nil {
		return false, err
	}

	// For global, check if app params exist
	if global {
		_, ok := acct.AppParams[aidx]
		return ok, nil
	}

	// Otherwise, check app local states
	_, ok := acct.AppLocalStates[aidx]
	return ok, nil
}

func (x *roundCowBase) getKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) (basics.TealValue, bool, error) {
	return x.l.GetKeyForRound(x.rnd, addr, aidx, global, key)
}

func (x *roundCowBase) getStorageCounts(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	return x.l.CountStorageForRound(x.rnd, addr, aidx, global)
}

func (x *roundCowBase) getStorageLimits(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	creator, exists, err := x.getCreator(basics.CreatableIndex(aidx), basics.AppCreatable)
	if err != nil {
		return basics.StateSchema{}, err
	}

	// App doesn't exist, so no storage may be allocated.
	if !exists {
		return basics.StateSchema{}, nil
	}

	record, err := x.lookup(creator)
	if err != nil {
		return basics.StateSchema{}, err
	}

	params, ok := record.AppParams[aidx]
	if !ok {
		// This should never happen. If app exists then we should have
		// found the creator successfully.
		err = fmt.Errorf("app %d not found in account %s", aidx, creator.String())
		return basics.StateSchema{}, err
	}

	if global {
		return params.GlobalStateSchema, nil
	}
	return params.LocalStateSchema, nil
}

// wrappers for roundCowState to satisfy the (current) apply.Balances interface
func (cs *roundCowState) Get(addr basics.Address, withPendingRewards bool) (basics.AccountData, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return basics.AccountData{}, err
	}
	if withPendingRewards {
		acct = acct.WithUpdatedRewards(cs.proto, cs.rewardsLevel())
	}
	return acct, nil
}

func (cs *roundCowState) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return cs.getCreator(cidx, ctype)
}

func (cs *roundCowState) Put(addr basics.Address, acct basics.AccountData) error {
	return cs.PutWithCreatable(addr, acct, nil, nil)
}

func (cs *roundCowState) PutWithCreatable(addr basics.Address, acct basics.AccountData, newCreatable *basics.CreatableLocator, deletedCreatable *basics.CreatableLocator) error {
	olddata, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	cs.put(addr, olddata, acct, newCreatable, deletedCreatable)
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
	cs.put(from, fromBal, fromBalNew, nil, nil)

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
	cs.put(to, toBal, toBalNew, nil, nil)

	return nil
}

func (cs *roundCowState) ConsensusParams() config.ConsensusParams {
	return cs.proto
}

func (cs *roundCowState) compactCert(certRnd basics.Round, cert compactcert.Cert, atRound basics.Round) error {
	lastCertRnd := cs.compactCertLast()

	certHdr, err := cs.blockHdr(certRnd)
	if err != nil {
		return err
	}

	proto := config.Consensus[certHdr.CurrentProtocol]
	votersRnd := certRnd.SubSaturate(basics.Round(proto.CompactCertRounds))
	votersHdr, err := cs.blockHdr(votersRnd)
	if err != nil {
		return err
	}

	err = validateCompactCert(certHdr, cert, votersHdr, lastCertRnd, atRound)
	if err != nil {
		return err
	}

	cs.sawCompactCert(certRnd)
	return nil
}

// BlockEvaluator represents an in-progress evaluation of a block
// against the ledger.
type BlockEvaluator struct {
	state    *roundCowState
	validate bool
	generate bool

	prevHeader  bookkeeping.BlockHeader // cached
	proto       config.ConsensusParams
	genesisHash crypto.Digest

	block        bookkeeping.Block
	blockTxBytes int

	blockGenerated bool // prevent repeated GenerateBlock calls

	l ledgerForEvaluator
}

type ledgerForEvaluator interface {
	CowBaseForEvaluator
	GenesisHash() crypto.Digest
	Totals(basics.Round) (AccountTotals, error)
	CompactCertVoters(basics.Round) (*VotersForRound, error)
}

// CowBaseForEvaluator represents subset of Ledger functionality needed for cow business
type CowBaseForEvaluator interface {
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, TxLease) error
	LookupWithoutRewards(basics.Round, basics.Address) (basics.AccountData, basics.Round, error)
	GetCreatorForRound(basics.Round, basics.CreatableIndex, basics.CreatableType) (basics.Address, bool, error)
	GetKeyForRound(basics.Round, basics.Address, basics.AppIndex, bool, string) (basics.TealValue, bool, error)
	CountStorageForRound(basics.Round, basics.Address, basics.AppIndex, bool) (basics.StateSchema, error)
}

// StartEvaluator creates a BlockEvaluator, given a ledger and a block header
// of the block that the caller is planning to evaluate. If the length of the
// payset being evaluated is known in advance, a paysetHint >= 0 can be
// passed, avoiding unnecessary payset slice growth.
func (l *Ledger) StartEvaluator(hdr bookkeeping.BlockHeader, paysetHint int) (*BlockEvaluator, error) {
	return startEvaluator(l, hdr, paysetHint, true, true)
}

func startEvaluator(l ledgerForEvaluator, hdr bookkeeping.BlockHeader, paysetHint int, validate bool, generate bool) (*BlockEvaluator, error) {
	proto, ok := config.Consensus[hdr.CurrentProtocol]
	if !ok {
		return nil, protocol.Error(hdr.CurrentProtocol)
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
		validate:    validate,
		generate:    generate,
		block:       bookkeeping.Block{BlockHeader: hdr},
		proto:       proto,
		genesisHash: l.GenesisHash(),
		l:           l,
	}

	// Preallocate space for the payset so that we don't have to
	// dynamically grow a slice (if evaluating a whole block).
	if paysetHint > 0 {
		if paysetHint > maxPaysetHint {
			paysetHint = maxPaysetHint
		}
		eval.block.Payset = make([]transactions.SignedTxnInBlock, 0, paysetHint)
	}

	prevProto := proto

	if hdr.Round > 0 {
		var err error
		eval.prevHeader, err = l.BlockHdr(base.rnd)
		if err != nil {
			return nil, fmt.Errorf("can't evaluate block %v without previous header: %v", hdr.Round, err)
		}

		base.txnCount = eval.prevHeader.TxnCounter
		base.compactCertSeen = eval.prevHeader.CompactCertLastRound
		prevProto, ok = config.Consensus[eval.prevHeader.CurrentProtocol]
		if !ok {
			return nil, protocol.Error(eval.prevHeader.CurrentProtocol)
		}
	}

	prevTotals, err := l.Totals(eval.prevHeader.Round)
	if err != nil {
		return nil, err
	}

	poolAddr := eval.prevHeader.RewardsPool
	// get the reward pool account data without any rewards
	incentivePoolData, _, err := l.LookupWithoutRewards(eval.prevHeader.Round, poolAddr)
	if err != nil {
		return nil, err
	}

	// this is expected to be a no-op, but update the rewards on the rewards pool if it was configured to receive rewards ( unlike mainnet ).
	incentivePoolData = incentivePoolData.WithUpdatedRewards(prevProto, eval.prevHeader.RewardsLevel)

	if generate {
		if eval.proto.SupportGenesisHash {
			eval.block.BlockHeader.GenesisHash = eval.genesisHash
		}
		eval.block.BlockHeader.RewardsState = eval.prevHeader.NextRewardsState(hdr.Round, proto, incentivePoolData.MicroAlgos, prevTotals.RewardUnits())
	}
	// set the eval state with the current header
	eval.state = makeRoundCowState(base, eval.block.BlockHeader, eval.prevHeader.TimeStamp)

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

	err = eval.state.Put(poolAddr, poolNew)
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
func (eval *BlockEvaluator) workaroundOverspentRewards(rewardPoolBalance basics.AccountData, headerRound basics.Round) (poolOld basics.AccountData, err error) {
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
	err = cow.checkDup(txn.Txn.First(), txn.Txn.Last(), txid, txlease{sender: txn.Txn.Sender, lease: txn.Txn.Lease})
	if err != nil {
		return err
	}

	return nil
}

// Transaction tentatively adds a new transaction as part of this block evaluation.
// If the transaction cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) Transaction(txn transactions.SignedTxn, ad transactions.ApplyData) error {
	return eval.transactionGroup([]transactions.SignedTxnWithAD{{
		SignedTxn: txn,
		ApplyData: ad,
	}})
}

// TransactionGroup tentatively adds a new transaction group as part of this block evaluation.
// If the transaction group cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) TransactionGroup(txads []transactions.SignedTxnWithAD) error {
	return eval.transactionGroup(txads)
}

// prepareEvalParams creates a logic.EvalParams for each ApplicationCall
// transaction in the group
func (eval *BlockEvaluator) prepareEvalParams(txgroup []transactions.SignedTxnWithAD) (res []*logic.EvalParams) {
	var groupNoAD []transactions.SignedTxn
	var minTealVersion uint64
	res = make([]*logic.EvalParams, len(txgroup))
	for i, txn := range txgroup {
		// Ignore any non-ApplicationCall transactions
		if txn.SignedTxn.Txn.Type != protocol.ApplicationCallTx {
			continue
		}

		// Initialize group without ApplyData lazily
		if groupNoAD == nil {
			groupNoAD = make([]transactions.SignedTxn, len(txgroup))
			for j := range txgroup {
				groupNoAD[j] = txgroup[j].SignedTxn
			}
			minTealVersion = logic.ComputeMinTealVersion(groupNoAD)
		}

		res[i] = &logic.EvalParams{
			Txn:            &groupNoAD[i],
			Proto:          &eval.proto,
			TxnGroup:       groupNoAD,
			GroupIndex:     i,
			MinTealVersion: &minTealVersion,
		}
	}
	return
}

// transactionGroup tentatively executes a group of transactions as part of this block evaluation.
// If the transaction group cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) transactionGroup(txgroup []transactions.SignedTxnWithAD) error {
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

	// Prepare eval params for any ApplicationCall transactions in the group
	evalParams := eval.prepareEvalParams(txgroup)

	// Evaluate each transaction in the group
	txibs = make([]transactions.SignedTxnInBlock, 0, len(txgroup))
	for gi, txad := range txgroup {
		var txib transactions.SignedTxnInBlock

		err := eval.transaction(txad.SignedTxn, evalParams[gi], txad.ApplyData, cow, &txib)
		if err != nil {
			return err
		}

		txibs = append(txibs, txib)

		if eval.validate {
			groupTxBytes += len(protocol.Encode(&txib))
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

	eval.block.Payset = append(eval.block.Payset, txibs...)
	eval.blockTxBytes += groupTxBytes
	cow.commitToParent()

	return nil
}

// transaction tentatively executes a new transaction as part of this block evaluation.
// If the transaction cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) transaction(txn transactions.SignedTxn, evalParams *logic.EvalParams, ad transactions.ApplyData, cow *roundCowState, txib *transactions.SignedTxnInBlock) error {
	var err error

	// Only compute the TxID once
	txid := txn.ID()

	if eval.validate {
		err = txn.Txn.Alive(eval.block)
		if err != nil {
			return err
		}

		// Transaction already in the ledger?
		err := cow.checkDup(txn.Txn.First(), txn.Txn.Last(), txid, txlease{sender: txn.Txn.Sender, lease: txn.Txn.Lease})
		if err != nil {
			return err
		}

		// Does the address that authorized the transaction actually match whatever address the sender has rekeyed to?
		// i.e., the sig/lsig/msig was checked against the txn.Authorizer() address, but does this match the sender's balrecord.AuthAddr?
		acctdata, err := cow.lookup(txn.Txn.Sender)
		if err != nil {
			return err
		}
		correctAuthorizer := acctdata.AuthAddr
		if (correctAuthorizer == basics.Address{}) {
			correctAuthorizer = txn.Txn.Sender
		}
		if txn.Authorizer() != correctAuthorizer {
			return fmt.Errorf("transaction %v: should have been authorized by %v but was actually authorized by %v", txn.ID(), correctAuthorizer, txn.Authorizer())
		}
	}

	spec := transactions.SpecialAddresses{
		FeeSink:     eval.block.BlockHeader.FeeSink,
		RewardsPool: eval.block.BlockHeader.RewardsPool,
	}

	// Apply the transaction, updating the cow balances
	applyData, err := applyTransaction(txn.Txn, cow, evalParams, spec, cow.txnCounter())
	if err != nil {
		return fmt.Errorf("transaction %v: %v", txid, err)
	}

	// Validate applyData if we are validating an existing block.
	// If we are validating and generating, we have no ApplyData yet.
	if eval.validate && !eval.generate {
		if eval.proto.ApplyData {
			if !ad.Equal(applyData) {
				return fmt.Errorf("transaction %v: applyData mismatch: %v != %v", txid, ad, applyData)
			}
		} else {
			if !ad.Equal(transactions.ApplyData{}) {
				return fmt.Errorf("transaction %v: applyData not supported", txid)
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
		// Skip FeeSink, RewardsPool, and CompactCertSender MinBalance checks here.
		// There's only a few accounts, so space isn't an issue, and we don't
		// expect them to have low balances, but if they do, it may cause
		// surprises.
		if addr == spec.FeeSink || addr == spec.RewardsPool || addr == transactions.CompactCertSender {
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
		effectiveMinBalance := dataNew.MinBalance(&eval.proto)
		if dataNew.MicroAlgos.Raw < effectiveMinBalance.Raw {
			return fmt.Errorf("transaction %v: account %v balance %d below min %d (%d assets)",
				txid, addr, dataNew.MicroAlgos.Raw, effectiveMinBalance.Raw, len(dataNew.Assets))
		}

		// Check if we have exceeded the maximum minimum balance
		if eval.proto.MaximumMinimumBalance != 0 {
			if effectiveMinBalance.Raw > eval.proto.MaximumMinimumBalance {
				return fmt.Errorf("transaction %v: account %v would use too much space after this transaction. Minimum balance requirements would be %d (greater than max %d)", txid, addr, effectiveMinBalance.Raw, eval.proto.MaximumMinimumBalance)
			}
		}
	}

	// Remember this txn
	cow.addTx(txn.Txn, txid)

	return nil
}

// applyTransaction changes the balances according to this transaction.
func applyTransaction(tx transactions.Transaction, balances *roundCowState, evalParams *logic.EvalParams, spec transactions.SpecialAddresses, ctr uint64) (ad transactions.ApplyData, err error) {
	params := balances.ConsensusParams()

	// move fee to pool
	err = balances.Move(tx.Sender, spec.FeeSink, tx.Fee, &ad.SenderRewards, nil)
	if err != nil {
		return
	}

	// rekeying: update balrecord.AuthAddr to tx.RekeyTo if provided
	if (tx.RekeyTo != basics.Address{}) {
		var acct basics.AccountData
		acct, err = balances.Get(tx.Sender, false)
		if err != nil {
			return
		}
		// Special case: rekeying to the account's actual address just sets acct.AuthAddr to 0
		// This saves 32 bytes in your balance record if you want to go back to using your original key
		if tx.RekeyTo == tx.Sender {
			acct.AuthAddr = basics.Address{}
		} else {
			acct.AuthAddr = tx.RekeyTo
		}

		err = balances.Put(tx.Sender, acct)
		if err != nil {
			return
		}
	}

	switch tx.Type {
	case protocol.PaymentTx:
		err = apply.Payment(tx.PaymentTxnFields, tx.Header, balances, spec, &ad)

	case protocol.KeyRegistrationTx:
		err = apply.Keyreg(tx.KeyregTxnFields, tx.Header, balances, spec, &ad)

	case protocol.AssetConfigTx:
		err = apply.AssetConfig(tx.AssetConfigTxnFields, tx.Header, balances, spec, &ad, ctr)

	case protocol.AssetTransferTx:
		err = apply.AssetTransfer(tx.AssetTransferTxnFields, tx.Header, balances, spec, &ad)

	case protocol.AssetFreezeTx:
		err = apply.AssetFreeze(tx.AssetFreezeTxnFields, tx.Header, balances, spec, &ad)

	case protocol.ApplicationCallTx:
		err = apply.ApplicationCall(tx.ApplicationCallTxnFields, tx.Header, balances, &ad, evalParams, ctr)

	case protocol.CompactCertTx:
		err = balances.compactCert(tx.CertRound, tx.Cert, tx.Header.FirstValid)

	default:
		err = fmt.Errorf("Unknown transaction type %v", tx.Type)
	}

	// If the protocol does not support rewards in ApplyData,
	// clear them out.
	if !params.RewardsInApplyData {
		ad.SenderRewards = basics.MicroAlgos{}
		ad.ReceiverRewards = basics.MicroAlgos{}
		ad.CloseRewards = basics.MicroAlgos{}
	}

	return
}

// compactCertVotersAndTotal returns the expected values of CompactCertVoters
// and CompactCertVotersTotal for a block.
func (eval *BlockEvaluator) compactCertVotersAndTotal() (root crypto.Digest, total basics.MicroAlgos, err error) {
	if eval.proto.CompactCertRounds == 0 {
		return
	}

	if eval.block.Round()%basics.Round(eval.proto.CompactCertRounds) != 0 {
		return
	}

	lookback := eval.block.Round().SubSaturate(basics.Round(eval.proto.CompactCertVotersLookback))
	voters, err := eval.l.CompactCertVoters(lookback)
	if err != nil {
		return
	}

	if voters != nil {
		root = voters.Tree.Root()
		total = voters.TotalWeight
	}

	return
}

// Call "endOfBlock" after all the block's rewards and transactions are processed.
func (eval *BlockEvaluator) endOfBlock() error {
	if eval.generate {
		eval.block.TxnRoot = eval.block.Payset.Commit(eval.proto.PaysetCommitFlat)
		if eval.proto.TxnCounter {
			eval.block.TxnCounter = eval.state.txnCounter()
		} else {
			eval.block.TxnCounter = 0
		}

		var err error
		eval.block.CompactCertVoters, eval.block.CompactCertVotersTotal, err = eval.compactCertVotersAndTotal()
		if err != nil {
			return err
		}

		eval.block.CompactCertLastRound = eval.state.compactCertLast()
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

		expectedVoters, expectedVotersWeight, err := eval.compactCertVotersAndTotal()
		if err != nil {
			return err
		}
		if eval.block.CompactCertVoters != expectedVoters {
			return fmt.Errorf("CompactCertVoters wrong: %v != %v", eval.block.CompactCertVoters, expectedVoters)
		}
		if eval.block.CompactCertVotersTotal != expectedVotersWeight {
			return fmt.Errorf("CompactCertVotersTotal wrong: %v != %v", eval.block.CompactCertVotersTotal, expectedVotersWeight)
		}
		if eval.block.CompactCertLastRound != eval.state.compactCertLast() {
			return fmt.Errorf("CompactCertLastRound wrong: %v != %v", eval.block.CompactCertLastRound, eval.state.compactCertLast())
		}
	}

	return nil
}

// GenerateBlock produces a complete block from the BlockEvaluator.  This is
// used during proposal to get an actual block that will be proposed, after
// feeding in tentative transactions into this block evaluator.
//
// After a call to GenerateBlock, the BlockEvaluator can still be used to
// accept transactions.  However, to guard against reuse, subsequent calls
// to GenerateBlock on the same BlockEvaluator will fail.
func (eval *BlockEvaluator) GenerateBlock() (*ValidatedBlock, error) {
	if !eval.generate {
		logging.Base().Panicf("GenerateBlock() called but generate is false")
	}

	if eval.blockGenerated {
		return nil, fmt.Errorf("GenerateBlock already called on this BlockEvaluator")
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
	}
	eval.blockGenerated = true
	eval.state = makeRoundCowState(eval.state, eval.block.BlockHeader, eval.prevHeader.TimeStamp)
	return &vb, nil
}

type evalTxValidator struct {
	txcache          VerifiedTxnCache
	block            bookkeeping.Block
	proto            config.ConsensusParams
	verificationPool execpool.BacklogPool

	ctx      context.Context
	cf       context.CancelFunc
	txgroups chan []transactions.SignedTxnWithAD
	done     chan error
}

func (validator *evalTxValidator) run() {
	for txgroup := range validator.txgroups {
		select {
		case <-validator.ctx.Done():
			validator.done <- validator.ctx.Err()
			validator.cf()
			close(validator.done)
			return
		default:
		}
		groupNoAD := make([]transactions.SignedTxn, len(txgroup))
		for i := range txgroup {
			groupNoAD[i] = txgroup[i].SignedTxn
		}
		ctxs := verify.PrepareContexts(groupNoAD, validator.block.BlockHeader)

		for gi, tx := range txgroup {
			err := validateTransaction(tx.SignedTxn, validator.block, validator.proto, validator.txcache, ctxs[gi], validator.verificationPool)
			if err != nil {
				validator.done <- err
				validator.cf()
				close(validator.done)
				return
			}
		}
	}
	close(validator.done)
}

func validateTransaction(txn transactions.SignedTxn, block bookkeeping.Block, proto config.ConsensusParams, txcache VerifiedTxnCache, ctx verify.Context, verificationPool execpool.BacklogPool) error {
	// Transaction valid (not expired)?
	err := txn.Txn.Alive(block)
	if err != nil {
		return err
	}

	if txcache == nil || !txcache.Verified(txn, ctx.Params) {
		err = verify.TxnPool(&txn, ctx, verificationPool)
		if err != nil {
			return fmt.Errorf("transaction %v: failed to verify: %v", txn.ID(), err)
		}
	}
	return nil
}

// used by Ledger.Validate() Ledger.AddBlock() Ledger.trackerEvalVerified()(accountUpdates.loadFromDisk())
//
// Validate: eval(ctx, blk, true, txcache, executionPool)
// AddBlock: eval(context.Background(), blk, false, nil, nil)
// tracker:  eval(context.Background(), blk, false, nil, nil)
func eval(ctx context.Context, l ledgerForEvaluator, blk bookkeeping.Block, validate bool, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (StateDelta, error) {
	eval, err := startEvaluator(l, blk.BlockHeader, len(blk.Payset), validate, false)
	if err != nil {
		return StateDelta{}, err
	}

	// Next, transactions
	paysetgroups, err := blk.DecodePaysetGroups()
	if err != nil {
		return StateDelta{}, err
	}

	var txvalidator evalTxValidator
	ctx, cf := context.WithCancel(ctx)
	defer cf()
	if validate {
		proto, ok := config.Consensus[blk.CurrentProtocol]
		if !ok {
			return StateDelta{}, protocol.Error(blk.CurrentProtocol)
		}
		txvalidator.txcache = txcache
		txvalidator.block = blk
		txvalidator.proto = proto
		txvalidator.verificationPool = executionPool

		txvalidator.ctx = ctx
		txvalidator.cf = cf
		txvalidator.txgroups = make(chan []transactions.SignedTxnWithAD, len(paysetgroups))
		txvalidator.done = make(chan error, 1)
		go txvalidator.run()
	}

	for _, txgroup := range paysetgroups {
		select {
		case <-ctx.Done():
			select {
			case err := <-txvalidator.done:
				return StateDelta{}, err
			default:
			}
			return StateDelta{}, ctx.Err()
		default:
		}

		if validate {
			txvalidator.txgroups <- txgroup
		}
		err = eval.TransactionGroup(txgroup)
		if err != nil {
			return StateDelta{}, err
		}
	}

	// Finally, procees any pending end-of-block state changes
	err = eval.endOfBlock()
	if err != nil {
		return StateDelta{}, err
	}

	// If validating, do final block checks that depend on our new state
	if validate {
		close(txvalidator.txgroups)
		err, gotErr := <-txvalidator.done
		if gotErr && err != nil {
			return StateDelta{}, err
		}
		err = eval.finalValidation()
		if err != nil {
			return StateDelta{}, err
		}
	}

	return eval.state.mods, nil
}

// Validate uses the ledger to validate block blk as a candidate next block.
// It returns an error if blk is not the expected next block, or if blk is
// not a valid block (e.g., it has duplicate transactions, overspends some
// account, etc).
func (l *Ledger) Validate(ctx context.Context, blk bookkeeping.Block, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (*ValidatedBlock, error) {
	delta, err := eval(ctx, l, blk, true, txcache, executionPool)
	if err != nil {
		return nil, err
	}

	vb := ValidatedBlock{
		blk:   blk,
		delta: delta,
	}
	return &vb, nil
}

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

// WithSeed returns a copy of the ValidatedBlock with a modified seed.
func (vb ValidatedBlock) WithSeed(s committee.Seed) ValidatedBlock {
	newblock := vb.blk
	newblock.BlockHeader.Seed = s

	return ValidatedBlock{
		blk:   newblock,
		delta: vb.delta,
	}
}
