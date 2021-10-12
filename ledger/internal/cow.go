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

package internal

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

//   ___________________
// < cow = Copy On Write >
//   -------------------
//          \   ^__^
//           \  (oo)\_______
//              (__)\       )\/\
//                  ||----w |
//                  ||     ||

type roundCowParent interface {
	lookup(basics.Address) (basics.AccountData, error)
	checkDup(basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error
	txnCounter() uint64
	getCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error)
	compactCertNext() basics.Round
	blockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error)
	getStorageCounts(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error)
	// note: getStorageLimits is redundant with the other methods
	// and is provided to optimize state schema lookups
	getStorageLimits(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error)
	allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error)
	getKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) (basics.TealValue, bool, error)
}

type roundCowState struct {
	lookupParent roundCowParent
	commitParent *roundCowState
	proto        config.ConsensusParams
	mods         ledgercore.StateDelta

	// count of transactions. Formerly, we used len(cb.mods), but that
	// does not count inner transactions.
	txnCount uint64

	// storage deltas populated as side effects of AppCall transaction
	// 1. Opt-in/Close actions (see Allocate/Deallocate)
	// 2. Stateful TEAL evaluation (see SetKey/DelKey)
	// must be incorporated into mods.accts before passing deltas forward
	sdeltas map[basics.Address]map[storagePtr]*storageDelta

	// either or not maintain compatibility with original app refactoring behavior
	// this is needed for generating old eval delta in new code
	compatibilityMode bool
	// cache mainaining accountIdx used in getKey for local keys access
	compatibilityGetKeyCache map[basics.Address]map[storagePtr]uint64

	// index of a txn within a group; used in conjunction with trackedCreatables
	groupIdx int
	// track creatables created during each transaction in the round
	trackedCreatables map[int]basics.CreatableIndex

	// prevTotals contains the accounts totals for the previous round. It's being used to calculate the totals for the new round
	// so that we could perform the validation test on these to ensure the block evaluator generate a valid changeset.
	prevTotals ledgercore.AccountTotals
}

func makeRoundCowState(b roundCowParent, hdr bookkeeping.BlockHeader, proto config.ConsensusParams, prevTimestamp int64, prevTotals ledgercore.AccountTotals, hint int) *roundCowState {
	cb := roundCowState{
		lookupParent:      b,
		commitParent:      nil,
		proto:             proto,
		mods:              ledgercore.MakeStateDelta(&hdr, prevTimestamp, hint, 0),
		sdeltas:           make(map[basics.Address]map[storagePtr]*storageDelta),
		trackedCreatables: make(map[int]basics.CreatableIndex),
		prevTotals:        prevTotals,
	}

	// compatibilityMode retains producing application' eval deltas under the following rule:
	// local delta has account index as it specified in TEAL either in set/del key or prior get key calls.
	// The predicate is that complex in order to cover all the block seen on testnet and mainnet.
	compatibilityMode := (hdr.CurrentProtocol == protocol.ConsensusV24) &&
		(hdr.NextProtocol != protocol.ConsensusV26 || (hdr.UpgradePropose == "" && hdr.UpgradeApprove == false && hdr.Round < hdr.UpgradeState.NextProtocolVoteBefore))
	if compatibilityMode {
		cb.compatibilityMode = true
		cb.compatibilityGetKeyCache = make(map[basics.Address]map[storagePtr]uint64)
	}
	return &cb
}

func (cb *roundCowState) deltas() ledgercore.StateDelta {
	var err error
	if len(cb.sdeltas) == 0 {
		return cb.mods
	}

	// Apply storage deltas to account deltas
	// 1. Ensure all addresses from sdeltas have entries in accts because
	//    SetKey/DelKey work only with sdeltas, so need to pull missing accounts
	// 2. Call applyStorageDelta for every delta per account
	for addr, smap := range cb.sdeltas {
		var delta basics.AccountData
		var exist bool
		if delta, exist = cb.mods.Accts.Get(addr); !exist {
			ad, err := cb.lookup(addr)
			if err != nil {
				panic(fmt.Sprintf("fetching account data failed for addr %s: %s", addr.String(), err.Error()))
			}
			delta = ad
		}
		for aapp, storeDelta := range smap {
			if delta, err = applyStorageDelta(delta, aapp, storeDelta); err != nil {
				panic(fmt.Sprintf("applying storage delta failed for addr %s app %d: %s", addr.String(), aapp.aidx, err.Error()))
			}
		}
		cb.mods.Accts.Upsert(addr, delta)
	}
	return cb.mods
}

func (cb *roundCowState) rewardsLevel() uint64 {
	return cb.mods.Hdr.RewardsLevel
}

func (cb *roundCowState) round() basics.Round {
	return cb.mods.Hdr.Round
}

func (cb *roundCowState) prevTimestamp() int64 {
	return cb.mods.PrevTimestamp
}

func (cb *roundCowState) getCreatableIndex(groupIdx int) basics.CreatableIndex {
	return cb.trackedCreatables[groupIdx]
}

func (cb *roundCowState) getCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (creator basics.Address, ok bool, err error) {
	delta, ok := cb.mods.Creatables[cidx]
	if ok {
		if delta.Created && delta.Ctype == ctype {
			return delta.Creator, true, nil
		}
		return basics.Address{}, false, nil
	}
	return cb.lookupParent.getCreator(cidx, ctype)
}

func (cb *roundCowState) lookup(addr basics.Address) (data basics.AccountData, err error) {
	d, ok := cb.mods.Accts.Get(addr)
	if ok {
		return d, nil
	}

	return cb.lookupParent.lookup(addr)
}

func (cb *roundCowState) checkDup(firstValid, lastValid basics.Round, txid transactions.Txid, txl ledgercore.Txlease) error {
	_, present := cb.mods.Txids[txid]
	if present {
		return &ledgercore.TransactionInLedgerError{Txid: txid}
	}

	if cb.proto.SupportTransactionLeases && (txl.Lease != [32]byte{}) {
		expires, ok := cb.mods.Txleases[txl]
		if ok && cb.mods.Hdr.Round <= expires {
			return ledgercore.MakeLeaseInLedgerError(txid, txl)
		}
	}

	return cb.lookupParent.checkDup(firstValid, lastValid, txid, txl)
}

func (cb *roundCowState) txnCounter() uint64 {
	return cb.lookupParent.txnCounter() + cb.txnCount
}

func (cb *roundCowState) compactCertNext() basics.Round {
	if cb.mods.CompactCertNext != 0 {
		return cb.mods.CompactCertNext
	}
	return cb.lookupParent.compactCertNext()
}

func (cb *roundCowState) blockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	return cb.lookupParent.blockHdr(r)
}

func (cb *roundCowState) trackCreatable(creatableIndex basics.CreatableIndex) {
	cb.trackedCreatables[cb.groupIdx] = creatableIndex
}

func (cb *roundCowState) incTxnCount() {
	cb.txnCount++
}

func (cb *roundCowState) addTx(txn transactions.Transaction, txid transactions.Txid) {
	cb.mods.Txids[txid] = txn.LastValid
	cb.incTxnCount()
	if txn.Lease != [32]byte{} {
		cb.mods.Txleases[ledgercore.Txlease{Sender: txn.Sender, Lease: txn.Lease}] = txn.LastValid
	}
}

func (cb *roundCowState) setCompactCertNext(rnd basics.Round) {
	cb.mods.CompactCertNext = rnd
}

func (cb *roundCowState) child(hint int) *roundCowState {
	ch := roundCowState{
		lookupParent: cb,
		commitParent: cb,
		proto:        cb.proto,
		mods:         ledgercore.MakeStateDelta(cb.mods.Hdr, cb.mods.PrevTimestamp, hint, cb.mods.CompactCertNext),
		sdeltas:      make(map[basics.Address]map[storagePtr]*storageDelta),
	}

	// clone tracked creatables
	ch.trackedCreatables = make(map[int]basics.CreatableIndex)
	for i, tc := range cb.trackedCreatables {
		ch.trackedCreatables[i] = tc
	}

	if cb.compatibilityMode {
		ch.compatibilityMode = cb.compatibilityMode
		ch.compatibilityGetKeyCache = make(map[basics.Address]map[storagePtr]uint64)
	}
	return &ch
}

// setGroupIdx sets this transaction's index within its group
func (cb *roundCowState) setGroupIdx(txnIdx int) {
	cb.groupIdx = txnIdx
}

func (cb *roundCowState) commitToParent() {
	cb.commitParent.mods.Accts.MergeAccounts(cb.mods.Accts)

	for txid, lv := range cb.mods.Txids {
		cb.commitParent.mods.Txids[txid] = lv
	}
	cb.commitParent.txnCount += cb.txnCount

	for txl, expires := range cb.mods.Txleases {
		cb.commitParent.mods.Txleases[txl] = expires
	}
	for cidx, delta := range cb.mods.Creatables {
		cb.commitParent.mods.Creatables[cidx] = delta
	}
	for addr, smod := range cb.sdeltas {
		for aapp, nsd := range smod {
			lsd, ok := cb.commitParent.sdeltas[addr][aapp]
			if ok {
				lsd.applyChild(nsd)
			} else {
				_, ok = cb.commitParent.sdeltas[addr]
				if !ok {
					cb.commitParent.sdeltas[addr] = make(map[storagePtr]*storageDelta)
				}
				cb.commitParent.sdeltas[addr][aapp] = nsd
			}
		}
	}
	cb.commitParent.mods.CompactCertNext = cb.mods.CompactCertNext
	for index, created := range cb.mods.ModifiedAssetHoldings {
		cb.commitParent.mods.ModifiedAssetHoldings[index] = created
	}
	for index, created := range cb.mods.ModifiedAppLocalStates {
		cb.commitParent.mods.ModifiedAppLocalStates[index] = created
	}
}

func (cb *roundCowState) modifiedAccounts() []basics.Address {
	return cb.mods.Accts.ModifiedAccounts()
}

// errUnsupportedChildCowTotalCalculation is returned by CalculateTotals when called by a child roundCowState instance
var errUnsupportedChildCowTotalCalculation = errors.New("the method CalculateTotals should be called only on a top-level roundCowState")

// CalculateTotals calculates the totals given the changes in the StateDelta.
// these changes allow the validator to validate that the totals still align with the
// expected values. ( i.e. total amount of algos in the system should remain consistent )
func (cb *roundCowState) CalculateTotals() error {
	// this method applies only for the top level roundCowState
	if cb.commitParent != nil {
		return errUnsupportedChildCowTotalCalculation
	}
	totals := cb.prevTotals
	var ot basics.OverflowTracker
	totals.ApplyRewards(cb.mods.Hdr.RewardsLevel, &ot)

	for i := 0; i < cb.mods.Accts.Len(); i++ {
		accountAddr, updatedAccountData := cb.mods.Accts.GetByIdx(i)
		previousAccountData, lookupError := cb.lookupParent.lookup(accountAddr)
		if lookupError != nil {
			return fmt.Errorf("roundCowState.CalculateTotals unable to load account data for address %v", accountAddr)
		}
		totals.DelAccount(cb.proto, previousAccountData, &ot)
		totals.AddAccount(cb.proto, updatedAccountData, &ot)
	}

	if ot.Overflowed {
		return fmt.Errorf("roundCowState: CalculateTotals %d overflowed totals", cb.mods.Hdr.Round)
	}
	if totals.All() != cb.prevTotals.All() {
		return fmt.Errorf("roundCowState: CalculateTotals sum of money changed from %d to %d", cb.prevTotals.All().Raw, totals.All().Raw)
	}

	cb.mods.Totals = totals
	return nil
}
