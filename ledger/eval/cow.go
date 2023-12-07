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

package eval

import (
	"errors"
	"fmt"
	"sync"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"golang.org/x/exp/maps"
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
	// lookup retrieves data about an address, eventually querying the ledger if the address was not found in cache.
	lookup(basics.Address) (ledgercore.AccountData, error)

	// lookupAppParams, lookupAssetParams, lookupAppLocalState, and lookupAssetHolding retrieve data for a given address and ID.
	// If cacheOnly is set, the ledger DB will not be queried, and only the cache will be consulted.
	// This is used when we know a given value is already in cache (from a previous query for that same address and ID),
	// and would rather have an error returned if that assumption is wrong, rather than hit the ledger.
	lookupAppParams(addr basics.Address, aidx basics.AppIndex, cacheOnly bool) (ledgercore.AppParamsDelta, bool, error)
	lookupAssetParams(addr basics.Address, aidx basics.AssetIndex, cacheOnly bool) (ledgercore.AssetParamsDelta, bool, error)
	lookupAppLocalState(addr basics.Address, aidx basics.AppIndex, cacheOnly bool) (ledgercore.AppLocalStateDelta, bool, error)
	lookupAssetHolding(addr basics.Address, aidx basics.AssetIndex, cacheOnly bool) (ledgercore.AssetHoldingDelta, bool, error)

	checkDup(basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error
	Counter() uint64
	getCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error)
	GetStateProofNextRound() basics.Round
	BlockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error)
	getStorageCounts(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error)
	// note: getStorageLimits is redundant with the other methods
	// and is provided to optimize state schema lookups
	getStorageLimits(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error)
	allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error)
	getKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) (basics.TealValue, bool, error)
	kvGet(key string) ([]byte, bool, error)
	GetStateProofVerificationContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error)
	GenesisHash() crypto.Digest
}

// When adding new fields make sure to clear them in the roundCowState.recycle() as well to avoid dirty state
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
	// 2. Application evaluation (see setKey/delKey)
	// must be incorporated into mods.accts before passing deltas forward
	sdeltas map[basics.Address]map[storagePtr]*storageDelta

	// whether or not to maintain compatibility with original app refactoring behavior
	// this is needed for generating old eval delta in new code
	compatibilityMode bool
	// cache maintaining accountIdx used in getKey for local keys access
	compatibilityGetKeyCache map[basics.Address]map[storagePtr]uint64

	// prevTotals contains the accounts totals for the previous round. It's being used to calculate the totals for the new round
	// so that we could perform the validation test on these to ensure the block evaluator generate a valid changeset.
	prevTotals ledgercore.AccountTotals
}

var childPool = sync.Pool{
	New: func() interface{} {
		return &roundCowState{}
	},
}

func makeRoundCowState(b roundCowParent, hdr bookkeeping.BlockHeader, proto config.ConsensusParams, prevTimestamp int64, prevTotals ledgercore.AccountTotals, hint int) *roundCowState {
	cb := roundCowState{
		lookupParent: b,
		commitParent: nil,
		proto:        proto,
		mods:         ledgercore.MakeStateDelta(&hdr, prevTimestamp, hint, 0),
		sdeltas:      make(map[basics.Address]map[storagePtr]*storageDelta),
		prevTotals:   prevTotals,
	}

	// compatibilityMode retains producing application' eval deltas under the following rule:
	// local delta has account index as it specified in TEAL either in set/del key or prior get key calls.
	// The predicate is that complex in order to cover all the block seen on testnet and mainnet.
	compatibilityMode := (hdr.CurrentProtocol == protocol.ConsensusV24) &&
		(hdr.NextProtocol != protocol.ConsensusV26 || (hdr.UpgradePropose == "" && !hdr.UpgradeApprove && hdr.Round < hdr.UpgradeState.NextProtocolVoteBefore))
	if compatibilityMode {
		cb.compatibilityMode = true
		cb.compatibilityGetKeyCache = make(map[basics.Address]map[storagePtr]uint64)
	}
	return &cb
}

func (cb *roundCowState) deltas() ledgercore.StateDelta {
	// Apply storage deltas to account deltas
	for addr, smap := range cb.sdeltas {
		for aapp, storeDelta := range smap {
			if err := applyStorageDelta(cb, addr, aapp, storeDelta); err != nil {
				panic(fmt.Sprintf("applying storage delta failed for addr %s app %d: %s", addr.String(), aapp.aidx, err.Error()))
			}
		}
	}

	// Populate old values by looking through parent
	for key, value := range cb.mods.KvMods {
		old, _, err := cb.lookupParent.kvGet(key) // Because of how boxes are prefetched, value will be cached
		if err != nil {
			panic(fmt.Errorf("Error looking up %v : %w", key, err))
		}
		value.OldData = old
		cb.mods.KvMods[key] = value
	}

	return cb.mods
}

func (cb *roundCowState) rewardsLevel() uint64 {
	return cb.mods.Hdr.RewardsLevel
}

func (cb *roundCowState) Round() basics.Round {
	return cb.mods.Hdr.Round
}

func (cb *roundCowState) PrevTimestamp() int64 {
	return cb.mods.PrevTimestamp
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

func (cb *roundCowState) lookup(addr basics.Address) (data ledgercore.AccountData, err error) {
	d, ok := cb.mods.Accts.GetData(addr)
	if ok {
		return d, nil
	}

	return cb.lookupParent.lookup(addr)
}

func (cb *roundCowState) lookupAppParams(addr basics.Address, aidx basics.AppIndex, cacheOnly bool) (ledgercore.AppParamsDelta, bool, error) {
	params, ok := cb.mods.Accts.GetAppParams(addr, aidx)
	if ok {
		return params, ok, nil
	}

	return cb.lookupParent.lookupAppParams(addr, aidx, cacheOnly)
}

func (cb *roundCowState) lookupAssetParams(addr basics.Address, aidx basics.AssetIndex, cacheOnly bool) (ledgercore.AssetParamsDelta, bool, error) {
	params, ok := cb.mods.Accts.GetAssetParams(addr, aidx)
	if ok {
		return params, ok, nil
	}

	return cb.lookupParent.lookupAssetParams(addr, aidx, cacheOnly)
}

func (cb *roundCowState) lookupAppLocalState(addr basics.Address, aidx basics.AppIndex, cacheOnly bool) (ledgercore.AppLocalStateDelta, bool, error) {
	state, ok := cb.mods.Accts.GetAppLocalState(addr, aidx)
	if ok {
		return state, ok, nil
	}

	return cb.lookupParent.lookupAppLocalState(addr, aidx, cacheOnly)
}

func (cb *roundCowState) lookupAssetHolding(addr basics.Address, aidx basics.AssetIndex, cacheOnly bool) (ledgercore.AssetHoldingDelta, bool, error) {
	holding, ok := cb.mods.Accts.GetAssetHolding(addr, aidx)
	if ok {
		return holding, ok, nil
	}

	return cb.lookupParent.lookupAssetHolding(addr, aidx, cacheOnly)
}

func (cb *roundCowState) checkDup(firstValid, lastValid basics.Round, txid transactions.Txid, txl ledgercore.Txlease) error {
	_, present := cb.mods.Txids[txid]
	if present {
		return &ledgercore.TransactionInLedgerError{Txid: txid, InBlockEvaluator: true}
	}

	if cb.proto.SupportTransactionLeases && (txl.Lease != [32]byte{}) {
		expires, ok := cb.mods.Txleases[txl]
		if ok && cb.mods.Hdr.Round <= expires {
			return ledgercore.MakeLeaseInLedgerError(txid, txl, true)
		}
	}

	return cb.lookupParent.checkDup(firstValid, lastValid, txid, txl)
}

func (cb *roundCowState) Counter() uint64 {
	return cb.lookupParent.Counter() + cb.txnCount
}

func (cb *roundCowState) GetStateProofNextRound() basics.Round {
	if cb.mods.StateProofNext != 0 {
		return cb.mods.StateProofNext
	}
	return cb.lookupParent.GetStateProofNextRound()
}

func (cb *roundCowState) BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	return cb.lookupParent.BlockHdr(r)
}

func (cb *roundCowState) GenesisHash() crypto.Digest {
	return cb.lookupParent.GenesisHash()
}

func (cb *roundCowState) GetStateProofVerificationContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	return cb.lookupParent.GetStateProofVerificationContext(stateProofLastAttestedRound)
}

func (cb *roundCowState) incTxnCount() {
	cb.txnCount++
}

func (cb *roundCowState) addTx(txn transactions.Transaction, txid transactions.Txid) {
	cb.mods.Txids[txid] = ledgercore.IncludedTransactions{LastValid: txn.LastValid, Intra: uint64(len(cb.mods.Txids))}
	cb.incTxnCount()
	if txn.Lease != [32]byte{} {
		cb.mods.AddTxLease(ledgercore.Txlease{Sender: txn.Sender, Lease: txn.Lease}, txn.LastValid)
	}
}

func (cb *roundCowState) SetStateProofNextRound(rnd basics.Round) {
	cb.mods.StateProofNext = rnd
}

func (cb *roundCowState) child(hint int) *roundCowState {
	ch := childPool.Get().(*roundCowState)
	ch.lookupParent = cb
	ch.commitParent = cb
	ch.proto = cb.proto
	ch.mods.PopulateStateDelta(cb.mods.Hdr, cb.mods.PrevTimestamp, hint, cb.mods.StateProofNext)

	if ch.sdeltas == nil {
		ch.sdeltas = make(map[basics.Address]map[storagePtr]*storageDelta)
	}

	if cb.compatibilityMode {
		ch.compatibilityMode = cb.compatibilityMode
		if ch.compatibilityGetKeyCache == nil {
			ch.compatibilityGetKeyCache = make(map[basics.Address]map[storagePtr]uint64)
		}
	}
	return ch
}

func (cb *roundCowState) commitToParent() {
	cb.commitParent.mods.Accts.MergeAccounts(cb.mods.Accts)

	commitParentBaseIdx := uint64(len(cb.commitParent.mods.Txids))
	for txid, incTxn := range cb.mods.Txids {
		cb.commitParent.mods.Txids[txid] = ledgercore.IncludedTransactions{LastValid: incTxn.LastValid, Intra: commitParentBaseIdx + incTxn.Intra}
	}
	cb.commitParent.txnCount += cb.txnCount

	for txl, expires := range cb.mods.Txleases {
		cb.commitParent.mods.AddTxLease(txl, expires)
	}
	for cidx, delta := range cb.mods.Creatables {
		cb.commitParent.mods.AddCreatable(cidx, delta)
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
	cb.commitParent.mods.StateProofNext = cb.mods.StateProofNext

	for key, value := range cb.mods.KvMods {
		cb.commitParent.mods.AddKvMod(key, value)
	}
}

func (cb *roundCowState) modifiedAccounts() []basics.Address {
	return cb.mods.Accts.ModifiedAccounts()
}

// reset resets the roundcowstate
func (cb *roundCowState) reset() {
	cb.lookupParent = nil
	cb.commitParent = nil
	cb.proto = config.ConsensusParams{}
	cb.mods.Reset()
	cb.txnCount = 0
	maps.Clear(cb.sdeltas)
	cb.compatibilityMode = false
	maps.Clear(cb.compatibilityGetKeyCache)
	cb.prevTotals = ledgercore.AccountTotals{}
}

// recycle resets the roundcowstate and returns it to the sync.Pool
func (cb *roundCowState) recycle() {
	cb.reset()
	childPool.Put(cb)
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
