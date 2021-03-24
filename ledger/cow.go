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
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
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
	getKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) (basics.TealValue, bool, error)
}

type roundCowState struct {
	lookupParent roundCowParent
	commitParent *roundCowState
	proto        config.ConsensusParams
	mods         ledgercore.StateDelta

	// storage deltas populated as side effects of AppCall transaction
	// 1. Opt-in/Close actions (see Allocate/Deallocate)
	// 2. Stateful TEAL evaluation (see SetKey/DelKey)
	// must be incorporated into mods.accts before passing deltas forward
	sdeltas map[basics.Address]map[storagePtr]*storageDelta

	isLeaf                   bool
	childState               *roundCowState
	includedTransactions     [16]txnLeaseValidityPair
	usedIncludedTransactions int
}
type txnLeaseValidityPair struct {
	txid      transactions.Txid
	lastValid basics.Round
	lease     ledgercore.Txlease
}

func makeRoundCowState(b roundCowParent, hdr bookkeeping.BlockHeader, prevTimestamp int64, hint int) *roundCowState {
	rcs := &roundCowState{
		lookupParent: b,
		commitParent: nil,
		proto:        config.Consensus[hdr.CurrentProtocol],
		mods:         ledgercore.MakeStateDelta(&hdr, prevTimestamp, hint, 0),
		sdeltas:      make(map[basics.Address]map[storagePtr]*storageDelta),
		isLeaf:       false,
	}
	rcs.childState = &roundCowState{
		isLeaf:       true,
		lookupParent: rcs,
		commitParent: rcs,
		proto:        config.Consensus[hdr.CurrentProtocol],
	}
	return rcs
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
	if cb.isLeaf {
		for txIdx := 0; txIdx < cb.usedIncludedTransactions; txIdx++ {
			if cb.includedTransactions[txIdx].txid == txid {
				return &ledgercore.TransactionInLedgerError{Txid: txid}
			}
		}
		if cb.proto.SupportTransactionLeases && (txl.Lease != [32]byte{}) {
			for txIdx := 0; txIdx < cb.usedIncludedTransactions; txIdx++ {
				if cb.includedTransactions[txIdx].lease == txl {
					if cb.mods.Hdr.Round <= cb.includedTransactions[txIdx].lastValid {
						return ledgercore.MakeLeaseInLedgerError(txid, txl)
					}
				}
			}
		}
		return cb.lookupParent.checkDup(firstValid, lastValid, txid, txl)
	}

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
	return cb.lookupParent.txnCounter() + uint64(len(cb.mods.Txids))
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

func (cb *roundCowState) put(addr basics.Address, new basics.AccountData, newCreatable *basics.CreatableLocator, deletedCreatable *basics.CreatableLocator) {
	cb.mods.Accts.Upsert(addr, new)

	if newCreatable != nil {
		cb.mods.Creatables[newCreatable.Index] = ledgercore.ModifiedCreatable{
			Ctype:   newCreatable.Type,
			Creator: newCreatable.Creator,
			Created: true,
		}
	}

	if deletedCreatable != nil {
		cb.mods.Creatables[deletedCreatable.Index] = ledgercore.ModifiedCreatable{
			Ctype:   deletedCreatable.Type,
			Creator: deletedCreatable.Creator,
			Created: false,
		}
	}
}

func (cb *roundCowState) addTx(txn transactions.Transaction, txid transactions.Txid) {
	if cb.isLeaf {
		cb.includedTransactions[cb.usedIncludedTransactions] =
			txnLeaseValidityPair{
				txid:      txid,
				lastValid: txn.LastValid,
				lease:     ledgercore.Txlease{Sender: txn.Sender, Lease: txn.Lease},
			}
		cb.usedIncludedTransactions++
		return
	}
	cb.mods.Txids[txid] = txn.LastValid
	cb.mods.Txleases[ledgercore.Txlease{Sender: txn.Sender, Lease: txn.Lease}] = txn.LastValid
}

func (cb *roundCowState) setCompactCertNext(rnd basics.Round) {
	cb.mods.CompactCertNext = rnd
}

func (cb *roundCowState) child() *roundCowState {
	// reset child
	if !cb.isLeaf {
		cb.childState.mods = ledgercore.MakeChildStateDelta(cb.mods.Hdr, cb.mods.PrevTimestamp, 1, 0)
		cb.childState.sdeltas = make(map[basics.Address]map[storagePtr]*storageDelta)
		cb.childState.usedIncludedTransactions = 0
		cb.childState.isLeaf = true
		return cb.childState
	}
	panic(nil)
}

func (cb *roundCowState) fullChild() *roundCowState {
	if cb.isLeaf {
		cb.isLeaf = false
		// perform conversion.
		mods := ledgercore.MakeStateDelta(cb.mods.Hdr, cb.mods.PrevTimestamp, 1, 0)
		cb.mods.Txids = mods.Txids
		cb.mods.Txleases = mods.Txleases
		for txIdx := 0; txIdx < cb.usedIncludedTransactions; txIdx++ {
			cb.mods.Txids[cb.includedTransactions[txIdx].txid] = cb.includedTransactions[txIdx].lastValid
			cb.mods.Txleases[cb.includedTransactions[txIdx].lease] = cb.includedTransactions[txIdx].lastValid
		}
	}
	return &roundCowState{
		lookupParent: cb,
		commitParent: cb,
		proto:        cb.proto,
		mods:         ledgercore.MakeStateDelta(cb.mods.Hdr, cb.mods.PrevTimestamp, 1, cb.mods.CompactCertNext),
		sdeltas:      make(map[basics.Address]map[storagePtr]*storageDelta),
	}
}

func (cb *roundCowState) commitToParent() {
	cb.commitParent.mods.Accts.MergeAccounts(cb.mods.Accts)

	if cb.isLeaf {
		for txIdx := 0; txIdx < cb.usedIncludedTransactions; txIdx++ {
			cb.commitParent.mods.Txids[cb.includedTransactions[txIdx].txid] = cb.includedTransactions[txIdx].lastValid
			cb.commitParent.mods.Txleases[cb.includedTransactions[txIdx].lease] = cb.includedTransactions[txIdx].lastValid
		}
	} else {
		for txid, lv := range cb.mods.Txids {
			cb.commitParent.mods.Txids[txid] = lv
		}
		for txl, expires := range cb.mods.Txleases {
			cb.commitParent.mods.Txleases[txl] = expires
		}
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
}

func (cb *roundCowState) modifiedAccounts() []basics.Address {
	return cb.mods.Accts.ModifiedAccounts()
}
