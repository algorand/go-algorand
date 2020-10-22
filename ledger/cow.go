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
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
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
	isDup(basics.Round, basics.Round, transactions.Txid, txlease) (bool, error)
	txnCounter() uint64
	getCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error)
	compactCertLast() basics.Round
	blockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error)
	getStorageCounts(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error)
	// note: getStorageLimits is redundant with the other methods
	// and is provided to optimize state schema lookups
	getStorageLimits(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error)
	Allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error)
	GetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) (basics.TealValue, bool, error)
}

type roundCowState struct {
	lookupParent roundCowParent
	commitParent *roundCowState
	proto        config.ConsensusParams
	mods         StateDelta
}

type storagePtr struct {
	aidx   basics.AppIndex
	global bool
}

type addrApp struct {
	addr   basics.Address
	aidx   basics.AppIndex
	global bool
}

// miniAccountDelta is like accountDelta, but it omits key-value stores.
type miniAccountDelta struct {
	old basics.AccountData
	new basics.AccountData
}

// StateDelta describes the delta between a given round to the previous round
type StateDelta struct {
	// modified accounts
	accts map[basics.Address]miniAccountDelta

	// new Txids for the txtail and TxnCounter, mapped to txn.LastValid
	Txids map[transactions.Txid]basics.Round

	// new txleases for the txtail mapped to expiration
	txleases map[txlease]basics.Round

	// new creatables creator lookup table
	creatables map[basics.CreatableIndex]modifiedCreatable

	// new block header; read-only
	hdr *bookkeeping.BlockHeader

	// last round for which we have seen a compact cert.
	// zero if no compact cert seen.
	compactCertSeen basics.Round

	// previous block timestamp
	prevTimestamp int64

	// storage deltas
	sdeltas map[basics.Address]map[storagePtr]*storageDelta
}

func makeRoundCowState(b roundCowParent, hdr bookkeeping.BlockHeader, prevTimestamp int64) *roundCowState {
	return &roundCowState{
		lookupParent: b,
		commitParent: nil,
		proto:        config.Consensus[hdr.CurrentProtocol],
		mods: StateDelta{
			accts:         make(map[basics.Address]miniAccountDelta),
			Txids:         make(map[transactions.Txid]basics.Round),
			txleases:      make(map[txlease]basics.Round),
			creatables:    make(map[basics.CreatableIndex]modifiedCreatable),
			sdeltas:       make(map[basics.Address]map[storagePtr]*storageDelta),
			hdr:           &hdr,
			prevTimestamp: prevTimestamp,
		},
	}
}

func (cb *roundCowState) rewardsLevel() uint64 {
	return cb.mods.hdr.RewardsLevel
}

func (cb *roundCowState) getCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (creator basics.Address, ok bool, err error) {
	delta, ok := cb.mods.creatables[cidx]
	if ok {
		if delta.created && delta.ctype == ctype {
			return delta.creator, true, nil
		}
		return basics.Address{}, false, nil
	}
	return cb.lookupParent.getCreator(cidx, ctype)
}

func (cb *roundCowState) lookup(addr basics.Address) (data basics.AccountData, err error) {
	d, ok := cb.mods.accts[addr]
	if ok {
		return d.new, nil
	}

	return cb.lookupParent.lookup(addr)
}

func (cb *roundCowState) isDup(firstValid, lastValid basics.Round, txid transactions.Txid, txl txlease) (bool, error) {
	_, present := cb.mods.Txids[txid]
	if present {
		return true, nil
	}

	if cb.proto.SupportTransactionLeases && (txl.lease != [32]byte{}) {
		expires, ok := cb.mods.txleases[txl]
		if ok && cb.mods.hdr.Round <= expires {
			return true, nil
		}
	}

	return cb.lookupParent.isDup(firstValid, lastValid, txid, txl)
}

func (cb *roundCowState) txnCounter() uint64 {
	return cb.lookupParent.txnCounter() + uint64(len(cb.mods.Txids))
}

func (cb *roundCowState) compactCertLast() basics.Round {
	if cb.mods.compactCertSeen != 0 {
		return cb.mods.compactCertSeen
	}
	return cb.lookupParent.compactCertLast()
}

func (cb *roundCowState) blockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	return cb.lookupParent.blockHdr(r)
}

func (cb *roundCowState) put(addr basics.Address, old basics.AccountData, new basics.AccountData, newCreatable *basics.CreatableLocator, deletedCreatable *basics.CreatableLocator) {
	prev, present := cb.mods.accts[addr]
	if present {
		cb.mods.accts[addr] = miniAccountDelta{old: prev.old, new: new}
	} else {
		cb.mods.accts[addr] = miniAccountDelta{old: old, new: new}
	}

	if newCreatable != nil {
		cb.mods.creatables[newCreatable.Index] = modifiedCreatable{
			ctype:   newCreatable.Type,
			creator: newCreatable.Creator,
			created: true,
		}
	}

	if deletedCreatable != nil {
		cb.mods.creatables[deletedCreatable.Index] = modifiedCreatable{
			ctype:   deletedCreatable.Type,
			creator: deletedCreatable.Creator,
			created: false,
		}
	}
}

func (cb *roundCowState) addTx(txn transactions.Transaction, txid transactions.Txid) {
	cb.mods.Txids[txid] = txn.LastValid
	cb.mods.txleases[txlease{sender: txn.Sender, lease: txn.Lease}] = txn.LastValid
}

func (cb *roundCowState) sawCompactCert(rnd basics.Round) {
	cb.mods.compactCertSeen = rnd
}

func (cb *roundCowState) child() *roundCowState {
	return &roundCowState{
		lookupParent: cb,
		commitParent: cb,
		proto:        cb.proto,
		mods: StateDelta{
			accts:         make(map[basics.Address]miniAccountDelta),
			Txids:         make(map[transactions.Txid]basics.Round),
			txleases:      make(map[txlease]basics.Round),
			creatables:    make(map[basics.CreatableIndex]modifiedCreatable),
			sdeltas:       make(map[basics.Address]map[storagePtr]*storageDelta),
			hdr:           cb.mods.hdr,
			prevTimestamp: cb.mods.prevTimestamp,
		},
	}
}

func (cb *roundCowState) commitToParent() {
	for addr, delta := range cb.mods.accts {
		prev, present := cb.commitParent.mods.accts[addr]
		if present {
			cb.commitParent.mods.accts[addr] = miniAccountDelta{
				old: prev.old,
				new: delta.new,
			}
		} else {
			cb.commitParent.mods.accts[addr] = delta
		}
	}

	for txid, lv := range cb.mods.Txids {
		cb.commitParent.mods.Txids[txid] = lv
	}
	for txl, expires := range cb.mods.txleases {
		cb.commitParent.mods.txleases[txl] = expires
	}
	for cidx, delta := range cb.mods.creatables {
		cb.commitParent.mods.creatables[cidx] = delta
	}
	for addr, smod := range cb.mods.sdeltas {
		for aapp, nsd := range smod {
			lsd, ok := cb.commitParent.mods.sdeltas[addr][aapp]
			if ok {
				lsd.applyChild(nsd)
			} else {
				_, ok = cb.commitParent.mods.sdeltas[addr]
				if !ok {
					cb.commitParent.mods.sdeltas[addr] = make(map[storagePtr]*storageDelta)
				}
				cb.commitParent.mods.sdeltas[addr][aapp] = nsd
			}
		}
	}
	cb.commitParent.mods.compactCertSeen = cb.mods.compactCertSeen
}

func (cb *roundCowState) modifiedAccounts() []basics.Address {
	res := make([]basics.Address, len(cb.mods.accts))
	i := 0
	for addr := range cb.mods.accts {
		res[i] = addr
		i++
	}
	return res
}
