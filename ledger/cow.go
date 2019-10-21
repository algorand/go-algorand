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
	"fmt"

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
	isDup(basics.Round, transactions.Txid, txlease) (bool, error)
	txnCounter() uint64
	GetAssetCreator(assetIdx basics.AssetIndex) (basics.Address, error)
}

type roundCowState struct {
	lookupParent roundCowParent
	commitParent *roundCowState
	proto        config.ConsensusParams
	mods         stateDelta
}

type stateDelta struct {
	// modified accounts
	accts map[basics.Address]accountDelta

	// new Txids for the txtail and TxnCounter
	txids map[transactions.Txid]struct{}

	// new txleases for the txtail mapped to expiration
	txleases map[txlease]basics.Round

	// new assets creator lookup table
	assetCreators map[basics.AssetIndex]basics.Address

	// assets queued for deletion
	deletedAssets map[basics.AssetIndex]bool

	// new block header; read-only
	hdr *bookkeeping.BlockHeader
}

func makeRoundCowState(b roundCowParent, hdr bookkeeping.BlockHeader) *roundCowState {
	return &roundCowState{
		lookupParent: b,
		commitParent: nil,
		proto:        config.Consensus[hdr.CurrentProtocol],
		mods: stateDelta{
			accts:         make(map[basics.Address]accountDelta),
			txids:         make(map[transactions.Txid]struct{}),
			txleases:      make(map[txlease]basics.Round),
			assetCreators: make(map[basics.AssetIndex]basics.Address),
			deletedAssets: make(map[basics.AssetIndex]bool),
			hdr:           &hdr,
		},
	}
}

func (cb *roundCowState) rewardsLevel() uint64 {
	return cb.mods.hdr.RewardsLevel
}

func (cb *roundCowState) GetAssetCreator(aidx basics.AssetIndex) (basics.Address, error) {
	c, ok := cb.mods.assetCreators[aidx]
	if ok {
		return c, nil
	}
	_, ok = cb.mods.deletedAssets[aidx]
	if ok {
		return basics.Address{}, fmt.Errorf("asset %v has been deleted", aidx)
	}
	return cb.lookupParent.GetAssetCreator(aidx)
}

func (cb *roundCowState) lookup(addr basics.Address) (data basics.AccountData, err error) {
	d, ok := cb.mods.accts[addr]
	if ok {
		return d.new, nil
	}

	return cb.lookupParent.lookup(addr)
}

func (cb *roundCowState) isDup(firstValid basics.Round, txid transactions.Txid, txl txlease) (bool, error) {
	_, present := cb.mods.txids[txid]
	if present {
		return true, nil
	}

	if cb.proto.SupportTransactionLeases && (txl.lease != [32]byte{}) {
		expires, ok := cb.mods.txleases[txl]
		if ok && cb.mods.hdr.Round <= expires {
			return true, nil
		}
	}

	return cb.lookupParent.isDup(firstValid, txid, txl)
}

func (cb *roundCowState) txnCounter() uint64 {
	return cb.lookupParent.txnCounter() + uint64(len(cb.mods.txids))
}

func (cb *roundCowState) put(addr basics.Address, old basics.AccountData, new basics.AccountData) {
	prev, present := cb.mods.accts[addr]
	if present {
		cb.mods.accts[addr] = accountDelta{old: prev.old, new: new}
	} else {
		cb.mods.accts[addr] = accountDelta{old: old, new: new}
	}

	// Get which asset indexes were created and deleted, and update state
	// to reflect that
	created, deleted := getChangedAssetIndices(accountDelta{old: old, new: new})
	for _, aidx := range created {
		cb.mods.assetCreators[aidx] = addr
	}
	for _, aidx := range deleted {
		if _, ok := cb.mods.assetCreators[aidx]; ok {
			delete(cb.mods.assetCreators, aidx)
			break
		}
		cb.mods.deletedAssets[aidx] = true
	}
}

func (cb *roundCowState) addTx(txn transactions.Transaction) {
	cb.mods.txids[txn.ID()] = struct{}{}
	cb.mods.txleases[txlease{sender: txn.Sender, lease: txn.Lease}] = txn.LastValid
}

func (cb *roundCowState) child() *roundCowState {
	return &roundCowState{
		lookupParent: cb,
		commitParent: cb,
		proto:        cb.proto,
		mods: stateDelta{
			accts:         make(map[basics.Address]accountDelta),
			txids:         make(map[transactions.Txid]struct{}),
			txleases:      make(map[txlease]basics.Round),
			assetCreators: make(map[basics.AssetIndex]basics.Address),
			deletedAssets: make(map[basics.AssetIndex]bool),
			hdr:           cb.mods.hdr,
		},
	}
}

func (cb *roundCowState) commitToParent() {
	for addr, delta := range cb.mods.accts {
		prev, present := cb.commitParent.mods.accts[addr]
		if present {
			cb.commitParent.mods.accts[addr] = accountDelta{
				old: prev.old,
				new: delta.new,
			}
		} else {
			cb.commitParent.mods.accts[addr] = delta
		}
	}

	for txid := range cb.mods.txids {
		cb.commitParent.mods.txids[txid] = struct{}{}
	}
	for txl, expires := range cb.mods.txleases {
		cb.commitParent.mods.txleases[txl] = expires
	}
	for aidx, creator := range cb.mods.assetCreators {
		cb.commitParent.mods.assetCreators[aidx] = creator
	}
	for aidx := range cb.mods.deletedAssets {
		cb.commitParent.mods.deletedAssets[aidx] = true
	}
}

func (cb *roundCowState) modifiedAccounts() []basics.Address {
	var res []basics.Address
	for addr := range cb.mods.accts {
		res = append(res, addr)
	}
	return res
}
