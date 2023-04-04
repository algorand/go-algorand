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

package generickv

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

// schema:
// "account"-<addr>-latest        +1 (for all accounts)
// "account"-<addr>-<round>       historical (only turned on for online

// ..
// "account"-<addr>-<round> <--- latest less than `rnd` param
// ..

// "account"-<addr>-horizon-320      (320 ago)

// # Only  for Online Accounts

// Note: think about hwo to round encode this data..

// true index, for a given round, the top N balance addresses
// "crazy thing"-<round>-<balance>-<addr>
// "crazy thing"-horizon-<size>-<addr> // value: {rnd, balance}   // cutoff points
//               2187-$500-chris
//               2188-$1000-chris
//               <------ cutoff happened here
//               2199-$5-nacho value: nil
//               2200-$35-chris <--
//               2200-$20-nacho <--
//               2202-$0-chris <-- // offline
//               2249-$10-chris <-- // online
//
// new write, just get added, new balance and the round
// we need to figure out the online/offline/online/offline thing

// # Going Online
// - Write "crazy thing"-<rnd>-<balance>-<addr>
// - you are not really online until the "online" event falls off the horizon
// - we need to write the horizon entry when this happens with the same balance as the online event

// GetRangeReverse(["crazy-horizon-*"])
//    .Map(|data| decode(data))
//    .Extend(/* this stuff below */
// GetRangeReverse(["crazy-1900-*", "crazy-2200-*"])
//    .Map(|data| decode(data))
//  ) // closing the extend
//    .SortBy(|x| x.balance)
//    .DedupBy(|x| x.addr)

// Horizon cleanup (online process)
// - Move the horizon..
//    cost here is the # of online accounts that did not change in 319 accounts and where not already in this situation last round.
// - This can be done with a GetRange before the deleting to find the latest of each
// - DeleteRange("account"-<addr>-<round value of xxx - 320>)
// this requires moving the horizon for ppl that fell off
//    ""

// # When/how do we cleanup things in the horizon?
//  - we can delete it when the latest balance older than the horizon is $0

// Option B (radicall):
//	  "really crazy"-round    -> value: "pick a tree"  data
//	  "really crazy"-round    -> value: "pick a tree"  data

type KvWrite interface {
	Set(key, value []byte) error
	Delete(key []byte) error
	DeleteRange(start, end []byte) error
}

type accountsWriter struct {
	kvw KvWrite
	kvr KvRead
}

type accountRef struct {
	addr        basics.Address
	normBalance uint64
}

func (ref accountRef) AccountRefMarker() {}

type resourceRef struct {
	addr basics.Address
	aidx basics.CreatableIndex
}

func (ref resourceRef) ResourceRefMarker() {}

type creatableRef struct {
	cidx basics.CreatableIndex
}

func (ref creatableRef) CreatableRefMarker() {}

// MakeAccountsWriter returns a kv db agnostic AccountsWriter.
// TODO: we should discuss what is the best approach for this `kvr KvRead`.
// the problem is that `OnlineAccountsDelete` requires reading and writing.
// the cleanest approach is to move that method to a separate interface, and have it only be available on 'transactions'.
// although a snapshot+batch should be able to support it too since its all reads, then writes.
func MakeAccountsWriter(kvw KvWrite, kvr KvRead) *accountsWriter {
	return &accountsWriter{kvw, kvr}
}

func (w *accountsWriter) InsertAccount(addr basics.Address, normBalance uint64, data trackerdb.BaseAccountData) (ref trackerdb.AccountRef, err error) {
	// write account entry
	raw := protocol.Encode(&data)
	err = w.kvw.Set(accountKey(addr), raw)
	if err != nil {
		return nil, err
	}

	// TODO: the normalized entry might only be needed if the account is online

	// write secondary index entry by normBalance
	err = w.kvw.Set(accountBalanceKey(normBalance, addr), []byte{})
	if err != nil {
		return nil, err
	}

	return accountRef{addr, normBalance}, nil
}

func (w *accountsWriter) DeleteAccount(ref trackerdb.AccountRef) (rowsAffected int64, err error) {
	xref := ref.(accountRef)

	// delete account entry
	err = w.kvw.Delete(accountKey(xref.addr))
	if err != nil {
		return 0, err
	}

	// delete secondary index entry by normBalance
	err = w.kvw.Delete(accountBalanceKey(xref.normBalance, xref.addr))
	if err != nil {
		return 0, err
	}

	return 1, nil
}

func (w *accountsWriter) UpdateAccount(ref trackerdb.AccountRef, normBalance uint64, data trackerdb.BaseAccountData) (rowsAffected int64, err error) {
	xref := ref.(accountRef)

	// overwrite account entry
	raw := protocol.Encode(&data)
	err = w.kvw.Set(accountKey(xref.addr), raw)
	if err != nil {
		return 0, err
	}

	// update the normBalance entry only if the value changed
	if normBalance != xref.normBalance {
		// delete *old* secondary index entry by normBalance
		// Note: we take the old value from the account ref!
		err = w.kvw.Delete(accountBalanceKey(xref.normBalance, xref.addr))
		if err != nil {
			return 0, err
		}

		// write *new* secondary index entry by normBalance
		// Note: we make sure to write the *new* value out
		err = w.kvw.Set(accountBalanceKey(normBalance, xref.addr), []byte{})
		if err != nil {
			return 0, err
		}
	}

	return 1, nil
}

func (w *accountsWriter) InsertResource(acctRef trackerdb.AccountRef, aidx basics.CreatableIndex, data trackerdb.ResourcesData) (ref trackerdb.ResourceRef, err error) {
	xref := acctRef.(accountRef)

	// write resource entry
	raw := protocol.Encode(&data)
	err = w.kvw.Set(resourceKey(xref.addr, aidx), raw)
	if err != nil {
		return nil, err
	}

	return resourceRef{xref.addr, aidx}, nil
}

func (w *accountsWriter) DeleteResource(acctRef trackerdb.AccountRef, aidx basics.CreatableIndex) (rowsAffected int64, err error) {
	xref := acctRef.(accountRef)

	// delete resource entry
	err = w.kvw.Delete(resourceKey(xref.addr, aidx))
	if err != nil {
		return 0, err
	}

	return 1, nil
}

func (w *accountsWriter) UpdateResource(acctRef trackerdb.AccountRef, aidx basics.CreatableIndex, data trackerdb.ResourcesData) (rowsAffected int64, err error) {
	xref := acctRef.(accountRef)

	// update resource entry
	raw := protocol.Encode(&data)
	err = w.kvw.Set(resourceKey(xref.addr, aidx), raw)
	if err != nil {
		return 0, err
	}

	return 1, nil
}

func (w *accountsWriter) UpsertKvPair(key string, value []byte) error {
	// upsert kv entry
	err := w.kvw.Set(appKvKey(key), value)
	if err != nil {
		return err
	}

	return nil
}

func (w *accountsWriter) DeleteKvPair(key string) error {
	// delete kv entry
	err := w.kvw.Delete(appKvKey(key))
	if err != nil {
		return err
	}

	return nil
}

type creatableEntry struct {
	_struct     struct{} `codec:",omitempty,omitemptyarray"`
	Ctype       basics.CreatableType
	CreatorAddr []byte
}

func (w *accountsWriter) InsertCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType, creator []byte) (ref trackerdb.CreatableRef, err error) {
	// insert creatable entry
	raw := protocol.Encode(&creatableEntry{Ctype: ctype, CreatorAddr: creator})
	err = w.kvw.Set(creatableKey(cidx), raw)
	if err != nil {
		return
	}

	return creatableRef{cidx}, nil
}

func (w *accountsWriter) DeleteCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType) (rowsAffected int64, err error) {
	// delete creatable entry
	err = w.kvw.Delete(creatableKey(cidx))
	if err != nil {
		return 0, err
	}

	return 1, nil
}

func (w *accountsWriter) Close() {

}
