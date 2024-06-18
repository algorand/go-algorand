// Copyright (C) 2019-2024 Algorand, Inc.
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
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

// KvWrite is a low level KV db interface for writing.
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
	addr basics.Address
}

func (accountRef) AccountRefMarker() {}
func (ref accountRef) String() string {
	return fmt.Sprintf("accountRef{%s}", ref.addr.String())
}

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
	key := accountKey(addr)
	err = w.kvw.Set(key[:], raw)
	if err != nil {
		return nil, err
	}

	return accountRef{addr}, nil
}

func (w *accountsWriter) DeleteAccount(ref trackerdb.AccountRef) (rowsAffected int64, err error) {
	xref := ref.(accountRef)

	// delete account entry
	key := accountKey(xref.addr)
	err = w.kvw.Delete(key[:])
	if err != nil {
		return 0, err
	}

	return 1, nil
}

func (w *accountsWriter) UpdateAccount(ref trackerdb.AccountRef, normBalance uint64, data trackerdb.BaseAccountData) (rowsAffected int64, err error) {
	xref := ref.(accountRef)

	// overwrite account entry
	raw := protocol.Encode(&data)
	key := accountKey(xref.addr)
	err = w.kvw.Set(key[:], raw)
	if err != nil {
		return 0, err
	}

	return 1, nil
}

func (w *accountsWriter) InsertResource(acctRef trackerdb.AccountRef, aidx basics.CreatableIndex, data trackerdb.ResourcesData) (ref trackerdb.ResourceRef, err error) {
	xref := acctRef.(accountRef)

	// write resource entry
	raw := protocol.Encode(&data)
	key := resourceKey(xref.addr, aidx)
	err = w.kvw.Set(key[:], raw)
	if err != nil {
		return nil, err
	}

	return resourceRef{xref.addr, aidx}, nil
}

func (w *accountsWriter) DeleteResource(acctRef trackerdb.AccountRef, aidx basics.CreatableIndex) (rowsAffected int64, err error) {
	xref := acctRef.(accountRef)

	// delete resource entry
	key := resourceKey(xref.addr, aidx)
	err = w.kvw.Delete(key[:])
	if err != nil {
		return 0, err
	}

	return 1, nil
}

func (w *accountsWriter) UpdateResource(acctRef trackerdb.AccountRef, aidx basics.CreatableIndex, data trackerdb.ResourcesData) (rowsAffected int64, err error) {
	xref := acctRef.(accountRef)

	// update resource entry
	raw := protocol.Encode(&data)
	key := resourceKey(xref.addr, aidx)
	err = w.kvw.Set(key[:], raw)
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
	key := creatableKey(cidx)
	err = w.kvw.Set(key[:], raw)
	if err != nil {
		return
	}

	return creatableRef{cidx}, nil
}

func (w *accountsWriter) DeleteCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType) (rowsAffected int64, err error) {
	// delete creatable entry
	key := creatableKey(cidx)
	err = w.kvw.Delete(key[:])
	if err != nil {
		return 0, err
	}

	return 1, nil
}

func (w *accountsWriter) Close() {

}
