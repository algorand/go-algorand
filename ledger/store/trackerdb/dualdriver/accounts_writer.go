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

package dualdriver

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
)

type accountsWriter struct {
	primary   trackerdb.AccountsWriter
	secondary trackerdb.AccountsWriter
}

// Close implements trackerdb.AccountsWriter
func (aw *accountsWriter) Close() {
	aw.primary.Close()
	aw.secondary.Close()
}

// DeleteAccount implements trackerdb.AccountsWriter
func (aw *accountsWriter) DeleteAccount(accRef trackerdb.AccountRef) (rowsAffected int64, err error) {
	// parse ref
	xRef := accRef.(accountRef)
	// Note: rowsAffected is ignored because it is not possible to determine this correctly in all engines
	rowsAffectedP, errP := aw.primary.DeleteAccount(xRef.primary)
	_, errS := aw.secondary.DeleteAccount(xRef.secondary)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	return rowsAffectedP, nil
}

// DeleteCreatable implements trackerdb.AccountsWriter
func (aw *accountsWriter) DeleteCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType) (rowsAffected int64, err error) {
	// Note: rowsAffected is ignored because it is not possible to determine this correctly in all engines
	rowsAffectedP, errP := aw.primary.DeleteCreatable(cidx, ctype)
	_, errS := aw.secondary.DeleteCreatable(cidx, ctype)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	return rowsAffectedP, nil
}

// DeleteKvPair implements trackerdb.AccountsWriter
func (aw *accountsWriter) DeleteKvPair(key string) error {
	errP := aw.primary.DeleteKvPair(key)
	errS := aw.secondary.DeleteKvPair(key)
	// coalesce errors
	return coalesceErrors(errP, errS)
}

// DeleteResource implements trackerdb.AccountsWriter
func (aw *accountsWriter) DeleteResource(accRef trackerdb.AccountRef, aidx basics.CreatableIndex) (rowsAffected int64, err error) {
	// parse ref
	xRef := accRef.(accountRef)
	// Note: rowsAffected is ignored because it is not possible to determine this correctly in all engines
	rowsAffectedP, errP := aw.primary.DeleteResource(xRef.primary, aidx)
	_, errS := aw.secondary.DeleteResource(xRef.secondary, aidx)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	return rowsAffectedP, nil
}

// InsertAccount implements trackerdb.AccountsWriter
func (aw *accountsWriter) InsertAccount(addr basics.Address, normBalance uint64, data trackerdb.BaseAccountData) (ref trackerdb.AccountRef, err error) {
	// Note: we do not check the refs since they are internal to the engines and wont match
	refP, errP := aw.primary.InsertAccount(addr, normBalance, data)
	refS, errS := aw.secondary.InsertAccount(addr, normBalance, data)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// return ref
	return accountRef{refP, refS}, nil
}

// InsertCreatable implements trackerdb.AccountsWriter
func (aw *accountsWriter) InsertCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType, creator []byte) (ref trackerdb.CreatableRef, err error) {
	// Note: we do not check the refs since they are internal to the engines and wont match
	refP, errP := aw.primary.InsertCreatable(cidx, ctype, creator)
	refS, errS := aw.secondary.InsertCreatable(cidx, ctype, creator)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// return ref
	return creatableRef{refP, refS}, nil
}

// InsertResource implements trackerdb.AccountsWriter
func (aw *accountsWriter) InsertResource(accRef trackerdb.AccountRef, aidx basics.CreatableIndex, data trackerdb.ResourcesData) (ref trackerdb.ResourceRef, err error) {
	// parse ref
	xRef := accRef.(accountRef)
	// Note: we do not check the refs since they are internal to the engines and wont match
	refP, errP := aw.primary.InsertResource(xRef.primary, aidx, data)
	refS, errS := aw.secondary.InsertResource(xRef.secondary, aidx, data)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// return ref
	return resourceRef{refP, refS}, nil
}

// UpdateAccount implements trackerdb.AccountsWriter
func (aw *accountsWriter) UpdateAccount(accRef trackerdb.AccountRef, normBalance uint64, data trackerdb.BaseAccountData) (rowsAffected int64, err error) {
	// parse ref
	xRef := accRef.(accountRef)
	// Note: rowsAffected is ignored because it is not possible to determine this correctly in all engines
	rowsAffectedP, errP := aw.primary.UpdateAccount(xRef.primary, normBalance, data)
	_, errS := aw.secondary.UpdateAccount(xRef.secondary, normBalance, data)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	return rowsAffectedP, nil
}

// UpdateResource implements trackerdb.AccountsWriter
func (aw *accountsWriter) UpdateResource(accRef trackerdb.AccountRef, aidx basics.CreatableIndex, data trackerdb.ResourcesData) (rowsAffected int64, err error) {
	// parse ref
	xRef := accRef.(accountRef)
	// Note: rowsAffected is ignored because it is not possible to determine this correctly in all engines
	rowsAffectedP, errP := aw.primary.UpdateResource(xRef.primary, aidx, data)
	_, errS := aw.secondary.UpdateResource(xRef.secondary, aidx, data)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	return rowsAffectedP, nil
}

// UpsertKvPair implements trackerdb.AccountsWriter
func (aw *accountsWriter) UpsertKvPair(key string, value []byte) error {
	errP := aw.primary.UpsertKvPair(key, value)
	errS := aw.secondary.UpsertKvPair(key, value)
	// coalesce errors
	return coalesceErrors(errP, errS)
}
