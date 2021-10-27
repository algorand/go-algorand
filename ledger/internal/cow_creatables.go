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
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/apply"
)

func (cs *roundCowState) TotalAppParams(creator basics.Address) (int, error) {
	acct, err := cs.lookup(creator)
	if err != nil {
		return 0, err
	}
	return len(acct.AppParams), nil
}
func (cs *roundCowState) TotalAppLocalState(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return len(acct.AppLocalStates), nil
}
func (cs *roundCowState) TotalAssetHolding(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return len(acct.Assets), nil
}
func (cs *roundCowState) TotalAssetParams(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return len(acct.AssetParams), nil
}

func (cs *roundCowState) GetAppParams(creator basics.Address, aidx basics.AppIndex) (params basics.AppParams, err error) {
	record, err := cs.lookup(creator)
	if err != nil {
		return
	}
	params, ok := record.AppParams[aidx]
	if !ok {
		err = apply.ErrAppNotFound
		return
	}
	return
}
func (cs *roundCowState) GetAppLocalState(addr basics.Address, aidx basics.AppIndex) (state basics.AppLocalState, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	state, ok := acct.AppLocalStates[aidx]
	if !ok {
		err = apply.ErrAppNotFound
		return
	}
	return
}
func (cs *roundCowState) GetAssetHolding(addr basics.Address, aidx basics.AssetIndex) (holding basics.AssetHolding, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	holding, ok := acct.Assets[aidx]
	if !ok {
		err = apply.ErrAssetNotFound
		return
	}
	return
}
func (cs *roundCowState) GetAssetParams(addr basics.Address, aidx basics.AssetIndex) (params basics.AssetParams, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	params, ok := acct.AssetParams[aidx]
	if !ok {
		err = apply.ErrAssetNotFound
		return
	}
	return
}

func (cs *roundCowState) PutAppParams(addr basics.Address, aidx basics.AppIndex, params basics.AppParams) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	acct.AppParams[aidx] = params
	return cs.Put(addr, acct)
}
func (cs *roundCowState) PutAppLocalState(addr basics.Address, aidx basics.AppIndex, state basics.AppLocalState) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	acct.AppLocalStates[aidx] = state
	return cs.Put(addr, acct)
}
func (cs *roundCowState) PutAssetHolding(addr basics.Address, aidx basics.AssetIndex, data basics.AssetHolding) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	acct.Assets[aidx] = data
	return cs.Put(addr, acct)
}
func (cs *roundCowState) PutAssetParams(addr basics.Address, aidx basics.AssetIndex, data basics.AssetParams) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	acct.AssetParams[aidx] = data
	return cs.Put(addr, acct)
}

func (cs *roundCowState) DeleteAppParams(addr basics.Address, aidx basics.AppIndex) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	delete(acct.AppParams, aidx)
	return cs.Put(addr, acct)
}
func (cs *roundCowState) DeleteAppLocalState(addr basics.Address, aidx basics.AppIndex) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	delete(acct.AppLocalStates, aidx)
	return cs.Put(addr, acct)
}
func (cs *roundCowState) DeleteAssetHolding(addr basics.Address, aidx basics.AssetIndex) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	delete(acct.Assets, aidx)
	return cs.Put(addr, acct)
}
func (cs *roundCowState) DeleteAssetParams(addr basics.Address, aidx basics.AssetIndex) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	delete(acct.AssetParams, aidx)
	return cs.Put(addr, acct)
}

func (cs *roundCowState) CheckAppLocalState(addr basics.Address, aidx basics.AppIndex) (ok bool, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	_, ok = acct.AppLocalStates[aidx]
	return
}

func (cs *roundCowState) CheckAssetParams(addr basics.Address, aidx basics.AssetIndex) (ok bool, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	_, ok = acct.AssetParams[aidx]
	return
}
