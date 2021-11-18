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
)

// These functions ensure roundCowState satisfies the methods for
// accessing asset and app data in the apply.Balances interface.

func (cs *roundCowState) CountAppParams(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return len(acct.AppParams), nil
}
func (cs *roundCowState) CountAppLocalState(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return len(acct.AppLocalStates), nil
}
func (cs *roundCowState) CountAssetHolding(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return len(acct.Assets), nil
}
func (cs *roundCowState) CountAssetParams(addr basics.Address) (int, error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return 0, err
	}
	return len(acct.AssetParams), nil
}

func (cs *roundCowState) GetAppParams(addr basics.Address, aidx basics.AppIndex) (ret basics.AppParams, ok bool, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	ret, ok = acct.AppParams[aidx]
	return
}
func (cs *roundCowState) GetAppLocalState(addr basics.Address, aidx basics.AppIndex) (ret basics.AppLocalState, ok bool, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	ret, ok = acct.AppLocalStates[aidx]
	return
}
func (cs *roundCowState) GetAssetHolding(addr basics.Address, aidx basics.AssetIndex) (ret basics.AssetHolding, ok bool, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	ret, ok = acct.Assets[aidx]
	return
}
func (cs *roundCowState) GetAssetParams(addr basics.Address, aidx basics.AssetIndex) (ret basics.AssetParams, ok bool, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	ret, ok = acct.AssetParams[aidx]
	return
}

func (cs *roundCowState) PutAppParams(addr basics.Address, aidx basics.AppIndex, params basics.AppParams) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	m := make(map[basics.AppIndex]basics.AppParams, len(acct.AppParams))
	for k, v := range acct.AppParams {
		m[k] = v
	}
	m[aidx] = params
	acct.AppParams = m
	return cs.putAccount(addr, acct)
}
func (cs *roundCowState) PutAppLocalState(addr basics.Address, aidx basics.AppIndex, state basics.AppLocalState) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	m := make(map[basics.AppIndex]basics.AppLocalState, len(acct.AppLocalStates))
	for k, v := range acct.AppLocalStates {
		m[k] = v
	}
	m[aidx] = state
	acct.AppLocalStates = m
	return cs.putAccount(addr, acct)
}
func (cs *roundCowState) PutAssetHolding(addr basics.Address, aidx basics.AssetIndex, data basics.AssetHolding) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	m := make(map[basics.AssetIndex]basics.AssetHolding, len(acct.Assets))
	for k, v := range acct.Assets {
		m[k] = v
	}
	m[aidx] = data
	acct.Assets = m
	return cs.putAccount(addr, acct)
}
func (cs *roundCowState) PutAssetParams(addr basics.Address, aidx basics.AssetIndex, data basics.AssetParams) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	m := make(map[basics.AssetIndex]basics.AssetParams, len(acct.AssetParams))
	for k, v := range acct.AssetParams {
		m[k] = v
	}
	m[aidx] = data
	acct.AssetParams = m
	return cs.putAccount(addr, acct)
}

func (cs *roundCowState) DeleteAppParams(addr basics.Address, aidx basics.AppIndex) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	m := make(map[basics.AppIndex]basics.AppParams, len(acct.AppParams))
	for k, v := range acct.AppParams {
		m[k] = v
	}
	delete(m, aidx)
	acct.AppParams = m
	return cs.putAccount(addr, acct)
}
func (cs *roundCowState) DeleteAppLocalState(addr basics.Address, aidx basics.AppIndex) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	m := make(map[basics.AppIndex]basics.AppLocalState, len(acct.AppLocalStates))
	for k, v := range acct.AppLocalStates {
		m[k] = v
	}
	delete(m, aidx)
	acct.AppLocalStates = m
	return cs.putAccount(addr, acct)
}
func (cs *roundCowState) DeleteAssetHolding(addr basics.Address, aidx basics.AssetIndex) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	m := make(map[basics.AssetIndex]basics.AssetHolding, len(acct.Assets))
	for k, v := range acct.Assets {
		m[k] = v
	}
	delete(m, aidx)
	acct.Assets = m
	return cs.putAccount(addr, acct)
}
func (cs *roundCowState) DeleteAssetParams(addr basics.Address, aidx basics.AssetIndex) error {
	acct, err := cs.lookup(addr)
	if err != nil {
		return err
	}
	m := make(map[basics.AssetIndex]basics.AssetParams, len(acct.AssetParams))
	for k, v := range acct.AssetParams {
		m[k] = v
	}
	delete(m, aidx)
	acct.AssetParams = m
	return cs.putAccount(addr, acct)
}

func (cs *roundCowState) HasAppLocalState(addr basics.Address, aidx basics.AppIndex) (ok bool, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	_, ok = acct.AppLocalStates[aidx]
	return
}

func (cs *roundCowState) HasAssetParams(addr basics.Address, aidx basics.AssetIndex) (ok bool, err error) {
	acct, err := cs.lookup(addr)
	if err != nil {
		return
	}
	_, ok = acct.AssetParams[aidx]
	return
}
