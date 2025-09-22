// Copyright (C) 2019-2025 Algorand, Inc.
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
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// These functions ensure roundCowState satisfies the methods for
// accessing asset and app data in the apply.Balances interface.

func (cs *roundCowState) GetAppParams(addr basics.Address, aidx basics.AppIndex) (ret basics.AppParams, ok bool, err error) {
	var d ledgercore.AppParamsDelta
	d, ok, err = cs.lookupAppParams(addr, aidx, false)
	if err != nil || !ok {
		return
	}
	if d.Deleted {
		ok = false
		return
	}
	if d.Params == nil {
		// found and not deleled => must exist. Err if not
		err = fmt.Errorf("GetAppParams got a nil entry for (%s, %d): %p, %v", addr.String(), aidx, d.Params, d.Deleted)
	}
	ret = *d.Params
	return
}

func (cs *roundCowState) GetAppLocalState(addr basics.Address, aidx basics.AppIndex) (ret basics.AppLocalState, ok bool, err error) {
	var d ledgercore.AppLocalStateDelta
	d, ok, err = cs.lookupAppLocalState(addr, aidx, false)
	if err != nil || !ok {
		return
	}
	if d.Deleted {
		ok = false
		return
	}
	if d.LocalState == nil {
		// found and not deleled => must exist. Err if not
		err = fmt.Errorf("GetAppLocalState got a nil entry for (%s, %d): %p, %v", addr.String(), aidx, d.LocalState, d.Deleted)
	}
	ret = *d.LocalState
	return
}

func (cs *roundCowState) GetAssetHolding(addr basics.Address, aidx basics.AssetIndex) (ret basics.AssetHolding, ok bool, err error) {
	var d ledgercore.AssetHoldingDelta
	d, ok, err = cs.lookupAssetHolding(addr, aidx, false)
	if err != nil || !ok {
		return
	}
	if d.Deleted {
		ok = false
		return
	}
	if d.Holding == nil {
		// found and not deleted => must exist. Err if not
		err = fmt.Errorf("GetAssetHolding got a nil entry for (%s, %d): %p, %v", addr, aidx, d.Holding, d.Deleted)
	}
	ret = *d.Holding
	return
}

func (cs *roundCowState) GetAssetParams(addr basics.Address, aidx basics.AssetIndex) (ret basics.AssetParams, ok bool, err error) {
	var d ledgercore.AssetParamsDelta
	d, ok, err = cs.lookupAssetParams(addr, aidx, false)
	if err != nil || !ok {
		return
	}
	if d.Deleted {
		ok = false
		return
	}
	if d.Params == nil {
		// found and not deleted => must exist. Err if not
		err = fmt.Errorf("GetAppLocalState got a nil entry for (%s, %d): %p, %v", addr.String(), aidx, d.Params, d.Deleted)
	}
	ret = *d.Params
	return
}

func (cs *roundCowState) PutAppParams(addr basics.Address, aidx basics.AppIndex, params basics.AppParams) error {
	return cs.putAppParams(addr, aidx, ledgercore.AppParamsDelta{Params: &params})
}

func (cs *roundCowState) putAppParams(addr basics.Address, aidx basics.AppIndex, params ledgercore.AppParamsDelta) error {
	state, _, err := cs.lookupAppLocalState(addr, aidx, true) // should be cached
	if err != nil {
		return err
	}
	cs.mods.Accts.UpsertAppResource(addr, aidx, params, state)
	return nil
}

func (cs *roundCowState) PutAppLocalState(addr basics.Address, aidx basics.AppIndex, state basics.AppLocalState) error {
	return cs.putAppLocalState(addr, aidx, ledgercore.AppLocalStateDelta{LocalState: &state})
}

func (cs *roundCowState) putAppLocalState(addr basics.Address, aidx basics.AppIndex, state ledgercore.AppLocalStateDelta) error {
	params, _, err := cs.lookupAppParams(addr, aidx, true) // should be cached
	if err != nil {
		return err
	}
	cs.mods.Accts.UpsertAppResource(addr, aidx, params, state)
	return nil
}

func (cs *roundCowState) PutAssetHolding(addr basics.Address, aidx basics.AssetIndex, data basics.AssetHolding) error {
	return cs.putAssetHolding(addr, aidx, ledgercore.AssetHoldingDelta{Holding: &data})
}

func (cs *roundCowState) putAssetHolding(addr basics.Address, aidx basics.AssetIndex, data ledgercore.AssetHoldingDelta) error {
	params, _, err := cs.lookupAssetParams(addr, aidx, true) // should be cached
	if err != nil {
		return err
	}
	cs.mods.Accts.UpsertAssetResource(addr, aidx, params, data)
	return nil
}

func (cs *roundCowState) PutAssetParams(addr basics.Address, aidx basics.AssetIndex, data basics.AssetParams) error {
	return cs.putAssetParams(addr, aidx, ledgercore.AssetParamsDelta{Params: &data})
}

func (cs *roundCowState) putAssetParams(addr basics.Address, aidx basics.AssetIndex, data ledgercore.AssetParamsDelta) error {
	holding, _, err := cs.lookupAssetHolding(addr, aidx, true) // should be cached
	if err != nil {
		return err
	}
	cs.mods.Accts.UpsertAssetResource(addr, aidx, data, holding)
	return nil
}

func (cs *roundCowState) DeleteAppParams(addr basics.Address, aidx basics.AppIndex) error {
	if _, ok := cs.mods.Accts.GetData(addr); !ok {
		return fmt.Errorf("DeleteAppParams: %s not found in deltas for %d", addr.String(), aidx)
	}

	return cs.putAppParams(addr, aidx, ledgercore.AppParamsDelta{Deleted: true})
}

func (cs *roundCowState) DeleteAppLocalState(addr basics.Address, aidx basics.AppIndex) error {
	if _, ok := cs.mods.Accts.GetData(addr); !ok {
		return fmt.Errorf("DeleteAppLocalState: %s not found in deltas for %d", addr.String(), aidx)
	}

	return cs.putAppLocalState(addr, aidx, ledgercore.AppLocalStateDelta{Deleted: true})
}

func (cs *roundCowState) DeleteAssetHolding(addr basics.Address, aidx basics.AssetIndex) error {
	if _, ok := cs.mods.Accts.GetData(addr); !ok {
		return fmt.Errorf("DeleteAssetHolding: %s not found in deltas for %d", addr.String(), aidx)
	}

	return cs.putAssetHolding(addr, aidx, ledgercore.AssetHoldingDelta{Deleted: true})
}

func (cs *roundCowState) DeleteAssetParams(addr basics.Address, aidx basics.AssetIndex) error {
	if _, ok := cs.mods.Accts.GetData(addr); !ok {
		return fmt.Errorf("DeleteAssetParams: %s not found in deltas for %d", addr.String(), aidx)
	}

	return cs.putAssetParams(addr, aidx, ledgercore.AssetParamsDelta{Deleted: true})
}

func (cs *roundCowState) HasAppLocalState(addr basics.Address, aidx basics.AppIndex) (ok bool, err error) {
	d, ok, err := cs.lookupAppLocalState(addr, aidx, false)
	if err != nil {
		return false, err
	}
	if d.Deleted || d.LocalState == nil {
		ok = false
	}
	return ok, nil
}

func (cs *roundCowState) HasAssetParams(addr basics.Address, aidx basics.AssetIndex) (ok bool, err error) {
	d, ok, err := cs.lookupAssetParams(addr, aidx, false)
	if err != nil {
		return false, err
	}
	if d.Deleted || d.Params == nil {
		ok = false
	}
	return ok, nil
}
