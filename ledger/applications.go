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
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

type appTealEvaluator struct {
	evalParams logic.EvalParams
}

// Eval evaluates a stateful TEAL program for an application. InitLedger must
// be called before calling Eval.
func (ae *appTealEvaluator) Eval(program []byte) (pass bool, stateDelta basics.EvalDelta, err error) {
	if ae.evalParams.Ledger == nil {
		err = fmt.Errorf("appTealEvaluator Ledger not initialized")
		return
	}
	return logic.EvalStateful(program, ae.evalParams)
}

// Check computes the cost of a TEAL program for an application. InitLedger must
// be called before calling Check.
func (ae *appTealEvaluator) Check(program []byte) (cost int, err error) {
	if ae.evalParams.Ledger == nil {
		err = fmt.Errorf("appTealEvaluator Ledger not initialized")
		return
	}
	return logic.CheckStateful(program, ae.evalParams)
}

func (ae *appTealEvaluator) InitLedger(balances transactions.Balances, params basics.AppParams, whitelist []basics.Address, appIdx basics.AppIndex) error {
	ledger, err := newAppLedger(balances, params, whitelist, appIdx)
	if err != nil {
		return err
	}

	ae.evalParams.Ledger = ledger
	return nil
}

// appLedger implements logic.LedgerForLogic
type appLedger struct {
	addresses map[basics.Address]bool
	balances  transactions.Balances
	appIdx    basics.AppIndex
	params    basics.AppParams
}

func newAppLedger(balances transactions.Balances, params basics.AppParams, whitelist []basics.Address, appIdx basics.AppIndex) (al *appLedger, err error) {
	if balances == nil {
		err = fmt.Errorf("cannot create appLedger with nil balances")
		return
	}

	if len(whitelist) < 1 {
		err = fmt.Errorf("appLedger whitelist should at least include txn sender")
		return
	}

	if appIdx == 0 {
		err = fmt.Errorf("cannot create appLedger for appIdx 0")
		return
	}

	al = &appLedger{}
	al.appIdx = appIdx
	al.balances = balances
	al.addresses = make(map[basics.Address]bool)
	al.params = params
	for _, addr := range whitelist {
		al.addresses[addr] = true
	}

	return al, nil
}

func (al *appLedger) Balance(addr basics.Address) (uint64, error) {
	// Ensure requested address is on whitelist
	if !al.addresses[addr] {
		return 0, fmt.Errorf("cannot access balance for %s, not sender or in txn.Addresses", addr.String())
	}

	// Fetch record with pending rewards applied
	record, err := al.balances.Get(addr, true)
	if err != nil {
		return 0, err
	}

	return record.MicroAlgos.Raw, nil
}

// AppGlobalState returns the global state key/value store for this
// application. The returned map must NOT be modified.
func (al *appLedger) AppGlobalState() (basics.TealKeyValue, error) {
	keyValue := al.params.GlobalState
	if keyValue == nil {
		keyValue = make(basics.TealKeyValue)
	}
	return keyValue, nil
}

// AppLocalState returns the local state key/value store for this
// account and application. The returned map must NOT be modified.
func (al *appLedger) AppLocalState(addr basics.Address, appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	// Allow referring to the current appIdx as 0
	if appIdx == 0 {
		appIdx = al.appIdx
	}

	// Ensure requested address is on whitelist
	if !al.addresses[addr] {
		return nil, fmt.Errorf("cannot access localstate for %s, not sender or in txn.Addresses", addr.String())
	}

	// Don't fetch with pending rewards here since we are only returning
	// the LocalState, not the balance
	record, err := al.balances.Get(addr, false)
	if err != nil {
		return nil, err
	}

	localState, ok := record.AppLocalStates[appIdx]
	if !ok {
		return nil, fmt.Errorf("addr %s not opted in to app %d, cannot fetch state", addr.String(), appIdx)
	}

	// KeyValue might be nil, so make sure we don't return a nil map
	keyValue := localState.KeyValue
	if keyValue == nil {
		keyValue = make(basics.TealKeyValue)
	}

	return keyValue, nil
}

func (al *appLedger) AssetHolding(addr basics.Address, assetIdx basics.AssetIndex) (holding basics.AssetHolding, err error) {
	// Ensure requested address is on whitelist
	if !al.addresses[addr] {
		err = fmt.Errorf("cannot access asset holding for %s, not sender or in txn.Addresses", addr.String())
		return
	}

	// Fetch the requested balance record
	record, err := al.balances.Get(addr, false)
	if err != nil {
		return
	}

	// Ensure we have the requested holding
	holding, ok := record.Assets[assetIdx]
	if !ok {
		err = fmt.Errorf("account %s has not opted in to asset %d", addr.String(), assetIdx)
		return
	}

	return holding, nil
}

func (al *appLedger) AssetParams(addr basics.Address, assetIdx basics.AssetIndex) (params basics.AssetParams, err error) {
	// Ensure requested address is on whitelist
	if !al.addresses[addr] {
		err = fmt.Errorf("cannot access asset params for %s, not sender or in txn.Addresses", addr.String())
		return
	}

	// Fetch the requested balance record
	record, err := al.balances.Get(addr, false)
	if err != nil {
		return
	}

	// Ensure account created the requested asset
	params, ok := record.AssetParams[assetIdx]
	if !ok {
		err = fmt.Errorf("account %s has not created asset %d", addr.String(), assetIdx)
		return
	}

	return params, nil
}

func (al *appLedger) RoundNumber() uint64 {
	// TODO(applications): implement me
	return 1
}
