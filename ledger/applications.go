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

// TODO remove round from balances

// AppTealGlobals contains data accessible by the "global" opcode.
type AppTealGlobals struct {
	CurrentRound    basics.Round
	LatestTimestamp int64
}

// appTealEvaluator implements transactions.StateEvaluator. When applying an
// ApplicationCall transaction, InitLedger is called, followed by Check and/or
// Eval. These pass the initialized LedgerForLogic (appLedger) to the TEAL
// interpreter.
type appTealEvaluator struct {
	evalParams logic.EvalParams
	AppTealGlobals
}

// appLedger implements logic.LedgerForLogic
type appLedger struct {
	addresses map[basics.Address]bool
	apps      map[basics.AppIndex]bool
	balances  transactions.Balances
	appIdx    basics.AppIndex
	AppTealGlobals
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

// InitLedger initializes an appLedger, which satisfies the
// logic.LedgerForLogic interface. The acctWhitelist lists all the accounts
// whose balance records we can fetch information like LocalState and balance
// from, and the appGlobalWhitelist lists all the app IDs we are allowed to
// fetch global state for (which requires looking up the creator's balance
// record).
func (ae *appTealEvaluator) InitLedger(balances transactions.Balances, acctWhitelist []basics.Address, appGlobalWhitelist []basics.AppIndex, appIdx basics.AppIndex) error {
	ledger, err := newAppLedger(balances, acctWhitelist, appGlobalWhitelist, appIdx, ae.AppTealGlobals)
	if err != nil {
		return err
	}

	ae.evalParams.Ledger = ledger
	return nil
}

func newAppLedger(balances transactions.Balances, acctWhitelist []basics.Address, appGlobalWhitelist []basics.AppIndex, appIdx basics.AppIndex, globals AppTealGlobals) (al *appLedger, err error) {
	if balances == nil {
		err = fmt.Errorf("cannot create appLedger with nil balances")
		return
	}

	if len(acctWhitelist) < 1 {
		err = fmt.Errorf("appLedger acct whitelist should at least include txn sender")
		return
	}

	if len(appGlobalWhitelist) < 1 {
		err = fmt.Errorf("appLedger app whitelist should at least include this appIdx")
		return
	}

	if appIdx == 0 {
		err = fmt.Errorf("cannot create appLedger for appIdx 0")
		return
	}

	al = &appLedger{}
	al.appIdx = appIdx
	al.balances = balances
	al.addresses = make(map[basics.Address]bool, len(acctWhitelist))
	al.apps = make(map[basics.AppIndex]bool, len(appGlobalWhitelist))
	al.AppTealGlobals = globals

	for _, addr := range acctWhitelist {
		al.addresses[addr] = true
	}

	for _, aidx := range appGlobalWhitelist {
		al.apps[aidx] = true
	}

	return al, nil
}

// MakeDebugAppLedger returns logic.LedgerForLogic suitable for debug or dryrun
func MakeDebugAppLedger(balances transactions.Balances, acctWhitelist []basics.Address, appGlobalWhitelist []basics.AppIndex, appIdx basics.AppIndex, globals AppTealGlobals) (al logic.LedgerForLogic, err error) {
	return newAppLedger(balances, acctWhitelist, appGlobalWhitelist, appIdx, globals)
}

func (al *appLedger) Balance(addr basics.Address) (res basics.MicroAlgos, err error) {
	// Ensure requested address is on whitelist
	if !al.addresses[addr] {
		err = fmt.Errorf("cannot access balance for %s, not sender or in txn.Addresses", addr.String())
		return
	}

	// Fetch record with pending rewards applied
	record, err := al.balances.Get(addr, true)
	if err != nil {
		return
	}

	return record.MicroAlgos, nil
}

// AppGlobalState returns the global state key/value store for the requested
// application. The returned map must NOT be modified.
func (al *appLedger) AppGlobalState(appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	// Allow referring to the current appIdx as 0
	var params basics.AppParams
	if appIdx == 0 {
		appIdx = al.appIdx
	}

	// Ensure requested app is on whitelist
	if !al.apps[appIdx] {
		return nil, fmt.Errorf("cannot access global state for %d, is not for this app (%d) or in txn.ForeignApps", appIdx, al.appIdx)
	}

	// Find app creator (and check if app exists)
	creator, ok, err := al.balances.GetAppCreator(appIdx)
	if err != nil {
		return nil, err
	}

	// Ensure app exists
	if !ok {
		return nil, fmt.Errorf("app %d does not exist", appIdx)
	}

	// Fetch creator's balance record
	record, err := al.balances.Get(creator, false)
	if err != nil {
		return nil, err
	}

	// Ensure creator has expected params
	params, ok = record.AppParams[appIdx]
	if !ok {
		return nil, fmt.Errorf("app %d not found in account %s", appIdx, creator.String())
	}

	// GlobalState might be nil, so make sure we don't return a nil map
	keyValue := params.GlobalState
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

	// Ensure account is opted in
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

func (al *appLedger) Round() basics.Round {
	return al.CurrentRound
}

func (al *appLedger) LatestTimestamp() int64 {
	return al.AppTealGlobals.LatestTimestamp
}

func (al *appLedger) ApplicationID() basics.AppIndex {
	return al.appIdx
}
