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

func (ae appTealEvaluator) Eval(program []byte) (pass bool, stateDelta basics.EvalDelta, err error) {
	return logic.EvalStatefull(program, ae.evalParams)
}

// appLedger implements logic.LedgerForLogic
type appLedger struct {
	addresses map[basics.Address]bool
	balances  transactions.Balances
}

func newAppLedger(balances transactions.Balances, whitelist []basics.Address) (al *appLedger, err error) {
	if balances == nil {
		err = fmt.Errorf("cannot create appLedger with nil balances")
		return
	}

	if len(whitelist) < 1 {
		err = fmt.Errorf("appLedger whitelist should at least include txn sender")
		return
	}

	al = &appLedger{}
	al.balances = balances
	al.addresses = make(map[basics.Address]bool)
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

func (al *appLedger) AppGlobalState(appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	return nil, nil
}

func (al *appLedger) AppLocalState(addr basics.Address, appIdx basics.AppIndex) (basics.TealKeyValue, error) {
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

	_, ok := record.AppLocalStates[appIdx]
	if !ok {
		return nil, fmt.Errorf("addr %s not opted in to app %d, cannot fetch state", addr.String(), appIdx)
	}

	// Clone LocalState so that we don't edit it in place
	cloned := record.AppLocalStates[appIdx].Clone()

	return cloned.KeyValue, nil
}

func (al *appLedger) AssetHolding(addr basics.Address, assetID uint64) (basics.AssetHolding, error) {
	// TOOD(application)
	return basics.AssetHolding{}, fmt.Errorf("AssetHolding not implemented")
}

func (al *appLedger) AssetParams(addr basics.Address, assetID uint64) (basics.AssetParams, error) {
	// TOOD(application)
	return basics.AssetParams{}, fmt.Errorf("AssetParams not implemented")
}
