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

package main

import (
	"fmt"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

type localLedger struct {
	round      int
	balances   map[basics.Address]basics.AccountData
	txnGroup   []transactions.SignedTxn
	groupIndex int
}

func (l *localLedger) Balance(addr basics.Address) (basics.MicroAlgos, error) {
	br, ok := l.balances[addr]
	if !ok {
		return basics.MicroAlgos{}, fmt.Errorf("no such address %s", addr.String())
	}
	return br.MicroAlgos, nil
}

func (l *localLedger) Round() basics.Round {
	return basics.Round(l.round)
}

func (l *localLedger) AppGlobalState(appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	var ap basics.AppParams
	if appIdx == 0 {
		if l.groupIndex >= len(l.txnGroup) {
			return basics.TealKeyValue{}, fmt.Errorf("can't resolve application %d", appIdx)
		}
		appIdx = l.txnGroup[l.groupIndex].Txn.ApplicationID
	}

	allowed := false
	if appIdx == l.txnGroup[l.groupIndex].Txn.ApplicationID {
		allowed = true
	} else {
		for _, faIdx := range l.txnGroup[l.groupIndex].Txn.ForeignApps {
			if appIdx == faIdx {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return basics.TealKeyValue{}, fmt.Errorf("access to the app forbidden %d", appIdx)
	}

	for _, br := range l.balances {
		var ok bool
		ap, ok = br.AppParams[appIdx]
		if ok {
			return ap.GlobalState, nil
		}

	}
	return basics.TealKeyValue{}, fmt.Errorf("no such application %d", appIdx)
}

func (l *localLedger) AppLocalState(addr basics.Address, appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	if appIdx == 0 {
		if l.groupIndex >= len(l.txnGroup) {
			return basics.TealKeyValue{}, fmt.Errorf("can't resolve application %d", appIdx)
		}
		appIdx = l.txnGroup[l.groupIndex].Txn.ApplicationID
	}

	br, ok := l.balances[addr]
	if !ok {
		return basics.TealKeyValue{}, fmt.Errorf("no such address %s", addr.String())
	}
	ls, ok := br.AppLocalStates[appIdx]
	if !ok {
		return basics.TealKeyValue{}, fmt.Errorf("no local state for application %d", appIdx)
	}
	return ls.KeyValue, nil
}

func (l *localLedger) AssetHolding(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetHolding, error) {
	br, ok := l.balances[addr]
	if !ok {
		return basics.AssetHolding{}, fmt.Errorf("no such address %s", addr.String())
	}
	ah, ok := br.Assets[assetIdx]
	if !ok {
		return basics.AssetHolding{}, fmt.Errorf("no such asset %d", assetIdx)
	}
	return ah, nil
}

func (l *localLedger) AssetParams(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetParams, error) {
	br, ok := l.balances[addr]
	if !ok {
		return basics.AssetParams{}, fmt.Errorf("no such address %s", addr.String())
	}
	ap, ok := br.AssetParams[assetIdx]
	if !ok {
		return basics.AssetParams{}, fmt.Errorf("no such asset %d", assetIdx)
	}
	return ap, nil
}
