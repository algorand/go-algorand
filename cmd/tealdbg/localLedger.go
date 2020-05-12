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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger"
)

type balancesAdapter struct {
	balances   map[basics.Address]basics.AccountData
	txnGroup   []transactions.SignedTxn
	groupIndex int
	proto      config.ConsensusParams
	round      int
}

const defaultNewAppIdx = 1380011588

func makeAppLedger(
	balances map[basics.Address]basics.AccountData, txnGroup []transactions.SignedTxn,
	groupIndex int, proto config.ConsensusParams, round int, latestTimestamp int64,
) (logic.LedgerForLogic, error) {

	if groupIndex >= len(txnGroup) {
		return nil, fmt.Errorf("invalid groupIndex %d exceed txn group length %d", groupIndex, len(txnGroup))
	}
	txn := txnGroup[groupIndex]

	accounts := []basics.Address{txn.Txn.Sender}
	for _, addr := range txn.Txn.Accounts {
		accounts = append(accounts, addr)
	}

	appIdx := txn.Txn.ApplicationID
	if appIdx == 0 {
		// presumably this is app create transaction, initialize with some value
		appIdx = defaultNewAppIdx
	}

	apps := []basics.AppIndex{appIdx}
	for _, aid := range txn.Txn.ForeignApps {
		apps = append(apps, aid)
	}

	ba := &balancesAdapter{
		balances:   balances,
		txnGroup:   txnGroup,
		groupIndex: groupIndex,
		proto:      proto,
		round:      round,
	}

	return ledger.MakeDebugAppLedger(ba, accounts, apps, appIdx, ledger.AppTealGlobals{CurrentRound: basics.Round(round), LatestTimestamp: latestTimestamp})
}

func (ba *balancesAdapter) Get(addr basics.Address, withPendingRewards bool) (basics.BalanceRecord, error) {
	br, ok := ba.balances[addr]
	if !ok {
		return basics.BalanceRecord{}, nil
	}
	return basics.BalanceRecord{Addr: addr, AccountData: br}, nil
}

func (ba *balancesAdapter) Round() basics.Round {
	return basics.Round(ba.round)
}

func (ba *balancesAdapter) GetAssetCreator(assetIdx basics.AssetIndex) (basics.Address, bool, error) {
	for addr, br := range ba.balances {
		if _, ok := br.AssetParams[assetIdx]; ok {
			return addr, true, nil
		}
	}
	return basics.Address{}, false, nil
}

func (ba *balancesAdapter) GetAppCreator(appIdx basics.AppIndex) (basics.Address, bool, error) {
	for addr, br := range ba.balances {
		if _, ok := br.AppParams[appIdx]; ok {
			return addr, true, nil
		}
	}
	return basics.Address{}, false, nil
}

func (ba *balancesAdapter) ConsensusParams() config.ConsensusParams {
	return ba.proto
}

func (ba *balancesAdapter) PutWithCreatables(basics.BalanceRecord, []basics.CreatableLocator, []basics.CreatableLocator) error {
	return nil
}

func (ba *balancesAdapter) Put(basics.BalanceRecord) error {
	return nil
}

func (ba *balancesAdapter) Move(src, dst basics.Address, amount basics.MicroAlgos, srcRewards, dstRewards *basics.MicroAlgos) error {
	return nil
}
