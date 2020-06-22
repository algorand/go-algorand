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
	"math/rand"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
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

func makeAppLedger(
	balances map[basics.Address]basics.AccountData, txnGroup []transactions.SignedTxn,
	groupIndex int, proto config.ConsensusParams, round int, latestTimestamp int64,
	appIdx basics.AppIndex, painless bool,
) (logic.LedgerForLogic, appState, error) {

	if groupIndex >= len(txnGroup) {
		return nil, appState{}, fmt.Errorf("invalid groupIndex %d exceed txn group length %d", groupIndex, len(txnGroup))
	}
	txn := txnGroup[groupIndex]

	accounts := []basics.Address{txn.Txn.Sender}
	for _, addr := range txn.Txn.Accounts {
		accounts = append(accounts, addr)
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

	appsExist := make(map[basics.AppIndex]bool, len(apps))
	states := makeAppState()
	states.appIdx = appIdx
	for _, aid := range apps {
		for addr, ad := range balances {
			if params, ok := ad.AppParams[aid]; ok {
				states.global[aid] = params.GlobalState
				appsExist[aid] = true
			}
			if local, ok := ad.AppLocalStates[aid]; ok {
				ls, ok := states.locals[addr]
				if !ok {
					ls = make(map[basics.AppIndex]basics.TealKeyValue)
				}
				ls[aid] = local.KeyValue
				states.locals[addr] = ls
			}
		}
	}

	// painless mode creates all missed global states and opt-in all mentioned accounts
	if painless {
		for _, aid := range apps {
			if ok := appsExist[aid]; !ok {
				// create balance record and AppParams for this app
				addr, err := getRandomAddress()
				if err != nil {
					return nil, appState{}, err
				}
				ad := basics.AccountData{
					AppParams: map[basics.AppIndex]basics.AppParams{
						aid: {
							LocalStateSchema:  makeSchema(),
							GlobalStateSchema: makeSchema(),
							GlobalState:       make(basics.TealKeyValue),
						},
					},
				}
				balances[addr] = ad
			}
			for _, addr := range accounts {
				ad, ok := balances[addr]
				if !ok {
					ad = basics.AccountData{
						AppLocalStates: map[basics.AppIndex]basics.AppLocalState{},
					}
					balances[addr] = ad
				}
				if ad.AppLocalStates == nil {
					ad.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
				}
				_, ok = ad.AppLocalStates[aid]
				if !ok {
					ad.AppLocalStates[aid] = basics.AppLocalState{
						Schema: makeSchema(),
					}
				}
			}
		}
	}

	appGlobals := ledger.AppTealGlobals{CurrentRound: basics.Round(round), LatestTimestamp: latestTimestamp}
	ledger, err := ledger.MakeDebugAppLedger(ba, accounts, apps, appIdx, basics.AppParams{}, appGlobals)
	return ledger, states, err
}

func makeSchema() basics.StateSchema {
	return basics.StateSchema{
		NumUint:      16,
		NumByteSlice: 16,
	}
}

func getRandomAddress() (basics.Address, error) {
	const rl = 16
	b := make([]byte, rl)
	_, err := rand.Read(b)
	if err != nil {
		return basics.Address{}, err
	}

	address := crypto.Hash(b)
	return basics.Address(address), nil
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
