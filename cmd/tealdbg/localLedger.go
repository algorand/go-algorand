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
	round      uint64
}

func makeAppLedger(
	balances map[basics.Address]basics.AccountData, txnGroup []transactions.SignedTxn,
	groupIndex int, proto config.ConsensusParams, round uint64, latestTimestamp int64,
	appIdx basics.AppIndex, painless bool,
) (logic.LedgerForLogic, appState, error) {

	if groupIndex >= len(txnGroup) {
		return nil, appState{}, fmt.Errorf("invalid groupIndex %d exceed txn group length %d", groupIndex, len(txnGroup))
	}
	txn := txnGroup[groupIndex]

	accounts := []basics.Address{txn.Txn.Sender}
	accounts = append(accounts, txn.Txn.Accounts...)

	apps := []basics.AppIndex{appIdx}
	apps = append(apps, txn.Txn.ForeignApps...)

	ba := &balancesAdapter{
		balances:   balances,
		txnGroup:   txnGroup,
		groupIndex: groupIndex,
		proto:      proto,
		round:      round,
	}

	appsExist := make(map[basics.AppIndex]bool, len(apps))
	states := makeAppState()
	states.schemas = makeSchemas()
	states.appIdx = appIdx
	for _, aid := range apps {
		for addr, ad := range balances {
			if params, ok := ad.AppParams[aid]; ok {
				if aid == appIdx {
					states.schemas = params.StateSchemas
				}
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
							StateSchemas: makeSchemas(),
							GlobalState:  make(basics.TealKeyValue),
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
						Schema: makeLocalSchema(),
					}
				}
			}
		}
	}

	appGlobals := ledger.AppTealGlobals{CurrentRound: basics.Round(round), LatestTimestamp: latestTimestamp}
	ledger, err := ledger.MakeDebugAppLedger(ba, appIdx, states.schemas, appGlobals)
	return ledger, states, err
}

func makeSchemas() basics.StateSchemas {
	return basics.StateSchemas{
		LocalStateSchema:  makeLocalSchema(),
		GlobalStateSchema: makeGlobalSchema(),
	}
}

func makeLocalSchema() basics.StateSchema {
	return basics.StateSchema{
		NumUint:      16,
		NumByteSlice: 16,
	}
}

func makeGlobalSchema() basics.StateSchema {
	return basics.StateSchema{
		NumUint:      64,
		NumByteSlice: 64,
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

func (ba *balancesAdapter) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	switch ctype {
	case basics.AssetCreatable:
		assetIdx := basics.AssetIndex(cidx)
		for addr, br := range ba.balances {
			if _, ok := br.AssetParams[assetIdx]; ok {
				return addr, true, nil
			}
		}
		return basics.Address{}, false, nil
	case basics.AppCreatable:
		appIdx := basics.AppIndex(cidx)
		for addr, br := range ba.balances {
			if _, ok := br.AppParams[appIdx]; ok {
				return addr, true, nil
			}
		}
		return basics.Address{}, false, nil
	}
	return basics.Address{}, false, fmt.Errorf("unknown creatable type %d", ctype)
}

func (ba *balancesAdapter) ConsensusParams() config.ConsensusParams {
	return ba.proto
}

func (ba *balancesAdapter) PutWithCreatable(basics.BalanceRecord, *basics.CreatableLocator, *basics.CreatableLocator) error {
	return nil
}

func (ba *balancesAdapter) Put(basics.BalanceRecord) error {
	return nil
}

func (ba *balancesAdapter) Move(src, dst basics.Address, amount basics.MicroAlgos, srcRewards, dstRewards *basics.MicroAlgos) error {
	return nil
}
