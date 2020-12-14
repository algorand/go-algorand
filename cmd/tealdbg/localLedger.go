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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/protocol"
)

// AccountIndexerResponse represents the Account Response object from querying indexer
type AccountIndexerResponse struct {
	// Account information at a given round.
	//
	// Definition:
	// data/basics/userBalance.go : AccountData
	Account generated.Account `json:"account"`

	// Round at which the results were computed.
	CurrentRound uint64 `json:"current-round"`
}

// ApplicationIndexerResponse represents the Application Response object from querying indexer
type ApplicationIndexerResponse struct {

	// Application index and its parameters
	Application generated.Application `json:"application,omitempty"`

	// Round at which the results were computed.
	CurrentRound uint64 `json:"current-round"`
}

type localLedger struct {
	balances        map[basics.Address]basics.AccountData
	txnGroup        []transactions.SignedTxn
	groupIndex      int
	round           uint64
	aidx            basics.AppIndex
	latestTimestamp int64
}

func makeBalancesAdapter(
	balances map[basics.Address]basics.AccountData, txnGroup []transactions.SignedTxn,
	groupIndex int, proto string, round uint64, latestTimestamp int64,
	appIdx basics.AppIndex, painless bool, indexerURL string, indexerToken string,
) (apply.Balances, AppState, error) {

	if groupIndex >= len(txnGroup) {
		return nil, AppState{}, fmt.Errorf("invalid groupIndex %d exceed txn group length %d", groupIndex, len(txnGroup))
	}
	txn := txnGroup[groupIndex]

	accounts := []basics.Address{txn.Txn.Sender}
	accounts = append(accounts, txn.Txn.Accounts...)

	apps := []basics.AppIndex{appIdx}
	apps = append(apps, txn.Txn.ForeignApps...)

	// populate balances from the indexer if not already
	if indexerURL != "" {
		for _, acc := range accounts {
			// only populate from indexer if balance record not specified
			if _, ok := balances[acc]; !ok {
				var err error
				balances[acc], err = getBalanceFromIndexer(indexerURL, indexerToken, acc, round)
				if err != nil {
					return nil, AppState{}, err
				}
			}
		}
		for _, app := range apps {
			creator, err := getAppCreatorFromIndexer(indexerURL, indexerToken, app)
			if err != nil {
				return nil, AppState{}, err
			}
			balances[creator], err = getBalanceFromIndexer(indexerURL, indexerToken, creator, round)
			if err != nil {
				return nil, AppState{}, err
			}
		}
	}

	ll := &localLedger{
		balances:   balances,
		txnGroup:   txnGroup,
		groupIndex: groupIndex,
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
					return nil, AppState{}, err
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

	ba := ledger.MakeDebugBalances(ll, basics.Round(round), protocol.ConsensusVersion(proto), latestTimestamp)
	ll.aidx = appIdx
	return ba, states, nil
}

func getAppCreatorFromIndexer(indexerURL string, indexerToken string, app basics.AppIndex) (basics.Address, error) {
	queryString := fmt.Sprintf("%s/v2/applications/%d", indexerURL, app)
	client := &http.Client{}
	request, err := http.NewRequest("GET", queryString, nil)
	request.Header.Set("X-Indexer-API-Token", indexerToken)
	resp, err := client.Do(request)
	if err != nil {
		return basics.Address{}, fmt.Errorf("application request error: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		msg, _ := ioutil.ReadAll(resp.Body)
		return basics.Address{}, fmt.Errorf("application response error: %s, status code: %d, request: %s", string(msg), resp.StatusCode, queryString)
	}
	var appResp ApplicationIndexerResponse
	err = json.NewDecoder(resp.Body).Decode(&appResp)
	if err != nil {
		return basics.Address{}, fmt.Errorf("application response decode error: %s", err)
	}

	creator, err := basics.UnmarshalChecksumAddress(appResp.Application.Params.Creator)

	if err != nil {
		return basics.Address{}, fmt.Errorf("UnmarshalChecksumAddress error: %s", err)
	}
	return creator, nil
}

func getBalanceFromIndexer(indexerURL string, indexerToken string, account basics.Address, round uint64) (basics.AccountData, error) {
	queryString := fmt.Sprintf("%s/v2/accounts/%s?round=%d", indexerURL, account, round)
	client := &http.Client{}
	request, err := http.NewRequest("GET", queryString, nil)
	request.Header.Set("X-Indexer-API-Token", indexerToken)
	resp, err := client.Do(request)
	if err != nil {
		return basics.AccountData{}, fmt.Errorf("account request error: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		msg, _ := ioutil.ReadAll(resp.Body)
		return basics.AccountData{}, fmt.Errorf("account response error: %s, status code: %d, request: %s", string(msg), resp.StatusCode, queryString)
	}
	var accountResp AccountIndexerResponse
	err = json.NewDecoder(resp.Body).Decode(&accountResp)
	if err != nil {
		return basics.AccountData{}, fmt.Errorf("account response decode error: %s", err)
	}
	balance, err := v2.AccountToAccountData(&accountResp.Account)
	if err != nil {
		return basics.AccountData{}, fmt.Errorf("AccountToAccountData error: %s", err)
	}
	return balance, nil
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

func (l *localLedger) BlockHdr(basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{}, nil
}

func (l *localLedger) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledger.TxLease) error {
	return nil
}

func (l *localLedger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (basics.AccountData, basics.Round, error) {
	return l.balances[addr], rnd, nil
}

func (l *localLedger) GetCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	switch ctype {
	case basics.AssetCreatable:
		assetIdx := basics.AssetIndex(cidx)
		for addr, br := range l.balances {
			if _, ok := br.AssetParams[assetIdx]; ok {
				return addr, true, nil
			}
		}
		return basics.Address{}, false, nil
	case basics.AppCreatable:
		appIdx := basics.AppIndex(cidx)
		for addr, br := range l.balances {
			if _, ok := br.AppParams[appIdx]; ok {
				return addr, true, nil
			}
		}
		return basics.Address{}, false, nil
	}
	return basics.Address{}, false, fmt.Errorf("unknown creatable type %d", ctype)
}
