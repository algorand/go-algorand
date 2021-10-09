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
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// ProcessBlockForIndexer ..
func (eval *BlockEvaluator) ProcessBlockForIndexer(block *bookkeeping.Block) (ledgercore.StateDelta, []transactions.SignedTxnInBlock, error) {
	paysetgroups, err := block.DecodePaysetGroups()
	if err != nil {
		return ledgercore.StateDelta{}, []transactions.SignedTxnInBlock{},
			fmt.Errorf("ProcessBlockForIndexer() err: %w", err)
	}

	for _, group := range paysetgroups {
		err = eval.TransactionGroup(group)
		if err != nil {
			return ledgercore.StateDelta{}, []transactions.SignedTxnInBlock{},
				fmt.Errorf("ProcessBlockForIndexer() err: %w", err)
		}
	}

	// Finally, process any pending end-of-block state changes.
	err = eval.endOfBlock()
	if err != nil {
		return ledgercore.StateDelta{}, []transactions.SignedTxnInBlock{},
			fmt.Errorf("ProcessBlockForIndexer() err: %w", err)
	}

	// here, in the EvalForIndexer, we don't want to call finalValidation(). This would
	// skip the calculation of the account totals in the state delta, which is a serious
	// issue if it were to be used by algod, but it's perfectly fine for the indexer since
	// it doesn't track any totals and therefore cannot calculate the new totals.

	return eval.state.deltas(), eval.block.Payset, nil
}

// PreloadAccountDataCache initialize the account data cache so that we won't need to make a
// ledger query for that account.
func (eval *BlockEvaluator) PreloadAccountDataCache(accountDataMap map[basics.Address]*basics.AccountData) {
	base := eval.state.lookupParent.(*roundCowBase)
	for address, accountData := range accountDataMap {
		if accountData == nil {
			base.accounts[address] = basics.AccountData{}
		} else {
			base.accounts[address] = *accountData
		}
	}
}

// EvalForIndexerResources contains resources preloaded from the Indexer database.
// Indexer is able to do the preloading more efficiently than the evaluator loading
// resources one by one.
type EvalForIndexerResources struct {
	// The map value is nil iff the account does not exist. The account data is owned here.
	Accounts map[basics.Address]*basics.AccountData
	Creators map[Creatable]ledgercore.FoundAddress
}

// SaveResourcesInCowBase saves the given resources into the rowCowBase accounts & creators cache.
func (eval *BlockEvaluator) SaveResourcesInCowBase(resources EvalForIndexerResources) {
	base := eval.state.lookupParent.(*roundCowBase)
	for address, accountData := range resources.Accounts {
		if accountData == nil {
			base.accounts[address] = basics.AccountData{}
		} else {
			base.accounts[address] = *accountData
		}
	}

	base.creators = resources.Creators
}
