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

package ledger

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// A ledger interface that Indexer implements. This is a simplified version of the
// ledgerForEvaluator interface. Certain functions that the evaluator doesn't use
// in the trusting mode are excluded, and the present functions only request data
// at the latest round.
type indexerLedgerForEval interface {
	LatestBlockHdr() (bookkeeping.BlockHeader, error)
	// The value of the returned map is nil iff the account was not found.
	LookupWithoutRewards(map[basics.Address]struct{}) (map[basics.Address]*basics.AccountData, error)
	GetAssetCreator(map[basics.AssetIndex]struct{}) (map[basics.AssetIndex]FoundAddress, error)
	GetAppCreator(map[basics.AppIndex]struct{}) (map[basics.AppIndex]FoundAddress, error)
	LatestTotals() (ledgercore.AccountTotals, error)
}

// Converter between indexerLedgerForEval and ledgerForEvaluator interfaces.
type indexerLedgerConnector struct {
	il          indexerLedgerForEval
	genesisHash crypto.Digest
	latestRound basics.Round
}

// BlockHdr is part of ledgerForEvaluator interface.
func (l indexerLedgerConnector) BlockHdr(round basics.Round) (bookkeeping.BlockHeader, error) {
	if round != l.latestRound {
		return bookkeeping.BlockHeader{}, fmt.Errorf(
			"BlockHdr() evaluator called this function for the wrong round %d, "+
				"latest round is %d",
			round, l.latestRound)
	}
	return l.il.LatestBlockHdr()
}

// CheckDup is part of ledgerForEvaluator interface.
func (l indexerLedgerConnector) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, TxLease) error {
	// This function is not used by evaluator.
	return errors.New("CheckDup() not implemented")
}

// LookupWithoutRewards is part of ledgerForEvaluator interface.
func (l indexerLedgerConnector) LookupWithoutRewards(round basics.Round, address basics.Address) (basics.AccountData, basics.Round, error) {
	accountDataMap, err :=
		l.il.LookupWithoutRewards(map[basics.Address]struct{}{address: {}})
	if err != nil {
		return basics.AccountData{}, basics.Round(0), err
	}

	accountData := accountDataMap[address]
	if accountData == nil {
		return basics.AccountData{}, round, nil
	}
	return *accountData, round, nil
}

// GetCreatorForRound is part of ledgerForEvaluator interface.
func (l indexerLedgerConnector) GetCreatorForRound(_ basics.Round, cindex basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	var foundAddress FoundAddress

	switch ctype {
	case basics.AssetCreatable:
		foundAddresses, err :=
			l.il.GetAssetCreator(map[basics.AssetIndex]struct{}{basics.AssetIndex(cindex): {}})
		if err != nil {
			return basics.Address{}, false, err
		}
		foundAddress = foundAddresses[basics.AssetIndex(cindex)]
	case basics.AppCreatable:
		foundAddresses, err :=
			l.il.GetAppCreator(map[basics.AppIndex]struct{}{basics.AppIndex(cindex): {}})
		if err != nil {
			return basics.Address{}, false, err
		}
		foundAddress = foundAddresses[basics.AppIndex(cindex)]
	default:
		return basics.Address{}, false, fmt.Errorf("unknown creatable type %v", ctype)
	}

	return foundAddress.Address, foundAddress.Exists, nil
}

// GenesisHash is part of ledgerForEvaluator interface.
func (l indexerLedgerConnector) GenesisHash() crypto.Digest {
	return l.genesisHash
}

// Totals is part of ledgerForEvaluator interface.
func (l indexerLedgerConnector) LatestTotals() (rnd basics.Round, totals ledgercore.AccountTotals, err error) {
	totals, err = l.il.LatestTotals()
	rnd = l.latestRound
	return
}

// CompactCertVoters is part of ledgerForEvaluator interface.
func (l indexerLedgerConnector) CompactCertVoters(_ basics.Round) (*VotersForRound, error) {
	// This function is not used by evaluator.
	return nil, errors.New("CompactCertVoters() not implemented")
}

func makeIndexerLedgerConnector(il indexerLedgerForEval, genesisHash crypto.Digest, latestRound basics.Round) indexerLedgerConnector {
	return indexerLedgerConnector{
		il:          il,
		genesisHash: genesisHash,
		latestRound: latestRound,
	}
}

// Returns all addresses referenced in `block`.
func getBlockAddresses(block *bookkeeping.Block) map[basics.Address]struct{} {
	// Reserve a reasonable memory size for the map.
	res := make(map[basics.Address]struct{}, len(block.Payset)+2)
	res[block.FeeSink] = struct{}{}
	res[block.RewardsPool] = struct{}{}

	var refAddresses []basics.Address
	for _, stib := range block.Payset {
		getTxnAddresses(&stib.Txn, &refAddresses)
		for _, address := range refAddresses {
			res[address] = struct{}{}
		}
	}

	return res
}

// EvalForIndexer evaluates a block without validation using the given `proto`.
// Return the state delta and transactions with modified apply data according to `proto`.
// This function is used by Indexer which modifies `proto` to retrieve the asset
// close amount for each transaction even when the real consensus parameters do not
// support it.
func EvalForIndexer(il indexerLedgerForEval, block *bookkeeping.Block, proto config.ConsensusParams) (ledgercore.StateDelta, []transactions.SignedTxnInBlock, error) {
	ilc := makeIndexerLedgerConnector(il, block.GenesisHash(), block.Round()-1)

	eval, err := startEvaluator(
		ilc, block.BlockHeader, proto, len(block.Payset), false, false)
	if err != nil {
		return ledgercore.StateDelta{}, []transactions.SignedTxnInBlock{},
			fmt.Errorf("EvalForIndexer() err: %w", err)
	}

	// Preload most needed accounts.
	{
		accountDataMap, err := il.LookupWithoutRewards(getBlockAddresses(block))
		if err != nil {
			return ledgercore.StateDelta{}, []transactions.SignedTxnInBlock{},
				fmt.Errorf("EvalForIndexer() err: %w", err)
		}
		base := eval.state.lookupParent.(*roundCowBase)
		for address, accountData := range accountDataMap {
			if accountData == nil {
				base.accounts[address] = basics.AccountData{}
			} else {
				base.accounts[address] = *accountData
			}
		}
	}

	paysetgroups, err := block.DecodePaysetGroups()
	if err != nil {
		return ledgercore.StateDelta{}, []transactions.SignedTxnInBlock{},
			fmt.Errorf("EvalForIndexer() err: %w", err)
	}

	for _, group := range paysetgroups {
		err = eval.TransactionGroup(group)
		if err != nil {
			return ledgercore.StateDelta{}, []transactions.SignedTxnInBlock{},
				fmt.Errorf("EvalForIndexer() err: %w", err)
		}
	}

	// Finally, process any pending end-of-block state changes.
	err = eval.endOfBlock()
	if err != nil {
		return ledgercore.StateDelta{}, []transactions.SignedTxnInBlock{},
			fmt.Errorf("EvalForIndexer() err: %w", err)
	}

	// here, in the EvalForIndexer, we don't want to call finalValidation(). This would
	// skip the calculation of the account totals in the state delta, which is a serious
	// issue if it were to be used by algod, but it's perfectly fine for the indexer since
	// it doesn't track any totals and therefore cannot calculate the new totals.

	return eval.state.deltas(), eval.block.Payset, nil
}
