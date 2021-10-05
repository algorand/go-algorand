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
	"github.com/algorand/go-algorand/ledger/internal"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// A ledger interface that Indexer implements. This is a simplified version of the
// LedgerForEvaluator interface. Certain functions that the evaluator doesn't use
// in the trusting mode are excluded, and the present functions only request data
// at the latest round.
type indexerLedgerForEval interface {
	LatestBlockHdr() (bookkeeping.BlockHeader, error)
	// The value of the returned map is nil iff the account was not found.
	LookupWithoutRewards(map[basics.Address]struct{}) (map[basics.Address]*basics.AccountData, error)
	GetAssetCreator(map[basics.AssetIndex]struct{}) (map[basics.AssetIndex]ledgercore.FoundAddress, error)
	GetAppCreator(map[basics.AppIndex]struct{}) (map[basics.AppIndex]ledgercore.FoundAddress, error)
	LatestTotals() (ledgercore.AccountTotals, error)
}

// Converter between indexerLedgerForEval and LedgerForEvaluator interfaces.
type indexerLedgerConnector struct {
	il          indexerLedgerForEval
	genesisHash crypto.Digest
	latestRound basics.Round
}

// BlockHdr is part of LedgerForEvaluator interface.
func (l indexerLedgerConnector) BlockHdr(round basics.Round) (bookkeeping.BlockHeader, error) {
	if round != l.latestRound {
		return bookkeeping.BlockHeader{}, fmt.Errorf(
			"BlockHdr() evaluator called this function for the wrong round %d, "+
				"latest round is %d",
			round, l.latestRound)
	}
	return l.il.LatestBlockHdr()
}

// CheckDup is part of LedgerForEvaluator interface.
func (l indexerLedgerConnector) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error {
	// This function is not used by evaluator.
	return errors.New("CheckDup() not implemented")
}

// LookupWithoutRewards is part of LedgerForEvaluator interface.
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

// GetCreatorForRound is part of LedgerForEvaluator interface.
func (l indexerLedgerConnector) GetCreatorForRound(_ basics.Round, cindex basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	var foundAddress ledgercore.FoundAddress

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

// GenesisHash is part of LedgerForEvaluator interface.
func (l indexerLedgerConnector) GenesisHash() crypto.Digest {
	return l.genesisHash
}

// Totals is part of LedgerForEvaluator interface.
func (l indexerLedgerConnector) LatestTotals() (rnd basics.Round, totals ledgercore.AccountTotals, err error) {
	totals, err = l.il.LatestTotals()
	rnd = l.latestRound
	return
}

// CompactCertVoters is part of LedgerForEvaluator interface.
func (l indexerLedgerConnector) CompactCertVoters(_ basics.Round) (*ledgercore.VotersForRound, error) {
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

// Write the list of addresses referenced in `txn` to `out`. Addresses might repeat.
func getTxnAddresses(txn *transactions.Transaction, out *[]basics.Address) {
	*out = (*out)[:0]

	*out = append(
		*out, txn.Sender, txn.Receiver, txn.CloseRemainderTo, txn.AssetSender,
		txn.AssetReceiver, txn.AssetCloseTo, txn.FreezeAccount)
	*out = append(*out, txn.ApplicationCallTxnFields.Accounts...)
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

	eval, err := internal.StartEvaluator(
		ilc, block.BlockHeader, proto, len(block.Payset), false, false, 0)
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
		eval.PreloadAccountDataCache(accountDataMap)
	}

	return eval.ProcessBlockForIndexer(block)
}
