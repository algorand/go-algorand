// Copyright (C) 2019-2022 Algorand, Inc.
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
// at the latest round. However, functions below can be used for batch querying.
type indexerLedgerForEval interface {
	LatestBlockHdr() (bookkeeping.BlockHeader, error)
	// The value of the returned map is nil iff the account was not found.
	LookupWithoutRewards(map[basics.Address]struct{}) (map[basics.Address]*ledgercore.AccountData, error)
	// The returned map must have the same structure (elements) as the input map.
	// If a resource is not found, it must be nil in `ledgercore.AccountResource`.
	LookupResources(map[basics.Address]map[Creatable]struct{}) (map[basics.Address]map[Creatable]ledgercore.AccountResource, error)
	GetAssetCreator(map[basics.AssetIndex]struct{}) (map[basics.AssetIndex]FoundAddress, error)
	GetAppCreator(map[basics.AppIndex]struct{}) (map[basics.AppIndex]FoundAddress, error)
	LatestTotals() (ledgercore.AccountTotals, error)
}

// FoundAddress is a wrapper for an address and a boolean.
type FoundAddress struct {
	Address basics.Address
	Exists  bool
}

// EvalForIndexerResources contains resources preloaded from the Indexer database.
// Indexer is able to do the preloading more efficiently than the evaluator loading
// resources one by one.
type EvalForIndexerResources struct {
	// The map value is nil iff the account does not exist. The account data is owned here.
	Accounts  map[basics.Address]*ledgercore.AccountData
	Resources map[basics.Address]map[Creatable]ledgercore.AccountResource
	Creators  map[Creatable]FoundAddress
}

// Creatable represent a single creatable object.
type Creatable struct {
	Index basics.CreatableIndex
	Type  basics.CreatableType
}

// Converter between indexerLedgerForEval and ledgerForEvaluator interfaces.
type indexerLedgerConnector struct {
	il             indexerLedgerForEval
	genesisHash    crypto.Digest
	genesisProto   config.ConsensusParams
	latestRound    basics.Round
	roundResources EvalForIndexerResources
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
func (l indexerLedgerConnector) LookupWithoutRewards(round basics.Round, address basics.Address) (ledgercore.AccountData, basics.Round, error) {
	// check to see if the account data in the cache.
	if pad, has := l.roundResources.Accounts[address]; has {
		if pad == nil {
			return ledgercore.AccountData{}, round, nil
		}
		return *pad, round, nil
	}

	accountDataMap, err := l.il.LookupWithoutRewards(map[basics.Address]struct{}{address: {}})
	if err != nil {
		return ledgercore.AccountData{}, basics.Round(0), err
	}

	accountData := accountDataMap[address]
	if accountData == nil {
		return ledgercore.AccountData{}, round, nil
	}
	return *accountData, round, nil
}

func (l indexerLedgerConnector) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	r, err := l.lookupResource(rnd, addr, basics.CreatableIndex(aidx), basics.AppCreatable)
	return ledgercore.AppResource{AppParams: r.AppParams, AppLocalState: r.AppLocalState}, err
}

func (l indexerLedgerConnector) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	r, err := l.lookupResource(rnd, addr, basics.CreatableIndex(aidx), basics.AssetCreatable)
	return ledgercore.AssetResource{AssetParams: r.AssetParams, AssetHolding: r.AssetHolding}, err
}

func (l indexerLedgerConnector) lookupResource(round basics.Round, address basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (ledgercore.AccountResource, error) {
	// check to see if the account data in the cache.
	if creatableMap, ok := l.roundResources.Resources[address]; ok {
		if resource, ok := creatableMap[Creatable{aidx, ctype}]; ok {
			return resource, nil
		}
	}

	accountResourceMap, err :=
		l.il.LookupResources(map[basics.Address]map[Creatable]struct{}{address: {{aidx, ctype}: {}}})
	if err != nil {
		return ledgercore.AccountResource{}, err
	}

	return accountResourceMap[address][Creatable{aidx, ctype}], nil
}

func (l indexerLedgerConnector) LookupKv(rnd basics.Round, key string) (*string, error) {
	panic("not implemented")
}

// GetCreatorForRound is part of LedgerForEvaluator interface.
func (l indexerLedgerConnector) GetCreatorForRound(_ basics.Round, cindex basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	var foundAddress FoundAddress
	var has bool
	// check to see if the account data in the cache.
	if foundAddress, has = l.roundResources.Creators[Creatable{Index: cindex, Type: ctype}]; has {
		return foundAddress.Address, foundAddress.Exists, nil
	}

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

// GenesisProto is part of LedgerForEvaluator interface.
func (l indexerLedgerConnector) GenesisProto() config.ConsensusParams {
	return l.genesisProto
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

func makeIndexerLedgerConnector(il indexerLedgerForEval, genesisHash crypto.Digest, genesisProto config.ConsensusParams, latestRound basics.Round, roundResources EvalForIndexerResources) indexerLedgerConnector {
	return indexerLedgerConnector{
		il:             il,
		genesisHash:    genesisHash,
		genesisProto:   genesisProto,
		latestRound:    latestRound,
		roundResources: roundResources,
	}
}

// EvalForIndexer evaluates a block without validation using the given `proto`.
// Return the state delta and transactions with modified apply data according to `proto`.
// This function is used by Indexer which modifies `proto` to retrieve the asset
// close amount for each transaction even when the real consensus parameters do not
// support it.
func EvalForIndexer(il indexerLedgerForEval, block *bookkeeping.Block, proto config.ConsensusParams, resources EvalForIndexerResources) (ledgercore.StateDelta, []transactions.SignedTxnInBlock, error) {
	ilc := makeIndexerLedgerConnector(il, block.GenesisHash(), proto, block.Round()-1, resources)

	eval, err := internal.StartEvaluator(
		ilc, block.BlockHeader,
		internal.EvaluatorOptions{
			PaysetHint:  len(block.Payset),
			ProtoParams: &proto,
			Generate:    false,
			Validate:    false,
		})
	if err != nil {
		return ledgercore.StateDelta{}, []transactions.SignedTxnInBlock{},
			fmt.Errorf("EvalForIndexer() err: %w", err)
	}

	return eval.ProcessBlockForIndexer(block)
}
