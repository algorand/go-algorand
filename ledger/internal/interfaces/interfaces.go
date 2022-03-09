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

package interfaces

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)
// LedgerForCowBase represents subset of Ledger functionality needed for cow business
type LedgerForCowBase interface {
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error
	LookupWithoutRewards(basics.Round, basics.Address) (ledgercore.AccountData, basics.Round, error)
	LookupAsset(basics.Round, basics.Address, basics.AssetIndex) (ledgercore.AssetResource, error)
	LookupApplication(basics.Round, basics.Address, basics.AppIndex) (ledgercore.AppResource, error)
	GetCreatorForRound(basics.Round, basics.CreatableIndex, basics.CreatableType) (basics.Address, bool, error)
}

// LedgerForEvaluator defines the ledger interface needed by the evaluator.
type LedgerForEvaluator interface {
	LedgerForCowBase
	GenesisHash() crypto.Digest
	GenesisProto() config.ConsensusParams
	LatestTotals() (basics.Round, ledgercore.AccountTotals, error)
	CompactCertVoters(basics.Round) (*ledgercore.VotersForRound, error)
}
