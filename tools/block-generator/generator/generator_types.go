// Copyright (C) 2019-2025 Algorand, Inc.
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

package generator

import (
	"io"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	txn "github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// Generator is the interface needed to generate blocks.
type Generator interface {
	WriteReport(output io.Writer) error
	WriteGenesis(output io.Writer) error
	WriteBlock(output io.Writer, round basics.Round) error
	WriteAccount(output io.Writer, accountString string) error
	WriteDeltas(output io.Writer, round basics.Round) error
	WriteStatus(output io.Writer) error
	Stop()
}

type generator struct {
	verbose bool
	log     logging.Logger

	config GenerationConfig

	// payment transaction metadata
	numPayments uint64

	// Number of algorand accounts
	numAccounts uint64

	// Block stuff
	round         basics.Round
	txnCounter    uint64
	prevBlockHash string
	timestamp     int64
	protocol      protocol.ConsensusVersion
	params        config.ConsensusParams
	genesis       bookkeeping.Genesis
	genesisID     string
	genesisHash   crypto.Digest

	// Rewards stuff
	feeSink                   basics.Address
	rewardsPool               basics.Address
	rewardsLevel              uint64
	rewardsResidue            uint64
	rewardsRate               uint64
	rewardsRecalculationRound uint64

	// balances for all accounts. To avoid crypto and reduce storage, accounts are faked.
	// The account is based on the index into the balances array.
	balances []uint64

	// assets is a minimal representation of the asset holdings, it doesn't
	// include the frozen state.
	assets []*assetData
	// pendingAssets is used to hold newly created assets so that they are not used before
	// being created.
	pendingAssets []*assetData

	// pendingAppMap provides a live mapping from appID to appData for each appKind
	// for the current round
	pendingAppMap map[appKind]map[basics.AppIndex]*appData

	// pendingAppSlice provides a live slice of appData for each appKind. The reason
	// for maintaining both appMap and pendingAppSlice is to enable
	// randomly selecting an app to interact with and yet easily access it once
	// its identifier is known
	pendingAppSlice map[appKind][]*appData

	// appMap and appSlice store the information from their corresponding pending*
	// data structures at the end of each round and for the rest of the experiment
	appMap   map[appKind]map[basics.AppIndex]*appData
	appSlice map[appKind][]*appData

	// accountAppOptins is used to keep track of which accounts have opted into
	// an app and enable random selection.
	accountAppOptins map[appKind]map[uint64][]basics.AppIndex

	transactionWeights []float32

	payTxWeights   []float32
	assetTxWeights []float32
	appTxWeights   []float32

	// Reporting information from transaction type to data
	reportData Report
	// latestData keeps a count of how many transactions of each
	// txType occurred in the current round.
	latestData map[TxTypeID]uint64

	// ledger
	ledger *ledger.Ledger

	// latestBlockMsgp caches the latest written block
	latestBlockMsgp []byte

	// latestPaysetWithExpectedID provides the ordered payset transactions
	// together the expected asset/app IDs (or 0 if not applicable)
	latestPaysetWithExpectedID []txnWithExpectedID

	roundOffset basics.Round
}
type assetData struct {
	assetID basics.AssetIndex
	creator uint64
	name    string
	// Holding at index 0 is the creator.
	holdings []*assetHolding
	// Set of holders in the holdings array for easy reference.
	holders map[uint64]*assetHolding
}

type appData struct {
	appID  basics.AppIndex
	sender uint64
	kind   appKind
	optins map[uint64]bool
}

type assetHolding struct {
	acctIndex uint64
	balance   uint64
}

// Report is the generation report.
type Report struct {
	InitialRound basics.Round        `json:"initial_round"`
	Counters     map[string]uint64   `json:"counters"`
	Transactions map[TxTypeID]TxData `json:"transactions"`
}

// EffectsReport collates transaction counts caused by a root transaction.
type EffectsReport map[string]uint64

// TxData is the generator report data.
type TxData struct {
	GenerationTime  time.Duration `json:"generation_time_milli"`
	GenerationCount uint64        `json:"num_generated"`
}

// TxEffect summarizes a txn type count caused by a root transaction.
type TxEffect struct {
	effect string
	count  uint64
}

// txnWithExpectedID rolls up an expected asset/app ID for non-pay txns
// together with a signedTxn expected to be in the payset.
type txnWithExpectedID struct {
	expectedID uint64
	signedTxn  *txn.SignedTxn
	intra      uint64
	nextIntra  uint64
}
