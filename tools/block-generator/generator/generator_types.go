// Copyright (C) 2019-2023 Algorand, Inc.
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
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/protocol"
)

// Generator is the interface needed to generate blocks.
type Generator interface {
	WriteReport(output io.Writer) error
	WriteGenesis(output io.Writer) error
	WriteBlock(output io.Writer, round uint64) error
	WriteAccount(output io.Writer, accountString string) error
	WriteDeltas(output io.Writer, round uint64) error
	WriteStatus(output io.Writer) error
	Stop()
}

type generator struct {
	config GenerationConfig

	// payment transaction metadata
	numPayments uint64

	// Number of algorand accounts
	numAccounts uint64

	// Block stuff
	round         uint64
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

	// apps is a minimal representation of the app holdings
	apps map[appKind][]*appData
	// pendingApps is used to hold newly created apps so that they are not used before
	// being created.
	pendingApps map[appKind][]*appData

	transactionWeights []float32

	payTxWeights   []float32
	assetTxWeights []float32
	appTxWeights   []float32

	// Reporting information from transaction type to data
	reportData Report

	// ledger
	ledger *ledger.Ledger

	// cache the latest written block
	latestBlockMsgp []byte

	roundOffset uint64
}

type assetData struct {
	assetID uint64
	creator uint64
	name    string
	// Holding at index 0 is the creator.
	holdings []*assetHolding
	// Set of holders in the holdings array for easy reference.
	holders map[uint64]*assetHolding
}

type appData struct {
	appID   uint64
	creator uint64
	kind    appKind
	// Holding at index 0 is the creator.
	holdings []*appHolding
	// Set of holders in the holdings array for easy reference.
	holders map[uint64]*appHolding
	// TODO: more data, not sure yet exactly what
}

type assetHolding struct {
	acctIndex uint64
	balance   uint64
}

type appHolding struct {
	appIndex uint64
	// TODO: more data, not sure yet exactly what
}

// Report is the generation report.
type Report map[TxTypeID]TxData

// TxData is the generator report data.
type TxData struct {
	GenerationTime  time.Duration `json:"generation_time_milli"`
	GenerationCount uint64        `json:"num_generated"`
}
