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
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	"github.com/algorand/avm-abi/apps"
	"github.com/algorand/go-algorand/agreement"
	cconfig "github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	txn "github.com/algorand/go-algorand/data/transactions"
)

// ---- templates ----

//go:embed teal/poap_boxes.teal
var approvalBoxes string

//go:embed teal/poap_clear.teal
var clearBoxes string

//go:embed teal/swap_amm.teal
var approvalSwap string

//go:embed teal/swap_clear.teal
var clearSwap string

// ---- init ----

// effects is a map that contains the hard-coded non-trivial
// consequents of a transaction type:
//
// appBoxesCreate: 1 sibling payment tx
// appBoxesOptin: 1 sibling payment tx, 2 inner tx
var effects map[TxTypeID][]TxEffect

func init() {
	effects = map[TxTypeID][]TxEffect{
		appBoxesCreate: {
			{effectPaymentTxSibling, 1},
		},
		appBoxesOptin: {
			{effectPaymentTxSibling, 1},
			{effectInnerTx, 2},
		},
	}
}

// ---- constructors ----

// MakeGenerator initializes the Generator object.
func MakeGenerator(dbround uint64, bkGenesis bookkeeping.Genesis, config GenerationConfig, verbose bool) (Generator, error) {
	if err := config.validateWithDefaults(false); err != nil {
		return nil, fmt.Errorf("invalid generator configuration: %w", err)
	}

	var proto protocol.ConsensusVersion = "future"
	gen := &generator{
		verbose:                   verbose,
		config:                    config,
		protocol:                  proto,
		params:                    cconfig.Consensus[proto],
		genesis:                   bkGenesis,
		genesisHash:               [32]byte{},
		genesisID:                 "blockgen-test",
		prevBlockHash:             "",
		round:                     0,
		txnCounter:                startingTxnCounter,
		timestamp:                 0,
		rewardsLevel:              0,
		rewardsResidue:            0,
		rewardsRate:               0,
		rewardsRecalculationRound: 0,
		reportData:                make(map[TxTypeID]TxData),
		latestData:                make(map[TxTypeID]uint64),
		roundOffset:               dbround,
	}

	gen.feeSink[31] = 1
	gen.rewardsPool[31] = 2
	gen.genesisHash[31] = 3

	// if genesis is provided
	if bkGenesis.Network != "" {
		gen.genesisID = bkGenesis.ID()
		gen.genesisHash = bkGenesis.Hash()
	}

	gen.resetPendingApps()
	gen.appSlice = map[appKind][]*appData{
		appKindBoxes: make([]*appData, 0),
		appKindSwap:  make([]*appData, 0),
	}
	gen.appMap = map[appKind]map[uint64]*appData{
		appKindBoxes: make(map[uint64]*appData),
		appKindSwap:  make(map[uint64]*appData),
	}
	gen.accountAppOptins = map[appKind]map[uint64][]uint64{
		appKindBoxes: make(map[uint64][]uint64),
		appKindSwap:  make(map[uint64][]uint64),
	}

	gen.initializeAccounting()
	gen.initializeLedger()
	for _, val := range getTransactionOptions() {
		switch val {
		case paymentTx:
			gen.transactionWeights = append(gen.transactionWeights, config.PaymentTransactionFraction)
		case assetTx:
			gen.transactionWeights = append(gen.transactionWeights, config.AssetTransactionFraction)
		case applicationTx:
			gen.transactionWeights = append(gen.transactionWeights, config.AppTransactionFraction)

		}
	}
	if _, valid, err := validateSumCloseToOne(asPtrSlice(gen.transactionWeights)); err != nil || !valid {
		return gen, fmt.Errorf("invalid transaction config - bad txn distribution valid=%t: %w", valid, err)
	}

	for _, val := range getPaymentTxOptions() {
		switch val {
		case paymentAcctCreateTx:
			gen.payTxWeights = append(gen.payTxWeights, config.PaymentNewAccountFraction)
		case paymentPayTx:
			gen.payTxWeights = append(gen.payTxWeights, config.PaymentFraction)
		}
	}
	if _, valid, err := validateSumCloseToOne(asPtrSlice(gen.payTxWeights)); err != nil || !valid {
		return gen, fmt.Errorf("invalid payment config - bad txn distribution valid=%t: %w", valid, err)
	}

	for _, val := range getAssetTxOptions() {
		switch val {
		case assetCreate:
			gen.assetTxWeights = append(gen.assetTxWeights, config.AssetCreateFraction)
		case assetDestroy:
			gen.assetTxWeights = append(gen.assetTxWeights, config.AssetDestroyFraction)
		case assetOptin:
			gen.assetTxWeights = append(gen.assetTxWeights, config.AssetOptinFraction)
		case assetXfer:
			gen.assetTxWeights = append(gen.assetTxWeights, config.AssetXferFraction)
		case assetClose:
			gen.assetTxWeights = append(gen.assetTxWeights, config.AssetCloseFraction)
		}
	}
	if _, valid, err := validateSumCloseToOne(asPtrSlice(gen.assetTxWeights)); err != nil || !valid {
		return gen, fmt.Errorf("invalid asset config - bad txn distribution valid=%t: %w", valid, err)
	}

	for _, val := range getAppTxOptions() {
		switch val {
		case appSwapCreate:
			gen.appTxWeights = append(gen.appTxWeights, config.AppSwapFraction*config.AppSwapCreateFraction)
		case appSwapUpdate:
			gen.appTxWeights = append(gen.appTxWeights, config.AppSwapFraction*config.AppSwapUpdateFraction)
		case appSwapDelete:
			gen.appTxWeights = append(gen.appTxWeights, config.AppSwapFraction*config.AppSwapDeleteFraction)
		case appSwapOptin:
			gen.appTxWeights = append(gen.appTxWeights, config.AppSwapFraction*config.AppSwapOptinFraction)
		case appSwapCall:
			gen.appTxWeights = append(gen.appTxWeights, config.AppSwapFraction*config.AppSwapCallFraction)
		case appSwapClose:
			gen.appTxWeights = append(gen.appTxWeights, config.AppSwapFraction*config.AppSwapCloseFraction)
		case appSwapClear:
			gen.appTxWeights = append(gen.appTxWeights, config.AppSwapFraction*config.AppSwapClearFraction)
		case appBoxesCreate:
			gen.appTxWeights = append(gen.appTxWeights, config.AppBoxesFraction*config.AppBoxesCreateFraction)
		case appBoxesUpdate:
			gen.appTxWeights = append(gen.appTxWeights, config.AppBoxesFraction*config.AppBoxesUpdateFraction)
		case appBoxesDelete:
			gen.appTxWeights = append(gen.appTxWeights, config.AppBoxesFraction*config.AppBoxesDeleteFraction)
		case appBoxesOptin:
			gen.appTxWeights = append(gen.appTxWeights, config.AppBoxesFraction*config.AppBoxesOptinFraction)
		case appBoxesCall:
			gen.appTxWeights = append(gen.appTxWeights, config.AppBoxesFraction*config.AppBoxesCallFraction)
		case appBoxesClose:
			gen.appTxWeights = append(gen.appTxWeights, config.AppBoxesFraction*config.AppBoxesCloseFraction)
		case appBoxesClear:
			gen.appTxWeights = append(gen.appTxWeights, config.AppBoxesFraction*config.AppBoxesClearFraction)
		}
	}
	if _, valid, err := validateSumCloseToOne(asPtrSlice(gen.appTxWeights)); err != nil || !valid {
		return gen, fmt.Errorf("invalid app config - bad txn distribution valid=%t: %w", valid, err)
	}

	return gen, nil
}

func (g *generator) resetPendingApps() {
	g.pendingAppSlice = map[appKind][]*appData{
		appKindBoxes: make([]*appData, 0),
		appKindSwap:  make([]*appData, 0),
	}
	g.pendingAppMap = map[appKind]map[uint64]*appData{
		appKindBoxes: make(map[uint64]*appData),
		appKindSwap:  make(map[uint64]*appData),
	}
}

// initializeAccounting creates the genesis accounts.
func (g *generator) initializeAccounting() {
	g.numPayments = 0
	g.numAccounts = g.config.NumGenesisAccounts
	for i := uint64(0); i < g.config.NumGenesisAccounts; i++ {
		g.balances = append(g.balances, g.config.GenesisAccountInitialBalance)
	}
}

func (g *generator) initializeLedger() {
	genBal := convertToGenesisBalances(g.balances)
	// add rewards pool with min balance
	genBal[g.rewardsPool] = basics.AccountData{
		MicroAlgos: basics.MicroAlgos{Raw: g.params.MinBalance},
	}
	bal := bookkeeping.MakeGenesisBalances(genBal, g.feeSink, g.rewardsPool)
	block, err := bookkeeping.MakeGenesisBlock(g.protocol, bal, g.genesisID, g.genesisHash)
	if err != nil {
		fmt.Printf("error making genesis: %v\n.", err)
		os.Exit(1)
	}
	var prefix string
	if g.genesisID == "" {
		prefix = "block-generator"
	} else {
		prefix = g.genesisID
	}
	l, err := ledger.OpenLedger(logging.Base(), prefix, true, ledgercore.InitState{
		Block:       block,
		Accounts:    bal.Balances,
		GenesisHash: g.genesisHash,
	}, cconfig.GetDefaultLocal())
	if err != nil {
		fmt.Printf("error initializing ledger: %v\n.", err)
		os.Exit(1)
	}
	g.ledger = l
}

// ---- implement Generator interface ----

func (g *generator) WriteReport(output io.Writer) error {
	return json.NewEncoder(output).Encode(g.reportData)
}

// WriteGenesis writes the genesis file and advances the round.
func (g *generator) WriteGenesis(output io.Writer) error {
	defer g.recordData(track(genesis))

	// return user provided genesis
	if g.genesis.Network != "" {
		_, err := output.Write(protocol.EncodeJSON(g.genesis))
		return err
	}

	// return synthetic genesis
	var allocations []bookkeeping.GenesisAllocation
	for i := uint64(0); i < g.config.NumGenesisAccounts; i++ {
		addr := indexToAccount(i)
		allocations = append(allocations, bookkeeping.GenesisAllocation{
			Address: addr.String(),
			State: bookkeeping.GenesisAccountData{
				MicroAlgos: basics.MicroAlgos{Raw: g.config.GenesisAccountInitialBalance},
			},
		})
	}
	// Also add the rewards pool account with minimum balance. Without it, the evaluator
	// crashes.
	allocations = append(allocations, bookkeeping.GenesisAllocation{
		Address: g.rewardsPool.String(),
		Comment: "RewardsPool",
		State: bookkeeping.GenesisAccountData{
			MicroAlgos: basics.MicroAlgos{Raw: g.params.MinBalance},
			Status:     basics.NotParticipating,
		},
	})

	gen := bookkeeping.Genesis{
		SchemaID:    "v1",
		Network:     "generated-network",
		Proto:       g.protocol,
		Allocation:  allocations,
		RewardsPool: g.rewardsPool.String(),
		FeeSink:     g.feeSink.String(),
		Timestamp:   g.timestamp,
	}

	_, err := output.Write(protocol.EncodeJSON(gen))
	return err
}

// WriteBlock generates a block full of new transactions and writes it to the writer.
// The most recent round is cached, allowing requests to the same round multiple times.
// This is motivated by the fact that Conduit's logic requests the initial round during
// its Init() for catchup purposes, and once again when it starts ingesting blocks.
// There are a few constraints on the generator arising from the fact that
// blocks must be generated sequentially and that a fixed offset between the
// database round and the generator round is presumed:
//   - requested round < offset ---> error
//   - requested round == offset: the generator will provide a genesis block or offset block
//   - requested round == generator's round + offset ---> generate a block,
//     advance the round, and cache the block in case of repeated requests.
//   - requested round == generator's round + offset - 1 ---> write the cached block
//     but do not advance the round.
//   - requested round < generator's round + offset - 1 ---> error
//
// NOTE: nextRound represents the generator's expectations about the next database round.
func (g *generator) WriteBlock(output io.Writer, round uint64) error {
	if round < g.roundOffset {
		return fmt.Errorf("cannot generate block for round %d, already in database", round)
	}

	nextRound := g.round + g.roundOffset
	cachedRound := nextRound - 1

	if round != nextRound && round != cachedRound {
		return fmt.Errorf(
			"generator only supports sequential block access. Expected %d or %d but received request for %d",
			cachedRound,
			nextRound,
			round,
		)
	}
	// round must either be nextRound or cachedRound

	if round == cachedRound {
		// one round behind, so write the cached block (if non-empty)
		fmt.Printf("Received round request %d, but nextRound=%d. Not finishing round.\n", round, nextRound)
		if len(g.latestBlockMsgp) != 0 {
			// write the msgpack bytes for a block
			_, err := output.Write(g.latestBlockMsgp)
			if err != nil {
				return err
			}
		}
		return nil
	}
	// round == nextRound case

	err := g.startRound()
	if err != nil {
		return err
	}
	numTxnForBlock := g.txnForRound(g.round)

	var intra uint64 = 0
	var cert rpcs.EncodedBlockCert
	if g.round == 0 {
		// we'll write genesis block / offset round for non-empty database
		cert.Block, _, _ = g.ledger.BlockCert(basics.Round(round - g.roundOffset))
	} else {
		// generate a block
		cert.Block.BlockHeader = bookkeeping.BlockHeader{
			Round:          basics.Round(g.round),
			Branch:         bookkeeping.BlockHash{},
			Seed:           committee.Seed{},
			TxnCommitments: bookkeeping.TxnCommitments{NativeSha512_256Commitment: crypto.Digest{}},
			TimeStamp:      g.timestamp,
			GenesisID:      g.genesisID,
			GenesisHash:    g.genesisHash,
			RewardsState: bookkeeping.RewardsState{
				FeeSink:                   g.feeSink,
				RewardsPool:               g.rewardsPool,
				RewardsLevel:              0,
				RewardsRate:               0,
				RewardsResidue:            0,
				RewardsRecalculationRound: 0,
			},
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: g.protocol,
			},
			UpgradeVote:        bookkeeping.UpgradeVote{},
			StateProofTracking: nil,
		}

		// Generate the transactions
		transactions := []txn.SignedTxnInBlock{}
		for intra < numTxnForBlock {
			var signedTxns []txn.SignedTxn
			var ads []txn.ApplyData
			var err error
			signedTxns, ads, intra, err = g.generateSignedTxns(g.round, intra)
			if err != nil {
				// return err
				return fmt.Errorf("failed to generate transaction: %w", err)
			}
			if len(signedTxns) == 0 {
				return fmt.Errorf("failed to generate transaction: no transactions given")
			}
			if len(signedTxns) != len(ads) {
				return fmt.Errorf("failed to generate transaction: mismatched number of signed transactions (%d) and apply data (%d)", len(signedTxns), len(ads))
			}
			for i, stx := range signedTxns {
				stib, err := cert.Block.BlockHeader.EncodeSignedTxn(stx, ads[i])
				if err != nil {
					return fmt.Errorf("failed to encode transaction: %w", err)
				}
				transactions = append(transactions, stib)
			}
		}

		if intra < numTxnForBlock {
			return fmt.Errorf("not enough transactions generated: %d > %d", numTxnForBlock, intra)
		}

		cert.Block.BlockHeader.TxnCounter = g.txnCounter + intra
		cert.Block.Payset = transactions
		cert.Certificate = agreement.Certificate{} // empty certificate for clarity

		var errs []error
		err := g.ledger.AddBlock(cert.Block, cert.Certificate)
		if err != nil {
			errs = append(errs, fmt.Errorf("error in AddBlock: %w", err))
		}
		if g.verbose {
			errs2 := g.introspectLedgerVsGenerator(g.round, intra)
			if errs2 != nil {
				errs = append(errs, errs2...)
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("%d error(s): %v", len(errs), errs)
		}
	}
	cert.Block.BlockHeader.Round = basics.Round(round)

	// write the msgpack bytes for a block
	g.latestBlockMsgp = protocol.EncodeMsgp(&cert)
	_, err = output.Write(g.latestBlockMsgp)
	if err != nil {
		return err
	}

	g.finishRound()
	return nil
}

func (g *generator) WriteAccount(output io.Writer, accountString string) error {
	addr, err := basics.UnmarshalChecksumAddress(accountString)
	if err != nil {
		return fmt.Errorf("failed to unmarshal address: %w", err)
	}

	idx := accountToIndex(addr)

	// Asset Holdings
	assets := make([]model.AssetHolding, 0)
	createdAssets := make([]model.Asset, 0)
	for _, a := range g.assets {
		// holdings
		if holding := a.holders[idx]; holding != nil {
			assets = append(assets, model.AssetHolding{
				Amount:   holding.balance,
				AssetID:  a.assetID,
				IsFrozen: false,
			})
		}
		// creator
		if len(a.holdings) > 0 && a.holdings[0].acctIndex == idx {
			nameBytes := []byte(a.name)
			asset := model.Asset{
				Index: a.assetID,
				Params: model.AssetParams{
					Creator:  accountString,
					Decimals: 0,
					Clawback: &accountString,
					Freeze:   &accountString,
					Manager:  &accountString,
					Reserve:  &accountString,
					Name:     &a.name,
					NameB64:  &nameBytes,
					Total:    assetTotal,
				},
			}
			asset.Params.DefaultFrozen = new(bool)
			*(asset.Params.DefaultFrozen) = false
			createdAssets = append(createdAssets, asset)
		}
	}

	data := model.Account{
		Address:                     accountString,
		Amount:                      g.balances[idx],
		AmountWithoutPendingRewards: g.balances[idx],
		AppsLocalState:              nil,
		AppsTotalExtraPages:         nil,
		AppsTotalSchema:             nil,
		Assets:                      &assets,
		AuthAddr:                    nil,
		CreatedApps:                 nil,
		CreatedAssets:               &createdAssets,
		Participation:               nil,
		PendingRewards:              0,
		RewardBase:                  nil,
		Rewards:                     0,
		Round:                       g.round - 1,
		SigType:                     nil,
		Status:                      "Offline",
	}

	return json.NewEncoder(output).Encode(data)
}

// WriteDeltas generates returns the deltas for payset.
func (g *generator) WriteDeltas(output io.Writer, round uint64) error {
	// the first generated round has no statedelta.
	if round-g.roundOffset == 0 {
		data, _ := encode(protocol.CodecHandle, ledgercore.StateDelta{})
		_, err := output.Write(data)
		if err != nil {
			return err
		}
		return nil
	}
	delta, err := g.ledger.GetStateDeltaForRound(basics.Round(round - g.roundOffset))
	if err != nil {
		return fmt.Errorf("err getting state delta for round %d: %w", round, err)
	}
	// msgp encode deltas
	data, err := encode(protocol.CodecHandle, delta)
	if err != nil {
		return err
	}
	_, err = output.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func (g *generator) WriteStatus(output io.Writer) error {
	response := model.NodeStatusResponse{
		LastRound: g.round + g.roundOffset,
	}
	return json.NewEncoder(output).Encode(response)
}

// Stop cleans up allocated resources.
func (g *generator) Stop() {
	g.ledger.Close()
}

// ---- transaction options vectors ----

func getTransactionOptions() []interface{} {
	return []interface{}{paymentTx, assetTx, applicationTx}
}

func getPaymentTxOptions() []interface{} {
	return []interface{}{paymentAcctCreateTx, paymentPayTx}
}

func getAssetTxOptions() []interface{} {
	return []interface{}{assetCreate, assetDestroy, assetOptin, assetClose, assetXfer}
}

func getAppTxOptions() []interface{} {
	return []interface{}{
		appSwapCreate, appSwapUpdate, appSwapDelete, appSwapOptin, appSwapCall, appSwapClose, appSwapClear,
		appBoxesCreate, appBoxesUpdate, appBoxesDelete, appBoxesOptin, appBoxesCall, appBoxesClose, appBoxesClear,
	}
}

// ---- Transaction Generation (Pay/Asset/Apps) ----

func (g *generator) generateSignedTxns(round uint64, intra uint64) ([]txn.SignedTxn, []txn.ApplyData, uint64 /* nextIntra */, error) {
	// TODO: return the number of transactions generated instead of updating intra!!!
	selection, err := weightedSelection(g.transactionWeights, getTransactionOptions(), paymentTx)
	if err != nil {
		return nil, nil, intra, err
	}

	var signedTxns []txn.SignedTxn
	var ads []txn.ApplyData
	var nextIntra uint64
	var expectedID uint64
	switch selection {
	case paymentTx:
		var signedTxn txn.SignedTxn
		var ad txn.ApplyData
		signedTxn, ad, nextIntra, err = g.generatePaymentTxn(round, intra)
		signedTxns = []txn.SignedTxn{signedTxn}
		ads = []txn.ApplyData{ad}
	case assetTx:
		var signedTxn txn.SignedTxn
		var ad txn.ApplyData
		signedTxn, ad, nextIntra, expectedID, err = g.generateAssetTxn(round, intra)
		signedTxns = []txn.SignedTxn{signedTxn}
		ads = []txn.ApplyData{ad}
	case applicationTx:
		signedTxns, ads, nextIntra, expectedID, err = g.generateAppTxn(round, intra)
	default:
		return nil, nil, intra, fmt.Errorf("no generator available for %s", selection)
	}

	if err != nil {
		return nil, nil, intra, fmt.Errorf("error generating transaction: %w", err)
	}

	if len(signedTxns) == 0 {
		return nil, nil, intra, fmt.Errorf("no transactions generated")
	}

	for i := range signedTxns {
		g.latestPaysetWithExpectedID = append(
			g.latestPaysetWithExpectedID,
			txnWithExpectedID{
				expectedID: expectedID,
				signedTxn:  &signedTxns[i],
				intra:      intra,
				nextIntra:  nextIntra,
			},
		)
	}
	return signedTxns, ads, nextIntra, nil
}

// ---- 1. Pay Transactions ----

// generatePaymentTxn creates a new payment transaction. The sender is always a genesis account, the receiver is random,
// or a new account.
func (g *generator) generatePaymentTxn(round uint64, intra uint64) (txn.SignedTxn, txn.ApplyData, uint64 /* nextIntra */, error) {
	selection, err := weightedSelection(g.payTxWeights, getPaymentTxOptions(), paymentPayTx)
	if err != nil {
		return txn.SignedTxn{}, txn.ApplyData{}, intra, err
	}
	return g.generatePaymentTxnInternal(selection.(TxTypeID), round, intra)
}

func (g *generator) generatePaymentTxnInternal(selection TxTypeID, round uint64, intra uint64) (txn.SignedTxn, txn.ApplyData, uint64 /* nextIntra */, error) {
	defer g.recordData(track(selection))
	minBal := g.params.MinBalance

	// default amount
	amount := uint64(1)

	// Select a receiver
	var receiveIndex uint64
	switch selection {
	case paymentPayTx:
		receiveIndex = rand.Uint64() % g.numAccounts
	case paymentAcctCreateTx:
		// give new accounts get extra algos for sending other transactions
		amount = minBal * 100
		g.balances = append(g.balances, 0)
		receiveIndex = g.numAccounts
		g.numAccounts++
	}
	total := amount + g.params.MinTxnFee

	// Select a sender from genesis account
	sendIndex := g.numPayments % g.config.NumGenesisAccounts
	if g.balances[sendIndex] < (total + minBal) {
		fmt.Printf("\n\ngeneratePaymentTxnInternal(): the sender account does not have enough algos for the transfer. idx %d, payment number %d\n\n", sendIndex, g.numPayments)
		os.Exit(1)
	}

	sender := indexToAccount(sendIndex)
	receiver := indexToAccount(receiveIndex)

	g.balances[sendIndex] -= total
	g.balances[receiveIndex] += amount

	g.numPayments++

	transaction := g.makePaymentTxn(g.makeTxnHeader(sender, round, intra), receiver, amount, basics.Address{})
	return signTxn(transaction), txn.ApplyData{}, intra + 1, nil
}

// ---- 2. Asset Transactions ----

func (g *generator) generateAssetTxn(round uint64, intra uint64) (txn.SignedTxn, txn.ApplyData, uint64 /* nextIntra */, uint64 /* assetID */, error) {
	start := time.Now()
	selection, err := weightedSelection(g.assetTxWeights, getAssetTxOptions(), assetXfer)
	if err != nil {
		return txn.SignedTxn{}, txn.ApplyData{}, intra, 0, err
	}

	actual, transaction, assetID := g.generateAssetTxnInternal(selection.(TxTypeID), round, intra)
	defer g.recordData(actual, start)

	if transaction.Type == "" {
		fmt.Println("Empty asset transaction.")
		os.Exit(1)
	}

	return signTxn(transaction), txn.ApplyData{}, intra + 1, assetID, nil
}

func (g *generator) generateAssetTxnInternal(txType TxTypeID, round uint64, intra uint64) (actual TxTypeID, txn txn.Transaction, assetID uint64) {
	return g.generateAssetTxnInternalHint(txType, round, intra, 0, nil)
}

func (g *generator) generateAssetTxnInternalHint(txType TxTypeID, round uint64, intra uint64, hintIndex uint64, hint *assetData) (actual TxTypeID, txn txn.Transaction, assetID uint64) {
	actual = txType
	// If there are no assets the next operation needs to be a create.
	numAssets := uint64(len(g.assets))

	if numAssets == 0 {
		actual = assetCreate
	}
	var senderIndex uint64
	if actual == assetCreate {
		numAssets += uint64(len(g.pendingAssets))
		senderIndex = numAssets % g.config.NumGenesisAccounts
		senderAcct := indexToAccount(senderIndex)

		total := assetTotal
		assetID = g.txnCounter + intra + 1
		assetName := fmt.Sprintf("asset #%d", assetID)
		txn = g.makeAssetCreateTxn(g.makeTxnHeader(senderAcct, round, intra), total, false, assetName)
		// Compute asset ID and initialize holdings
		holding := assetHolding{
			acctIndex: senderIndex,
			balance:   total,
		}
		a := assetData{
			name:     assetName,
			assetID:  assetID,
			creator:  senderIndex,
			holdings: []*assetHolding{&holding},
			holders:  map[uint64]*assetHolding{senderIndex: &holding},
		}

		g.pendingAssets = append(g.pendingAssets, &a)
	} else {
		var assetIndex uint64
		var asset *assetData
		if hint != nil {
			assetIndex = hintIndex
			asset = hint
		} else {
			assetIndex = rand.Uint64() % numAssets
			asset = g.assets[assetIndex]
		}

		switch actual {
		case assetDestroy:
			// delete asset

			// If the creator doesn't have all of them, close instead
			if asset.holdings[0].balance != assetTotal {
				return g.generateAssetTxnInternalHint(assetClose, round, intra, assetIndex, asset)
			}

			senderIndex = asset.creator
			creator := indexToAccount(senderIndex)
			assetID = asset.assetID
			txn = g.makeAssetDestroyTxn(g.makeTxnHeader(creator, round, intra), assetID)

			// Remove asset by moving the last element to the deleted index then trimming the slice.
			g.assets[assetIndex] = g.assets[numAssets-1]
			g.assets = g.assets[:numAssets-1]
		case assetOptin:
			// select a random account from asset to optin

			// If every account holds the asset, close instead of optin
			if uint64(len(asset.holdings)) == g.numAccounts {
				return g.generateAssetTxnInternalHint(assetClose, round, intra, assetIndex, asset)
			}

			// look for an account that does not hold the asset
			exists := true
			for exists {
				senderIndex = rand.Uint64() % g.numAccounts
				exists = asset.holders[senderIndex] != nil
			}
			account := indexToAccount(senderIndex)
			assetID = asset.assetID
			txn = g.makeAssetAcceptanceTxn(g.makeTxnHeader(account, round, intra), assetID)

			holding := assetHolding{
				acctIndex: senderIndex,
				balance:   0,
			}
			asset.holdings = append(asset.holdings, &holding)
			asset.holders[senderIndex] = &holding
		case assetXfer:
			// send from creator (holder[0]) to another random holder (same address is valid)

			// If there aren't enough assets to close one, optin an account instead
			if len(asset.holdings) == 1 {
				return g.generateAssetTxnInternalHint(assetOptin, round, intra, assetIndex, asset)
			}

			senderIndex = asset.holdings[0].acctIndex
			sender := indexToAccount(senderIndex)

			receiverArrayIndex := (rand.Uint64() % (uint64(len(asset.holdings)) - uint64(1))) + uint64(1)
			receiver := indexToAccount(asset.holdings[receiverArrayIndex].acctIndex)
			amount := uint64(10)

			assetID = asset.assetID
			txn = g.makeAssetTransferTxn(g.makeTxnHeader(sender, round, intra), receiver, amount, basics.Address{}, assetID)

			if asset.holdings[0].balance < amount {
				fmt.Printf("\n\ncreator doesn't have enough funds for asset %d\n\n", assetID)
				os.Exit(1)
			}
			if g.balances[asset.holdings[0].acctIndex] < g.params.MinTxnFee {
				fmt.Printf("\n\ncreator doesn't have enough funds for transaction %d\n\n", assetID)
				os.Exit(1)
			}

			asset.holdings[0].balance -= amount
			asset.holdings[receiverArrayIndex].balance += amount
		case assetClose:
			// select a holder of a random asset to close out
			// If there aren't enough assets to close one, optin an account instead
			if len(asset.holdings) == 1 {
				return g.generateAssetTxnInternalHint(
					assetOptin, round, intra, assetIndex, asset)
			}

			numHoldings := uint64(len(asset.holdings))
			closeIndex := (rand.Uint64() % (numHoldings - 1)) + uint64(1)
			senderIndex = asset.holdings[closeIndex].acctIndex
			sender := indexToAccount(senderIndex)

			closeToAcctIndex := asset.holdings[0].acctIndex
			closeToAcct := indexToAccount(closeToAcctIndex)

			assetID = asset.assetID
			txn = g.makeAssetTransferTxn(
				g.makeTxnHeader(sender, round, intra), closeToAcct, 0, closeToAcct, assetID)

			asset.holdings[0].balance += asset.holdings[closeIndex].balance

			// Remove asset by moving the last element to the deleted index then trimming the slice.
			asset.holdings[closeIndex] = asset.holdings[numHoldings-1]
			asset.holdings = asset.holdings[:numHoldings-1]
			delete(asset.holders, senderIndex)
		default:
		}
	}

	if indexToAccount(senderIndex) != txn.Sender {
		fmt.Printf("failed to properly set sender index.")
		os.Exit(1)
	}

	if g.balances[senderIndex] < txn.Fee.ToUint64() {
		fmt.Printf("\n\nthe sender account does not have enough algos for the transfer. idx %d, asset transaction type %v, num %d\n\n", senderIndex, actual, g.reportData[actual].GenerationCount)
		os.Exit(1)
	}

	if assetID == 0 {
		fmt.Printf("\n\nassetID is 0 but should have been set by \ngenerateAssetTxnInternalHint(txType=%s, round=%d, intra=%d, hintIndex=%d, hintIsNil=%t)\nactual=%s\n\n",
			txType, round, intra, hintIndex, hint == nil, actual)
		os.Exit(1)
	}

	g.balances[senderIndex] -= txn.Fee.ToUint64()

	return
}

// ---- 3. App Transactions ----

func (g *generator) generateAppTxn(round uint64, intra uint64) ([]txn.SignedTxn, []txn.ApplyData, uint64 /* nextIntra */, uint64 /* appID */, error) {
	start := time.Now()
	selection, err := weightedSelection(g.appTxWeights, getAppTxOptions(), appSwapCall)
	if err != nil {
		return nil, nil, intra, 0, err
	}

	actual, signedTxns, appID, err := g.generateAppCallInternal(selection.(TxTypeID), round, intra, nil)
	if err != nil {
		return nil, nil, intra, appID, fmt.Errorf("unexpected error received from generateAppCallInternal(): %w", err)
	}

	if _, ok := effects[actual]; ok {
		txCount, err := g.countAndRecordEffects(actual, start)
		intra += txCount
		if err != nil {
			return nil, nil, intra, appID, fmt.Errorf("failed to record app transaction %s: %w", actual, err)
		}
	} else { // no effects for actual, so exactly 1 transaction
		g.recordData(actual, start)
		intra++
	}

	ads := make([]txn.ApplyData, len(signedTxns))
	for i := range signedTxns {
		ads[i] = txn.ApplyData{}
	}

	return signedTxns, ads, intra, appID, nil
}

// generateAppCallInternal is the main workhorse for generating app transactions.
// Senders are always genesis accounts, to avoid running out of funds.
func (g *generator) generateAppCallInternal(txType TxTypeID, round, intra uint64, hintApp *appData) (TxTypeID, []txn.SignedTxn, uint64 /* appID */, error) {
	var senderIndex uint64
	if hintApp != nil {
		senderIndex = hintApp.sender
	} else {
		senderIndex = rand.Uint64() % g.config.NumGenesisAccounts
	}
	senderAcct := indexToAccount(senderIndex)

	actual, kind, appCallType, appID, err := g.getActualAppCall(txType, senderIndex)
	if err != nil {
		return "", nil, appID, err
	}
	if hintApp != nil && hintApp.appID != 0 {
		// can only override the appID when non-zero in hintApp
		appID = hintApp.appID
	}
	// WLOG: the matched cases below are now well-defined thanks to getActualAppCall()

	var signedTxns []txn.SignedTxn
	switch appCallType {
	case appTxTypeCreate:
		appID = g.txnCounter + intra + 1
		signedTxns = g.makeAppCreateTxn(kind, senderAcct, round, intra, appID)
		reSignTxns(signedTxns)

		for k := range g.appMap {
			if g.appMap[k][appID] != nil {
				return "", nil, appID, fmt.Errorf("should never happen! app %d already exists for kind %s", appID, k)
			}
			if g.pendingAppMap[k][appID] != nil {
				return "", nil, appID, fmt.Errorf("should never happen! app %d already pending for kind %s", appID, k)
			}
		}

		ad := &appData{
			appID:  appID,
			sender: senderIndex,
			kind:   kind,
			optins: map[uint64]bool{},
		}

		g.pendingAppSlice[kind] = append(g.pendingAppSlice[kind], ad)
		g.pendingAppMap[kind][appID] = ad

	case appTxTypeOptin:
		signedTxns = g.makeAppOptinTxn(senderAcct, round, intra, kind, appID)
		reSignTxns(signedTxns)
		if g.pendingAppMap[kind][appID] == nil {
			ad := &appData{
				appID:  appID,
				sender: senderIndex,
				kind:   kind,
				optins: map[uint64]bool{},
			}
			g.pendingAppMap[kind][appID] = ad
			g.pendingAppSlice[kind] = append(g.pendingAppSlice[kind], ad)
		}
		g.pendingAppMap[kind][appID].optins[senderIndex] = true

	case appTxTypeCall:
		signedTxns = []txn.SignedTxn{
			signTxn(g.makeAppCallTxn(senderAcct, round, intra, appID)),
		}

	default:
		return "", nil, appID, fmt.Errorf("unimplemented: invalid transaction type <%s> for app %d", appCallType, appID)
	}

	return actual, signedTxns, appID, nil
}

func (g *generator) getAppData(existing bool, kind appKind, senderIndex, appID uint64) (*appData, bool /* appInMap */, bool /* senderOptedin */) {
	var appMapOrPendingAppMap map[appKind]map[uint64]*appData
	if existing {
		appMapOrPendingAppMap = g.appMap
	} else {
		appMapOrPendingAppMap = g.pendingAppMap
	}

	ad, ok := appMapOrPendingAppMap[kind][appID]
	if !ok {
		return nil, false, false
	}
	if !ad.optins[senderIndex] {
		return ad, true, false
	}
	return ad, true, true
}

// getActualAppCall returns the actual transaction type, app kind, app transaction type and appID
// * it returns actual = txType if there aren't any problems (for example create always is kept)
// * it creates the app if the app of the given kind doesn't exist
// * it switches to noopoc instead of optin when already opted into existing apps
// * it switches to create instead of optin when only opted into pending apps
// * it switches to optin when noopoc if not opted in and follows the logic of the optins above
// * the appID is 0 for creates, and otherwise a random appID from the existing apps for the kind
func (g *generator) getActualAppCall(txType TxTypeID, senderIndex uint64) (TxTypeID, appKind, appTxType, uint64 /* appID */, error) {
	isApp, kind, appTxType, err := parseAppTxType(txType)
	if err != nil {
		return "", 0, 0, 0, err
	}
	if !isApp {
		return "", 0, 0, 0, fmt.Errorf("should be an app but not parsed that way: %v", txType)
	}

	// creates get a quick pass:
	if appTxType == appTxTypeCreate {
		return txType, kind, appTxTypeCreate, 0, nil
	}

	numAppsForKind := uint64(len(g.appSlice[kind]))
	if numAppsForKind == 0 {
		// can't do anything else with the app if it doesn't exist, so must create it first!!!
		return getAppTxType(kind, appTxTypeCreate), kind, appTxTypeCreate, 0, nil
	}

	if appTxType == appTxTypeOptin {
		// pick a random app to optin:
		appID := g.appSlice[kind][rand.Uint64()%numAppsForKind].appID

		_, exists, optedIn := g.getAppData(true /* existing */, kind, senderIndex, appID)
		if !exists {
			return txType, kind, appTxType, appID, fmt.Errorf("should never happen! app %d of kind %s does not exist", appID, kind)
		}

		if optedIn {
			// already optedin, so call the app instead:
			return getAppTxType(kind, appTxTypeCall), kind, appTxTypeCall, appID, nil
		}

		_, _, optedInPending := g.getAppData(false /* pending */, kind, senderIndex, appID)
		if optedInPending {
			// about to get opted in, but can't optin twice or call yet, so create:
			return getAppTxType(kind, appTxTypeCreate), kind, appTxTypeCreate, appID, nil
		}
		// not opted in or pending, so optin:
		return txType, kind, appTxType, appID, nil
	}

	if appTxType != appTxTypeCall {
		return "", 0, 0, 0, fmt.Errorf("unimplemented transaction type for app %s from %s", appTxType, txType)
	}
	// WLOG appTxTypeCall:

	numAppsOptedin := uint64(len(g.accountAppOptins[kind][senderIndex]))
	if numAppsOptedin == 0 {
		// try again calling recursively but attempting to optin:
		return g.getActualAppCall(getAppTxType(kind, appTxTypeOptin), senderIndex)
	}
	// WLOG appTxTypeCall with available optins:

	appID := g.accountAppOptins[kind][senderIndex][rand.Uint64()%numAppsOptedin]
	return txType, kind, appTxType, appID, nil
}

// ---- metric data recorders ----

func track(id TxTypeID) (TxTypeID, time.Time) {
	return id, time.Now()
}

func (g *generator) recordData(id TxTypeID, start time.Time) {
	g.recordOccurrences(id, 1, start)
}

func (g *generator) recordOccurrences(id TxTypeID, count uint64, start time.Time) {
	g.latestData[id] += count
	data := g.reportData[id]
	data.GenerationCount += count
	data.GenerationTime += time.Since(start)
	g.reportData[id] = data
}

func (g *generator) countAndRecordEffects(id TxTypeID, start time.Time) (uint64, error) {
	g.recordData(id, start) // this may be a bug!!!
	count := uint64(1)
	if consequences, ok := effects[id]; ok {
		for _, effect := range consequences {
			count += effect.count
			g.recordOccurrences(effect.txType, effect.count, start)
		}
		return count, nil
	}
	return 1, fmt.Errorf("no effects for TxTypeId %v", id)
}

// ---- miscellaneous ----

func (g *generator) txnForRound(round uint64) uint64 {
	// There are no transactions in the 0th round
	if round == 0 {
		return 0
	}
	return g.config.TxnPerBlock
}

// startRound updates the generator's txnCounter based on the latest block header.
// It is assumed that g.round has already been incremented in finishRound()
func (g *generator) startRound() error {
	if g.round == 0 {
		// nothing to do in round 0
		return nil
	}

	latestHeader, err := g.ledger.BlockHdr(basics.Round(g.round - 1))
	if err != nil {
		return fmt.Errorf("Could not obtain block header for round %d: %w", g.round, err)
	}
	g.txnCounter = latestHeader.TxnCounter
	return nil
}

// finishRound tells the generator it can apply any pending state and updates its round
func (g *generator) finishRound() {
	g.timestamp += consensusTimeMilli
	g.round++

	// Apply pending assets...
	g.assets = append(g.assets, g.pendingAssets...)
	g.pendingAssets = nil

	g.latestPaysetWithExpectedID = nil
	g.latestData = make(map[TxTypeID]uint64)

	for kind, pendingAppSlice := range g.pendingAppSlice {
		for _, pendingApp := range pendingAppSlice {
			appID := pendingApp.appID
			if g.appMap[kind][appID] == nil {
				g.appSlice[kind] = append(g.appSlice[kind], pendingApp)
				g.appMap[kind][appID] = pendingApp
				for sender := range pendingApp.optins {
					g.accountAppOptins[kind][sender] = append(g.accountAppOptins[kind][sender], appID)
				}
			} else { // just union the optins when already exists
				for sender := range pendingApp.optins {
					g.appMap[kind][appID].optins[sender] = true
					g.accountAppOptins[kind][sender] = append(g.accountAppOptins[kind][sender], appID)
				}
			}
		}
	}
	g.resetPendingApps()
}

func signTxn(transaction txn.Transaction) txn.SignedTxn {
	stxn := txn.SignedTxn{
		Msig:     crypto.MultisigSig{},
		Lsig:     txn.LogicSig{},
		Txn:      transaction,
		AuthAddr: basics.Address{},
	}

	addSignature(&stxn)

	return stxn
}

func addSignature(stxn *txn.SignedTxn) {
	stxn.Sig = crypto.Signature{}
	// TODO: Would it be useful to generate a random signature?
	stxn.Sig[32] = 50
}

func reSignTxns(signedTxns []txn.SignedTxn) {
	for i := range signedTxns {
		addSignature(&signedTxns[i])
	}
}

func (g *generator) introspectLedgerVsGenerator(roundNumber, intra uint64) (errs []error) {
	round := basics.Round(roundNumber)
	block, err := g.ledger.Block(round)
	if err != nil {
		round = err.(ledgercore.ErrNoEntry).Committed
		fmt.Printf("WARNING: inconsistent generator v. ledger state. Reset round=%d: %v\n", round, err)
		errs = append(errs, err)
	}

	ledgerStateDeltas, err := g.ledger.GetStateDeltaForRound(round)
	if err != nil {
		errs = append(errs, err)
	}

	cumulative := make(map[TxTypeID]uint64)
	for ttID, data := range g.reportData {
		cumulative[ttID] = data.GenerationCount
	}

	sum := uint64(0)
	for ttID, cnt := range cumulative {
		if ttID == genesis {
			continue
		}
		sum += cnt
	}
	fmt.Print("--------------------\n")
	fmt.Printf("roundNumber (generator): %d\n", roundNumber)
	fmt.Printf("round (ledger): %d\n", round)
	fmt.Printf("g.txnCounter + intra: %d\n", g.txnCounter+intra)
	fmt.Printf("block.BlockHeader.TxnCounter: %d\n", block.BlockHeader.TxnCounter)
	fmt.Printf("len(g.latestPaysetWithExpectedID): %d\n", len(g.latestPaysetWithExpectedID))
	fmt.Printf("g.latestData: %+v\n", g.latestData)
	fmt.Printf("cumuluative : %+v\n", cumulative)
	fmt.Printf("all txn sum: %d\n", sum)
	fmt.Print("--------------------\n")

	// ---- FROM THE LEDGER: box and createable evidence ---- //

	ledgerBoxEvidenceCount := 0
	ledgerBoxEvidence := make(map[uint64][]uint64)
	boxes := ledgerStateDeltas.KvMods
	for k := range boxes {
		appID, nameIEsender, _ := apps.SplitBoxKey(k)
		ledgerBoxEvidence[appID] = append(ledgerBoxEvidence[appID], binary.LittleEndian.Uint64([]byte(nameIEsender))-1)
		ledgerBoxEvidenceCount++
	}

	// TODO: can get richer info about app-Creatables from:
	// updates.Accts.AppResources
	ledgerCreatableAppsEvidence := make(map[uint64]uint64)
	for creatableID, creatable := range ledgerStateDeltas.Creatables {
		if creatable.Ctype == basics.AppCreatable {
			ledgerCreatableAppsEvidence[uint64(creatableID)] = accountToIndex(creatable.Creator)
		}
	}
	fmt.Printf("ledgerBoxEvidenceCount: %d\n", ledgerBoxEvidenceCount)
	fmt.Printf("ledgerCreatableAppsEvidence: %d\n", len(ledgerCreatableAppsEvidence))

	// ---- FROM THE GENERATOR: expected created and optins ---- //

	expectedCreated := map[appKind]map[uint64]uint64{
		appKindBoxes: make(map[uint64]uint64),
		appKindSwap:  make(map[uint64]uint64),
	}
	expectedOptins := map[appKind]map[uint64]map[uint64]bool{
		appKindBoxes: make(map[uint64]map[uint64]bool),
		appKindSwap:  make(map[uint64]map[uint64]bool),
	}

	expectedOptinsCount := 0
	for kind, appMap := range g.pendingAppMap {
		for appID, ad := range appMap {
			if len(ad.optins) > 0 {
				expectedOptins[kind][appID] = ad.optins
				expectedOptinsCount += len(ad.optins)
			} else {
				expectedCreated[kind][appID] = ad.sender
			}
		}
	}
	fmt.Printf("expectedCreatedCount: %d\n", len(expectedCreated[appKindBoxes]))
	fmt.Printf("expectedOptinsCount: %d\n", expectedOptinsCount)

	// ---- COMPARE LEDGER AND GENERATOR EVIDENCE ---- //

	ledgerCreatablesUnexpected := map[uint64]uint64{}
	for creatableID, creator := range ledgerCreatableAppsEvidence {
		if expectedCreated[appKindSwap][creatableID] != creator && expectedCreated[appKindBoxes][creatableID] != creator {
			ledgerCreatablesUnexpected[creatableID] = creator
		}
	}
	generatorExpectedCreatablesNotFound := map[uint64]uint64{}
	for creatableID, creator := range expectedCreated[appKindBoxes] {
		if ledgerCreatableAppsEvidence[creatableID] != creator {
			generatorExpectedCreatablesNotFound[creatableID] = creator
		}
	}

	ledgerBoxOptinsUnexpected := map[uint64][]uint64{}
	for appId, boxOptins := range ledgerBoxEvidence {
		for _, optin := range boxOptins {
			if _, ok := expectedOptins[appKindBoxes][appId][optin]; !ok {
				ledgerBoxOptinsUnexpected[appId] = append(ledgerBoxOptinsUnexpected[appId], optin)
			}
		}
	}

	generatorExpectedOptinsNotFound := map[uint64][]uint64{}
	for appId, appOptins := range expectedOptins[appKindBoxes] {
		for optin := range appOptins {
			missing := true
			for _, boxOptin := range ledgerBoxEvidence[appId] {
				if boxOptin == optin {
					missing = false
					break
				}
			}
			if missing {
				generatorExpectedOptinsNotFound[appId] = append(generatorExpectedOptinsNotFound[appId], optin)
			}
		}
	}

	fmt.Printf("ledgerCreatablesUnexpected: %+v\n", ledgerCreatablesUnexpected)
	fmt.Printf("generatorExpectedCreatablesNotFound: %+v\n", generatorExpectedCreatablesNotFound)
	fmt.Printf("ledgerBoxOptinsUnexpected: %+v\n", ledgerBoxOptinsUnexpected)
	fmt.Printf("expectedOptinsNotFound: %+v\n", generatorExpectedOptinsNotFound)
	return errs
}
