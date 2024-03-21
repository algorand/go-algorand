// Copyright (C) 2019-2024 Algorand, Inc.
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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	cconfig "github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	txn "github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

const (
	BlockTotalSizeBytes    = "blocks_total_size_bytes"
	CommitWaitTimeMS       = "commit_wait_time_ms"
	BlockgenGenerateTimeMS = "blockgen_generate_time_ms"
	LedgerEvalTimeMS       = "ledger_eval_time_ms"
	LedgerValidateTimeMS   = "ledger_validate_time_ms"
)

// ---- constructors ----

// MakeGenerator initializes the Generator object.
func MakeGenerator(log logging.Logger, dbround uint64, bkGenesis bookkeeping.Genesis, config GenerationConfig, verbose bool) (Generator, error) {
	if err := config.validateWithDefaults(false); err != nil {
		return nil, fmt.Errorf("invalid generator configuration: %w", err)
	}

	if log == nil {
		log = logging.Base()
	}

	var proto protocol.ConsensusVersion = "future"
	gen := &generator{
		verbose:                   verbose,
		log:                       log,
		config:                    config,
		protocol:                  proto,
		params:                    cconfig.Consensus[proto],
		genesis:                   bkGenesis,
		genesisHash:               [32]byte{},
		genesisID:                 "blockgen-test",
		prevBlockHash:             "",
		round:                     0,
		timestamp:                 0,
		rewardsLevel:              0,
		rewardsResidue:            0,
		rewardsRate:               0,
		rewardsRecalculationRound: 0,
		latestData:                make(map[TxTypeID]uint64),
		roundOffset:               dbround,
	}
	gen.reportData.InitialRound = gen.roundOffset
	gen.reportData.Transactions = make(map[TxTypeID]TxData)
	gen.reportData.Counters = make(map[string]uint64)

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

// initializeAccounting creates the genesis accounts.
func (g *generator) initializeAccounting() {
	g.numPayments = 0
	g.numAccounts = g.config.NumGenesisAccounts
	for i := uint64(0); i < g.config.NumGenesisAccounts; i++ {
		g.balances = append(g.balances, g.config.GenesisAccountInitialBalance)
	}
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
		if g.verbose {
			fmt.Printf("Received round request %d, but nextRound=%d. Not finishing round.\n", round, nextRound)
		}
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
	if g.verbose && g.round == 0 {
		fmt.Printf("starting txnCounter: %d\n", g.txnCounter)
	}
	minTxnsForBlock := g.minTxnsForBlock(g.round)

	var cert rpcs.EncodedBlockCert
	if g.round == 0 {
		// we'll write genesis block / offset round for non-empty database
		cert.Block, _, _ = g.ledger.BlockCert(basics.Round(round - g.roundOffset))
	} else {
		start := time.Now()
		var generated, evaluated, validated time.Time
		if g.verbose {
			defer func() {
				fmt.Printf("block generation stats txn generation (%s), ledger eval (%s), ledger add block (%s)\n",
					generated.Sub(start), evaluated.Sub(generated), validated.Sub(evaluated))
			}()
		}

		g.setBlockHeader(&cert)

		intra := uint64(0)
		var txGroupsAD [][]txn.SignedTxnWithAD
		for intra < minTxnsForBlock {
			txGroupAD, numTxns, err := g.generateTxGroup(g.round, intra)
			if err != nil {
				return fmt.Errorf("failed to generate transaction: %w", err)
			}
			if len(txGroupAD) == 0 {
				return fmt.Errorf("failed to generate transaction: no transactions given")
			}
			txGroupsAD = append(txGroupsAD, txGroupAD)

			intra += numTxns
		}
		generated = time.Now()
		g.reportData.Counters[BlockgenGenerateTimeMS] += uint64(generated.Sub(start).Milliseconds())

		vBlock, ledgerTxnCount, commitWaitTime, err := g.evaluateBlock(cert.Block.BlockHeader, txGroupsAD, int(intra))
		if err != nil {
			return fmt.Errorf("failed to evaluate block: %w", err)
		}
		if ledgerTxnCount != g.txnCounter+intra {
			return fmt.Errorf("evaluateBlock() txn count mismatches theoretical intra: %d != %d", ledgerTxnCount, g.txnCounter+intra)
		}
		evaluated = time.Now()
		g.reportData.Counters[LedgerEvalTimeMS] += uint64(evaluated.Sub(generated).Milliseconds())

		err = g.ledger.AddValidatedBlock(*vBlock, cert.Certificate)
		if err != nil {
			return fmt.Errorf("failed to add validated block: %w", err)
		}
		validated = time.Now()
		g.reportData.Counters[CommitWaitTimeMS] += uint64(commitWaitTime.Milliseconds())
		g.reportData.Counters[LedgerValidateTimeMS] += uint64((validated.Sub(evaluated) - commitWaitTime).Milliseconds())

		cert.Block.Payset = vBlock.Block().Payset

		if g.verbose {
			errs := g.introspectLedgerVsGenerator(g.round, intra)
			if len(errs) > 0 {
				return fmt.Errorf("introspectLedgerVsGenerator: %w", errors.Join(errs...))
			}
		}
	}
	cert.Block.BlockHeader.Round = basics.Round(round)

	// write the msgpack bytes for a block
	g.latestBlockMsgp = protocol.EncodeMsgp(&cert)
	g.reportData.Counters[BlockTotalSizeBytes] += uint64(len(g.latestBlockMsgp))

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

func (g *generator) generateTxGroup(round uint64, intra uint64) ([]txn.SignedTxnWithAD, uint64 /* numTxns */, error) {
	selection, err := weightedSelection(g.transactionWeights, getTransactionOptions(), paymentTx)
	if err != nil {
		return nil, 0, err
	}

	var signedTxns []txn.SignedTxn
	var numTxns uint64
	var expectedID uint64
	switch selection {
	case paymentTx:
		var signedTxn txn.SignedTxn
		signedTxn, numTxns, err = g.generatePaymentTxn(round, intra)
		signedTxns = []txn.SignedTxn{signedTxn}
	case assetTx:
		var signedTxn txn.SignedTxn
		signedTxn, numTxns, expectedID, err = g.generateAssetTxn(round, intra)
		signedTxns = []txn.SignedTxn{signedTxn}
	case applicationTx:
		signedTxns, numTxns, expectedID, err = g.generateAppTxn(round, intra)
	default:
		return nil, 0, fmt.Errorf("no generator available for %s", selection)
	}

	if err != nil {
		return nil, numTxns, fmt.Errorf("error generating transaction: %w", err)
	}

	if len(signedTxns) == 0 {
		return nil, numTxns, fmt.Errorf("this should never happen! no transactions generated")
	}

	txnGroupAD := make([]txn.SignedTxnWithAD, len(signedTxns))
	for i := range signedTxns {
		txnGroupAD[i] = txn.SignedTxnWithAD{SignedTxn: signedTxns[i]}

		// for debugging:
		g.latestPaysetWithExpectedID = append(
			g.latestPaysetWithExpectedID,
			txnWithExpectedID{
				expectedID: expectedID,
				signedTxn:  &signedTxns[i],
				intra:      intra,
				nextIntra:  intra + numTxns,
			},
		)
	}
	return txnGroupAD, numTxns, nil
}

// ---- 1. Pay Transactions ----

// generatePaymentTxn creates a new payment transaction. The sender is always a genesis account, the receiver is random,
// or a new account.
func (g *generator) generatePaymentTxn(round uint64, intra uint64) (txn.SignedTxn, uint64 /* numTxns */, error) {
	selection, err := weightedSelection(g.payTxWeights, getPaymentTxOptions(), paymentPayTx)
	if err != nil {
		return txn.SignedTxn{}, 0, err
	}
	return g.generatePaymentTxnInternal(selection.(TxTypeID), round, intra)
}

func (g *generator) generatePaymentTxnInternal(selection TxTypeID, round uint64, intra uint64) (txn.SignedTxn, uint64 /* numTxns */, error) {
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
	return signTxn(transaction), 1, nil
}

// ---- 2. Asset Transactions ----

func (g *generator) generateAssetTxn(round uint64, intra uint64) (txn.SignedTxn, uint64 /* numTxns */, uint64 /* assetID */, error) {
	start := time.Now()
	selection, err := weightedSelection(g.assetTxWeights, getAssetTxOptions(), assetXfer)
	if err != nil {
		return txn.SignedTxn{}, 0, 0, err
	}

	actual, transaction, assetID := g.generateAssetTxnInternal(selection.(TxTypeID), round, intra)
	defer g.recordData(actual, start)

	if transaction.Type == "" {
		fmt.Println("Empty asset transaction.")
		os.Exit(1)
	}

	return signTxn(transaction), 1, assetID, nil
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
		fmt.Printf("\n\nthe sender account does not have enough algos for the transfer. idx %d, asset transaction type %v, num %d\n\n", senderIndex, actual, g.reportData.Transactions[actual].GenerationCount)
		os.Exit(1)
	}

	if assetID == 0 {
		fmt.Printf("\n\nthis should never happen: assetID is 0 but should have been set by \ngenerateAssetTxnInternalHint(txType=%s, round=%d, intra=%d, hintIndex=%d, hintIsNil=%t)\nactual=%s\n\n",
			txType, round, intra, hintIndex, hint == nil, actual)
		os.Exit(1)
	}

	g.balances[senderIndex] -= txn.Fee.ToUint64()

	return
}

// ---- metric data recorders ----

func track(id TxTypeID) (TxTypeID, time.Time) {
	return id, time.Now()
}

func (g *generator) recordData(id TxTypeID, start time.Time) {
	g.latestData[id]++
	data := g.reportData.Transactions[id]
	data.GenerationCount += 1
	data.GenerationTime += time.Since(start)
	g.reportData.Transactions[id] = data
}

// ---- sign transactions ----

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
