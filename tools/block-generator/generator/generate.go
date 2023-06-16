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
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

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
	"github.com/algorand/go-algorand/data/transactions"
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

// ---- constructors ----

// MakeGenerator initializes the Generator object.
func MakeGenerator(dbround uint64, bkGenesis bookkeeping.Genesis, config GenerationConfig) (Generator, error) {
	if err := config.validateWithDefaults(false); err != nil {
		return nil, fmt.Errorf("invalid generator configuration: %w", err)
	}

	var proto protocol.ConsensusVersion = "future"
	gen := &generator{
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

	gen.apps = make(map[appKind][]*appData)
	gen.pendingApps = make(map[appKind][]*appData)

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
//		advance the round, and cache the block in case of repeated requests.
//   - requested round == generator's round + offset - 1 ---> write the cached block
//		but do not advance the round.
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

	numTxnForBlock := g.txnForRound(g.round)

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
			TxnCounter:         g.txnCounter + numTxnForBlock,
			StateProofTracking: nil,
		}

		// Generate the transactions
		transactions := make([]transactions.SignedTxnInBlock, 0, numTxnForBlock)
		for i := uint64(0); i < numTxnForBlock; i++ {
			txn, ad, err := g.generateTransaction(g.round, i)
			if err != nil {
				panic(fmt.Sprintf("failed to generate transaction: %v\n", err))
			}
			stib, err := cert.Block.BlockHeader.EncodeSignedTxn(txn, ad)
			if err != nil {
				panic(fmt.Sprintf("failed to encode transaction: %v\n", err))
			}
			transactions = append(transactions, stib)
		}

		if numTxnForBlock != uint64(len(transactions)) {
			panic("Unexpected number of transactions.")
		}

		cert.Block.Payset = transactions
		cert.Certificate = agreement.Certificate{} // empty certificate for clarity

		err := g.ledger.AddBlock(cert.Block, cert.Certificate)
		if err != nil {
			return err
		}
	}
	cert.Block.BlockHeader.Round = basics.Round(round)

	// write the msgpack bytes for a block
	g.latestBlockMsgp = protocol.EncodeMsgp(&cert)
	_, err := output.Write(g.latestBlockMsgp)
	if err != nil {
		return err
	}

	g.finishRound(numTxnForBlock)
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

func (g *generator) generateTransaction(round uint64, intra uint64) (transactions.SignedTxn, transactions.ApplyData, error) {
	selection, err := weightedSelection(g.transactionWeights, getTransactionOptions(), paymentTx)
	if err != nil {
		return transactions.SignedTxn{}, transactions.ApplyData{}, err
	}

	switch selection {
	case paymentTx:
		return g.generatePaymentTxn(round, intra)
	case assetTx:
		return g.generateAssetTxn(round, intra)
	case applicationTx:
		return g.generateAppTxn(round, intra)
	default:
		return transactions.SignedTxn{}, transactions.ApplyData{}, fmt.Errorf("no generator available for %s", selection)
	}
}

// ---- 1. Pay Transactions ----

// generatePaymentTxn creates a new payment transaction. The sender is always a genesis account, the receiver is random,
// or a new account.
func (g *generator) generatePaymentTxn(round uint64, intra uint64) (transactions.SignedTxn, transactions.ApplyData, error) {
	selection, err := weightedSelection(g.payTxWeights, getPaymentTxOptions(), paymentPayTx)
	if err != nil {
		return transactions.SignedTxn{}, transactions.ApplyData{}, err
	}
	return g.generatePaymentTxnInternal(selection.(TxTypeID), round, intra)
}

func (g *generator) generatePaymentTxnInternal(selection TxTypeID, round uint64, intra uint64) (transactions.SignedTxn, transactions.ApplyData, error) {
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

	txn := g.makePaymentTxn(g.makeTxnHeader(sender, round, intra), receiver, amount, basics.Address{})
	return signTxn(txn), transactions.ApplyData{}, nil
}

// ---- 2. Asset Transactions ----

func (g *generator) generateAssetTxn(round uint64, intra uint64) (transactions.SignedTxn, transactions.ApplyData, error) {
	start := time.Now()
	selection, err := weightedSelection(g.assetTxWeights, getAssetTxOptions(), assetXfer)
	if err != nil {
		return transactions.SignedTxn{}, transactions.ApplyData{}, err
	}

	actual, txn := g.generateAssetTxnInternal(selection.(TxTypeID), round, intra)
	defer g.recordData(actual, start)

	// TODO: shouldn't we just return an error?
	if txn.Type == "" {
		fmt.Println("Empty asset transaction.")
		os.Exit(1)
	}

	return signTxn(txn), transactions.ApplyData{}, nil
}

func (g *generator) generateAssetTxnInternal(txType TxTypeID, round uint64, intra uint64) (actual TxTypeID, txn transactions.Transaction) {
	return g.generateAssetTxnInternalHint(txType, round, intra, 0, nil)
}

func (g *generator) generateAssetTxnInternalHint(txType TxTypeID, round uint64, intra uint64, hintIndex uint64, hint *assetData) (actual TxTypeID, txn transactions.Transaction) {
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
		assetID := g.txnCounter + intra + 1
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
			assetIndex = rand.Uint64()%numAssets
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
			txn = g.makeAssetDestroyTxn(g.makeTxnHeader(creator, round, intra), asset.assetID)

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
			txn = g.makeAssetAcceptanceTxn(g.makeTxnHeader(account, round, intra), asset.assetID)

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

			txn = g.makeAssetTransferTxn(g.makeTxnHeader(sender, round, intra), receiver, amount, basics.Address{}, asset.assetID)

			if asset.holdings[0].balance < amount {
				fmt.Printf("\n\ncreator doesn't have enough funds for asset %d\n\n", asset.assetID)
				os.Exit(1)
			}
			if g.balances[asset.holdings[0].acctIndex] < g.params.MinTxnFee {
				fmt.Printf("\n\ncreator doesn't have enough funds for transaction %d\n\n", asset.assetID)
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

			txn = g.makeAssetTransferTxn(
				g.makeTxnHeader(sender, round, intra), closeToAcct, 0, closeToAcct, asset.assetID)

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
	g.balances[senderIndex] -= txn.Fee.ToUint64()
	return
}

// ---- 3. App Transactions ----

func (g *generator) generateAppTxn(round uint64, intra uint64) (transactions.SignedTxn, transactions.ApplyData, error) {
	start := time.Now()
	selection, err := weightedSelection(g.appTxWeights, getAppTxOptions(), appSwapCall)
	if err != nil {
		return transactions.SignedTxn{}, transactions.ApplyData{}, err
	}

	actual, txn, err := g.generateAppCallInternal(selection.(TxTypeID), round, intra, 0, nil)
	if err != nil {
		return transactions.SignedTxn{}, transactions.ApplyData{}, fmt.Errorf("unexpected error received from generateAppCallInternal(): %w", err)
	}
	if txn.Type == "" {
		return transactions.SignedTxn{}, transactions.ApplyData{}, fmt.Errorf("missing transaction type for app transaction")
	}

	g.recordData(actual, start)
	return signTxn(txn), transactions.ApplyData{}, nil
}

func (g *generator) generateAppCallInternal(txType TxTypeID, round, intra, hintIndex uint64, hintApp *appData) (TxTypeID, transactions.Transaction, error) {
	actual := txType

	isApp, kind, appTx, err := parseAppTxType(txType)
	if err != nil {
		return "", transactions.Transaction{}, err
	}
	if !isApp {
		return "", transactions.Transaction{}, fmt.Errorf("should be an app but not parsed that way: %v", txType)
	}
	if appTx != appTxTypeCreate {
		return "", transactions.Transaction{}, fmt.Errorf("invalid transaction type for app %v", appTx)
	}

	var senderIndex uint64
	if hintApp != nil {
		return "", transactions.Transaction{}, fmt.Errorf("not ready for hint app %v", hintApp)
	} else {
		senderIndex = rand.Uint64() % g.numAccounts
	}

	actualAppTx := appTx

	numApps := uint64(len(g.apps[kind]))
	if numApps == 0 {
		actualAppTx = appTxTypeCreate
	}

	var txn transactions.Transaction
	if actualAppTx == appTxTypeCreate {
		numApps += uint64(len(g.pendingApps[kind]))
		senderIndex = numApps % g.config.NumGenesisAccounts
		senderAcct := indexToAccount(senderIndex)

		var approval, clear string
		if kind == appKindSwap {
			approval, clear = approvalSwap, clearSwap
		} else {
			approval, clear = approvalBoxes, clearBoxes
		}

		txn = g.makeAppCreateTxn(senderAcct, round, intra, approval, clear)

		appID := g.txnCounter + intra + 1
		holding := &appHolding{appIndex: appID}
		ad := &appData{
			appID:    appID,
			creator:  senderIndex,
			kind:     kind,
			holdings: []*appHolding{holding},
			holders:  map[uint64]*appHolding{senderIndex: holding},
		}
		g.pendingApps[kind] = append(g.pendingApps[kind], ad)
	}

	// account := indexToAccount(senderIndex)
	// txn = g.makeAppCallTxn(account, round, intra, round, approval, clear)

	if g.balances[senderIndex] < g.params.MinTxnFee {
		return "", transactions.Transaction{}, fmt.Errorf("the sender account does not have enough algos for the app call. idx %d, app transaction type %v, num %d\n\n", senderIndex, txType, g.reportData[txType].GenerationCount)
	}
	g.balances[senderIndex] -= g.params.MinTxnFee

	return actual, txn, nil
}

// ---- miscellaneous ----

func track(id TxTypeID) (TxTypeID, time.Time) {
	return id, time.Now()
}

func (g *generator) recordData(id TxTypeID, start time.Time) {
	data := g.reportData[id]
	data.GenerationCount++
	data.GenerationTime += time.Since(start)
	g.reportData[id] = data
}

func (g *generator) txnForRound(round uint64) uint64 {
	// There are no transactions in the 0th round
	if round == 0 {
		return 0
	}
	return g.config.TxnPerBlock
}

// finishRound tells the generator it can apply any pending state.
func (g *generator) finishRound(txnCount uint64) {
	g.txnCounter += txnCount

	g.timestamp += consensusTimeMilli
	g.round++

	// Apply pending assets...
	g.assets = append(g.assets, g.pendingAssets...)
	g.pendingAssets = nil

	// Apply pending apps...
	for _, kind := range []appKind{appKindSwap, appKindBoxes} {
		g.apps[kind] = append(g.apps[kind], g.pendingApps[kind]...)
		g.pendingApps[kind] = nil
	}
}

func signTxn(txn transactions.Transaction) transactions.SignedTxn {
	stxn := transactions.SignedTxn{
		Sig:      crypto.Signature{},
		Msig:     crypto.MultisigSig{},
		Lsig:     transactions.LogicSig{},
		Txn:      txn,
		AuthAddr: basics.Address{},
	}

	// TODO: Would it be useful to generate a random signature?
	stxn.Sig[32] = 50

	return stxn
}
