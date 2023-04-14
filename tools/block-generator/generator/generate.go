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
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	cconfig "github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/rpcs"
)

// TxTypeID is the transaction type.
type TxTypeID string

const (
	genesis TxTypeID = "genesis"

	// Payment Tx IDs
	paymentTx           TxTypeID = "pay"
	paymentAcctCreateTx TxTypeID = "pay_create"
	assetTx             TxTypeID = "asset"
	//keyRegistrationTx TxTypeID = "keyreg"
	//applicationCallTx TxTypeID = "appl"

	// Asset Tx IDs
	assetCreate  TxTypeID = "asset_create"
	assetOptin   TxTypeID = "asset_optin"
	assetXfer    TxTypeID = "asset_xfer"
	assetClose   TxTypeID = "asset_close"
	assetDestroy TxTypeID = "asset_destroy"

	assetTotal = uint64(100000000000000000)

	consensusTimeMilli int64 = 4500
)

// GenerationConfig defines the tunable parameters for block generation.
type GenerationConfig struct {
	Name                         string `yaml:"name"`
	NumGenesisAccounts           uint64 `yaml:"genesis_accounts"`
	GenesisAccountInitialBalance uint64 `yaml:"genesis_account_balance"`

	// Block generation
	TxnPerBlock uint64 `yaml:"tx_per_block"`

	// TX Distribution
	PaymentTransactionFraction float32 `yaml:"tx_pay_fraction"`
	AssetTransactionFraction   float32 `yaml:"tx_asset_fraction"`

	// Payment configuration
	PaymentNewAccountFraction float32 `yaml:"pay_acct_create_fraction"`
	PaymentFraction           float32 `yaml:"pay_xfer_fraction"`

	// Asset configuration
	AssetCreateFraction  float32 `yaml:"asset_create_fraction"`
	AssetDestroyFraction float32 `yaml:"asset_destroy_fraction"`
	AssetOptinFraction   float32 `yaml:"asset_optin_fraction"`
	AssetCloseFraction   float32 `yaml:"asset_close_fraction"`
	AssetXferFraction    float32 `yaml:"asset_xfer_fraction"`
}

func sumIsCloseToOne(numbers ...float32) bool {
	var sum float32
	for _, num := range numbers {
		sum += num
	}
	return sum > 0.99 && sum < 1.01
}

// MakeGenerator initializes the Generator object.
func MakeGenerator(config GenerationConfig) (Generator, error) {
	if !sumIsCloseToOne(config.PaymentTransactionFraction, config.AssetTransactionFraction) {
		return nil, fmt.Errorf("transaction distribution ratios should equal 1")
	}

	if !sumIsCloseToOne(config.PaymentNewAccountFraction, config.PaymentFraction) {
		return nil, fmt.Errorf("payment configuration ratios should equal 1")
	}

	if !sumIsCloseToOne(config.AssetCreateFraction, config.AssetDestroyFraction, config.AssetOptinFraction, config.AssetCloseFraction, config.AssetXferFraction) {
		return nil, fmt.Errorf("asset configuration ratios should equal 1")
	}

	var proto protocol.ConsensusVersion = "future"
	gen := &generator{
		config:                    config,
		protocol:                  proto,
		params:                    cconfig.Consensus[proto],
		genesisHash:               [32]byte{},
		genesisID:                 "blockgen-test",
		prevBlockHash:             "",
		round:                     0,
		txnCounter:                0,
		timestamp:                 0,
		rewardsLevel:              0,
		rewardsResidue:            0,
		rewardsRate:               0,
		rewardsRecalculationRound: 0,
		reportData:                make(map[TxTypeID]TxData),
	}

	gen.feeSink[31] = 1
	gen.rewardsPool[31] = 2
	gen.genesisHash[31] = 3

	gen.initializeAccounting()
	gen.initializeLedger()

	for _, val := range getTransactionOptions() {
		switch val {
		case paymentTx:
			gen.transactionWeights = append(gen.transactionWeights, config.PaymentTransactionFraction)
		case assetTx:
			gen.transactionWeights = append(gen.transactionWeights, config.AssetTransactionFraction)
		}
	}

	for _, val := range getPaymentTxOptions() {
		switch val {
		case paymentTx:
			gen.payTxWeights = append(gen.payTxWeights, config.PaymentFraction)
		case paymentAcctCreateTx:
			gen.payTxWeights = append(gen.payTxWeights, config.PaymentNewAccountFraction)
		}
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

	return gen, nil
}

// Generator is the interface needed to generate blocks.
type Generator interface {
	WriteReport(output io.Writer) error
	WriteGenesis(output io.Writer) error
	WriteBlock(output io.Writer, round uint64) error
	WriteAccount(output io.Writer, accountString string) error
	WriteStatus(output io.Writer) error
	WriteDeltas(output io.Writer, round uint64) error
	Accounts() <-chan basics.Address
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
	params        cconfig.ConsensusParams
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

	transactionWeights []float32
	payTxWeights       []float32
	assetTxWeights     []float32

	// Reporting information from transaction type to data
	reportData Report

	// ledger
	ledger *ledger.Ledger
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

type assetHolding struct {
	acctIndex uint64
	balance   uint64
}

// Report is the generation report.
type Report map[TxTypeID]TxData

// TxData is the generator report data.
type TxData struct {
	GenerationTime  time.Duration `json:"generation_time_milli"`
	GenerationCount uint64        `json:"num_generated"`
}

func track(id TxTypeID) (TxTypeID, time.Time) {
	return id, time.Now()
}
func (g *generator) recordData(id TxTypeID, start time.Time) {
	data := g.reportData[id]
	data.GenerationCount++
	data.GenerationTime += time.Since(start)
	g.reportData[id] = data
}

func (g *generator) WriteReport(output io.Writer) error {
	return json.NewEncoder(output).Encode(g.reportData)
}

func (g *generator) WriteStatus(output io.Writer) error {
	response := model.NodeStatusResponse{
		LastRound: g.round,
	}
	return json.NewEncoder(output).Encode(response)
}

func (g *generator) WriteGenesis(output io.Writer) error {
	defer g.recordData(track(genesis))
	var allocations []bookkeeping.GenesisAllocation

	for i := uint64(0); i < g.config.NumGenesisAccounts; i++ {
		addr := indexToAccount(i)
		allocations = append(allocations, bookkeeping.GenesisAllocation{
			Address: addr.String(),
			State: basics.AccountData{
				MicroAlgos: basics.MicroAlgos{Raw: g.config.GenesisAccountInitialBalance},
			},
		})
	}
	// Also add the rewards pool account with minimum balance. Without it, the evaluator
	// crashes.
	allocations = append(allocations, bookkeeping.GenesisAllocation{
		Address: g.rewardsPool.String(),
		Comment: "RewardsPool",
		State: basics.AccountData{
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

func getTransactionOptions() []interface{} {
	return []interface{}{paymentTx, assetTx}
}

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
	default:
		return transactions.SignedTxn{}, transactions.ApplyData{}, fmt.Errorf("no generator available for %s", selection)
	}
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
}

// WriteBlock generates a block full of new transactions and writes it to the writer.
func (g *generator) WriteBlock(output io.Writer, round uint64) error {

	if round != g.round {
		fmt.Printf("Generator only supports sequential block access. Expected %d but received request for %d.\n", g.round, round)
	}

	numTxnForBlock := g.txnForRound(round)

	// return genesis block
	if round == 0 {
		// write the msgpack bytes for a block
		block, err := rpcs.RawBlockBytes(g.ledger, basics.Round(round))
		if err != nil {
			return err
		}
		_, err = output.Write(block)
		if err != nil {
			return err
		}
		g.finishRound(numTxnForBlock)
		return nil
	}

	header := bookkeeping.BlockHeader{
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
		stib, err := header.EncodeSignedTxn(txn, ad)
		if err != nil {
			panic(fmt.Sprintf("failed to encode transaction: %v\n", err))
		}
		transactions = append(transactions, stib)
	}

	if numTxnForBlock != uint64(len(transactions)) {
		panic("Unexpected number of transactions.")
	}

	cert := rpcs.EncodedBlockCert{
		Block: bookkeeping.Block{
			BlockHeader: header,
			Payset:      transactions,
		},
		Certificate: agreement.Certificate{},
	}

	err := g.ledger.AddBlock(cert.Block, cert.Certificate)
	if err != nil {
		return err
	}
	// write the msgpack bytes for a block
	block, err := rpcs.RawBlockBytes(g.ledger, basics.Round(round))
	if err != nil {
		return err
	}
	_, err = output.Write(block)
	if err != nil {
		return err
	}
	g.finishRound(numTxnForBlock)
	return nil
}

// WriteDeltas generates returns the deltas for payset.
func (g *generator) WriteDeltas(output io.Writer, round uint64) error {
	delta, err := g.ledger.GetStateDeltaForRound(basics.Round(round))
	if err != nil {
		return fmt.Errorf("err getting state delta for round %d, %v", round, err)
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

// initializeAccounting creates the genesis accounts.
func (g *generator) initializeAccounting() {
	if g.config.NumGenesisAccounts == 0 {
		panic("Number of genesis accounts must be > 0.")
	}

	g.numPayments = 0
	g.numAccounts = g.config.NumGenesisAccounts
	for i := uint64(0); i < g.config.NumGenesisAccounts; i++ {
		g.balances = append(g.balances, g.config.GenesisAccountInitialBalance)
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

func getPaymentTxOptions() []interface{} {
	return []interface{}{paymentTx, paymentAcctCreateTx}
}

// generatePaymentTxn creates a new payment transaction. The sender is always a genesis account, the receiver is random,
// or a new account.
func (g *generator) generatePaymentTxn(round uint64, intra uint64) (transactions.SignedTxn, transactions.ApplyData, error) {
	selection, err := weightedSelection(g.payTxWeights, getPaymentTxOptions(), paymentTx)
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
	case paymentTx:
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

func getAssetTxOptions() []interface{} {
	return []interface{}{assetCreate, assetDestroy, assetOptin, assetXfer, assetClose}
}

func (g *generator) generateAssetTxnInternal(txType TxTypeID, round uint64, intra uint64) (actual TxTypeID, txn transactions.Transaction) {
	return g.generateAssetTxnInternalHint(txType, round, intra, 0, nil)
}

func (g *generator) generateAssetTxnInternalHint(txType TxTypeID, round uint64, intra uint64, hintIndex uint64, hint *assetData) (actual TxTypeID, txn transactions.Transaction) {
	actual = txType
	// If there are no assets the next operation needs to be a create.
	if len(g.assets) == 0 {
		actual = assetCreate
	}

	numAssets := uint64(len(g.assets))
	var senderIndex uint64

	if actual == assetCreate {
		numAssets = uint64(len(g.assets)) + uint64(len(g.pendingAssets))
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
		assetIndex := rand.Uint64() % numAssets
		asset := g.assets[assetIndex]
		if hint != nil {
			assetIndex = hintIndex
			asset = hint
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

func (g *generator) generateAssetTxn(round uint64, intra uint64) (transactions.SignedTxn, transactions.ApplyData, error) {
	start := time.Now()
	selection, err := weightedSelection(g.assetTxWeights, getAssetTxOptions(), assetXfer)
	if err != nil {
		return transactions.SignedTxn{}, transactions.ApplyData{}, err
	}

	actual, txn := g.generateAssetTxnInternal(selection.(TxTypeID), round, intra)
	defer g.recordData(actual, start)

	if txn.Type == "" {
		fmt.Println("Empty asset transaction.")
		os.Exit(1)
	}

	return signTxn(txn), transactions.ApplyData{}, nil
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
	l, err := ledger.OpenLedger(logging.Base(), "block-generator", true, ledgercore.InitState{
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

// Stop cleans up allocated resources.
func (g *generator) Stop() {
	g.ledger.Close()
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

// Accounts is used in the runner to generate a list of addresses.
func (g *generator) Accounts() <-chan basics.Address {
	results := make(chan basics.Address, 10)
	go func() {
		defer close(results)
		for i := uint64(0); i < g.numAccounts; i++ {
			results <- indexToAccount(i)
		}
	}()
	return results
}
