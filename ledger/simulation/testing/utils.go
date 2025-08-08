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

package simulationtesting

import (
	"math/rand"
	"testing"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

// Account contains public and private keys, as well as the state of an account
type Account struct {
	Addr     basics.Address
	Sk       *crypto.SignatureSecrets
	AcctData basics.AccountData
}

// TxnInfo contains information about the network used for instantiating txntest.Txns
type TxnInfo struct {
	LatestHeader bookkeeping.BlockHeader
}

// LatestRound returns the round number of the most recently committed block
func (info TxnInfo) LatestRound() basics.Round {
	return info.LatestHeader.Round
}

// CurrentProtocolParams returns the consensus parameters that the network is currently using
func (info TxnInfo) CurrentProtocolParams() config.ConsensusParams {
	return config.Consensus[info.LatestHeader.CurrentProtocol]
}

// NewTxn sets network-specific values to the given transaction
func (info TxnInfo) NewTxn(txn txntest.Txn) txntest.Txn {
	txn.FirstValid = info.LatestHeader.Round
	txn.GenesisID = info.LatestHeader.GenesisID
	txn.GenesisHash = info.LatestHeader.GenesisHash
	txn.FillDefaults(info.CurrentProtocolParams())
	return txn
}

// Environment contains the ledger and testing environment for transaction simulations. It also
// provides convenience methods to execute transactions against the ledger prior to simulation. This
// allows you to create specific a ledger state before running a simulation.
type Environment struct {
	t      *testing.T
	Ledger *data.Ledger
	Config config.Local
	// Accounts is a list of all accounts in the ledger, excluding the fee sink and rewards pool
	Accounts           []Account
	FeeSinkAccount     Account
	RewardsPoolAccount Account
	TxnInfo            TxnInfo
}

// Close reclaims resources used by the testing environment
func (env *Environment) Close() {
	env.Ledger.Close()
}

// nextBlock begins evaluation of a new block, after ledger creation or endBlock()
func (env *Environment) nextBlock() *eval.BlockEvaluator {
	env.t.Helper()
	rnd := env.Ledger.Latest()
	hdr, err := env.Ledger.BlockHdr(rnd)
	require.NoError(env.t, err)

	nextHdr := bookkeeping.MakeBlock(hdr).BlockHeader
	evaluator, err := env.Ledger.StartEvaluator(nextHdr, 0, 0, nil)
	require.NoError(env.t, err)
	return evaluator
}

// endBlock completes the block being created, returns the ValidatedBlock for inspection
func (env *Environment) endBlock(evaluator *eval.BlockEvaluator) *ledgercore.ValidatedBlock {
	env.t.Helper()
	unfinishedBlock, err := evaluator.GenerateBlock(nil)
	require.NoError(env.t, err)
	// Since we skip agreement, this block is imperfect w/ respect to seed/proposer/payouts
	validatedBlock := ledgercore.MakeValidatedBlock(unfinishedBlock.UnfinishedBlock(), unfinishedBlock.UnfinishedDeltas())
	err = env.Ledger.AddValidatedBlock(validatedBlock, agreement.Certificate{})
	require.NoError(env.t, err)
	return &validatedBlock
}

// Txn creates and executes a new block with the given transaction and returns its ApplyData
func (env *Environment) Txn(txn transactions.SignedTxn) transactions.ApplyData {
	env.t.Helper()

	evaluator := env.nextBlock()
	err := evaluator.Transaction(txn, transactions.ApplyData{})
	require.NoError(env.t, err)
	newBlock := env.endBlock(evaluator).Block()

	require.Len(env.t, newBlock.Payset, 1)

	env.TxnInfo.LatestHeader = newBlock.BlockHeader

	return newBlock.Payset[0].ApplyData
}

// CreateAsset creates an asset with the given parameters and returns its ID
func (env *Environment) CreateAsset(creator basics.Address, params basics.AssetParams) basics.AssetIndex {
	env.t.Helper()

	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:        protocol.AssetConfigTx,
		Sender:      creator,
		AssetParams: params,
	})

	ad := env.Txn(txn.SignedTxn())
	require.NotZero(env.t, ad.ConfigAsset)

	return ad.ConfigAsset
}

// AppParams mirrors basics.AppParams, but allows the approval and clear state programs to have the
// same values that txntest.Txn accepts
type AppParams struct {
	ApprovalProgram   interface{}
	ClearStateProgram interface{}
	GlobalState       basics.TealKeyValue
	LocalStateSchema  basics.StateSchema
	GlobalStateSchema basics.StateSchema
	ExtraProgramPages uint32
}

// CreateApp creates an application with the given parameters and returns its ID
func (env *Environment) CreateApp(creator basics.Address, params AppParams) basics.AppIndex {
	env.t.Helper()

	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:              protocol.ApplicationCallTx,
		Sender:            creator,
		ApprovalProgram:   params.ApprovalProgram,
		ClearStateProgram: params.ClearStateProgram,
		GlobalStateSchema: params.GlobalStateSchema,
		LocalStateSchema:  params.LocalStateSchema,
		ExtraProgramPages: params.ExtraProgramPages,
	})

	ad := env.Txn(txn.SignedTxn())
	require.NotZero(env.t, ad.ApplicationID)

	return ad.ApplicationID
}

// TransferAlgos transfers the given amount of Algos from one account to another
func (env *Environment) TransferAlgos(from, to basics.Address, amount uint64) {
	env.t.Helper()
	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   from,
		Receiver: to,
		Amount:   amount,
	})
	env.Txn(txn.SignedTxn())
}

// TransferAsset transfers the given amount of an asset from one account to another
func (env *Environment) TransferAsset(from, to basics.Address, assetID basics.AssetIndex, amount uint64) {
	env.t.Helper()
	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:          protocol.AssetTransferTx,
		Sender:        from,
		AssetReceiver: to,
		XferAsset:     assetID,
		AssetAmount:   amount,
	})
	env.Txn(txn.SignedTxn())
}

// OptIntoAsset opts the given account into the given asset
func (env *Environment) OptIntoAsset(address basics.Address, assetID basics.AssetIndex) {
	env.t.Helper()
	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:          protocol.AssetTransferTx,
		Sender:        address,
		AssetReceiver: address,
		XferAsset:     assetID,
	})
	env.Txn(txn.SignedTxn())
}

// OptIntoApp opts the given account into the given application
func (env *Environment) OptIntoApp(address basics.Address, appID basics.AppIndex) {
	env.t.Helper()
	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:          protocol.ApplicationCallTx,
		Sender:        address,
		ApplicationID: appID,
		OnCompletion:  transactions.OptInOC,
	})
	env.Txn(txn.SignedTxn())
}

// Rekey rekeys the given account to the given authorizer
func (env *Environment) Rekey(account, rekeyTo basics.Address) {
	env.t.Helper()
	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:    protocol.KeyRegistrationTx,
		Sender:  account,
		RekeyTo: rekeyTo,
	})
	env.Txn(txn.SignedTxn())
}

// PrepareSimulatorTest creates an environment to test transaction simulations. The caller is
// responsible for calling Close() on the returned Environment.
func PrepareSimulatorTest(t *testing.T) Environment {
	genesisInitState, keys := ledgertesting.GenerateInitState(t, protocol.ConsensusFuture, 200)

	// Prepare ledger
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)
	realLedger, err := ledger.OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err, "could not open ledger")

	ledger := &data.Ledger{Ledger: realLedger}

	// Reformat accounts
	accounts := make([]Account, 0, len(keys)-2) // -2 for pool and sink accounts
	var feeSinkAccount Account
	var rewardsPoolAccount Account
	for addr, key := range keys {
		account := Account{
			Addr:     addr,
			Sk:       key,
			AcctData: genesisInitState.Accounts[addr],
		}

		if addr == ledgertesting.SinkAddr() {
			feeSinkAccount = account
			continue
		}
		if addr == ledgertesting.PoolAddr() {
			rewardsPoolAccount = account
			continue
		}

		accounts = append(accounts, account)
	}

	latest := ledger.Latest()
	latestHeader, err := ledger.BlockHdr(latest)
	require.NoError(t, err)

	rand.Seed(time.Now().UnixNano())

	// append a random number of blocks to ensure simulation results have a valid LastRound field
	numBlocks := rand.Intn(4)
	for i := 0; i < numBlocks; i++ {
		nextBlock := bookkeeping.MakeBlock(latestHeader)
		nextBlock.TxnCounter = latestHeader.TxnCounter
		err = ledger.AddBlock(nextBlock, agreement.Certificate{})
		require.NoError(t, err)

		// round has advanced by 1
		require.Equal(t, latest+1, ledger.Latest())
		latest++

		latestHeader = nextBlock.BlockHeader
	}

	return Environment{
		t:                  t,
		Ledger:             ledger,
		Config:             cfg,
		Accounts:           accounts,
		FeeSinkAccount:     feeSinkAccount,
		RewardsPoolAccount: rewardsPoolAccount,
		TxnInfo:            TxnInfo{latestHeader},
	}
}
