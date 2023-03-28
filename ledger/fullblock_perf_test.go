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

package ledger

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type benchConfig struct {
	txnCount  uint64
	round     uint64
	b         *testing.B
	creator   basics.Address
	accts     []basics.Address
	acctToAst map[basics.Address]map[basics.AssetIndex]uint64
	acctToApp map[basics.Address]map[basics.AppIndex]struct{}
	l0        *Ledger
	l1        *Ledger
	eval      *eval.BlockEvaluator
	numPay    uint64
	numAst    uint64
	numApp    uint64
	blocks    []bookkeeping.Block
}

func setupEnv(b *testing.B, numAccts int) (bc *benchConfig) {
	dbTempDir := b.TempDir()
	name := b.Name()
	dbName := fmt.Sprintf("%s.%d", name, crypto.RandUint64())
	dbPrefix := filepath.Join(dbTempDir, dbName)

	genesisInitState := getInitState()

	// Use future protocol
	genesisInitState.Block.BlockHeader.GenesisHash = crypto.Digest{}
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusFuture
	genesisInitState.GenesisHash = crypto.Digest{1}
	genesisInitState.Block.BlockHeader.GenesisHash = crypto.Digest{1}

	// maintain a map from accounts to a map of assets and apps
	acctToAst := make(map[basics.Address]map[basics.AssetIndex]uint64)
	acctToApp := make(map[basics.Address]map[basics.AppIndex]struct{})
	accts := make([]basics.Address, 0, numAccts)
	// creator is the special rich account
	creator := basics.Address{}
	_, err := rand.Read(creator[:])
	require.NoError(b, err)
	genesisInitState.Accounts[creator] = basics_testing.MakeAccountData(basics.Offline, basics.MicroAlgos{Raw: 1234567890000000000})

	logger := logging.TestingLog(b)
	logger.SetLevel(logging.Warn)

	// open 2 ledgers: 1st for preparing the blocks, 2nd for measuring the time
	inMem := false
	cfg := config.GetDefaultLocal()
	cfg.Archival = false
	cfg.MaxAcctLookback = uint64(b.N) // prevent committing blocks into DB since we benchmark validation
	cfg.Archival = true
	cfg.MaxAcctLookback = uint64(b.N) // prevent committing blocks into DB since we benchmark validation
	l0, err := OpenLedger(logger, dbPrefix, inMem, genesisInitState, cfg)
	require.NoError(b, err)

	// open second ledger
	inMem = false
	cfg.Archival = false
	cfg.MaxAcctLookback = uint64(b.N) // prevent committing blocks into DB since we benchmark validation
	dbName = fmt.Sprintf("%s.%d.2", name, crypto.RandUint64())
	dbPrefix = filepath.Join(dbTempDir, dbName)
	l1, err := OpenLedger(logger, dbPrefix, inMem, genesisInitState, cfg)
	require.NoError(b, err)

	// init the first block
	blk := genesisInitState.Block
	blk.BlockHeader.Round++
	blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
	blk.BlockHeader.GenesisID = fmt.Sprintf("%s-genesis", b.Name())
	cert := agreement.Certificate{}

	err = l0.AddBlock(blk, cert)
	require.NoError(b, err)
	err = l1.AddBlock(blk, cert)
	require.NoError(b, err)

	newBlk := bookkeeping.MakeBlock(blk.BlockHeader)
	eval, err := l0.StartEvaluator(newBlk.BlockHeader, 5000, 0)
	require.NoError(b, err)

	bc = &benchConfig{
		txnCount:  0,
		round:     1,
		b:         b,
		creator:   creator,
		accts:     accts,
		acctToAst: acctToAst,
		acctToApp: acctToApp,
		l0:        l0,
		l1:        l1,
		eval:      eval,
	}

	// start the ledger with a pool of accounts
	for i := 0; i < numAccts; i++ {
		acct := addNewAccount(bc)
		payTo(bc, bc.creator, acct, 1234567890000)
	}

	addBlock(bc)
	vc := verify.GetMockedCache(true)
	for _, blk := range bc.blocks {
		_, err := eval.Eval(context.Background(), bc.l1, blk, true, vc, nil)
		require.NoError(b, err)
		err = bc.l1.AddBlock(blk, cert)
		require.NoError(b, err)
	}
	bc.blocks = bc.blocks[len(bc.blocks):]
	bc.txnCount = 0
	bc.round = 0
	bc.numPay = 0
	return bc
}

func sendAssetEvent(bc *benchConfig, newAccount bool) {

	// pick a random account
	randAcct1 := bc.accts[mrand.Intn(len(bc.accts))]
	randAcct2 := bc.accts[mrand.Intn(len(bc.accts))]
	if newAccount {
		randAcct2 = addNewAccount(bc)
		payTo(bc, bc.creator, randAcct2, 100000000)
	}

	var assIdx basics.AssetIndex
	for key, val := range bc.acctToAst[randAcct1] {
		if val > 1 {
			assIdx = key
			break
		}
	}

	if assIdx == 0 {
		assIdx = createAssetForAcct(bc, randAcct1)
	}

	// opt in to the asset
	if _, have := bc.acctToAst[randAcct2][assIdx]; !have {
		sendAssetTo(bc, randAcct2, randAcct2, assIdx, 0)
	}
	sendAssetTo(bc, randAcct1, randAcct2, assIdx, 1)
}

func appCallEvent(bc *benchConfig, newAccount bool) {

	// pick a random account
	randAcct1 := bc.accts[mrand.Intn(len(bc.accts))]
	randAcct2 := bc.accts[mrand.Intn(len(bc.accts))]
	if newAccount {
		randAcct2 = addNewAccount(bc)
		payTo(bc, bc.creator, randAcct2, 100000000)
	}

	var appIdx basics.AppIndex
	if len(bc.acctToApp) > 0 {
		randApp := mrand.Intn(len(bc.acctToApp))
		a := 0
		for key := range bc.acctToApp[randAcct1] {
			if a == randApp {
				appIdx = key
				break
			}
			a++
		}
	}

	if appIdx == 0 {
		appIdx = createAppForAcct(bc, randAcct1)
	}

	// opt in to the asset
	if _, have := bc.acctToApp[randAcct2][appIdx]; !have {
		optInApp(bc, randAcct2, appIdx)
	}
	callApp(bc, randAcct2, appIdx)
}

func payEvent(bc *benchConfig, newAccount bool) {
	// pick a random account
	randAcct1 := bc.accts[mrand.Intn(len(bc.accts))]
	randAcct2 := bc.accts[mrand.Intn(len(bc.accts))]
	if newAccount {
		randAcct2 = addNewAccount(bc)
		payTo(bc, bc.creator, randAcct2, 100000000)
	} else {
		payTo(bc, randAcct1, randAcct2, 10)
	}
}

func sendAssetTo(bc *benchConfig, from, to basics.Address, assIdx basics.AssetIndex, amt uint64) {
	tx := sendAssetTransaction(bc.txnCount, bc.round, from, to, assIdx, amt)
	var stxn transactions.SignedTxn
	stxn.Txn = tx
	stxn.Sig = crypto.Signature{1}
	addTransaction(bc, stxn)
	bc.numAst++
}

func payTo(bc *benchConfig, from, to basics.Address, amt uint64) {
	tx := createPaymentTransaction(uint64(bc.txnCount), bc.round, from, to, amt)
	var stxn transactions.SignedTxn
	stxn.Txn = tx
	stxn.Sig = crypto.Signature{1}
	addTransaction(bc, stxn)
	bc.numPay++
}

func createAssetForAcct(bc *benchConfig, acct basics.Address) (aidx basics.AssetIndex) {
	tx := createAssetTransaction(bc.txnCount, bc.round, acct)
	stxn := transactions.SignedTxn{Txn: tx, Sig: crypto.Signature{1}}
	aIdx := basics.AssetIndex(addTransaction(bc, stxn))
	if len(bc.acctToAst[acct]) == 0 {
		bc.acctToAst[acct] = make(map[basics.AssetIndex]uint64)
	}
	bc.acctToAst[acct][aIdx] = 3000000
	bc.numAst++
	return aIdx
}

func createAppForAcct(bc *benchConfig, acct basics.Address) (appIdx basics.AppIndex) {
	tx, err := makeAppTransaction(bc.txnCount, bc.round, acct)
	require.NoError(bc.b, err)
	stxn := transactions.SignedTxn{Txn: tx, Sig: crypto.Signature{1}}
	appIdx = basics.AppIndex(addTransaction(bc, stxn))
	if len(bc.acctToApp[acct]) == 0 {
		bc.acctToApp[acct] = make(map[basics.AppIndex]struct{})
	}
	bc.acctToApp[acct][appIdx] = struct{}{}
	bc.numApp++
	return appIdx
}

func optInApp(bc *benchConfig, acct basics.Address, appIdx basics.AppIndex) {
	tx := makeOptInAppTransaction(bc.txnCount, appIdx, bc.round, acct)
	var stxn transactions.SignedTxn
	stxn.Txn = tx
	stxn.Sig = crypto.Signature{1}
	addTransaction(bc, stxn)
	bc.numApp++
}

func callApp(bc *benchConfig, acct basics.Address, appIdx basics.AppIndex) {
	tx := callAppTransaction(bc.txnCount, appIdx, bc.round, acct)
	var stxn transactions.SignedTxn
	stxn.Txn = tx
	stxn.Sig = crypto.Signature{1}
	addTransaction(bc, stxn)
	bc.numApp++
}

func addNewAccount(bc *benchConfig) (acct basics.Address) {

	acct = basics.Address{}
	_, err := rand.Read(acct[:])
	require.NoError(bc.b, err)
	bc.accts = append(bc.accts, acct)
	return acct
}

func addTransaction(bc *benchConfig, stxn transactions.SignedTxn) uint64 {
	err := bc.eval.Transaction(stxn, transactions.ApplyData{})
	if err == ledgercore.ErrNoSpace {
		addBlock(bc)
		addTransaction(bc, stxn)
	} else {
		require.NoError(bc.b, err)
		bc.txnCount++
	}
	return bc.eval.TestingTxnCounter()
}

func addBlock(bc *benchConfig) {
	vblk, err := bc.eval.GenerateBlock()
	cert := agreement.Certificate{}
	require.NoError(bc.b, err)
	bc.blocks = append(bc.blocks, vblk.Block())

	err = bc.l0.AddBlock(vblk.Block(), cert)
	require.NoError(bc.b, err)

	_, last := bc.l0.LatestCommitted()
	prev, err := bc.l0.BlockHdr(basics.Round(last))
	require.NoError(bc.b, err)
	newBlk := bookkeeping.MakeBlock(prev)
	bc.eval, err = bc.l0.StartEvaluator(newBlk.BlockHeader, 5000, 0)
	bc.round++
	require.NoError(bc.b, err)
}

// BenchmarkBlockValidationJustPayNoNew sends payment transactions between existing accounts,
// by choosing pair of random accounts.
func BenchmarkBlockValidationJustPayNoNew(b *testing.B) {
	numAccts := 50000
	newAcctProb := 0.0

	// Set the probability in %
	payProb := 1.0
	astProb := 0.0
	//appsProb := 0
	benchmarkBlockValidationMix(b, newAcctProb, payProb, astProb, numAccts)
}

// BenchmarkBlockValidationJustPay sends payments between two random accounts, with
// 50% probability of creating a new account.
func BenchmarkBlockValidationJustPay(b *testing.B) {
	numAccts := 50000
	newAcctProb := 0.5

	// Set the probability in %
	payProb := 1.0
	astProb := 0.0
	//appsProb := 0
	benchmarkBlockValidationMix(b, newAcctProb, payProb, astProb, numAccts)
}

// BenchmarkBlockValidationNoNew executes payment, asset or application events with
// 30%, 50%, and 20% probability respectively among existing accounts.
// Note that each event may involve multiple transactions (e.g. opt in to asset,
// create app, opt in to app).
func BenchmarkBlockValidationNoNew(b *testing.B) {
	numAccts := 50000
	newAcctProb := 0.0

	// Set the probability in %
	payProb := 0.3
	astProb := 0.5
	//appsProb := 0.2
	benchmarkBlockValidationMix(b, newAcctProb, payProb, astProb, numAccts)
}

// BenchmarkBlockValidationMix executes payment, asset or application events with
// 30%, 50%, and 20% probability respectively among existing or new accounts.
// Note that each event may involve multiple transactions (e.g. funding new account,
// opt in to asset, create app, opt in to app).
func BenchmarkBlockValidationMix(b *testing.B) {
	numAccts := 50000
	newAcctProb := 0.5

	// Set the probability in %
	payProb := 0.3
	astProb := 0.5
	//appsProb := 0.2
	benchmarkBlockValidationMix(b, newAcctProb, payProb, astProb, numAccts)
}

func benchmarkBlockValidationMix(b *testing.B, newAcctProb, payProb, astProb float64, numAccts int) {
	bc := setupEnv(b, numAccts)

	numBlocks := uint64(b.N)
	cert := agreement.Certificate{}
	fmt.Printf("Preparing... /%d: ", numBlocks)
	s3 := time.Now()

	for bc.round < numBlocks {
		currentRound := bc.round
		for bc.round == currentRound {
			randNum := mrand.Float64()
			if randNum < payProb {
				// add pay transaction
				payEvent(bc, mrand.Float64() < newAcctProb)
			} else if randNum < payProb+astProb {
				// add asset transactions
				sendAssetEvent(bc, mrand.Float64() < newAcctProb)
			} else {
				// add app transaction
				appCallEvent(bc, mrand.Float64() < newAcctProb)
			}
		}
		if (currentRound+1)*10%(2*numBlocks) == 0 {
			fmt.Printf("%d%% %.1fs ", (currentRound+1)*100/numBlocks, time.Since(s3).Seconds())
			s3 = time.Now()
		}

	}
	fmt.Printf("\nSummary %d blocks and %d txns: pay %d/blk (%d%%) assets %d/blk (%d%%) apps %d/blk (%d%%)\n",
		numBlocks, bc.txnCount, bc.numPay/numBlocks, bc.numPay*100/bc.txnCount, bc.numAst/numBlocks, bc.numAst*100/bc.txnCount, bc.numApp/numBlocks, bc.numApp*100/bc.txnCount)

	// eval + add all the (valid) blocks to the second ledger, measuring it this time
	vc := verify.GetMockedCache(true)
	tt := time.Now()
	b.ResetTimer()
	for _, blk := range bc.blocks {
		_, err := eval.Eval(context.Background(), bc.l1, blk, true, vc, nil)
		require.NoError(b, err)
		err = bc.l1.AddBlock(blk, cert)
		require.NoError(b, err)
	}
	fmt.Printf("%.1f sec / %d blks\n", time.Since(tt).Seconds(), numBlocks)
}

func createPaymentTransaction(
	counter uint64,
	round uint64,
	sender basics.Address,
	receiver basics.Address,
	amount uint64) (txn transactions.Transaction) {

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)
	txn = transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(round),
			LastValid:   basics.Round(round + 1000),
			GenesisHash: crypto.Digest{1},
			Note:        note,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: amount},
		},
	}
	return
}

// prepares a create asset transaction
func createAssetTransaction(
	counter uint64,
	round uint64,
	sender basics.Address) (assetTx transactions.Transaction) {

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)
	assetTx = transactions.Transaction{
		Type: protocol.AssetConfigTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(round),
			LastValid:   basics.Round(round + 1000),
			GenesisHash: crypto.Digest{1},
			Note:        note,
		},
		AssetConfigTxnFields: transactions.AssetConfigTxnFields{
			AssetParams: basics.AssetParams{
				Total:         3000000,
				DefaultFrozen: false,
				Manager:       sender,
			},
		},
	}
	return
}

// prepares a send asset transaction
func sendAssetTransaction(
	counter uint64,
	round uint64,
	sender basics.Address,
	receiver basics.Address,
	assetID basics.AssetIndex,
	amt uint64) (tx transactions.Transaction) {

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)
	tx = transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(round),
			LastValid:   basics.Round(round + 1000),
			GenesisHash: crypto.Digest{1},
			Note:        note,
		},
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     assetID,
			AssetAmount:   amt,
			AssetReceiver: receiver,
		},
	}
	return
}

func makeAppTransaction(
	counter uint64,
	round uint64,
	sender basics.Address) (appTx transactions.Transaction, err error) {

	progCounter := uint64(1)
	progCounter = counter
	prog := fmt.Sprintf(`#pragma version 2
// a simple global and local calls counter app
byte b64 Y291bnRlcg== // counter
dup
app_global_get
int %d
+
app_global_put  // update the counter
int 0
int 0
app_opted_in
bnz opted_in
err
opted_in:
int 0  // account idx for app_local_put
byte b64 Y291bnRlcg== // counter
int 0
byte b64 Y291bnRlcg==
app_local_get
int 1  // increment
+
app_local_put
int 1
`, progCounter)

	approvalOps, err := logic.AssembleString(prog)
	if err != nil {
		return transactions.Transaction{}, err
	}
	clearstateOps, err := logic.AssembleString("#pragma version 2\nint 1")
	if err != nil {
		return transactions.Transaction{}, err
	}
	schema := basics.StateSchema{
		NumUint: 1,
	}

	// create the app
	appTx = transactions.Transaction{}
	appTx.Type = protocol.ApplicationCallTx
	appTx.OnCompletion = transactions.OptInOC
	appTx.ApprovalProgram = approvalOps.Program
	appTx.ClearStateProgram = clearstateOps.Program
	appTx.GlobalStateSchema = schema
	appTx.LocalStateSchema = schema

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)

	appTx.Header = transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
		FirstValid:  basics.Round(round),
		LastValid:   basics.Round(round + 1000),
		GenesisHash: crypto.Digest{1},
		Note:        note,
	}
	appTx.Type = protocol.ApplicationCallTx
	return
}

// prepares a opt-in app transaction
func makeOptInAppTransaction(
	counter uint64,
	appIdx basics.AppIndex,
	round uint64,
	sender basics.Address) (appTx transactions.Transaction) {

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)

	appTx = transactions.Transaction{}
	appTx.ApplicationID = basics.AppIndex(appIdx)
	appTx.OnCompletion = transactions.OptInOC

	appTx.Header = transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
		FirstValid:  basics.Round(round),
		LastValid:   basics.Round(round + 1000),
		GenesisHash: crypto.Digest{1},
		Note:        note,
	}
	appTx.Type = protocol.ApplicationCallTx
	return
}

// prepare app call transaction
func callAppTransaction(
	counter uint64,
	appIdx basics.AppIndex,
	round uint64,
	sender basics.Address) (appTx transactions.Transaction) {

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)

	appTx = transactions.Transaction{}
	appTx.ApplicationID = basics.AppIndex(appIdx)
	appTx.OnCompletion = transactions.NoOpOC

	appTx.Header = transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
		FirstValid:  basics.Round(round),
		LastValid:   basics.Round(round + 1000),
		GenesisHash: crypto.Digest{1},
		Note:        note,
	}
	appTx.Type = protocol.ApplicationCallTx
	return
}
