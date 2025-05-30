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

package ledger

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

var minFee basics.MicroAlgos

func init() {
	params := config.Consensus[protocol.ConsensusCurrentVersion]
	minFee = basics.MicroAlgos{Raw: params.MinTxnFee}
}

// BenchTxnGenerator generates transactions as long as asked for
type BenchTxnGenerator interface {
	// Prepare should be used for making pre-benchmark ledger initialization
	// like accounts funding, assets or apps creation
	Prepare(tb testing.TB, addrs []basics.Address, keys []*crypto.SignatureSecrets, rnd basics.Round, gh crypto.Digest) ([]transactions.SignedTxn, int)
	// Txn generates a single transaction
	Txn(tb testing.TB, addrs []basics.Address, keys []*crypto.SignatureSecrets, rnd basics.Round, gh crypto.Digest) transactions.SignedTxn
}

// BenchPaymentTxnGenerator generates payment transactions
type BenchPaymentTxnGenerator struct {
	counter int
}

func (g *BenchPaymentTxnGenerator) Prepare(tb testing.TB, addrs []basics.Address, keys []*crypto.SignatureSecrets, rnd basics.Round, gh crypto.Digest) ([]transactions.SignedTxn, int) {
	return nil, 0
}

func (g *BenchPaymentTxnGenerator) Txn(tb testing.TB, addrs []basics.Address, keys []*crypto.SignatureSecrets, rnd basics.Round, gh crypto.Digest) transactions.SignedTxn {
	sender := g.counter % len(addrs)
	receiver := (g.counter + 1) % len(addrs)
	// The following would create more random selection of accounts, and prevent a cache of half of the accounts..
	//		iDigest := crypto.Hash([]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)})
	//		sender := (uint64(iDigest[0]) + uint64(iDigest[1])*256 + uint64(iDigest[2])*256*256) % uint64(len(addrs))
	//		receiver := (uint64(iDigest[4]) + uint64(iDigest[5])*256 + uint64(iDigest[6])*256*256) % uint64(len(addrs))

	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addrs[sender],
			Fee:         minFee,
			FirstValid:  rnd,
			LastValid:   rnd,
			GenesisHash: gh,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addrs[receiver],
			Amount:   basics.MicroAlgos{Raw: 100},
		},
	}
	stxn := txn.Sign(keys[sender])
	g.counter++
	return stxn
}

// benchAppOptInsTxnGenerator generates payment transactions acrosss accounts that have
// opted into applications.
type benchAppOptInsTxnGenerator struct {
	NumApps               int
	MaxLocalSchemaEntries uint64
	Program               []byte
	ClearProgram          []byte
	OptedInAccts          []basics.Address
	OptedInAcctsIndices   []int
	MaxAppsOptedIn        int
	TransactionsType      protocol.TxType
	AppsOptedIn           map[basics.Address]map[basics.AppIndex]struct{}
}

func (g *benchAppOptInsTxnGenerator) Prepare(tb testing.TB, addrs []basics.Address, keys []*crypto.SignatureSecrets, rnd basics.Round, gh crypto.Digest) ([]transactions.SignedTxn, int) {
	maxLocalSchemaEntries := g.MaxLocalSchemaEntries
	maxAppsOptedIn := g.MaxAppsOptedIn

	// this function might create more transactions than a single block could contain.
	// estimate number of smaller blocks needed in order to set LastValid properly
	var optedInAccts = len(addrs) / 2
	const maxTxnPerBlock = 3000
	expectedTxnNum := g.NumApps + optedInAccts*maxAppsOptedIn/2
	expectedNumOfBlocks := expectedTxnNum/maxTxnPerBlock + 1

	createTxns := make([]transactions.SignedTxn, 0, g.NumApps)
	for i := 0; i < g.NumApps; i++ {
		creatorIdx := rand.Intn(len(addrs))
		creator := addrs[creatorIdx]
		txn := transactions.Transaction{
			Type: protocol.ApplicationCallTx,
			Header: transactions.Header{
				Sender:      creator,
				Fee:         minFee,
				FirstValid:  rnd,
				LastValid:   rnd + basics.Round(expectedNumOfBlocks),
				GenesisHash: gh,
				Note:        ledgertesting.RandomNote(),
			},
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApprovalProgram:   g.Program,
				ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
				LocalStateSchema:  basics.StateSchema{NumByteSlice: maxLocalSchemaEntries},
			},
		}
		stxn := txn.Sign(keys[creatorIdx])
		createTxns = append(createTxns, stxn)
	}

	g.AppsOptedIn = make(map[basics.Address]map[basics.AppIndex]struct{}, optedInAccts)
	appsOptedIn := g.AppsOptedIn

	optInTxns := make([]transactions.SignedTxn, 0, optedInAccts*maxAppsOptedIn/2)
	require.True(tb, g.NumApps > maxAppsOptedIn)
	optedInAddrIdx := rand.Perm(len(addrs))
	for i := 0; i < optedInAccts; i++ {
		senderIdx := optedInAddrIdx[i]
		sender := addrs[senderIdx]

		g.OptedInAccts = append(g.OptedInAccts, sender)
		g.OptedInAcctsIndices = append(g.OptedInAcctsIndices, senderIdx)

		acctOptIns := make(map[basics.AppIndex]struct{}, maxAppsOptedIn)

		appIdxPerm := rand.Perm(g.NumApps)
		for j := 0; j < rand.Int()%(maxAppsOptedIn+1); j++ {
			appIdx := basics.AppIndex(appIdxPerm[j] + 1)
			acctOptIns[appIdx] = struct{}{}

			txn := transactions.Transaction{
				Type: protocol.ApplicationCallTx,
				Header: transactions.Header{
					Sender:      sender,
					Fee:         minFee,
					FirstValid:  rnd,
					LastValid:   rnd + basics.Round(expectedNumOfBlocks),
					GenesisHash: gh,
				},
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID: appIdx,
					OnCompletion:  transactions.OptInOC,
				},
			}
			stxn := txn.Sign(keys[senderIdx])
			optInTxns = append(optInTxns, stxn)
		}
		appsOptedIn[sender] = acctOptIns
	}

	return append(createTxns, optInTxns...), maxTxnPerBlock
}

func (g *benchAppOptInsTxnGenerator) Txn(tb testing.TB, addrs []basics.Address, keys []*crypto.SignatureSecrets, rnd basics.Round, gh crypto.Digest) transactions.SignedTxn {
	switch g.TransactionsType {
	case protocol.PaymentTx:
		return g.generatePaymentTransaction(tb, addrs, keys, rnd, gh)
	case protocol.ApplicationCallTx:
		return g.generateAppCallTransaction(tb, addrs, keys, rnd, gh)
	default:
		tb.FailNow()
		return transactions.SignedTxn{}
	}
}

func (g *benchAppOptInsTxnGenerator) generatePaymentTransaction(tb testing.TB, addrs []basics.Address, keys []*crypto.SignatureSecrets, rnd basics.Round, gh crypto.Digest) transactions.SignedTxn {
	idx := rand.Intn(len(g.OptedInAcctsIndices))
	senderIdx := g.OptedInAcctsIndices[idx]
	sender := addrs[senderIdx]
	receiverIdx := rand.Intn(len(addrs))

	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         minFee,
			FirstValid:  rnd,
			LastValid:   rnd,
			GenesisHash: gh,
			Note:        ledgertesting.RandomNote(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addrs[receiverIdx],
			Amount:   basics.MicroAlgos{Raw: 100},
		},
	}
	stxn := txn.Sign(keys[senderIdx])
	return stxn
}

func (g *benchAppOptInsTxnGenerator) generateAppCallTransaction(tb testing.TB, addrs []basics.Address, keys []*crypto.SignatureSecrets, rnd basics.Round, gh crypto.Digest) transactions.SignedTxn {
	var senderIdx int
	for {
		idx := rand.Intn(len(g.OptedInAcctsIndices))
		senderIdx = g.OptedInAcctsIndices[idx]
		if len(g.AppsOptedIn[addrs[senderIdx]]) > 0 {
			break
		}
	}
	sender := addrs[senderIdx]
	// pick a random app.
	var appIdx basics.AppIndex

	appEntryIdx := rand.Intn(len(g.AppsOptedIn[addrs[senderIdx]]))
	for curAppIdx := range g.AppsOptedIn[addrs[senderIdx]] {
		if appEntryIdx == 0 {
			appIdx = curAppIdx
			break
		}
		appEntryIdx--
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         minFee,
			FirstValid:  rnd,
			LastValid:   rnd,
			GenesisHash: gh,
			Note:        ledgertesting.RandomNote(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appIdx,
			OnCompletion:  transactions.NoOpOC,
		},
	}
	stxn := txn.Sign(keys[senderIdx])
	return stxn
}

func BenchmarkBlockEvaluatorRAMCrypto(b *testing.B) {
	g := BenchPaymentTxnGenerator{}
	benchmarkBlockEvaluator(b, true, true, protocol.ConsensusCurrentVersion, &g)
}
func BenchmarkBlockEvaluatorRAMNoCrypto(b *testing.B) {
	g := BenchPaymentTxnGenerator{}
	benchmarkBlockEvaluator(b, true, false, protocol.ConsensusCurrentVersion, &g)
}
func BenchmarkBlockEvaluatorDiskCrypto(b *testing.B) {
	g := BenchPaymentTxnGenerator{}
	benchmarkBlockEvaluator(b, false, true, protocol.ConsensusCurrentVersion, &g)
}
func BenchmarkBlockEvaluatorDiskNoCrypto(b *testing.B) {
	g := BenchPaymentTxnGenerator{}
	benchmarkBlockEvaluator(b, false, false, protocol.ConsensusCurrentVersion, &g)
}

func BenchmarkBlockEvaluatorDiskAppOptIns(b *testing.B) {
	progSrc := `#pragma version 2
	intcblock 1
	intc_0`
	ops, err := logic.AssembleString(progSrc)
	require.NoError(b, err)
	g := benchAppOptInsTxnGenerator{
		NumApps:               500,
		MaxLocalSchemaEntries: config.Consensus[protocol.ConsensusFuture].MaxLocalSchemaEntries,
		Program:               ops.Program,
		ClearProgram:          ops.Program,
		MaxAppsOptedIn:        config.Consensus[protocol.ConsensusV30].MaxAppsOptedIn,
		TransactionsType:      protocol.PaymentTx,
	}
	benchmarkBlockEvaluator(b, false, false, protocol.ConsensusFuture, &g)
}

func BenchmarkBlockEvaluatorDiskAppCalls(b *testing.B) {
	// Go normally starts measuring the benchmark run time with b.N = 1, and then
	// adjusts b.N if the runtime is less than a second. In this case, the runtime
	// of the test for b.N = 1 is about 0.7 second, which cause the benchmark to be
	// executed twice. Running it twice would not be an issue on it's own; however,
	// the setup time for this test is 1.5 minutes long. By setting the b.N = 2, we
	// set up for success on the first iteration, and preventing a second iteration.
	if b.N < 2 {
		b.N = 2 //nolint:staticcheck // intentionally setting b.N
	}
	// program sets all 16 available keys of len 64 bytes to same values of 64 bytes
	source := `#pragma version 5
	txn OnCompletion
	int OptIn
	==
	bz done
	int 0
	store 0 // save loop var
loop:
	int 0  // acct index
	byte "012345678901234567890123456789012345678901234567890123456789ABC0"
	int 63
	load 0 // loop var
	int 0x41
	+
	setbyte // str[63] = chr(i + 'A')
	dup  // value is the same as key
	app_local_put
	load 0  // loop var
	int 1
	+
	dup
	store 0 // save loop var
	int 16
	<
	bnz loop
done:
	int 1
`
	programOps, err := logic.AssembleString(source)
	require.NoError(b, err)

	clearProgramSrc := `#pragma version 2
	intcblock 1
	intc_0`
	clearProgramOps, err := logic.AssembleString(clearProgramSrc)
	require.NoError(b, err)

	g := benchAppOptInsTxnGenerator{
		NumApps:               45000,
		MaxLocalSchemaEntries: config.Consensus[protocol.ConsensusFuture].MaxLocalSchemaEntries,
		Program:               programOps.Program,
		ClearProgram:          clearProgramOps.Program,
		MaxAppsOptedIn:        2,
		TransactionsType:      protocol.ApplicationCallTx,
	}
	benchmarkBlockEvaluator(b, false, false, protocol.ConsensusFuture, &g)
}

func BenchmarkBlockEvaluatorDiskFullAppOptIns(b *testing.B) {
	// program sets all 16 available keys of len 64 bytes to same values of 64 bytes
	source := `#pragma version 5
	txn OnCompletion
	int OptIn
	==
	bz done
	int 0
	store 0 // save loop var
loop:
	int 0  // acct index
	byte "012345678901234567890123456789012345678901234567890123456789ABC0"
	int 63
	load 0 // loop var
	int 0x41
	+
	setbyte // str[63] = chr(i + 'A')
	dup  // value is the same as key
	app_local_put
	load 0  // loop var
	int 1
	+
	dup
	store 0 // save loop var
	int 16
	<
	bnz loop
done:
	int 1
`
	programOps, err := logic.AssembleString(source)
	require.NoError(b, err)

	clearProgramSrc := `#pragma version 2
	intcblock 1
	intc_0`
	clearProgramOps, err := logic.AssembleString(clearProgramSrc)
	require.NoError(b, err)

	g := benchAppOptInsTxnGenerator{
		NumApps:               500,
		MaxLocalSchemaEntries: config.Consensus[protocol.ConsensusFuture].MaxLocalSchemaEntries,
		Program:               programOps.Program,
		ClearProgram:          clearProgramOps.Program,
		MaxAppsOptedIn:        config.Consensus[protocol.ConsensusV30].MaxAppsOptedIn,
		TransactionsType:      protocol.PaymentTx,
	}
	benchmarkBlockEvaluator(b, false, false, protocol.ConsensusFuture, &g)
}

func testLedgerCleanup(l *Ledger, dbName string, inMem bool) {
	l.Close()
	if !inMem {
		hits, err := filepath.Glob(dbName + "*.sqlite")
		if err != nil {
			return
		}
		for _, fname := range hits {
			os.Remove(fname)
		}
	}
}

// this variant focuses on benchmarking ledger.go `Eval()`, the rest is setup, it runs Eval() b.N times.
func benchmarkBlockEvaluator(b *testing.B, inMem bool, withCrypto bool, proto protocol.ConsensusVersion, txnSource BenchTxnGenerator) {
	deadlockDisable := deadlock.Opts.Disable
	deadlock.Opts.Disable = true
	defer func() { deadlock.Opts.Disable = deadlockDisable }()
	start := time.Now()
	genesisInitState, addrs, keys := ledgertesting.GenesisWithProto(100000, proto)
	dbName := fmt.Sprintf("%s.%d", b.Name(), crypto.RandUint64())
	cparams := config.Consensus[genesisInitState.Block.CurrentProtocol]
	cparams.MaxTxnBytesPerBlock = 1000000000 // very big, no limit
	config.Consensus[protocol.ConsensusVersion(dbName)] = cparams
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusVersion(dbName)
	cfg := config.GetDefaultLocal()
	cfg.Archival = false
	testingLog := logging.TestingLog(b)
	testingLog.SetLevel(logging.Error)
	l, err := OpenLedger(testingLog, dbName, inMem, genesisInitState, cfg)
	require.NoError(b, err)
	defer testLedgerCleanup(l, dbName, inMem)

	dbName2 := dbName + "_2"
	l2, err := OpenLedger(testingLog, dbName2, inMem, genesisInitState, cfg)
	require.NoError(b, err)
	defer testLedgerCleanup(l2, dbName2, inMem)

	bepprof := os.Getenv("BLOCK_EVAL_PPROF")
	if len(bepprof) > 0 {
		profpath := dbName + "_cpuprof"
		profout, err := os.Create(profpath)
		if err != nil {
			b.Fatal(err)
			return
		}
		b.Logf("%s: cpu profile for b.N=%d", profpath, b.N)
		pprof.StartCPUProfile(profout)
		defer func() {
			pprof.StopCPUProfile()
			profout.Close()
		}()
	}

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	// test speed of block building
	numTxns := 50000

	validatedBlock := benchmarkPreparePaymentTransactionsTesting(b, numTxns, txnSource, genesisInitState, addrs, keys, l, l2)

	blockBuildDone := time.Now()
	setupTime := blockBuildDone.Sub(start)
	b.Logf("BenchmarkBlockEvaluator setup time %s", setupTime.String())

	err = l.AddValidatedBlock(*validatedBlock, agreement.Certificate{})
	require.NoError(b, err)

	avbDone := time.Now()
	avbTime := avbDone.Sub(blockBuildDone)
	b.ReportMetric(float64(avbTime)/float64(numTxns), "ns/AddValidatedBlock_tx")

	// test speed of block validation
	// This should be the same as the eval line in ledger.go AddBlock()
	// This is pulled out to isolate Eval() time from db ops of AddValidatedBlock()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if withCrypto {
			_, err = l2.Validate(context.Background(), validatedBlock.Block(), backlogPool)
		} else {
			_, err = eval.Eval(context.Background(), l2, validatedBlock.Block(), false, nil, nil, l2.tracer)
		}
		require.NoError(b, err)
	}

	abDone := time.Now()
	abTime := abDone.Sub(avbDone)
	b.ReportMetric(float64(abTime)/float64(numTxns*b.N), "ns/eval_validate_tx")

	b.StopTimer()
}

func benchmarkPreparePaymentTransactionsTesting(b *testing.B, numTxns int, txnSource BenchTxnGenerator, genesisInitState ledgercore.InitState, addrs []basics.Address, keys []*crypto.SignatureSecrets, l, l2 *Ledger) *ledgercore.ValidatedBlock {
	newBlock := bookkeeping.MakeBlock(genesisInitState.Block.BlockHeader)
	bev, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0, nil)
	require.NoError(b, err)

	genHash := l.GenesisHash()
	// apply initialization transactions if any
	initSignedTxns, maxTxnPerBlock := txnSource.Prepare(b, addrs, keys, newBlock.Round(), genHash)
	if len(initSignedTxns) > 0 {

		var numBlocks uint64 = 0
		var unfinishedBlock *ledgercore.UnfinishedBlock
		var validatedBlock *ledgercore.ValidatedBlock

		// there might be more transactions than MaxTxnBytesPerBlock allows so
		// make smaller blocks to fit
		for i, stxn := range initSignedTxns {
			err := bev.Transaction(stxn, transactions.ApplyData{})
			require.NoError(b, err)
			if maxTxnPerBlock > 0 && i%maxTxnPerBlock == 0 || i == len(initSignedTxns)-1 {
				unfinishedBlock, err = bev.GenerateBlock(nil)
				require.NoError(b, err)
				// We are not setting seed & proposer details with
				// FinishBlock/WithProposer. When agreement actually does that,
				// it surely has some cost.
				vb := ledgercore.MakeValidatedBlock(unfinishedBlock.UnfinishedBlock(), unfinishedBlock.UnfinishedDeltas())
				validatedBlock = &vb
				for _, l := range []*Ledger{l, l2} {
					err = l.AddValidatedBlock(*validatedBlock, agreement.Certificate{})
					require.NoError(b, err)
				}
				newBlock = bookkeeping.MakeBlock(validatedBlock.Block().BlockHeader)
				bev, err = l.StartEvaluator(newBlock.BlockHeader, 0, 0, nil)
				require.NoError(b, err)
				numBlocks++
			}
		}

		// wait until everying is written and then reload ledgers in order
		// to start reading accounts from DB and not from caches/deltas
		var wg sync.WaitGroup
		for _, l := range []*Ledger{l, l2} {
			wg.Add(1)
			// committing might take a long time, do it parallel
			go func(l *Ledger) {
				commitRound(numBlocks, 0, l)
				l.reloadLedger()
				wg.Done()
			}(l)
		}
		wg.Wait()

		newBlock = bookkeeping.MakeBlock(validatedBlock.Block().BlockHeader)
		bev, err = l.StartEvaluator(newBlock.BlockHeader, 0, 0, nil)
		require.NoError(b, err)
	}

	setupDone := time.Now()

	for i := 0; i < numTxns; i++ {
		stxn := txnSource.Txn(b, addrs, keys, newBlock.Round(), genHash)
		err = bev.Transaction(stxn, transactions.ApplyData{})
		require.NoError(b, err)
	}

	// as above - this might be an underestimate because we skip agreement
	unfinishedBlock, err := bev.GenerateBlock(nil)
	require.NoError(b, err)
	validatedBlock := ledgercore.MakeValidatedBlock(unfinishedBlock.UnfinishedBlock(), unfinishedBlock.UnfinishedDeltas())

	blockBuildDone := time.Now()
	blockBuildTime := blockBuildDone.Sub(setupDone)
	b.ReportMetric(float64(blockBuildTime)/float64(numTxns), "ns/block_build_tx")

	return &validatedBlock
}
