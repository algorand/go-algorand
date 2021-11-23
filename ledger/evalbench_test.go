// Copyright (C) 2019-2021 Algorand, Inc.
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
	"github.com/algorand/go-algorand/ledger/internal"
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

// BenchAppTxnGenerator generates app opt in transactions
type BenchAppOptInsTxnGenerator struct {
	NumApps             int
	Proto               protocol.ConsensusVersion
	Program             []byte
	OptedInAccts        []basics.Address
	OptedInAcctsIndices []int
}

func (g *BenchAppOptInsTxnGenerator) Prepare(tb testing.TB, addrs []basics.Address, keys []*crypto.SignatureSecrets, rnd basics.Round, gh crypto.Digest) ([]transactions.SignedTxn, int) {
	maxLocalSchemaEntries := config.Consensus[g.Proto].MaxLocalSchemaEntries
	maxAppsOptedIn := config.Consensus[g.Proto].MaxAppsOptedIn

	// this function might create too much transaction even to fit into a single block
	// estimate number of smaller blocks needed in order to set LastValid properly
	const numAccts = 10000
	const maxTxnPerBlock = 10000
	expectedTxnNum := g.NumApps + numAccts*maxAppsOptedIn
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

	appsOptedIn := make(map[basics.Address]map[basics.AppIndex]struct{}, numAccts)

	optInTxns := make([]transactions.SignedTxn, 0, numAccts*maxAppsOptedIn)

	for i := 0; i < numAccts; i++ {
		var senderIdx int
		var sender basics.Address
		for {
			senderIdx = rand.Intn(len(addrs))
			sender = addrs[senderIdx]
			if len(appsOptedIn[sender]) < maxAppsOptedIn {
				appsOptedIn[sender] = make(map[basics.AppIndex]struct{}, maxAppsOptedIn)
				break
			}
		}
		g.OptedInAccts = append(g.OptedInAccts, sender)
		g.OptedInAcctsIndices = append(g.OptedInAcctsIndices, senderIdx)

		acctOptIns := appsOptedIn[sender]
		for j := 0; j < maxAppsOptedIn; j++ {
			var appIdx basics.AppIndex
			for {
				appIdx = basics.AppIndex(rand.Intn(g.NumApps) + 1)
				if _, ok := acctOptIns[appIdx]; !ok {
					acctOptIns[appIdx] = struct{}{}
					break
				}
			}

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
					ApplicationID: basics.AppIndex(appIdx),
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

func (g *BenchAppOptInsTxnGenerator) Txn(tb testing.TB, addrs []basics.Address, keys []*crypto.SignatureSecrets, rnd basics.Round, gh crypto.Digest) transactions.SignedTxn {
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
	g := BenchAppOptInsTxnGenerator{
		NumApps: 500,
		Proto:   protocol.ConsensusFuture,
		Program: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
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
	ops, err := logic.AssembleString(source)
	require.NoError(b, err)
	prog := ops.Program
	g := BenchAppOptInsTxnGenerator{
		NumApps: 500,
		Proto:   protocol.ConsensusFuture,
		Program: prog,
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
	cfg.Archival = true
	l, err := OpenLedger(logging.Base(), dbName, inMem, genesisInitState, cfg)
	require.NoError(b, err)
	defer testLedgerCleanup(l, dbName, inMem)

	dbName2 := dbName + "_2"
	l2, err := OpenLedger(logging.Base(), dbName2, inMem, genesisInitState, cfg)
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

	newBlock := bookkeeping.MakeBlock(genesisInitState.Block.BlockHeader)
	bev, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0)
	require.NoError(b, err)

	genHash := l.GenesisHash()

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	// apply initialization transations if any
	initSignedTxns, maxTxnPerBlock := txnSource.Prepare(b, addrs, keys, newBlock.Round(), genHash)
	if len(initSignedTxns) > 0 {

		var numBlocks uint64 = 0
		var validatedBlock *ledgercore.ValidatedBlock

		// there are might more transactions than MaxTxnBytesPerBlock allows
		// so make smaller blocks to fit
		for i, stxn := range initSignedTxns {
			err = bev.Transaction(stxn, transactions.ApplyData{})
			require.NoError(b, err)
			if maxTxnPerBlock > 0 && i%maxTxnPerBlock == 0 || i == len(initSignedTxns)-1 {
				validatedBlock, err = bev.GenerateBlock()
				require.NoError(b, err)
				for _, l := range []*Ledger{l, l2} {
					err = l.AddValidatedBlock(*validatedBlock, agreement.Certificate{})
					require.NoError(b, err)
				}
				newBlock = bookkeeping.MakeBlock(validatedBlock.Block().BlockHeader)
				bev, err = l.StartEvaluator(newBlock.BlockHeader, 0, 0)
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
		bev, err = l.StartEvaluator(newBlock.BlockHeader, 0, 0)
		require.NoError(b, err)
	}

	setupDone := time.Now()
	setupTime := setupDone.Sub(start)
	b.Logf("BenchmarkBlockEvaluator setup time %s", setupTime.String())

	// test speed of block building
	numTxns := 50000

	for i := 0; i < numTxns; i++ {
		stxn := txnSource.Txn(b, addrs, keys, newBlock.Round(), genHash)
		err = bev.Transaction(stxn, transactions.ApplyData{})
		require.NoError(b, err)
	}

	validatedBlock, err := bev.GenerateBlock()
	require.NoError(b, err)

	blockBuildDone := time.Now()
	blockBuildTime := blockBuildDone.Sub(setupDone)
	b.ReportMetric(float64(blockBuildTime)/float64(numTxns), "ns/block_build_tx")

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
			_, err = internal.Eval(context.Background(), l2, validatedBlock.Block(), false, nil, nil)
		}
		require.NoError(b, err)
	}

	abDone := time.Now()
	abTime := abDone.Sub(avbDone)
	b.ReportMetric(float64(abTime)/float64(numTxns*b.N), "ns/eval_validate_tx")

	b.StopTimer()
}
