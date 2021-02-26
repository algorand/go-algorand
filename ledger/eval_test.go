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
	"os"
	"path/filepath"
	"runtime/pprof"
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
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

var testPoolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var testSinkAddr = basics.Address{0x2c, 0x2a, 0x6c, 0xe9, 0xa9, 0xa7, 0xc2, 0x8c, 0x22, 0x95, 0xfd, 0x32, 0x4f, 0x77, 0xa5, 0x4, 0x8b, 0x42, 0xc2, 0xb7, 0xa8, 0x54, 0x84, 0xb6, 0x80, 0xb1, 0xe1, 0x3d, 0x59, 0x9b, 0xeb, 0x36}
var minFee basics.MicroAlgos

func init() {
	params := config.Consensus[protocol.ConsensusCurrentVersion]
	minFee = basics.MicroAlgos{Raw: params.MinTxnFee}
}

func TestBlockEvaluator(t *testing.T) {
	genesisInitState, addrs, keys := genesis(10)

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(logging.Base(), dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	newBlock := bookkeeping.MakeBlock(genesisInitState.Block.BlockHeader)
	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0)
	require.NoError(t, err)

	genHash := genesisInitState.Block.BlockHeader.GenesisHash
	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addrs[0],
			Fee:         minFee,
			FirstValid:  newBlock.Round(),
			LastValid:   newBlock.Round(),
			GenesisHash: genHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addrs[1],
			Amount:   basics.MicroAlgos{Raw: 100},
		},
	}

	// Correct signature should work
	st := txn.Sign(keys[0])
	err = eval.Transaction(st, transactions.ApplyData{})
	require.NoError(t, err)

	selfTxn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addrs[2],
			Fee:         minFee,
			FirstValid:  newBlock.Round(),
			LastValid:   newBlock.Round(),
			GenesisHash: genHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addrs[2],
			Amount:   basics.MicroAlgos{Raw: 100},
		},
	}
	err = eval.Transaction(selfTxn.Sign(keys[2]), transactions.ApplyData{})
	require.NoError(t, err)

	validatedBlock, err := eval.GenerateBlock()
	require.NoError(t, err)

	accts := genesisInitState.Accounts
	bal0 := accts[addrs[0]]
	bal1 := accts[addrs[1]]
	bal2 := accts[addrs[2]]

	l.AddValidatedBlock(*validatedBlock, agreement.Certificate{})

	bal0new, err := l.Lookup(newBlock.Round(), addrs[0])
	require.NoError(t, err)
	bal1new, err := l.Lookup(newBlock.Round(), addrs[1])
	require.NoError(t, err)
	bal2new, err := l.Lookup(newBlock.Round(), addrs[2])
	require.NoError(t, err)

	require.Equal(t, bal0new.MicroAlgos.Raw, bal0.MicroAlgos.Raw-minFee.Raw-100)
	require.Equal(t, bal1new.MicroAlgos.Raw, bal1.MicroAlgos.Raw+100)
	require.Equal(t, bal2new.MicroAlgos.Raw, bal2.MicroAlgos.Raw-minFee.Raw)
}

func TestRekeying(t *testing.T) {
	// Pretend rekeying is supported
	actual := config.Consensus[protocol.ConsensusCurrentVersion]
	pretend := actual
	pretend.SupportRekeying = true
	config.Consensus[protocol.ConsensusCurrentVersion] = pretend
	defer func() {
		config.Consensus[protocol.ConsensusCurrentVersion] = actual
	}()

	// Bring up a ledger
	genesisInitState, addrs, keys := genesis(10)
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(logging.Base(), dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	// Make a new block
	nextRound := l.Latest() + basics.Round(1)
	genHash := genesisInitState.Block.BlockHeader.GenesisHash

	// Test plan
	// Syntax: [A -> B][C, D] means transaction from A that rekeys to B with authaddr C and actual sig from D
	makeTxn := func(sender, rekeyto, authaddr basics.Address, signer *crypto.SignatureSecrets, uniq uint8) transactions.SignedTxn {
		txn := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      sender,
				Fee:         minFee,
				FirstValid:  nextRound,
				LastValid:   nextRound,
				GenesisHash: genHash,
				RekeyTo:     rekeyto,
				Note:        []byte{uniq},
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: sender,
			},
		}
		sig := signer.Sign(txn)
		return transactions.SignedTxn{Txn: txn, Sig: sig, AuthAddr: authaddr}
	}

	tryBlock := func(stxns []transactions.SignedTxn) error {
		// We'll make a block using the evaluator.
		// When generating a block, the evaluator doesn't check transaction sigs -- it assumes the transaction pool already did that.
		// So the ValidatedBlock that comes out isn't necessarily actually a valid block. We'll call Validate ourselves.

		newBlock := bookkeeping.MakeBlock(genesisInitState.Block.BlockHeader)
		eval, err := l.StartEvaluator(newBlock.BlockHeader, 0)
		require.NoError(t, err)

		for _, stxn := range stxns {
			err = eval.Transaction(stxn, transactions.ApplyData{})
			if err != nil {
				return err
			}
		}
		validatedBlock, err := eval.GenerateBlock()
		if err != nil {
			return err
		}

		backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
		defer backlogPool.Shutdown()
		_, err = l.Validate(context.Background(), validatedBlock.Block(), backlogPool)
		return err
	}

	// Preamble transactions, which all of the blocks in this test will start with
	// [A -> 0][0,A] (normal transaction)
	// [A -> B][0,A] (rekey)
	txn0 := makeTxn(addrs[0], basics.Address{}, basics.Address{}, keys[0], 0) // Normal transaction
	txn1 := makeTxn(addrs[0], addrs[1], basics.Address{}, keys[0], 1)         // Rekey transaction

	// Test 1: Do only good things
	// (preamble)
	// [A -> 0][B,B] (normal transaction using new key)
	// [A -> A][B,B] (rekey back to A, transaction still signed by B)
	// [A -> 0][0,A] (normal transaction again)
	test1txns := []transactions.SignedTxn{
		txn0, txn1, // (preamble)
		makeTxn(addrs[0], basics.Address{}, addrs[1], keys[1], 2),         // [A -> 0][B,B]
		makeTxn(addrs[0], addrs[0], addrs[1], keys[1], 3),                 // [A -> A][B,B]
		makeTxn(addrs[0], basics.Address{}, basics.Address{}, keys[0], 4), // [A -> 0][0,A]
	}
	err = tryBlock(test1txns)
	require.NoError(t, err)

	// Test 2: Use old key after rekeying
	// (preamble)
	// [A -> A][0,A] (rekey back to A, but signed by A instead of B)
	test2txns := []transactions.SignedTxn{
		txn0, txn1, // (preamble)
		makeTxn(addrs[0], addrs[0], basics.Address{}, keys[0], 2), // [A -> A][0,A]
	}
	err = tryBlock(test2txns)
	require.Error(t, err)

	// TODO: More tests
}

func TestPrepareEvalParams(t *testing.T) {
	eval := BlockEvaluator{
		prevHeader: bookkeeping.BlockHeader{
			TimeStamp: 1234,
			Round:     2345,
		},
		proto: config.ConsensusParams{
			Application: true,
		},
	}

	// Create some sample transactions
	payment := transactions.SignedTxnWithAD{
		SignedTxn: transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender: basics.Address{1, 2, 3, 4},
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: basics.Address{4, 3, 2, 1},
					Amount:   basics.MicroAlgos{Raw: 100},
				},
			},
		},
	}

	appcall1 := transactions.SignedTxnWithAD{
		SignedTxn: transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type: protocol.ApplicationCallTx,
				Header: transactions.Header{
					Sender: basics.Address{1, 2, 3, 4},
				},
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID: basics.AppIndex(1),
				},
			},
		},
	}

	appcall2 := appcall1
	appcall2.SignedTxn.Txn.ApplicationCallTxnFields.ApplicationID = basics.AppIndex(2)

	type evalTestCase struct {
		group []transactions.SignedTxnWithAD

		// indicates if prepareAppEvaluators should return a non-nil
		// appTealEvaluator for the txn at index i
		expected []bool
	}

	// Create some groups with these transactions
	cases := []evalTestCase{
		{[]transactions.SignedTxnWithAD{payment}, []bool{false}},
		{[]transactions.SignedTxnWithAD{appcall1}, []bool{true}},
		{[]transactions.SignedTxnWithAD{payment, payment}, []bool{false, false}},
		{[]transactions.SignedTxnWithAD{appcall1, payment}, []bool{true, false}},
		{[]transactions.SignedTxnWithAD{payment, appcall1}, []bool{false, true}},
		{[]transactions.SignedTxnWithAD{appcall1, appcall2}, []bool{true, true}},
		{[]transactions.SignedTxnWithAD{appcall1, appcall2, appcall1}, []bool{true, true, true}},
		{[]transactions.SignedTxnWithAD{payment, appcall1, payment}, []bool{false, true, false}},
		{[]transactions.SignedTxnWithAD{appcall1, payment, appcall2}, []bool{true, false, true}},
	}

	for i, testCase := range cases {
		t.Run(fmt.Sprintf("i=%d", i), func(t *testing.T) {
			res := eval.prepareEvalParams(testCase.group)
			require.Equal(t, len(res), len(testCase.group))

			// Compute the expected transaction group without ApplyData for
			// the test case
			expGroupNoAD := make([]transactions.SignedTxn, len(testCase.group))
			for j := range testCase.group {
				expGroupNoAD[j] = testCase.group[j].SignedTxn
			}

			// Ensure non app calls have a nil evaluator, and that non-nil
			// evaluators point to the right transactions and values
			for j, present := range testCase.expected {
				if present {
					require.NotNil(t, res[j])
					require.Equal(t, res[j].GroupIndex, j)
					require.Equal(t, res[j].TxnGroup, expGroupNoAD)
					require.Equal(t, *res[j].Proto, eval.proto)
					require.Equal(t, *res[j].Txn, testCase.group[j].SignedTxn)
				} else {
					require.Nil(t, res[j])
				}
			}
		})
	}
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

func testEvalAppGroup(t *testing.T, schema basics.StateSchema) (*BlockEvaluator, basics.Address, error) {
	genesisInitState, addrs, keys := genesis(10)

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	const inMem = true
	cfg := config.GetDefaultLocal()
	l, err := OpenLedger(logging.Base(), dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	newBlock := bookkeeping.MakeBlock(genesisInitState.Block.BlockHeader)
	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0)
	require.NoError(t, err)
	eval.validate = true
	eval.generate = false

	ops, err := logic.AssembleString(`#pragma version 2
	txn ApplicationID
	bz create
	byte "caller"
	txn Sender
	app_global_put
	b ok
create:
	byte "creator"
	txn Sender
	app_global_put
ok:
	int 1`)
	require.NoError(t, err, ops.Errors)
	approval := ops.Program
	ops, err = logic.AssembleString("#pragma version 2\nint 1")
	require.NoError(t, err)
	clear := ops.Program

	genHash := genesisInitState.Block.BlockHeader.GenesisHash
	header := transactions.Header{
		Sender:      addrs[0],
		Fee:         minFee,
		FirstValid:  newBlock.Round(),
		LastValid:   newBlock.Round(),
		GenesisHash: genHash,
	}
	appcall1 := transactions.Transaction{
		Type:   protocol.ApplicationCallTx,
		Header: header,
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			GlobalStateSchema: schema,
			ApprovalProgram:   approval,
			ClearStateProgram: clear,
		},
	}

	appcall2 := transactions.Transaction{
		Type:   protocol.ApplicationCallTx,
		Header: header,
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: 1,
		},
	}

	var group transactions.TxGroup
	group.TxGroupHashes = []crypto.Digest{crypto.HashObj(appcall1), crypto.HashObj(appcall2)}
	appcall1.Group = crypto.HashObj(group)
	appcall2.Group = crypto.HashObj(group)
	stxn1 := appcall1.Sign(keys[0])
	stxn2 := appcall2.Sign(keys[0])

	g := []transactions.SignedTxnWithAD{
		{
			SignedTxn: stxn1,
			ApplyData: transactions.ApplyData{
				EvalDelta: basics.EvalDelta{GlobalDelta: map[string]basics.ValueDelta{
					"creator": {Action: basics.SetBytesAction, Bytes: string(addrs[0][:])}},
				}},
		},
		{
			SignedTxn: stxn2,
			ApplyData: transactions.ApplyData{
				EvalDelta: basics.EvalDelta{GlobalDelta: map[string]basics.ValueDelta{
					"caller": {Action: basics.SetBytesAction, Bytes: string(addrs[0][:])}},
				}},
		},
	}
	err = eval.transactionGroup(g)
	return eval, addrs[0], err
}

// TestEvalAppStateCountsWithTxnGroup ensures txns in a group can't violate app state schema limits
// the test ensures that
// commitToParent -> applyChild copies child's cow state usage counts into parent
// and the usage counts correctly propagated from parent cow to child cow and back
func TestEvalAppStateCountsWithTxnGroup(t *testing.T) {
	_, _, err := testEvalAppGroup(t, basics.StateSchema{NumByteSlice: 1})
	require.Error(t, err)
	require.Contains(t, err.Error(), "store bytes count 2 exceeds schema bytes count 1")
}

// TestEvalAppAllocStateWithTxnGroup ensures roundCowState.deltas and applyStorageDelta
// produce correct results when a txn group has storage allocate and storage update actions
func TestEvalAppAllocStateWithTxnGroup(t *testing.T) {
	eval, addr, err := testEvalAppGroup(t, basics.StateSchema{NumByteSlice: 2})
	require.NoError(t, err)
	deltas := eval.state.deltas()
	ad, _ := deltas.Accts.Get(addr)
	state := ad.AppParams[1].GlobalState
	require.Equal(t, basics.TealValue{Type: basics.TealBytesType, Bytes: string(addr[:])}, state["caller"])
	require.Equal(t, basics.TealValue{Type: basics.TealBytesType, Bytes: string(addr[:])}, state["creator"])
}

func BenchmarkBlockEvaluatorRAMCrypto(b *testing.B) {
	benchmarkBlockEvaluator(b, true, true)
}
func BenchmarkBlockEvaluatorRAMNoCrypto(b *testing.B) {
	benchmarkBlockEvaluator(b, true, false)
}
func BenchmarkBlockEvaluatorDiskCrypto(b *testing.B) {
	benchmarkBlockEvaluator(b, false, true)
}
func BenchmarkBlockEvaluatorDiskNoCrypto(b *testing.B) {
	benchmarkBlockEvaluator(b, false, false)
}

// this variant focuses on benchmarking ledger.go `eval()`, the rest is setup, it runs eval() b.N times.
func benchmarkBlockEvaluator(b *testing.B, inMem bool, withCrypto bool) {
	deadlockDisable := deadlock.Opts.Disable
	deadlock.Opts.Disable = true
	defer func() { deadlock.Opts.Disable = deadlockDisable }()
	start := time.Now()
	genesisInitState, addrs, keys := genesis(100000)
	dbName := fmt.Sprintf("%s.%d", b.Name(), crypto.RandUint64())
	proto := config.Consensus[genesisInitState.Block.CurrentProtocol]
	proto.MaxTxnBytesPerBlock = 1000000000 // very big, no limit
	config.Consensus[protocol.ConsensusVersion(dbName)] = proto
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

	setupDone := time.Now()
	setupTime := setupDone.Sub(start)
	b.Logf("BenchmarkBlockEvaluator setup time %s", setupTime.String())

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

	// test speed of block building
	newBlock := bookkeeping.MakeBlock(genesisInitState.Block.BlockHeader)
	bev, err := l.StartEvaluator(newBlock.BlockHeader, 0)
	require.NoError(b, err)

	genHash := genesisInitState.Block.BlockHeader.GenesisHash

	numTxns := 50000

	for i := 0; i < numTxns; i++ {
		sender := i % len(addrs)
		receiver := (i + 1) % len(addrs)
		// The following would create more random selection of accounts, and prevent a cache of half of the accounts..
		//		iDigest := crypto.Hash([]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)})
		//		sender := (uint64(iDigest[0]) + uint64(iDigest[1])*256 + uint64(iDigest[2])*256*256) % uint64(len(addrs))
		//		receiver := (uint64(iDigest[4]) + uint64(iDigest[5])*256 + uint64(iDigest[6])*256*256) % uint64(len(addrs))
		txn := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      addrs[sender],
				Fee:         minFee,
				FirstValid:  newBlock.Round(),
				LastValid:   newBlock.Round(),
				GenesisHash: genHash,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: addrs[receiver],
				Amount:   basics.MicroAlgos{Raw: 100},
			},
		}
		st := txn.Sign(keys[sender])
		err = bev.Transaction(st, transactions.ApplyData{})
		require.NoError(b, err)
	}

	validatedBlock, err := bev.GenerateBlock()
	require.NoError(b, err)

	blockBuildDone := time.Now()
	blockBuildTime := blockBuildDone.Sub(setupDone)
	b.ReportMetric(float64(blockBuildTime)/float64(numTxns), "ns/block_build_tx")

	l.AddValidatedBlock(*validatedBlock, agreement.Certificate{})

	avbDone := time.Now()
	avbTime := avbDone.Sub(blockBuildDone)
	b.ReportMetric(float64(avbTime)/float64(numTxns), "ns/AddValidatedBlock_tx")

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	// test speed of block validation
	// This should be the same as the eval line in ledger.go AddBlock()
	// This is pulled out to isolate eval() time from db ops of AddValidatedBlock()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if withCrypto {
			_, err = l2.Validate(context.Background(), validatedBlock.blk, backlogPool)
		} else {
			_, err = eval(context.Background(), l2, validatedBlock.blk, false, nil, nil)
		}
		require.NoError(b, err)
	}

	abDone := time.Now()
	abTime := abDone.Sub(avbDone)
	b.ReportMetric(float64(abTime)/float64(numTxns*b.N), "ns/eval_validate_tx")

	b.StopTimer()
}
