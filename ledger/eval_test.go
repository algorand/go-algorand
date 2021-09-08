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
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
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
	partitiontest.PartitionTest(t)

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
	require.Equal(t, eval.specials.FeeSink, testSinkAddr)
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

	// Broken signature should fail
	stbad := st
	st.Sig[2] ^= 8
	txgroup := []transactions.SignedTxn{stbad}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)

	// Repeat should fail
	txgroup = []transactions.SignedTxn{st}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)
	err = eval.Transaction(st, transactions.ApplyData{})
	require.Error(t, err)

	// out of range should fail
	btxn := txn
	btxn.FirstValid++
	btxn.LastValid += 2
	st = btxn.Sign(keys[0])
	txgroup = []transactions.SignedTxn{st}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)
	err = eval.Transaction(st, transactions.ApplyData{})
	require.Error(t, err)

	// bogus group should fail
	btxn = txn
	btxn.Group[1] = 1
	st = btxn.Sign(keys[0])
	txgroup = []transactions.SignedTxn{st}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)
	err = eval.Transaction(st, transactions.ApplyData{})
	require.Error(t, err)

	// mixed fields should fail
	btxn = txn
	btxn.XferAsset = 3
	st = btxn.Sign(keys[0])
	txgroup = []transactions.SignedTxn{st}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)
	// We don't test eval.Transaction() here because it doesn't check txn.WellFormed(), instead relying on that to have already been checked by the transaction pool.
	// err = eval.Transaction(st, transactions.ApplyData{})
	// require.Error(t, err)

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
	stxn := selfTxn.Sign(keys[2])

	// TestTransactionGroup() and Transaction() should have the same outcome, but work slightly different code paths.
	txgroup = []transactions.SignedTxn{stxn}
	err = eval.TestTransactionGroup(txgroup)
	require.NoError(t, err)

	err = eval.Transaction(stxn, transactions.ApplyData{})
	require.NoError(t, err)

	t3 := txn
	t3.Amount.Raw++
	t4 := selfTxn
	t4.Amount.Raw++

	// a group without .Group should fail
	s3 := t3.Sign(keys[0])
	s4 := t4.Sign(keys[2])
	txgroup = []transactions.SignedTxn{s3, s4}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)
	txgroupad := transactions.WrapSignedTxnsWithAD(txgroup)
	err = eval.TransactionGroup(txgroupad)
	require.Error(t, err)

	// Test a group that should work
	var group transactions.TxGroup
	group.TxGroupHashes = []crypto.Digest{crypto.HashObj(t3), crypto.HashObj(t4)}
	t3.Group = crypto.HashObj(group)
	t4.Group = t3.Group
	s3 = t3.Sign(keys[0])
	s4 = t4.Sign(keys[2])
	txgroup = []transactions.SignedTxn{s3, s4}
	err = eval.TestTransactionGroup(txgroup)
	require.NoError(t, err)

	// disagreement on Group id should fail
	t4bad := t4
	t4bad.Group[3] ^= 3
	s4bad := t4bad.Sign(keys[2])
	txgroup = []transactions.SignedTxn{s3, s4bad}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)
	txgroupad = transactions.WrapSignedTxnsWithAD(txgroup)
	err = eval.TransactionGroup(txgroupad)
	require.Error(t, err)

	// missing part of the group should fail
	txgroup = []transactions.SignedTxn{s3}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)

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
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

	eval := BlockEvaluator{
		prevHeader: bookkeeping.BlockHeader{
			TimeStamp: 1234,
			Round:     2345,
		},
	}

	params := []config.ConsensusParams{
		{Application: true, MaxAppProgramCost: 700},
		config.Consensus[protocol.ConsensusV29],
		config.Consensus[protocol.ConsensusFuture],
	}

	// Create some sample transactions
	payment := txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   basics.Address{1, 2, 3, 4},
		Receiver: basics.Address{4, 3, 2, 1},
		Amount:   100,
	}.SignedTxnWithAD()

	appcall1 := txntest.Txn{
		Type:          protocol.ApplicationCallTx,
		Sender:        basics.Address{1, 2, 3, 4},
		ApplicationID: basics.AppIndex(1),
	}.SignedTxnWithAD()

	appcall2 := appcall1
	appcall2.SignedTxn.Txn.ApplicationCallTxnFields.ApplicationID = basics.AppIndex(2)

	type evalTestCase struct {
		group []transactions.SignedTxnWithAD

		// indicates if prepareAppEvaluators should return a non-nil
		// appTealEvaluator for the txn at index i
		expected []bool

		numAppCalls int
		// Used for checking transitive pointer equality in app calls
		// If there are no app calls in the group, it is set to -1
		firstAppCallIndex int
	}

	// Create some groups with these transactions
	cases := []evalTestCase{
		{[]transactions.SignedTxnWithAD{payment}, []bool{false}, 0, -1},
		{[]transactions.SignedTxnWithAD{appcall1}, []bool{true}, 1, 0},
		{[]transactions.SignedTxnWithAD{payment, payment}, []bool{false, false}, 0, -1},
		{[]transactions.SignedTxnWithAD{appcall1, payment}, []bool{true, false}, 1, 0},
		{[]transactions.SignedTxnWithAD{payment, appcall1}, []bool{false, true}, 1, 1},
		{[]transactions.SignedTxnWithAD{appcall1, appcall2}, []bool{true, true}, 2, 0},
		{[]transactions.SignedTxnWithAD{appcall1, appcall2, appcall1}, []bool{true, true, true}, 3, 0},
		{[]transactions.SignedTxnWithAD{payment, appcall1, payment}, []bool{false, true, false}, 1, 1},
		{[]transactions.SignedTxnWithAD{appcall1, payment, appcall2}, []bool{true, false, true}, 2, 0},
	}

	for i, param := range params {
		for j, testCase := range cases {
			t.Run(fmt.Sprintf("i=%d,j=%d", i, j), func(t *testing.T) {
				eval.proto = param
				res := eval.prepareEvalParams(testCase.group)
				require.Equal(t, len(res), len(testCase.group))

				// Compute the expected transaction group without ApplyData for
				// the test case
				expGroupNoAD := make([]transactions.SignedTxn, len(testCase.group))
				for k := range testCase.group {
					expGroupNoAD[k] = testCase.group[k].SignedTxn
				}

				// Ensure non app calls have a nil evaluator, and that non-nil
				// evaluators point to the right transactions and values
				for k, present := range testCase.expected {
					if present {
						require.NotNil(t, res[k])
						require.NotNil(t, res[k].PastSideEffects)
						require.Equal(t, res[k].GroupIndex, uint64(k))
						require.Equal(t, res[k].TxnGroup, expGroupNoAD)
						require.Equal(t, *res[k].Proto, eval.proto)
						require.Equal(t, *res[k].Txn, testCase.group[k].SignedTxn)
						require.Equal(t, res[k].MinTealVersion, res[testCase.firstAppCallIndex].MinTealVersion)
						require.Equal(t, res[k].PooledApplicationBudget, res[testCase.firstAppCallIndex].PooledApplicationBudget)
						if reflect.DeepEqual(param, config.Consensus[protocol.ConsensusV29]) {
							require.Equal(t, *res[k].PooledApplicationBudget, uint64(eval.proto.MaxAppProgramCost))
						} else if reflect.DeepEqual(param, config.Consensus[protocol.ConsensusFuture]) {
							require.Equal(t, *res[k].PooledApplicationBudget, uint64(eval.proto.MaxAppProgramCost*testCase.numAppCalls))
						}
					} else {
						require.Nil(t, res[k])
					}
				}
			})
		}
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
				EvalDelta: transactions.EvalDelta{GlobalDelta: map[string]basics.ValueDelta{
					"creator": {Action: basics.SetBytesAction, Bytes: string(addrs[0][:])}},
				}},
		},
		{
			SignedTxn: stxn2,
			ApplyData: transactions.ApplyData{
				EvalDelta: transactions.EvalDelta{GlobalDelta: map[string]basics.ValueDelta{
					"caller": {Action: basics.SetBytesAction, Bytes: string(addrs[0][:])}},
				}},
		},
	}
	txgroup := []transactions.SignedTxn{stxn1, stxn2}
	err = eval.TestTransactionGroup(txgroup)
	if err != nil {
		return eval, addrs[0], err
	}
	err = eval.transactionGroup(g)
	return eval, addrs[0], err
}

// TestEvalAppStateCountsWithTxnGroup ensures txns in a group can't violate app state schema limits
// the test ensures that
// commitToParent -> applyChild copies child's cow state usage counts into parent
// and the usage counts correctly propagated from parent cow to child cow and back
func TestEvalAppStateCountsWithTxnGroup(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, _, err := testEvalAppGroup(t, basics.StateSchema{NumByteSlice: 1})
	require.Error(t, err)
	require.Contains(t, err.Error(), "store bytes count 2 exceeds schema bytes count 1")
}

// TestEvalAppAllocStateWithTxnGroup ensures roundCowState.deltas and applyStorageDelta
// produce correct results when a txn group has storage allocate and storage update actions
func TestEvalAppAllocStateWithTxnGroup(t *testing.T) {
	partitiontest.PartitionTest(t)

	eval, addr, err := testEvalAppGroup(t, basics.StateSchema{NumByteSlice: 2})
	require.NoError(t, err)
	deltas := eval.state.deltas()
	ad, _ := deltas.Accts.Get(addr)
	state := ad.AppParams[1].GlobalState
	require.Equal(t, basics.TealValue{Type: basics.TealBytesType, Bytes: string(addr[:])}, state["caller"])
	require.Equal(t, basics.TealValue{Type: basics.TealBytesType, Bytes: string(addr[:])}, state["creator"])
}

func testEvalAppPoolingGroup(t *testing.T, schema basics.StateSchema, approvalProgram string, consensusVersion protocol.ConsensusVersion) error {
	genBalances, addrs, _ := newTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	eval := l.nextBlock(t)
	eval.proto = config.Consensus[consensusVersion]

	appcall1 := txntest.Txn{
		Sender:            addrs[0],
		Type:              protocol.ApplicationCallTx,
		GlobalStateSchema: schema,
		ApprovalProgram:   approvalProgram,
	}

	appcall2 := txntest.Txn{
		Sender:        addrs[0],
		Type:          protocol.ApplicationCallTx,
		ApplicationID: basics.AppIndex(1),
	}

	appcall3 := txntest.Txn{
		Sender:        addrs[1],
		Type:          protocol.ApplicationCallTx,
		ApplicationID: basics.AppIndex(1),
	}

	return eval.txgroup(t, &appcall1, &appcall2, &appcall3)
}

// TestEvalAppPooledBudgetWithTxnGroup ensures 3 app call txns can successfully pool
// budgets in a group txn and return an error if the budget is exceeded
func TestEvalAppPooledBudgetWithTxnGroup(t *testing.T) {
	partitiontest.PartitionTest(t)

	source := func(n int, m int) string {
		return "#pragma version 4\nbyte 0x1337BEEF\n" + strings.Repeat("keccak256\n", n) +
			strings.Repeat("substring 0 4\n", m) + "pop\nint 1\n"
	}

	params := []protocol.ConsensusVersion{
		protocol.ConsensusV29,
		protocol.ConsensusFuture,
	}

	cases := []struct {
		prog                 string
		isSuccessV29         bool
		isSuccessVFuture     bool
		expectedErrorV29     string
		expectedErrorVFuture string
	}{
		{source(5, 47), true, true,
			"",
			""},
		{source(5, 48), false, true,
			"pc=157 dynamic cost budget exceeded, executing pushint: remaining budget is 700 but program cost was 701",
			""},
		{source(16, 17), false, true,
			"pc= 12 dynamic cost budget exceeded, executing keccak256: remaining budget is 700 but program cost was 781",
			""},
		{source(16, 18), false, false,
			"pc= 12 dynamic cost budget exceeded, executing keccak256: remaining budget is 700 but program cost was 781",
			"pc= 78 dynamic cost budget exceeded, executing pushint: remaining budget is 2100 but program cost was 2101"},
	}

	for i, param := range params {
		for j, testCase := range cases {
			t.Run(fmt.Sprintf("i=%d,j=%d", i, j), func(t *testing.T) {
				err := testEvalAppPoolingGroup(t, basics.StateSchema{NumByteSlice: 3}, testCase.prog, param)
				if !testCase.isSuccessV29 && reflect.DeepEqual(param, protocol.ConsensusV29) {
					require.Error(t, err)
					require.Contains(t, err.Error(), testCase.expectedErrorV29)
				} else if !testCase.isSuccessVFuture && reflect.DeepEqual(param, protocol.ConsensusFuture) {
					require.Error(t, err)
					require.Contains(t, err.Error(), testCase.expectedErrorVFuture)
				}
			})
		}
	}
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
				Note:        randomNote(),
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
			Note:        randomNote(),
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

// this variant focuses on benchmarking ledger.go `eval()`, the rest is setup, it runs eval() b.N times.
func benchmarkBlockEvaluator(b *testing.B, inMem bool, withCrypto bool, proto protocol.ConsensusVersion, txnSource BenchTxnGenerator) {
	deadlockDisable := deadlock.Opts.Disable
	deadlock.Opts.Disable = true
	defer func() { deadlock.Opts.Disable = deadlockDisable }()
	start := time.Now()
	genesisInitState, addrs, keys := genesisWithProto(100000, proto)
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
	bev, err := l.StartEvaluator(newBlock.BlockHeader, 0)
	require.NoError(b, err)

	genHash := genesisInitState.Block.BlockHeader.GenesisHash

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	// apply initialization transations if any
	initSignedTxns, maxTxnPerBlock := txnSource.Prepare(b, addrs, keys, newBlock.Round(), genHash)
	if len(initSignedTxns) > 0 {
		// all init transactions need to be written to ledger before reopening and benchmarking
		for _, l := range []*Ledger{l, l2} {
			l.accts.ctxCancel() // force commitSyncer to exit

			// wait commitSyncer to exit
			// the test calls commitRound directly and does not need commitSyncer/committedUpTo
			select {
			case <-l.accts.commitSyncerClosed:
				break
			}
		}

		var numBlocks uint64 = 0
		var validatedBlock *ValidatedBlock

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
				newBlock = bookkeeping.MakeBlock(validatedBlock.blk.BlockHeader)
				bev, err = l.StartEvaluator(newBlock.BlockHeader, 0)
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
				l.accts.accountsWriting.Add(1)
				l.accts.commitRound(numBlocks, 0, 0)
				l.accts.accountsWriting.Wait()
				l.reloadLedger()
				wg.Done()
			}(l)
		}
		wg.Wait()

		newBlock = bookkeeping.MakeBlock(validatedBlock.blk.BlockHeader)
		bev, err = l.StartEvaluator(newBlock.BlockHeader, 0)
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

func TestCowCompactCert(t *testing.T) {
	partitiontest.PartitionTest(t)

	var certRnd basics.Round
	var certType protocol.CompactCertType
	var cert compactcert.Cert
	var atRound basics.Round
	var validate bool
	accts0 := randomAccounts(20, true)
	blocks := make(map[basics.Round]bookkeeping.BlockHeader)
	blockErr := make(map[basics.Round]error)
	ml := mockLedger{balanceMap: accts0, blocks: blocks, blockErr: blockErr}
	c0 := makeRoundCowState(
		&ml, bookkeeping.BlockHeader{}, config.Consensus[protocol.ConsensusCurrentVersion],
		0, 0)

	certType = protocol.CompactCertType(1234) // bad cert type
	err := c0.compactCert(certRnd, certType, cert, atRound, validate)
	require.Error(t, err)

	// no certRnd block
	certType = protocol.CompactCertBasic
	noBlockErr := errors.New("no block")
	blockErr[3] = noBlockErr
	certRnd = 3
	err = c0.compactCert(certRnd, certType, cert, atRound, validate)
	require.Error(t, err)

	// no votersRnd block
	// this is slightly a mess of things that don't quite line up with likely usage
	validate = true
	var certHdr bookkeeping.BlockHeader
	certHdr.CurrentProtocol = "TestCowCompactCert"
	certHdr.Round = 1
	proto := config.Consensus[certHdr.CurrentProtocol]
	proto.CompactCertRounds = 2
	config.Consensus[certHdr.CurrentProtocol] = proto
	blocks[certHdr.Round] = certHdr

	certHdr.Round = 15
	blocks[certHdr.Round] = certHdr
	certRnd = certHdr.Round
	blockErr[13] = noBlockErr
	err = c0.compactCert(certRnd, certType, cert, atRound, validate)
	require.Error(t, err)

	// validate fail
	certHdr.Round = 1
	certRnd = certHdr.Round
	err = c0.compactCert(certRnd, certType, cert, atRound, validate)
	require.Error(t, err)

	// fall through to no err
	validate = false
	err = c0.compactCert(certRnd, certType, cert, atRound, validate)
	require.NoError(t, err)

	// 100% coverage
}

// a couple trivial tests that don't need setup
// see TestBlockEvaluator for more
func TestTestTransactionGroup(t *testing.T) {
	partitiontest.PartitionTest(t)

	var txgroup []transactions.SignedTxn
	eval := BlockEvaluator{}
	err := eval.TestTransactionGroup(txgroup)
	require.NoError(t, err) // nothing to do, no problem

	eval.proto = config.Consensus[protocol.ConsensusCurrentVersion]
	txgroup = make([]transactions.SignedTxn, eval.proto.MaxTxGroupSize+1)
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err) // too many
}

// test BlockEvaluator.transactionGroup()
// some trivial checks that require no setup
func TestPrivateTransactionGroup(t *testing.T) {
	partitiontest.PartitionTest(t)

	var txgroup []transactions.SignedTxnWithAD
	eval := BlockEvaluator{}
	err := eval.transactionGroup(txgroup)
	require.NoError(t, err) // nothing to do, no problem

	eval.proto = config.Consensus[protocol.ConsensusCurrentVersion]
	txgroup = make([]transactions.SignedTxnWithAD, eval.proto.MaxTxGroupSize+1)
	err = eval.transactionGroup(txgroup)
	require.Error(t, err) // too many
}

// BlockEvaluator.workaroundOverspentRewards() fixed a couple issues on testnet.
// This is now part of history and has to be re-created when running catchup on testnet. So, test to ensure it keeps happenning.
func TestTestnetFixup(t *testing.T) {
	partitiontest.PartitionTest(t)

	eval := &BlockEvaluator{}
	var rewardPoolBalance basics.AccountData
	rewardPoolBalance.MicroAlgos.Raw = 1234
	var headerRound basics.Round
	testnetGenesisHash, _ := crypto.DigestFromString("JBR3KGFEWPEE5SAQ6IWU6EEBZMHXD4CZU6WCBXWGF57XBZIJHIRA")

	// not a fixup round, no change
	headerRound = 1
	poolOld, err := eval.workaroundOverspentRewards(rewardPoolBalance, headerRound)
	require.Equal(t, rewardPoolBalance, poolOld)
	require.NoError(t, err)

	eval.genesisHash = testnetGenesisHash
	eval.genesisHash[3]++

	specialRounds := []basics.Round{1499995, 2926564}
	for _, headerRound = range specialRounds {
		poolOld, err = eval.workaroundOverspentRewards(rewardPoolBalance, headerRound)
		require.Equal(t, rewardPoolBalance, poolOld)
		require.NoError(t, err)
	}

	for _, headerRound = range specialRounds {
		testnetFixupExecution(t, headerRound, 20000000000)
	}
	// do all the setup and do nothing for not a special round
	testnetFixupExecution(t, specialRounds[0]+1, 0)
}

func testnetFixupExecution(t *testing.T, headerRound basics.Round, poolBonus uint64) {
	testnetGenesisHash, _ := crypto.DigestFromString("JBR3KGFEWPEE5SAQ6IWU6EEBZMHXD4CZU6WCBXWGF57XBZIJHIRA")
	// big setup so we can move some algos
	// boilerplate like TestBlockEvaluator, but pretend to be testnet
	genesisInitState, addrs, keys := genesis(10)
	genesisInitState.Block.BlockHeader.GenesisHash = testnetGenesisHash
	genesisInitState.Block.BlockHeader.GenesisID = "testnet"
	genesisInitState.GenesisHash = testnetGenesisHash

	// for addr, adata := range genesisInitState.Accounts {
	// 	t.Logf("%s: %+v", addr.String(), adata)
	// }
	rewardPoolBalance := genesisInitState.Accounts[testPoolAddr]
	nextPoolBalance := rewardPoolBalance.MicroAlgos.Raw + poolBonus

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

	// won't work before funding bank
	if poolBonus > 0 {
		_, err = eval.workaroundOverspentRewards(rewardPoolBalance, headerRound)
		require.Error(t, err)
	}

	bankAddr, _ := basics.UnmarshalChecksumAddress("GD64YIY3TWGDMCNPP553DZPPR6LDUSFQOIJVFDPPXWEG3FVOJCCDBBHU5A")

	// put some algos in the bank so that fixup can pull from this account
	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addrs[0],
			Fee:         minFee,
			FirstValid:  newBlock.Round(),
			LastValid:   newBlock.Round(),
			GenesisHash: testnetGenesisHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: bankAddr,
			Amount:   basics.MicroAlgos{Raw: 20000000000 * 10},
		},
	}
	st := txn.Sign(keys[0])
	err = eval.Transaction(st, transactions.ApplyData{})
	require.NoError(t, err)

	poolOld, err := eval.workaroundOverspentRewards(rewardPoolBalance, headerRound)
	require.Equal(t, nextPoolBalance, poolOld.MicroAlgos.Raw)
	require.NoError(t, err)
}

// Test that ModifiedAssetHoldings in StateDelta is set correctly.
func TestModifiedAssetHoldings(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	const assetid basics.AssetIndex = 1

	createTxn := txntest.Txn{
		Type:   "acfg",
		Sender: addrs[0],
		Fee:    2000,
		AssetParams: basics.AssetParams{
			Total:    3,
			Decimals: 0,
			Manager:  addrs[0],
			Reserve:  addrs[0],
			Freeze:   addrs[0],
			Clawback: addrs[0],
		},
	}

	optInTxn := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[1],
		Fee:           2000,
		XferAsset:     assetid,
		AssetAmount:   0,
		AssetReceiver: addrs[1],
	}

	eval := l.nextBlock(t)
	eval.txns(t, &createTxn, &optInTxn)
	vb := l.endBlock(t, eval)

	{
		aa := ledgercore.AccountAsset{
			Address: addrs[0],
			Asset:   assetid,
		}
		created, ok := vb.delta.ModifiedAssetHoldings[aa]
		require.True(t, ok)
		assert.True(t, created)
	}
	{
		aa := ledgercore.AccountAsset{
			Address: addrs[1],
			Asset:   assetid,
		}
		created, ok := vb.delta.ModifiedAssetHoldings[aa]
		require.True(t, ok)
		assert.True(t, created)
	}

	optOutTxn := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[1],
		Fee:           1000,
		XferAsset:     assetid,
		AssetReceiver: addrs[0],
		AssetCloseTo:  addrs[0],
	}

	closeTxn := txntest.Txn{
		Type:        "acfg",
		Sender:      addrs[0],
		Fee:         1000,
		ConfigAsset: assetid,
	}

	eval = l.nextBlock(t)
	eval.txns(t, &optOutTxn, &closeTxn)
	vb = l.endBlock(t, eval)

	{
		aa := ledgercore.AccountAsset{
			Address: addrs[0],
			Asset:   assetid,
		}
		created, ok := vb.delta.ModifiedAssetHoldings[aa]
		require.True(t, ok)
		assert.False(t, created)
	}
	{
		aa := ledgercore.AccountAsset{
			Address: addrs[1],
			Asset:   assetid,
		}
		created, ok := vb.delta.ModifiedAssetHoldings[aa]
		require.True(t, ok)
		assert.False(t, created)
	}
}

// newTestGenesis creates a bunch of accounts, splits up 10B algos
// between them and the rewardspool and feesink, and gives out the
// addresses and secrets it creates to enable tests.  For special
// scenarios, manipulate these return values before using newTestLedger.
func newTestGenesis() (bookkeeping.GenesisBalances, []basics.Address, []*crypto.SignatureSecrets) {
	// irrelevant, but deterministic
	sink, err := basics.UnmarshalChecksumAddress("YTPRLJ2KK2JRFSZZNAF57F3K5Y2KCG36FZ5OSYLW776JJGAUW5JXJBBD7Q")
	if err != nil {
		panic(err)
	}
	rewards, err := basics.UnmarshalChecksumAddress("242H5OXHUEBYCGGWB3CQ6AZAMQB5TMCWJGHCGQOZPEIVQJKOO7NZXUXDQA")
	if err != nil {
		panic(err)
	}

	const count = 10
	addrs := make([]basics.Address, count)
	secrets := make([]*crypto.SignatureSecrets, count)
	accts := make(map[basics.Address]basics.AccountData)

	// 10 billion microalgos, across N accounts and pool and sink
	amount := 10 * 1000000000 * 1000000 / uint64(count+2)

	for i := 0; i < count; i++ {
		// Create deterministic addresses, so that output stays the same, run to run.
		var seed crypto.Seed
		seed[0] = byte(i)
		secrets[i] = crypto.GenerateSignatureSecrets(seed)
		addrs[i] = basics.Address(secrets[i].SignatureVerifier)

		adata := basics.AccountData{
			MicroAlgos: basics.MicroAlgos{Raw: amount},
		}
		accts[addrs[i]] = adata
	}

	accts[sink] = basics.AccountData{
		MicroAlgos: basics.MicroAlgos{Raw: amount},
		Status:     basics.NotParticipating,
	}

	accts[rewards] = basics.AccountData{
		MicroAlgos: basics.MicroAlgos{Raw: amount},
	}

	genBalances := bookkeeping.MakeGenesisBalances(accts, sink, rewards)

	return genBalances, addrs, secrets
}

// newTestLedger creates a in memory Ledger that is as realistic as
// possible.  It has Rewards and FeeSink properly configured.
func newTestLedger(t testing.TB, balances bookkeeping.GenesisBalances) *Ledger {
	l, _, _ := newTestLedgerImpl(t, balances, true)
	return l
}

func newTestLedgerOnDisk(t testing.TB, balances bookkeeping.GenesisBalances) (*Ledger, string, bookkeeping.Block) {
	return newTestLedgerImpl(t, balances, false)
}

func newTestLedgerImpl(t testing.TB, balances bookkeeping.GenesisBalances, inMem bool) (*Ledger, string, bookkeeping.Block) {
	var genHash crypto.Digest
	crypto.RandBytes(genHash[:])
	genBlock, err := bookkeeping.MakeGenesisBlock(protocol.ConsensusFuture,
		balances, "test", genHash)
	require.False(t, genBlock.FeeSink.IsZero())
	require.False(t, genBlock.RewardsPool.IsZero())
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(logging.Base(), dbName, inMem, InitState{
		Block:       genBlock,
		Accounts:    balances.Balances,
		GenesisHash: genHash,
	}, cfg)
	require.NoError(t, err)
	return l, dbName, genBlock
}

// nextBlock begins evaluation of a new block, after ledger creation or endBlock()
func (ledger *Ledger) nextBlock(t testing.TB) *BlockEvaluator {
	rnd := ledger.Latest()
	hdr, err := ledger.BlockHdr(rnd)
	require.NoError(t, err)

	nextHdr := bookkeeping.MakeBlock(hdr).BlockHeader
	eval, err := ledger.StartEvaluator(nextHdr, 0)
	require.NoError(t, err)
	return eval
}

// endBlock completes the block being created, returns the ValidatedBlock for inspection
func (ledger *Ledger) endBlock(t testing.TB, eval *BlockEvaluator) *ValidatedBlock {
	validatedBlock, err := eval.GenerateBlock()
	require.NoError(t, err)
	err = ledger.AddValidatedBlock(*validatedBlock, agreement.Certificate{})
	require.NoError(t, err)
	return validatedBlock
}

// lookup gets the current accountdata for an address
func (ledger *Ledger) lookup(t testing.TB, addr basics.Address) basics.AccountData {
	rnd := ledger.Latest()
	ad, err := ledger.Lookup(rnd, addr)
	require.NoError(t, err)
	return ad
}

// micros gets the current microAlgo balance for an address
func (ledger *Ledger) micros(t testing.TB, addr basics.Address) uint64 {
	return ledger.lookup(t, addr).MicroAlgos.Raw
}

// asa gets the current balance and optin status for some asa for an address
func (ledger *Ledger) asa(t testing.TB, addr basics.Address, asset basics.AssetIndex) (uint64, bool) {
	if holding, ok := ledger.lookup(t, addr).Assets[asset]; ok {
		return holding.Amount, true
	}
	return 0, false
}

func (eval *BlockEvaluator) fillDefaults(txn *txntest.Txn) {
	if txn.GenesisHash.IsZero() {
		txn.GenesisHash = eval.genesisHash
	}
	if txn.FirstValid == 0 {
		txn.FirstValid = eval.Round()
	}
	txn.FillDefaults(eval.proto)
}

func (eval *BlockEvaluator) txn(t testing.TB, txn *txntest.Txn, problem ...string) {
	t.Helper()
	eval.fillDefaults(txn)
	stxn := txn.SignedTxn()
	err := eval.testTransaction(stxn, eval.state.child(1))
	if err != nil {
		if len(problem) == 1 {
			require.Contains(t, err.Error(), problem[0])
		} else {
			require.NoError(t, err) // Will obviously fail
		}
		return
	}
	err = eval.Transaction(stxn, transactions.ApplyData{})
	if err != nil {
		if len(problem) == 1 {
			require.Contains(t, err.Error(), problem[0])
		} else {
			require.NoError(t, err) // Will obviously fail
		}
		return
	}
	require.Len(t, problem, 0)
}

func (eval *BlockEvaluator) txns(t testing.TB, txns ...*txntest.Txn) {
	t.Helper()
	for _, txn := range txns {
		eval.txn(t, txn)
	}
}

func (eval *BlockEvaluator) txgroup(t testing.TB, txns ...*txntest.Txn) error {
	t.Helper()
	for _, txn := range txns {
		eval.fillDefaults(txn)
	}
	txgroup := txntest.SignedTxns(txns...)

	err := eval.TestTransactionGroup(txgroup)
	if err != nil {
		return err
	}

	err = eval.transactionGroup(transactions.WrapSignedTxnsWithAD(txgroup))
	return err
}

func TestRewardsInAD(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	payTxn := txntest.Txn{Type: "pay", Sender: addrs[0], Receiver: addrs[1]}

	// Build up Residue in RewardsState so it's ready to pay
	for i := 1; i < 10; i++ {
		eval := l.nextBlock(t)
		l.endBlock(t, eval)
	}

	eval := l.nextBlock(t)
	eval.txn(t, &payTxn)
	payInBlock := eval.block.Payset[0]
	require.Greater(t, payInBlock.ApplyData.SenderRewards.Raw, uint64(1000))
	require.Greater(t, payInBlock.ApplyData.ReceiverRewards.Raw, uint64(1000))
	require.Equal(t, payInBlock.ApplyData.SenderRewards, payInBlock.ApplyData.ReceiverRewards)
	l.endBlock(t, eval)
}

func TestMinBalanceChanges(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	createTxn := txntest.Txn{
		Type:   "acfg",
		Sender: addrs[0],
		AssetParams: basics.AssetParams{
			Total:    3,
			Manager:  addrs[1],
			Reserve:  addrs[2],
			Freeze:   addrs[3],
			Clawback: addrs[4],
		},
	}

	const expectedID basics.AssetIndex = 1
	optInTxn := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[5],
		XferAsset:     expectedID,
		AssetReceiver: addrs[5],
	}

	ad0init := l.lookup(t, addrs[0])
	ad5init := l.lookup(t, addrs[5])

	eval := l.nextBlock(t)
	eval.txns(t, &createTxn, &optInTxn)
	l.endBlock(t, eval)

	ad0new := l.lookup(t, addrs[0])
	ad5new := l.lookup(t, addrs[5])

	proto := config.Consensus[eval.block.BlockHeader.CurrentProtocol]
	// Check balance and min balance requirement changes
	require.Equal(t, ad0init.MicroAlgos.Raw, ad0new.MicroAlgos.Raw+1000)                   // fee
	require.Equal(t, ad0init.MinBalance(&proto).Raw, ad0new.MinBalance(&proto).Raw-100000) // create
	require.Equal(t, ad5init.MicroAlgos.Raw, ad5new.MicroAlgos.Raw+1000)                   // fee
	require.Equal(t, ad5init.MinBalance(&proto).Raw, ad5new.MinBalance(&proto).Raw-100000) // optin

	optOutTxn := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[5],
		XferAsset:     expectedID,
		AssetReceiver: addrs[0],
		AssetCloseTo:  addrs[0],
	}

	closeTxn := txntest.Txn{
		Type:        "acfg",
		Sender:      addrs[1], // The manager, not the creator
		ConfigAsset: expectedID,
	}

	eval = l.nextBlock(t)
	eval.txns(t, &optOutTxn, &closeTxn)
	l.endBlock(t, eval)

	ad0final := l.lookup(t, addrs[0])
	ad5final := l.lookup(t, addrs[5])
	// Check we got our balance "back"
	require.Equal(t, ad0final.MinBalance(&proto), ad0init.MinBalance(&proto))
	require.Equal(t, ad5final.MinBalance(&proto), ad5init.MinBalance(&proto))
}

// Test that ModifiedAppLocalStates in StateDelta is set correctly.
func TestModifiedAppLocalStates(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	const appid basics.AppIndex = 1

	createTxn := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[0],
		ApprovalProgram: "int 1",
	}

	optInTxn := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appid,
		OnCompletion:  transactions.OptInOC,
	}

	eval := l.nextBlock(t)
	eval.txns(t, &createTxn, &optInTxn)
	vb := l.endBlock(t, eval)

	assert.Len(t, vb.delta.ModifiedAppLocalStates, 1)
	{
		aa := ledgercore.AccountApp{
			Address: addrs[1],
			App:     appid,
		}
		created, ok := vb.delta.ModifiedAppLocalStates[aa]
		require.True(t, ok)
		assert.True(t, created)
	}

	optOutTxn := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appid,
		OnCompletion:  transactions.CloseOutOC,
	}

	closeTxn := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[0],
		ApplicationID: appid,
		OnCompletion:  transactions.DeleteApplicationOC,
	}

	eval = l.nextBlock(t)
	eval.txns(t, &optOutTxn, &closeTxn)
	vb = l.endBlock(t, eval)

	assert.Len(t, vb.delta.ModifiedAppLocalStates, 1)
	{
		aa := ledgercore.AccountApp{
			Address: addrs[1],
			App:     appid,
		}
		created, ok := vb.delta.ModifiedAppLocalStates[aa]
		require.True(t, ok)
		assert.False(t, created)
	}
}

// Test that overriding the consensus parameters effects the generated apply data.
func TestCustomProtocolParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisBalances, addrs, _ := newTestGenesis()

	var genHash crypto.Digest
	crypto.RandBytes(genHash[:])
	block, err := bookkeeping.MakeGenesisBlock(protocol.ConsensusV24,
		genesisBalances, "test", genHash)

	dbName := fmt.Sprintf("%s", t.Name())
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(logging.Base(), dbName, true, InitState{
		Block:       block,
		Accounts:    genesisBalances.Balances,
		GenesisHash: genHash,
	}, cfg)
	require.NoError(t, err)
	defer l.Close()

	const assetid basics.AssetIndex = 1
	proto := config.Consensus[protocol.ConsensusV24]

	block = bookkeeping.MakeBlock(block.BlockHeader)

	createTxn := txntest.Txn{
		Type:        "acfg",
		Sender:      addrs[0],
		GenesisHash: block.GenesisHash(),
		AssetParams: basics.AssetParams{
			Total:    200,
			Decimals: 0,
			Manager:  addrs[0],
			Reserve:  addrs[0],
			Freeze:   addrs[0],
			Clawback: addrs[0],
		},
	}
	createTxn.FillDefaults(proto)
	createStib, err := block.BlockHeader.EncodeSignedTxn(
		createTxn.SignedTxn(), transactions.ApplyData{})
	require.NoError(t, err)

	optInTxn := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[1],
		GenesisHash:   block.GenesisHash(),
		XferAsset:     assetid,
		AssetAmount:   0,
		AssetReceiver: addrs[1],
	}
	optInTxn.FillDefaults(proto)
	optInStib, err := block.BlockHeader.EncodeSignedTxn(
		optInTxn.SignedTxn(), transactions.ApplyData{})
	require.NoError(t, err)

	fundTxn := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[0],
		GenesisHash:   block.GenesisHash(),
		XferAsset:     assetid,
		AssetAmount:   100,
		AssetReceiver: addrs[1],
	}
	fundTxn.FillDefaults(proto)
	fundStib, err := block.BlockHeader.EncodeSignedTxn(
		fundTxn.SignedTxn(), transactions.ApplyData{})
	require.NoError(t, err)

	optOutTxn := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[1],
		GenesisHash:   block.GenesisHash(),
		XferAsset:     assetid,
		AssetAmount:   30,
		AssetReceiver: addrs[0],
		AssetCloseTo:  addrs[0],
	}
	optOutTxn.FillDefaults(proto)
	optOutStib, err := block.BlockHeader.EncodeSignedTxn(
		optOutTxn.SignedTxn(), transactions.ApplyData{})
	require.NoError(t, err)

	block.Payset = []transactions.SignedTxnInBlock{
		createStib, optInStib, fundStib, optOutStib,
	}

	proto.EnableAssetCloseAmount = true
	_, modifiedTxns, err := Eval(l, &block, proto)
	require.NoError(t, err)

	require.Equal(t, 4, len(modifiedTxns))
	assert.Equal(t, uint64(70), modifiedTxns[3].AssetClosingAmount)
}

// TestAppInsMinBalance checks that accounts with MaxAppsOptedIn are accepted by block evaluator
// and do not cause any MaximumMinimumBalance problems
func TestAppInsMinBalance(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	const appid basics.AppIndex = 1

	maxAppsOptedIn := config.Consensus[protocol.ConsensusFuture].MaxAppsOptedIn
	require.Greater(t, maxAppsOptedIn, 0)
	maxAppsCreated := config.Consensus[protocol.ConsensusFuture].MaxAppsCreated
	require.Greater(t, maxAppsCreated, 0)
	maxLocalSchemaEntries := config.Consensus[protocol.ConsensusFuture].MaxLocalSchemaEntries
	require.Greater(t, maxLocalSchemaEntries, uint64(0))

	txnsCreate := make([]*txntest.Txn, 0, maxAppsOptedIn)
	txnsOptIn := make([]*txntest.Txn, 0, maxAppsOptedIn)
	appsCreated := make(map[basics.Address]int, len(addrs)-1)

	acctIdx := 0
	for i := 0; i < maxAppsOptedIn; i++ {
		creator := addrs[acctIdx]
		createTxn := txntest.Txn{
			Type:             protocol.ApplicationCallTx,
			Sender:           creator,
			ApprovalProgram:  "int 1",
			LocalStateSchema: basics.StateSchema{NumByteSlice: maxLocalSchemaEntries},
			Note:             randomNote(),
		}
		txnsCreate = append(txnsCreate, &createTxn)
		count := appsCreated[creator]
		count++
		appsCreated[creator] = count
		if count == maxAppsCreated {
			acctIdx++
		}

		optInTxn := txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        addrs[9],
			ApplicationID: appid + basics.AppIndex(i),
			OnCompletion:  transactions.OptInOC,
		}
		txnsOptIn = append(txnsOptIn, &optInTxn)
	}

	eval := l.nextBlock(t)
	txns := append(txnsCreate, txnsOptIn...)
	eval.txns(t, txns...)
	vb := l.endBlock(t, eval)
	assert.Len(t, vb.delta.ModifiedAppLocalStates, 50)
}
