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

package internal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

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
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
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

	genesisInitState, addrs, keys := ledgertesting.Genesis(10)

	genesisBalances := bookkeeping.GenesisBalances{
		Balances:    genesisInitState.Accounts,
		FeeSink:     testSinkAddr,
		RewardsPool: testPoolAddr,
		Timestamp:   0,
	}
	l := newTestLedger(t, genesisBalances)

	genesisBlockHeader, err := l.BlockHdr(basics.Round(0))
	newBlock := bookkeeping.MakeBlock(genesisBlockHeader)
	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0)
	require.NoError(t, err)
	require.Equal(t, eval.specials.FeeSink, testSinkAddr)

	genHash := l.GenesisHash()
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
	genesisInitState, addrs, keys := ledgertesting.Genesis(10)
	genesisBalances := bookkeeping.GenesisBalances{
		Balances:    genesisInitState.Accounts,
		FeeSink:     testSinkAddr,
		RewardsPool: testPoolAddr,
		Timestamp:   0,
	}
	l := newTestLedger(t, genesisBalances)

	// Make a new block
	nextRound := l.Latest() + basics.Round(1)
	genHash := l.GenesisHash()

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
		genesisHdr, err := l.BlockHdr(basics.Round(0))
		require.NoError(t, err)
		newBlock := bookkeeping.MakeBlock(genesisHdr)
		eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0)
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
	err := tryBlock(test1txns)
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

func testEvalAppGroup(t *testing.T, schema basics.StateSchema) (*BlockEvaluator, basics.Address, error) {
	genesisInitState, addrs, keys := ledgertesting.Genesis(10)

	genesisBalances := bookkeeping.GenesisBalances{
		Balances:    genesisInitState.Accounts,
		FeeSink:     testSinkAddr,
		RewardsPool: testPoolAddr,
		Timestamp:   0,
	}
	l := newTestLedger(t, genesisBalances)

	blkHeader, err := l.BlockHdr(basics.Round(0))
	require.NoError(t, err)
	newBlock := bookkeeping.MakeBlock(blkHeader)
	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0)
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

	genHash := l.GenesisHash()
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
				},
				ApplicationID: 1,
			},
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
	err = eval.TransactionGroup(g)
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

	eval := l.nextBlock(t)
	eval.validate = true
	eval.generate = false

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

func TestCowCompactCert(t *testing.T) {
	partitiontest.PartitionTest(t)

	var certRnd basics.Round
	var certType protocol.CompactCertType
	var cert compactcert.Cert
	var atRound basics.Round
	var validate bool
	accts0 := ledgertesting.RandomAccounts(20, true)
	blocks := make(map[basics.Round]bookkeeping.BlockHeader)
	blockErr := make(map[basics.Round]error)
	ml := mockLedger{balanceMap: accts0, blocks: blocks, blockErr: blockErr}
	c0 := makeRoundCowState(
		&ml, bookkeeping.BlockHeader{}, config.Consensus[protocol.ConsensusCurrentVersion],
		0, ledgercore.AccountTotals{}, 0)

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
	err := eval.TransactionGroup(txgroup)
	require.NoError(t, err) // nothing to do, no problem

	eval.proto = config.Consensus[protocol.ConsensusCurrentVersion]
	txgroup = make([]transactions.SignedTxnWithAD, eval.proto.MaxTxGroupSize+1)
	err = eval.TransactionGroup(txgroup)
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
	genesisInitState, addrs, keys := ledgertesting.Genesis(10)
	genesisInitState.Block.BlockHeader.GenesisHash = testnetGenesisHash
	genesisInitState.Block.BlockHeader.GenesisID = "testnet"
	genesisInitState.GenesisHash = testnetGenesisHash

	rewardPoolBalance := genesisInitState.Accounts[testPoolAddr]
	nextPoolBalance := rewardPoolBalance.MicroAlgos.Raw + poolBonus

	l := newTestLedger(t, bookkeeping.GenesisBalances{
		Balances:    genesisInitState.Accounts,
		FeeSink:     testSinkAddr,
		RewardsPool: testPoolAddr,
	})
	l.blocks[0] = genesisInitState.Block
	l.genesisHash = genesisInitState.GenesisHash

	newBlock := bookkeeping.MakeBlock(genesisInitState.Block.BlockHeader)
	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0)
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
		created, ok := vb.Delta().ModifiedAssetHoldings[aa]
		require.True(t, ok)
		assert.True(t, created)
	}
	{
		aa := ledgercore.AccountAsset{
			Address: addrs[1],
			Asset:   assetid,
		}
		created, ok := vb.Delta().ModifiedAssetHoldings[aa]
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
		created, ok := vb.Delta().ModifiedAssetHoldings[aa]
		require.True(t, ok)
		assert.False(t, created)
	}
	{
		aa := ledgercore.AccountAsset{
			Address: addrs[1],
			Asset:   assetid,
		}
		created, ok := vb.Delta().ModifiedAssetHoldings[aa]
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

type evalTestLedger struct {
	blocks        map[basics.Round]bookkeeping.Block
	roundBalances map[basics.Round]map[basics.Address]basics.AccountData
	genesisHash   crypto.Digest
	feeSink       basics.Address
	rewardsPool   basics.Address
	latestTotals  ledgercore.AccountTotals
}

// newTestLedger creates a in memory Ledger that is as realistic as
// possible.  It has Rewards and FeeSink properly configured.
func newTestLedger(t testing.TB, balances bookkeeping.GenesisBalances) *evalTestLedger {
	l := &evalTestLedger{
		blocks:        make(map[basics.Round]bookkeeping.Block),
		roundBalances: make(map[basics.Round]map[basics.Address]basics.AccountData),
		feeSink:       balances.FeeSink,
		rewardsPool:   balances.RewardsPool,
	}

	crypto.RandBytes(l.genesisHash[:])
	genBlock, err := bookkeeping.MakeGenesisBlock(protocol.ConsensusFuture,
		balances, "test", l.genesisHash)
	require.NoError(t, err)
	l.roundBalances[0] = balances.Balances
	l.blocks[0] = genBlock

	// calculate the accounts totals.
	var ot basics.OverflowTracker
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	for _, acctData := range balances.Balances {
		l.latestTotals.AddAccount(proto, acctData, &ot)
	}

	require.False(t, genBlock.FeeSink.IsZero())
	require.False(t, genBlock.RewardsPool.IsZero())
	return l
}

// Validate uses the ledger to validate block blk as a candidate next block.
// It returns an error if blk is not the expected next block, or if blk is
// not a valid block (e.g., it has duplicate transactions, overspends some
// account, etc).
func (ledger *evalTestLedger) Validate(ctx context.Context, blk bookkeeping.Block, executionPool execpool.BacklogPool) (*ledgercore.ValidatedBlock, error) {
	verifiedTxnCache := verify.MakeVerifiedTransactionCache(config.GetDefaultLocal().VerifiedTranscationsCacheSize)

	delta, err := Eval(ctx, ledger, blk, true, verifiedTxnCache, executionPool)
	if err != nil {
		return nil, err
	}

	vb := ledgercore.MakeValidatedBlock(blk, delta)
	return &vb, nil
}

// StartEvaluator creates a BlockEvaluator, given a ledger and a block header
// of the block that the caller is planning to evaluate. If the length of the
// payset being evaluated is known in advance, a paysetHint >= 0 can be
// passed, avoiding unnecessary payset slice growth.
func (ledger *evalTestLedger) StartEvaluator(hdr bookkeeping.BlockHeader, paysetHint, maxTxnBytesPerBlock int) (*BlockEvaluator, error) {
	proto, ok := config.Consensus[hdr.CurrentProtocol]
	if !ok {
		return nil, protocol.Error(hdr.CurrentProtocol)
	}

	return StartEvaluator(ledger, hdr, proto, paysetHint, true, true, maxTxnBytesPerBlock)
}

// GetCreatorForRound takes a CreatableIndex and a CreatableType and tries to
// look up a creator address, setting ok to false if the query succeeded but no
// creator was found.
func (ledger *evalTestLedger) GetCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (creator basics.Address, ok bool, err error) {
	balances := ledger.roundBalances[rnd]
	for addr, balance := range balances {
		if _, has := balance.AssetParams[basics.AssetIndex(cidx)]; has {
			return addr, true, nil
		}
		if _, has := balance.AppParams[basics.AppIndex(cidx)]; has {
			return addr, true, nil
		}
	}
	return basics.Address{}, false, nil
}

// LatestTotals returns the totals of all accounts for the most recent round, as well as the round number.
func (ledger *evalTestLedger) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	return basics.Round(len(ledger.blocks)).SubSaturate(1), ledger.latestTotals, nil
}

// LookupWithoutRewards is like Lookup but does not apply pending rewards up
// to the requested round rnd.
func (ledger *evalTestLedger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (basics.AccountData, basics.Round, error) {
	return ledger.roundBalances[rnd][addr], rnd, nil
}

// GenesisHash returns the genesis hash for this ledger.
func (ledger *evalTestLedger) GenesisHash() crypto.Digest {
	return ledger.genesisHash
}

// Latest returns the latest known block round added to the ledger.
func (ledger *evalTestLedger) Latest() basics.Round {
	return basics.Round(len(ledger.blocks)).SubSaturate(1)
}

// AddValidatedBlock adds a new block to the ledger, after the block has
// been validated by calling Ledger.Validate().  This saves the cost of
// having to re-compute the effect of the block on the ledger state, if
// the block has previously been validated.  Otherwise, AddValidatedBlock
// behaves like AddBlock.
func (ledger *evalTestLedger) AddValidatedBlock(vb ledgercore.ValidatedBlock, cert agreement.Certificate) error {
	blk := vb.Block()
	ledger.blocks[blk.Round()] = blk
	newBalances := make(map[basics.Address]basics.AccountData)

	// copy the previous balances.
	for k, v := range ledger.roundBalances[vb.Block().Round()-1] {
		newBalances[k] = v
	}
	// update
	deltas := vb.Delta()
	for _, addr := range deltas.Accts.ModifiedAccounts() {
		accountData, _ := deltas.Accts.Get(addr)
		newBalances[addr] = accountData
	}
	ledger.roundBalances[vb.Block().Round()] = newBalances
	ledger.latestTotals = vb.Delta().Totals
	return nil
}

// Lookup uses the accounts tracker to return the account state for a
// given account in a particular round.  The account values reflect
// the changes of all blocks up to and including rnd.
func (ledger *evalTestLedger) Lookup(rnd basics.Round, addr basics.Address) (basics.AccountData, error) {
	balances, has := ledger.roundBalances[rnd]
	if !has {
		return basics.AccountData{}, errors.New("invalid round specified")
	}

	return balances[addr], nil
}
func (ledger *evalTestLedger) BlockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	block, has := ledger.blocks[rnd]
	if !has {
		return bookkeeping.BlockHeader{}, errors.New("invalid round specified")
	}
	return block.BlockHeader, nil
}

func (ledger *evalTestLedger) CompactCertVoters(rnd basics.Round) (*ledgercore.VotersForRound, error) {
	return nil, errors.New("untested code path")
}

// GetCreator is like GetCreatorForRound, but for the latest round and race-free
// with respect to ledger.Latest()
func (ledger *evalTestLedger) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	latestRound := ledger.Latest()
	return ledger.GetCreatorForRound(latestRound, cidx, ctype)
}

func (ledger *evalTestLedger) CheckDup(currentProto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl ledgercore.Txlease) error {
	for _, block := range ledger.blocks {
		for _, txn := range block.Payset {
			if lastValid != txn.Txn.LastValid {
				continue
			}
			currentTxid := txn.Txn.ID()
			if bytes.Equal(txid[:], currentTxid[:]) {
				return &ledgercore.TransactionInLedgerError{Txid: txid}
			}
		}
	}
	// todo - support leases.
	return nil
}

// nextBlock begins evaluation of a new block, after ledger creation or endBlock()
func (ledger *evalTestLedger) nextBlock(t testing.TB) *BlockEvaluator {
	rnd := ledger.Latest()
	hdr, err := ledger.BlockHdr(rnd)
	require.NoError(t, err)

	nextHdr := bookkeeping.MakeBlock(hdr).BlockHeader
	eval, err := ledger.StartEvaluator(nextHdr, 0, 0)
	require.NoError(t, err)
	return eval
}

// endBlock completes the block being created, returns the ValidatedBlock for inspection
func (ledger *evalTestLedger) endBlock(t testing.TB, eval *BlockEvaluator) *ledgercore.ValidatedBlock {
	validatedBlock, err := eval.GenerateBlock()
	require.NoError(t, err)
	err = ledger.AddValidatedBlock(*validatedBlock, agreement.Certificate{})
	require.NoError(t, err)
	return validatedBlock
}

// lookup gets the current accountdata for an address
func (ledger *evalTestLedger) lookup(t testing.TB, addr basics.Address) basics.AccountData {
	rnd := ledger.Latest()
	ad, err := ledger.Lookup(rnd, addr)
	require.NoError(t, err)
	return ad
}

// micros gets the current microAlgo balance for an address
func (ledger *evalTestLedger) micros(t testing.TB, addr basics.Address) uint64 {
	return ledger.lookup(t, addr).MicroAlgos.Raw
}

// asa gets the current balance and optin status for some asa for an address
func (ledger *evalTestLedger) asa(t testing.TB, addr basics.Address, asset basics.AssetIndex) (uint64, bool) {
	if holding, ok := ledger.lookup(t, addr).Assets[asset]; ok {
		return holding.Amount, true
	}
	return 0, false
}

// asaParams gets the asset params for a given asa index
func (ledger *evalTestLedger) asaParams(t testing.TB, asset basics.AssetIndex) (basics.AssetParams, error) {
	creator, ok, err := ledger.GetCreator(basics.CreatableIndex(asset), basics.AssetCreatable)
	if err != nil {
		return basics.AssetParams{}, err
	}
	if !ok {
		return basics.AssetParams{}, fmt.Errorf("no asset (%d)", asset)
	}
	if params, ok := ledger.lookup(t, creator).AssetParams[asset]; ok {
		return params, nil
	}
	return basics.AssetParams{}, fmt.Errorf("bad lookup (%d)", asset)
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
	err := eval.TestTransaction(stxn, eval.state.child(1))
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

	err = eval.TransactionGroup(transactions.WrapSignedTxnsWithAD(txgroup))
	return err
}

func TestRewardsInAD(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
	l := newTestLedger(t, genBalances)

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

	assert.Len(t, vb.Delta().ModifiedAppLocalStates, 1)
	{
		aa := ledgercore.AccountApp{
			Address: addrs[1],
			App:     appid,
		}
		created, ok := vb.Delta().ModifiedAppLocalStates[aa]
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

	assert.Len(t, vb.Delta().ModifiedAppLocalStates, 1)
	{
		aa := ledgercore.AccountApp{
			Address: addrs[1],
			App:     appid,
		}
		created, ok := vb.Delta().ModifiedAppLocalStates[aa]
		require.True(t, ok)
		assert.False(t, created)
	}
}

// TestAppInsMinBalance checks that accounts with MaxAppsOptedIn are accepted by block evaluator
// and do not cause any MaximumMinimumBalance problems
func TestAppInsMinBalance(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
	l := newTestLedger(t, genBalances)

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
			Note:             ledgertesting.RandomNote(),
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
	assert.Len(t, vb.Delta().ModifiedAppLocalStates, 50)
}

// TestGhostTransactions confirms that accounts that don't even exist
// can be the Sender in some situations.  If some other transaction
// covers the fee, and the transaction itself does not require an
// asset or a min balance, it's fine.
func TestGhostTransactions(t *testing.T) {
	t.Skip("Behavior should be changed so test passes.")

	/*
		I think we have a behavior we should fix.  I’m going to call these
		transactions where the Sender has no account and the fee=0 “ghost”
		transactions.  In a ghost transaction, we still call balances.Move to
		“pay” the fee.  Further, Move does not short-circuit a Move of 0 (for
		good reason, allowing compounding).  Therefore, in Move, we do rewards
		processing on the “ghost” account.  That causes us to want to write a
		new accountdata for them.  But if we do that, the minimum balance
		checker will catch it, and kill the transaction because the ghost isn’t
		allowed to have a balance of 0.  I don’t think we can short-circuit
		Move(0) because a zero pay is a known way to get your rewards
		actualized. Instead, I advocate that we short-circuit the call to Move
		for 0 fees.

		// move fee to pool
		if !tx.Fee.IsZero() {
			err = balances.Move(tx.Sender, eval.specials.FeeSink, tx.Fee, &ad.SenderRewards, nil)
			if err != nil {
				return
			}
		}

		I think this must be controlled by consensus upgrade, but I would love
		to be told I’m wrong.  The other option is to outlaw these
		transactions, but even that requires changing code if we want to be
		exactly correct, because they are currently allowed when there are no
		rewards to get paid out (as would happen in a new network, or if we
		stop participation rewards - notice that this test only fails on the
		4th attempt, once rewards have accumulated).

		Will suggested that we could treat Ghost accounts as non-partipating.
		Maybe that would allow the Move code to avoid trying to update
		accountdata.
	*/

	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
	l := newTestLedger(t, genBalances)

	asaIndex := basics.AssetIndex(1)

	asa := txntest.Txn{
		Type:   "acfg",
		Sender: addrs[0],
		AssetParams: basics.AssetParams{
			Total:     1000000,
			Decimals:  3,
			UnitName:  "oz",
			AssetName: "Gold",
			URL:       "https://gold.rush/",
			Clawback:  basics.Address{0x0c, 0x0b, 0x0a, 0x0c},
			Freeze:    basics.Address{0x0f, 0x0e, 0xe, 0xe},
			Manager:   basics.Address{0x0a, 0x0a, 0xe},
		},
	}

	eval := l.nextBlock(t)
	eval.txn(t, &asa)
	l.endBlock(t, eval)

	benefactor := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: addrs[0],
		Fee:      2000,
	}

	ghost := basics.Address{0x01}
	ephemeral := []txntest.Txn{
		{
			Type:     "pay",
			Amount:   0,
			Sender:   ghost,
			Receiver: ghost,
			Fee:      0,
		},
		{
			Type:          "axfer",
			AssetAmount:   0,
			Sender:        ghost,
			AssetReceiver: basics.Address{0x02},
			XferAsset:     basics.AssetIndex(1),
			Fee:           0,
		},
		{
			Type:          "axfer",
			AssetAmount:   0,
			Sender:        basics.Address{0x0c, 0x0b, 0x0a, 0x0c},
			AssetReceiver: addrs[0],
			AssetSender:   addrs[1],
			XferAsset:     asaIndex,
			Fee:           0,
		},
		{
			Type:          "afrz",
			Sender:        basics.Address{0x0f, 0x0e, 0xe, 0xe},
			FreezeAccount: addrs[0], // creator, therefore is opted in
			FreezeAsset:   asaIndex,
			AssetFrozen:   true,
			Fee:           0,
		},
		{
			Type:          "afrz",
			Sender:        basics.Address{0x0f, 0x0e, 0xe, 0xe},
			FreezeAccount: addrs[0], // creator, therefore is opted in
			FreezeAsset:   asaIndex,
			AssetFrozen:   false,
			Fee:           0,
		},
	}

	for i, e := range ephemeral {
		eval = l.nextBlock(t)
		err := eval.txgroup(t, &benefactor, &e)
		require.NoError(t, err, "i=%d %s", i, e.Type)
		l.endBlock(t, eval)
	}
}

type getCreatorForRoundResult struct {
	address basics.Address
	exists  bool
}

type testCowBaseLedger struct {
	creators []getCreatorForRoundResult
}

func (l *testCowBaseLedger) BlockHdr(basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{}, errors.New("not implemented")
}

func (l *testCowBaseLedger) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error {
	return errors.New("not implemented")
}

func (l *testCowBaseLedger) LookupWithoutRewards(basics.Round, basics.Address) (basics.AccountData, basics.Round, error) {
	return basics.AccountData{}, basics.Round(0), errors.New("not implemented")
}

func (l *testCowBaseLedger) GetCreatorForRound(_ basics.Round, cindex basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	res := l.creators[0]
	l.creators = l.creators[1:]
	return res.address, res.exists, nil
}

func TestCowBaseCreatorsCache(t *testing.T) {
	partitiontest.PartitionTest(t)

	addresses := make([]basics.Address, 3)
	for i := 0; i < len(addresses); i++ {
		_, err := rand.Read(addresses[i][:])
		require.NoError(t, err)
	}

	creators := []getCreatorForRoundResult{
		{address: addresses[0], exists: true},
		{address: basics.Address{}, exists: false},
		{address: addresses[1], exists: true},
		{address: basics.Address{}, exists: false},
	}
	l := testCowBaseLedger{
		creators: creators,
	}

	base := roundCowBase{
		l:        &l,
		creators: map[Creatable]ledgercore.FoundAddress{},
	}

	cindex := []basics.CreatableIndex{9, 10, 9, 10}
	ctype := []basics.CreatableType{
		basics.AssetCreatable,
		basics.AssetCreatable,
		basics.AppCreatable,
		basics.AppCreatable,
	}
	for i := 0; i < 2; i++ {
		for j, expected := range creators {
			address, exists, err := base.getCreator(cindex[j], ctype[j])
			require.NoError(t, err)

			assert.Equal(t, expected.address, address)
			assert.Equal(t, expected.exists, exists)
		}
	}
}

// TestEvalFunctionForExpiredAccounts tests that the eval function will correctly mark accounts as offline
func TestEvalFunctionForExpiredAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisInitState, addrs, keys := ledgertesting.GenesisWithProto(10, protocol.ConsensusFuture)

	sendAddr := addrs[0]
	recvAddr := addrs[1]

	// the last round that the recvAddr is valid for
	recvAddrLastValidRound := basics.Round(2)

	// the target round we want to advance the evaluator to
	targetRound := basics.Round(4)

	// Set all to online except the sending address
	for _, addr := range addrs {
		if addr == sendAddr {
			continue
		}
		tmp := genesisInitState.Accounts[addr]
		tmp.Status = basics.Online
		genesisInitState.Accounts[addr] = tmp
	}

	// Choose recvAddr to have a last valid round less than genesis block round
	{
		tmp := genesisInitState.Accounts[recvAddr]
		tmp.VoteLastValid = recvAddrLastValidRound
		genesisInitState.Accounts[recvAddr] = tmp
	}

	genesisBalances := bookkeeping.GenesisBalances{
		Balances:    genesisInitState.Accounts,
		FeeSink:     testSinkAddr,
		RewardsPool: testPoolAddr,
		Timestamp:   0,
	}
	l := newTestLedger(t, genesisBalances)

	newBlock := bookkeeping.MakeBlock(l.blocks[0].BlockHeader)

	blkEval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0)
	require.NoError(t, err)

	// Advance the evaluator a couple rounds...
	for i := uint64(0); i < uint64(targetRound); i++ {
		l.endBlock(t, blkEval)
		blkEval = l.nextBlock(t)
	}

	require.Greater(t, uint64(blkEval.Round()), uint64(recvAddrLastValidRound))

	genHash := l.GenesisHash()
	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sendAddr,
			Fee:         minFee,
			FirstValid:  newBlock.Round(),
			LastValid:   blkEval.Round(),
			GenesisHash: genHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: recvAddr,
			Amount:   basics.MicroAlgos{Raw: 100},
		},
	}

	st := txn.Sign(keys[0])
	err = blkEval.Transaction(st, transactions.ApplyData{})
	require.NoError(t, err)

	// Make sure we validate our block as well
	blkEval.validate = true

	validatedBlock, err := blkEval.GenerateBlock()
	require.NoError(t, err)

	_, err = Eval(context.Background(), l, validatedBlock.Block(), false, nil, nil)
	require.NoError(t, err)

	badBlock := *validatedBlock

	// First validate that bad block is fine if we dont touch it...
	_, err = Eval(context.Background(), l, badBlock.Block(), true, verify.GetMockedCache(true), nil)
	require.NoError(t, err)

	badBlock = *validatedBlock

	// Introduce an unknown address to introduce an error
	badBlockObj := badBlock.Block()
	badBlockObj.ExpiredParticipationAccounts = append(badBlockObj.ExpiredParticipationAccounts, basics.Address{1})
	badBlock = ledgercore.MakeValidatedBlock(badBlockObj, badBlock.Delta())

	_, err = Eval(context.Background(), l, badBlock.Block(), true, verify.GetMockedCache(true), nil)
	require.Error(t, err)

	badBlock = *validatedBlock

	addressToCopy := badBlock.Block().ExpiredParticipationAccounts[0]

	// Add more than the expected number of accounts
	badBlockObj = badBlock.Block()
	for i := 0; i < blkEval.proto.MaxProposedExpiredOnlineAccounts+1; i++ {
		badBlockObj.ExpiredParticipationAccounts = append(badBlockObj.ExpiredParticipationAccounts, addressToCopy)
	}
	badBlock = ledgercore.MakeValidatedBlock(badBlockObj, badBlock.Delta())

	_, err = Eval(context.Background(), l, badBlock.Block(), true, verify.GetMockedCache(true), nil)
	require.Error(t, err)

	badBlock = *validatedBlock

	// Duplicate an address
	badBlockObj = badBlock.Block()
	badBlockObj.ExpiredParticipationAccounts = append(badBlockObj.ExpiredParticipationAccounts, badBlockObj.ExpiredParticipationAccounts[0])
	badBlock = ledgercore.MakeValidatedBlock(badBlockObj, badBlock.Delta())

	_, err = Eval(context.Background(), l, badBlock.Block(), true, verify.GetMockedCache(true), nil)
	require.Error(t, err)

	badBlock = *validatedBlock
	// sanity check that bad block is being actually copied and not just the pointer
	_, err = Eval(context.Background(), l, badBlock.Block(), true, verify.GetMockedCache(true), nil)
	require.NoError(t, err)

}

type failRoundCowParent struct {
	roundCowBase
}

func (p *failRoundCowParent) lookup(basics.Address) (basics.AccountData, error) {
	return basics.AccountData{}, fmt.Errorf("disk I/O fail (on purpose)")
}

// TestExpiredAccountGenerationWithDiskFailure tests edge cases where disk failures can lead to ledger look up failures
func TestExpiredAccountGenerationWithDiskFailure(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisInitState, addrs, keys := ledgertesting.GenesisWithProto(10, protocol.ConsensusFuture)

	sendAddr := addrs[0]
	recvAddr := addrs[1]

	// the last round that the recvAddr is valid for
	recvAddrLastValidRound := basics.Round(10)

	// the target round we want to advance the evaluator to
	targetRound := basics.Round(4)

	// Set all to online except the sending address
	for _, addr := range addrs {
		if addr == sendAddr {
			continue
		}
		tmp := genesisInitState.Accounts[addr]
		tmp.Status = basics.Online
		genesisInitState.Accounts[addr] = tmp
	}

	// Choose recvAddr to have a last valid round less than genesis block round
	{
		tmp := genesisInitState.Accounts[recvAddr]
		tmp.VoteLastValid = recvAddrLastValidRound
		genesisInitState.Accounts[recvAddr] = tmp
	}

	l := newTestLedger(t, bookkeeping.GenesisBalances{
		Balances:    genesisInitState.Accounts,
		FeeSink:     testSinkAddr,
		RewardsPool: testPoolAddr,
		Timestamp:   0,
	})

	newBlock := bookkeeping.MakeBlock(l.blocks[0].BlockHeader)

	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0)
	require.NoError(t, err)

	// Advance the evaluator a couple rounds...
	for i := uint64(0); i < uint64(targetRound); i++ {
		l.endBlock(t, eval)
		eval = l.nextBlock(t)
	}

	genHash := l.GenesisHash()
	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sendAddr,
			Fee:         minFee,
			FirstValid:  newBlock.Round(),
			LastValid:   eval.Round(),
			GenesisHash: genHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: recvAddr,
			Amount:   basics.MicroAlgos{Raw: 100},
		},
	}

	st := txn.Sign(keys[0])
	err = eval.Transaction(st, transactions.ApplyData{})
	require.NoError(t, err)

	eval.validate = true
	eval.generate = false

	eval.block.ExpiredParticipationAccounts = append(eval.block.ExpiredParticipationAccounts, recvAddr)

	err = eval.endOfBlock()
	require.Error(t, err)

	eval.block.ExpiredParticipationAccounts = []basics.Address{
		basics.Address{},
	}
	eval.state.mods.Accts = ledgercore.AccountDeltas{}
	eval.state.lookupParent = &failRoundCowParent{}
	err = eval.endOfBlock()
	require.Error(t, err)

	err = eval.resetExpiredOnlineAccountsParticipationKeys()
	require.Error(t, err)

}

// TestExpiredAccountGeneration test that expired accounts are added to a block header and validated
func TestExpiredAccountGeneration(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisInitState, addrs, keys := ledgertesting.GenesisWithProto(10, protocol.ConsensusFuture)

	sendAddr := addrs[0]
	recvAddr := addrs[1]

	// the last round that the recvAddr is valid for
	recvAddrLastValidRound := basics.Round(2)

	// the target round we want to advance the evaluator to
	targetRound := basics.Round(4)

	// Set all to online except the sending address
	for _, addr := range addrs {
		if addr == sendAddr {
			continue
		}
		tmp := genesisInitState.Accounts[addr]
		tmp.Status = basics.Online
		genesisInitState.Accounts[addr] = tmp
	}

	// Choose recvAddr to have a last valid round less than genesis block round
	{
		tmp := genesisInitState.Accounts[recvAddr]
		tmp.VoteLastValid = recvAddrLastValidRound
		genesisInitState.Accounts[recvAddr] = tmp
	}

	l := newTestLedger(t, bookkeeping.GenesisBalances{
		Balances:    genesisInitState.Accounts,
		FeeSink:     testSinkAddr,
		RewardsPool: testPoolAddr,
		Timestamp:   0,
	})

	newBlock := bookkeeping.MakeBlock(l.blocks[0].BlockHeader)

	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0)
	require.NoError(t, err)

	// Advance the evaluator a couple rounds...
	for i := uint64(0); i < uint64(targetRound); i++ {
		l.endBlock(t, eval)
		eval = l.nextBlock(t)
	}

	require.Greater(t, uint64(eval.Round()), uint64(recvAddrLastValidRound))

	genHash := l.GenesisHash()
	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sendAddr,
			Fee:         minFee,
			FirstValid:  newBlock.Round(),
			LastValid:   eval.Round(),
			GenesisHash: genHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: recvAddr,
			Amount:   basics.MicroAlgos{Raw: 100},
		},
	}

	st := txn.Sign(keys[0])
	err = eval.Transaction(st, transactions.ApplyData{})
	require.NoError(t, err)

	// Make sure we validate our block as well
	eval.validate = true

	validatedBlock, err := eval.GenerateBlock()
	require.NoError(t, err)

	listOfExpiredAccounts := validatedBlock.Block().ParticipationUpdates.ExpiredParticipationAccounts

	require.Equal(t, 1, len(listOfExpiredAccounts))
	expiredAccount := listOfExpiredAccounts[0]
	require.Equal(t, expiredAccount, recvAddr)

	recvAcct, err := eval.state.lookup(recvAddr)
	require.NoError(t, err)
	require.Equal(t, recvAcct.Status, basics.Offline)
	require.Equal(t, recvAcct.VoteFirstValid, basics.Round(0))
	require.Equal(t, recvAcct.VoteLastValid, basics.Round(0))
	require.Equal(t, recvAcct.VoteKeyDilution, uint64(0))
	require.Equal(t, recvAcct.VoteID, crypto.OneTimeSignatureVerifier{})
	require.Equal(t, recvAcct.SelectionID, crypto.VRFVerifier{})

}
