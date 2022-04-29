// Copyright (C) 2019-2022 Algorand, Inc.
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

package internal_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/internal"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
)

var minFee basics.MicroAlgos

func init() {
	params := config.Consensus[protocol.ConsensusCurrentVersion]
	minFee = basics.MicroAlgos{Raw: params.MinTxnFee}
}

func TestBlockEvaluator(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genesisInitState, addrs, keys := ledgertesting.Genesis(10)

	l, err := ledger.OpenLedger(logging.TestingLog(t), t.Name(), true, genesisInitState, config.GetDefaultLocal())
	require.NoError(t, err)
	defer l.Close()

	genesisBlockHeader, err := l.BlockHdr(basics.Round(0))
	require.NoError(t, err)
	newBlock := bookkeeping.MakeBlock(genesisBlockHeader)
	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0)
	require.NoError(t, err)

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

	bal0new, _, _, err := l.LookupAccount(newBlock.Round(), addrs[0])
	require.NoError(t, err)
	bal1new, _, _, err := l.LookupAccount(newBlock.Round(), addrs[1])
	require.NoError(t, err)
	bal2new, _, _, err := l.LookupAccount(newBlock.Round(), addrs[2])
	require.NoError(t, err)

	require.Equal(t, bal0new.MicroAlgos.Raw, bal0.MicroAlgos.Raw-minFee.Raw-100)
	require.Equal(t, bal1new.MicroAlgos.Raw, bal1.MicroAlgos.Raw+100)
	require.Equal(t, bal2new.MicroAlgos.Raw, bal2.MicroAlgos.Raw-minFee.Raw)
}

func TestRekeying(t *testing.T) {
	partitiontest.PartitionTest(t)
	// t.Parallel() NO! This test manipulates []protocol.Consensus

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

	l, err := ledger.OpenLedger(logging.TestingLog(t), t.Name(), true, genesisInitState, config.GetDefaultLocal())
	require.NoError(t, err)
	defer l.Close()

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

// TestEvalAppState ensures txns in a group can't violate app state schema
// limits the test ensures that commitToParent -> applyChild copies child's cow
// state usage counts into parent and the usage counts correctly propagated from
// parent cow to child cow and back. When limits are not violated, the test
// ensures that the updates are correct.
func TestEvalAppState(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// v24 = apps
	testConsensusRange(t, 24, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		appcall1 := txntest.Txn{
			Type:              protocol.ApplicationCallTx,
			Sender:            addrs[0],
			GlobalStateSchema: basics.StateSchema{NumByteSlice: 1},
			ApprovalProgram: `#pragma version 2
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
	int 1`,
			ClearStateProgram: "#pragma version 2\nint 1",
		}

		appcall2 := txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        addrs[0],
			ApplicationID: 1,
		}

		dl.beginBlock()
		dl.txgroup("store bytes count 2 exceeds schema bytes count 1", &appcall1, &appcall2)

		appcall1.GlobalStateSchema = basics.StateSchema{NumByteSlice: 2}
		dl.txgroup("", &appcall1, &appcall2)
		vb := dl.endBlock()
		deltas := vb.Delta()

		params, ok := deltas.Accts.GetAppParams(addrs[0], 1)
		require.True(t, ok)
		state := params.Params.GlobalState
		require.Equal(t, basics.TealValue{Type: basics.TealBytesType, Bytes: string(addrs[0][:])}, state["caller"])
		require.Equal(t, basics.TealValue{Type: basics.TealBytesType, Bytes: string(addrs[0][:])}, state["creator"])
	})
}

// nextBlock begins evaluation of a new block, after ledger creation or endBlock()
func nextBlock(t testing.TB, ledger *ledger.Ledger) *internal.BlockEvaluator {
	rnd := ledger.Latest()
	hdr, err := ledger.BlockHdr(rnd)
	require.NoError(t, err)

	nextHdr := bookkeeping.MakeBlock(hdr).BlockHeader
	nextHdr.TimeStamp = hdr.TimeStamp + 1 // ensure deterministic tests
	eval, err := internal.StartEvaluator(ledger, nextHdr, internal.EvaluatorOptions{
		Generate: true,
		Validate: true, // Do the complete checks that a new txn would be subject to
	})
	require.NoError(t, err)
	return eval
}

func fillDefaults(t testing.TB, ledger *ledger.Ledger, eval *internal.BlockEvaluator, txn *txntest.Txn) {
	if txn.GenesisHash.IsZero() && ledger.GenesisProto().SupportGenesisHash {
		txn.GenesisHash = ledger.GenesisHash()
	}
	if txn.FirstValid == 0 {
		txn.FirstValid = eval.Round()
	}

	txn.FillDefaults(ledger.GenesisProto())
}

func txns(t testing.TB, ledger *ledger.Ledger, eval *internal.BlockEvaluator, txns ...*txntest.Txn) {
	t.Helper()
	for _, txn1 := range txns {
		txn(t, ledger, eval, txn1)
	}
}

func txn(t testing.TB, ledger *ledger.Ledger, eval *internal.BlockEvaluator, txn *txntest.Txn, problem ...string) {
	t.Helper()
	fillDefaults(t, ledger, eval, txn)
	err := eval.Transaction(txn.SignedTxn(), transactions.ApplyData{})
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

func txgroup(t testing.TB, ledger *ledger.Ledger, eval *internal.BlockEvaluator, txns ...*txntest.Txn) error {
	t.Helper()
	for _, txn := range txns {
		fillDefaults(t, ledger, eval, txn)
	}
	txgroup := txntest.SignedTxns(txns...)

	return eval.TransactionGroup(transactions.WrapSignedTxnsWithAD(txgroup))
}

func testEvalAppPoolingGroup(t *testing.T, schema basics.StateSchema, approvalProgram string, consensusVersion protocol.ConsensusVersion) error {
	genesisInitState, addrs, _ := ledgertesting.GenesisWithProto(10, consensusVersion)

	l, err := ledger.OpenLedger(logging.TestingLog(t), "", true, genesisInitState, config.GetDefaultLocal())
	require.NoError(t, err)
	defer l.Close()

	eval := nextBlock(t, l)

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

	return txgroup(t, l, eval, &appcall1, &appcall2, &appcall3)
}

// TestEvalAppPooledBudgetWithTxnGroup ensures 3 app call txns can successfully pool
// budgets in a group txn and return an error if the budget is exceeded
func TestEvalAppPooledBudgetWithTxnGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
			"pc=157 dynamic cost budget exceeded, executing pushint",
			""},
		{source(16, 17), false, true,
			"pc= 12 dynamic cost budget exceeded, executing keccak256",
			""},
		{source(16, 18), false, false,
			"pc= 12 dynamic cost budget exceeded, executing keccak256",
			"pc= 78 dynamic cost budget exceeded, executing pushint"},
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

// endBlock completes the block being created, returns the ValidatedBlock for inspection
func endBlock(t testing.TB, ledger *ledger.Ledger, eval *internal.BlockEvaluator) *ledgercore.ValidatedBlock {
	validatedBlock, err := eval.GenerateBlock()
	require.NoError(t, err)
	err = ledger.AddValidatedBlock(*validatedBlock, agreement.Certificate{})
	require.NoError(t, err)
	return validatedBlock
}

// lookup gets the current accountdata for an address
func lookup(t testing.TB, ledger *ledger.Ledger, addr basics.Address) basics.AccountData {
	ad, _, _, err := ledger.LookupLatest(addr)
	require.NoError(t, err)
	return ad
}

// micros gets the current microAlgo balance for an address
func micros(t testing.TB, ledger *ledger.Ledger, addr basics.Address) uint64 {
	return lookup(t, ledger, addr).MicroAlgos.Raw
}

// holding gets the current balance and optin status for some asa for an address
func holding(t testing.TB, ledger *ledger.Ledger, addr basics.Address, asset basics.AssetIndex) (uint64, bool) {
	if holding, ok := lookup(t, ledger, addr).Assets[asset]; ok {
		return holding.Amount, true
	}
	return 0, false
}

// asaParams gets the asset params for a given asa index
func asaParams(t testing.TB, ledger *ledger.Ledger, asset basics.AssetIndex) (basics.AssetParams, error) {
	creator, ok, err := ledger.GetCreator(basics.CreatableIndex(asset), basics.AssetCreatable)
	if err != nil {
		return basics.AssetParams{}, err
	}
	if !ok {
		return basics.AssetParams{}, fmt.Errorf("no asset (%d)", asset)
	}
	if params, ok := lookup(t, ledger, creator).AssetParams[asset]; ok {
		return params, nil
	}
	return basics.AssetParams{}, fmt.Errorf("bad lookup (%d)", asset)
}

func TestGarbageClearState(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// v24 = apps
	testConsensusRange(t, 24, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		createTxn := txntest.Txn{
			Type:              "appl",
			Sender:            addrs[0],
			ApprovalProgram:   "int 1",
			ClearStateProgram: []byte{},
		}

		dl.txn(&createTxn, "invalid program (empty)")

		createTxn.ClearStateProgram = []byte{0xfe} // bad uvarint
		dl.txn(&createTxn, "invalid version")
	})
}

func TestRewardsInAD(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// v15 put rewards into ApplyData
	testConsensusRange(t, 11, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		payTxn := txntest.Txn{Type: protocol.PaymentTx, Sender: addrs[0], Receiver: addrs[1]}

		// Build up Residue in RewardsState so it's ready to pay
		for i := 1; i < 10; i++ {
			dl.fullBlock()
		}

		vb := dl.fullBlock(&payTxn)
		payInBlock := vb.Block().Payset[0]
		if ver >= 15 {
			require.Greater(t, payInBlock.ApplyData.SenderRewards.Raw, uint64(1000))
			require.Greater(t, payInBlock.ApplyData.ReceiverRewards.Raw, uint64(1000))
			require.Equal(t, payInBlock.ApplyData.SenderRewards, payInBlock.ApplyData.ReceiverRewards)
		} else {
			require.EqualValues(t, 0, payInBlock.ApplyData.SenderRewards.Raw)
			require.EqualValues(t, 0, payInBlock.ApplyData.ReceiverRewards.Raw)
		}
	})
}

func TestMinBalanceChanges(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genesisInitState, addrs, _ := ledgertesting.Genesis(10)

	l, err := ledger.OpenLedger(logging.TestingLog(t), t.Name(), true, genesisInitState, config.GetDefaultLocal())
	require.NoError(t, err)
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

	ad0init, _, _, err := l.LookupLatest(addrs[0])
	require.NoError(t, err)
	ad5init, _, _, err := l.LookupLatest(addrs[5])
	require.NoError(t, err)

	eval := nextBlock(t, l)
	txns(t, l, eval, &createTxn, &optInTxn)
	endBlock(t, l, eval)

	ad0new, _, _, err := l.LookupLatest(addrs[0])
	require.NoError(t, err)
	ad5new, _, _, err := l.LookupLatest(addrs[5])
	require.NoError(t, err)

	proto := l.GenesisProto()
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

	eval = nextBlock(t, l)
	txns(t, l, eval, &optOutTxn, &closeTxn)
	endBlock(t, l, eval)

	ad0final, _, _, err := l.LookupLatest(addrs[0])
	require.NoError(t, err)
	ad5final, _, _, err := l.LookupLatest(addrs[5])
	require.NoError(t, err)
	// Check we got our balance "back"
	require.Equal(t, ad0final.MinBalance(&proto), ad0init.MinBalance(&proto))
	require.Equal(t, ad5final.MinBalance(&proto), ad5init.MinBalance(&proto))
}

// TestDeleteNonExistantKeys checks if the EvalDeltas from deleting missing keys are correct
func TestDeleteNonExistantKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// teal v2 (apps)
	testConsensusRange(t, 24, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		const appid basics.AppIndex = 1

		createTxn := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
byte "missing_global"
app_global_del
int 0
byte "missing_local"
app_local_del
`),
		}

		optInTxn := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[1],
			ApplicationID: appid,
			OnCompletion:  transactions.OptInOC,
		}

		vb := dl.fullBlock(&createTxn, &optInTxn)
		require.Len(t, vb.Block().Payset[1].EvalDelta.GlobalDelta, 0)
		// For a while, we encoded an empty localdelta
		deltas := 1
		if ver >= 27 {
			deltas = 0
		}
		require.Len(t, vb.Block().Payset[1].EvalDelta.LocalDeltas, deltas)
	})
}

// TestAppInsMinBalance checks that accounts with MaxAppsOptedIn are accepted by block evaluator
// and do not cause any MaximumMinimumBalance problems
func TestAppInsMinBalance(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genesisInitState, addrs, _ := ledgertesting.Genesis(10)
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusV30

	l, err := ledger.OpenLedger(logging.TestingLog(t), t.Name(), true, genesisInitState, config.GetDefaultLocal())
	require.NoError(t, err)
	defer l.Close()

	const appid basics.AppIndex = 1

	maxAppsOptedIn := config.Consensus[protocol.ConsensusV30].MaxAppsOptedIn
	require.Greater(t, maxAppsOptedIn, 0)
	maxAppsCreated := config.Consensus[protocol.ConsensusV30].MaxAppsCreated
	require.Greater(t, maxAppsCreated, 0)
	maxLocalSchemaEntries := config.Consensus[protocol.ConsensusV30].MaxLocalSchemaEntries
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

	eval := nextBlock(t, l)
	txns1 := append(txnsCreate, txnsOptIn...)
	txns(t, l, eval, txns1...)
	vb := endBlock(t, l, eval)
	mods := vb.Delta()
	appAppResources := mods.Accts.GetAllAppResources()
	appParamsCount := 0
	appLocalStatesCount := 0
	for _, ap := range appAppResources {
		if ap.Params.Params != nil {
			appParamsCount++
		}
		if ap.State.LocalState != nil {
			appLocalStatesCount++
		}
	}
	require.Equal(t, appLocalStatesCount, 50)
	require.Equal(t, appParamsCount, 50)
}

func TestDuplicates(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	testConsensusRange(t, 11, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		pay := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: addrs[1],
			Amount:   10,
		}
		dl.txn(&pay)
		dl.txn(&pay, "transaction already in ledger")

		// Test same transaction in a later block
		dl.txn(&pay, "transaction already in ledger")

		// Change the note so it can go in again
		pay.Note = []byte("1")
		dl.txn(&pay)

		// Change note again, but try the txn twice in same group
		if dl.generator.GenesisProto().MaxTxGroupSize > 1 {
			pay.Note = []byte("2")
			dl.txgroup("transaction already in ledger", &pay, &pay)
		}
	})
}

var consensusByNumber = []protocol.ConsensusVersion{
	"", "", "", "", "", "", "",
	protocol.ConsensusV7,
	protocol.ConsensusV8,
	protocol.ConsensusV9,
	protocol.ConsensusV10,
	protocol.ConsensusV11, // first with viable payset commit type
	protocol.ConsensusV12,
	protocol.ConsensusV13,
	protocol.ConsensusV14,
	protocol.ConsensusV15, // rewards in AD
	protocol.ConsensusV16,
	protocol.ConsensusV17,
	protocol.ConsensusV18,
	protocol.ConsensusV19,
	protocol.ConsensusV20,
	protocol.ConsensusV21,
	protocol.ConsensusV22,
	protocol.ConsensusV23,
	protocol.ConsensusV24, // teal v2 (apps)
	protocol.ConsensusV25,
	protocol.ConsensusV26,
	protocol.ConsensusV27,
	protocol.ConsensusV28,
	protocol.ConsensusV29,
	protocol.ConsensusV30, // teal v5 (inner txs)
	protocol.ConsensusV31, // teal v6 (inner txs with appls)
	protocol.ConsensusV32, // unlimited assets and apps
	protocol.ConsensusFuture,
}

func TestContainsLatestVersion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// This confirms that the proto before future has no ApprovedUpgrades.  Once
	// it does, that new version should be added to consensusByNumber.
	require.Len(t, config.Consensus[consensusByNumber[len(consensusByNumber)-2]].ApprovedUpgrades, 0)
	// And no funny business with vFuture
	require.Equal(t, protocol.ConsensusFuture, consensusByNumber[len(consensusByNumber)-1])
}

// testConsensusRange allows for running tests against a range of consensus
// versions. Generally `start` will be the version that introduced the feature,
// and `stop` will be 0 to indicate it should work right on up through vFuture.
// `stop` will be an actual version number if we're confirming that something
// STOPS working as of a particular version.  When writing the test for a new
// feature that is currently in vFuture, use the expected version number as
// `start`.  That will correspond to vFuture until a new consensus version is
// created and inserted in consensusByNumber. At that point, your feature is
// probably active in that version. (If it's being held in vFuture, just
// increment your `start`.)
func testConsensusRange(t *testing.T, start, stop int, test func(t *testing.T, ver int)) {
	if stop == 0 { // Treat 0 as "future"
		stop = len(consensusByNumber) - 1
	}
	for i := start; i <= stop; i++ {
		var version string
		if i == len(consensusByNumber)-1 {
			version = "vFuture"
		} else {
			version = fmt.Sprintf("v%d", i)
		}
		t.Run(fmt.Sprintf("cv=%s", version), func(t *testing.T) {
			test(t, i)
		})
	}
}

func benchConsensusRange(b *testing.B, start, stop int, bench func(t *testing.B, ver int)) {
	if stop == 0 { // Treat 0 as "future"
		stop = len(consensusByNumber) - 1
	}
	for i := start; i <= stop; i++ {
		var version string
		if i == len(consensusByNumber)-1 {
			version = "vFuture"
		} else {
			version = fmt.Sprintf("v%d", i)
		}
		b.Run(fmt.Sprintf("cv=%s", version), func(b *testing.B) { bench(b, i) })
	}
}

// TestLogsInBlock ensures that logs appear in the block properly
func TestLogsInBlock(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// Run tests from v30 onward
	testConsensusRange(t, 30, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		createTxn := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: "byte \"APP\"\n log\n int 1",
			// Fail the clear state
			ClearStateProgram: "byte \"CLR\"\n log\n int 0",
		}
		vb := dl.fullBlock(&createTxn)
		createInBlock := vb.Block().Payset[0]
		appId := createInBlock.ApplyData.ApplicationID
		require.Equal(t, "APP", createInBlock.ApplyData.EvalDelta.Logs[0])

		optInTxn := txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        addrs[1],
			ApplicationID: appId,
			OnCompletion:  transactions.OptInOC,
		}
		vb = dl.fullBlock(&optInTxn)
		optInInBlock := vb.Block().Payset[0]
		require.Equal(t, "APP", optInInBlock.ApplyData.EvalDelta.Logs[0])

		clearTxn := txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        addrs[1],
			ApplicationID: appId,
			OnCompletion:  transactions.ClearStateOC,
		}
		vb = dl.fullBlock(&clearTxn)
		clearInBlock := vb.Block().Payset[0]
		// Logs do not appear if the ClearState failed
		require.Len(t, clearInBlock.ApplyData.EvalDelta.Logs, 0)
	})
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
	t.Parallel()

	genesisInitState, addrs, _ := ledgertesting.Genesis(10)

	l, err := ledger.OpenLedger(logging.TestingLog(t), t.Name(), true, genesisInitState, config.GetDefaultLocal())
	require.NoError(t, err)
	defer l.Close()

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

	eval := nextBlock(t, l)
	txn(t, l, eval, &asa)
	endBlock(t, l, eval)

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
		eval = nextBlock(t, l)
		err := txgroup(t, l, eval, &benefactor, &e)
		require.NoError(t, err, "i=%d %s", i, e.Type)
		endBlock(t, l, eval)
	}
}
