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

package eval

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/logic/mocktracer"
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

func TestBlockEvaluatorFeeSink(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisInitState, _, _ := ledgertesting.Genesis(10)

	genesisBalances := bookkeeping.GenesisBalances{
		Balances:    genesisInitState.Accounts,
		FeeSink:     testSinkAddr,
		RewardsPool: testPoolAddr,
		Timestamp:   0,
	}
	l := newTestLedger(t, genesisBalances)

	genesisBlockHeader, err := l.BlockHdr(basics.Round(0))
	require.NoError(t, err)
	newBlock := bookkeeping.MakeBlock(genesisBlockHeader)
	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0, nil)
	require.NoError(t, err)
	require.Equal(t, eval.specials.FeeSink, testSinkAddr)
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
	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0, nil)
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
			ApplicationID: 1001,
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
				ApplicationID: 1001,
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
	t.Parallel()

	_, _, err := testEvalAppGroup(t, basics.StateSchema{NumByteSlice: 1})
	require.ErrorContains(t, err, "store bytes count 2 exceeds schema bytes count 1")
}

// TestEvalAppAllocStateWithTxnGroup ensures roundCowState.deltas and applyStorageDelta
// produce correct results when a txn group has storage allocate and storage update actions
func TestEvalAppAllocStateWithTxnGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	eval, addr, err := testEvalAppGroup(t, basics.StateSchema{NumByteSlice: 2})
	require.NoError(t, err)
	deltas := eval.state.deltas()
	ad, _ := deltas.Accts.GetBasicsAccountData(addr)
	state := ad.AppParams[1001].GlobalState
	require.Equal(t, basics.TealValue{Type: basics.TealBytesType, Bytes: string(addr[:])}, state["caller"])
	require.Equal(t, basics.TealValue{Type: basics.TealBytesType, Bytes: string(addr[:])}, state["creator"])
}

// a couple trivial tests that don't need setup
// see TestBlockEvaluator for more
func TestTestTransactionGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var txgroup []transactions.SignedTxn
	eval := BlockEvaluator{}
	err := eval.TestTransactionGroup(txgroup)
	require.NoError(t, err) // nothing to do, no problem

	eval.proto = config.Consensus[protocol.ConsensusCurrentVersion]
	txgroup = make([]transactions.SignedTxn, eval.proto.MaxTxGroupSize+1)
	err = eval.TestTransactionGroup(txgroup)
	require.ErrorContains(t, err, "group size")
}

// test BlockEvaluator.transactionGroup()
// some trivial checks that require no setup
func TestPrivateTransactionGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var txgroup []transactions.SignedTxnWithAD
	eval := BlockEvaluator{}
	err := eval.TransactionGroup(txgroup)
	require.NoError(t, err) // nothing to do, no problem

	eval.proto = config.Consensus[protocol.ConsensusCurrentVersion]
	txgroup = make([]transactions.SignedTxnWithAD, eval.proto.MaxTxGroupSize+1)
	err = eval.TransactionGroup(txgroup)
	require.ErrorContains(t, err, "group size")
}

func TestTransactionGroupWithTracer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// In all cases, a group of three transactions is tested. They are:
	//   1. A basic app call transaction
	//   2. A payment transaction
	//   3. An app call transaction that spawns inners. This is from the mocktracer scenarios.

	scenarios := mocktracer.GetTestScenarios()

	type tracerTestCase struct {
		name                 string
		firstTxnBehavior     string
		innerAppCallScenario mocktracer.TestScenarioGenerator
	}
	var testCases []tracerTestCase

	firstIteration := true
	for scenarioName, scenario := range scenarios {
		firstTxnBehaviors := []string{"approve"}
		if firstIteration {
			// When the first transaction rejects or errors, the behavior of the later transactions
			// don't matter, so we only want to test these cases with any one mocktracer scenario.
			firstTxnBehaviors = append(firstTxnBehaviors, "reject", "error")
			firstIteration = false
		}

		for _, firstTxnTxnBehavior := range firstTxnBehaviors {
			testCases = append(testCases, tracerTestCase{
				name:                 fmt.Sprintf("firstTxnBehavior=%s,scenario=%s", firstTxnTxnBehavior, scenarioName),
				firstTxnBehavior:     firstTxnTxnBehavior,
				innerAppCallScenario: scenario,
			})
		}
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			genesisInitState, addrs, keys := ledgertesting.Genesis(10)

			basicAppID := basics.AppIndex(1001)
			innerAppID := basics.AppIndex(1003)
			innerAppAddress := innerAppID.Address()
			balances := genesisInitState.Accounts
			balances[innerAppAddress] = basics_testing.MakeAccountData(basics.Offline, basics.MicroAlgos{Raw: 1_000_000})

			genesisBalances := bookkeeping.GenesisBalances{
				Balances:    balances,
				FeeSink:     testSinkAddr,
				RewardsPool: testPoolAddr,
				Timestamp:   0,
			}
			l := newTestLedger(t, genesisBalances)

			blkHeader, err := l.BlockHdr(basics.Round(0))
			require.NoError(t, err)
			newBlock := bookkeeping.MakeBlock(blkHeader)
			tracer := &mocktracer.Tracer{}
			eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0, tracer)
			require.NoError(t, err)
			eval.validate = true
			eval.generate = true

			genHash := l.GenesisHash()

			var basicAppCallReturn string
			switch testCase.firstTxnBehavior {
			case "approve":
				basicAppCallReturn = "int 1"
			case "reject":
				basicAppCallReturn = "int 0"
			case "error":
				basicAppCallReturn = "err"
			default:
				require.Fail(t, "Unexpected firstTxnBehavior")
			}
			// a basic app call
			basicAppCallTxn := txntest.Txn{
				Type:   protocol.ApplicationCallTx,
				Sender: addrs[0],
				ApprovalProgram: fmt.Sprintf(`#pragma version 6
byte "hello"
log
%s`, basicAppCallReturn),
				ClearStateProgram: `#pragma version 6
int 1`,

				FirstValid:  newBlock.Round(),
				LastValid:   newBlock.Round() + 1000,
				Fee:         minFee,
				GenesisHash: genHash,
			}

			// a non-app call txn
			payTxn := txntest.Txn{
				Type:             protocol.PaymentTx,
				Sender:           addrs[1],
				Receiver:         addrs[2],
				CloseRemainderTo: addrs[3],
				Amount:           1_000_000,

				FirstValid:  newBlock.Round(),
				LastValid:   newBlock.Round() + 1000,
				Fee:         minFee,
				GenesisHash: genHash,
			}
			// an app call with inner txn
			innerAppCallTxn := txntest.Txn{
				Type:   protocol.ApplicationCallTx,
				Sender: addrs[4],
				ClearStateProgram: `#pragma version 6
int 1`,

				FirstValid:  newBlock.Round(),
				LastValid:   newBlock.Round() + 1000,
				Fee:         minFee,
				GenesisHash: genHash,
			}

			expectedFeeSinkDataForScenario := ledgercore.ToAccountData(balances[testSinkAddr])
			expectedFeeSinkDataForScenario.MicroAlgos.Raw += basicAppCallTxn.Txn().Fee.Raw
			if testCase.firstTxnBehavior == "approve" {
				expectedFeeSinkDataForScenario.MicroAlgos.Raw += payTxn.Txn().Fee.Raw
			}

			scenario := testCase.innerAppCallScenario(mocktracer.TestScenarioInfo{
				CallingTxn:     innerAppCallTxn.Txn(),
				SenderData:     ledgercore.ToAccountData(balances[addrs[4]]),
				AppAccountData: ledgercore.ToAccountData(balances[innerAppAddress]),
				FeeSinkData:    expectedFeeSinkDataForScenario,
				FeeSinkAddr:    testSinkAddr,
				MinFee:         minFee,
				CreatedAppID:   innerAppID,
				BlockHeader:    eval.block.BlockHeader,
				PrevTimestamp:  blkHeader.TimeStamp,
			})
			innerAppCallTxn.ApprovalProgram = scenario.Program

			txntest.Group(&basicAppCallTxn, &payTxn, &innerAppCallTxn)

			// Update the expected state delta to reflect the inner app call txid
			scenarioTxidValue, ok := scenario.ExpectedStateDelta.Txids[transactions.Txid{}]
			if ok {
				delete(scenario.ExpectedStateDelta.Txids, transactions.Txid{})
				scenario.ExpectedStateDelta.Txids[innerAppCallTxn.Txn().ID()] = scenarioTxidValue
			}
			for i := range scenario.ExpectedEvents {
				deltas := scenario.ExpectedEvents[i].Deltas
				if deltas == nil {
					continue
				}
				txidValue, ok := deltas.Txids[transactions.Txid{}]
				if ok {
					delete(deltas.Txids, transactions.Txid{})
					deltas.Txids[innerAppCallTxn.Txn().ID()] = txidValue
				}
			}

			txgroup := transactions.WrapSignedTxnsWithAD([]transactions.SignedTxn{
				basicAppCallTxn.Txn().Sign(keys[0]),
				payTxn.Txn().Sign(keys[1]),
				innerAppCallTxn.Txn().Sign(keys[4]),
			})

			require.Len(t, eval.block.Payset, 0)

			err = eval.TransactionGroup(txgroup)
			switch testCase.firstTxnBehavior {
			case "approve":
				if len(scenario.ExpectedError) != 0 {
					require.ErrorContains(t, err, scenario.ExpectedError)
					require.Len(t, eval.block.Payset, 0)
				} else {
					require.NoError(t, err)
					require.Len(t, eval.block.Payset, 3)
				}
			case "reject":
				require.ErrorContains(t, err, "transaction rejected by ApprovalProgram")
				require.Len(t, eval.block.Payset, 0)
			case "error":
				require.ErrorContains(t, err, "logic eval error: err opcode executed")
				require.Len(t, eval.block.Payset, 0)
			}

			expectedBasicAppCallAD := transactions.ApplyData{
				ApplicationID: basicAppID,
				EvalDelta: transactions.EvalDelta{
					GlobalDelta: basics.StateDelta{},
					LocalDeltas: map[uint64]basics.StateDelta{},
					Logs:        []string{"hello"},
				},
			}
			expectedPayTxnAD :=
				transactions.ApplyData{
					ClosingAmount: basics.MicroAlgos{
						Raw: balances[payTxn.Sender].MicroAlgos.Raw - payTxn.Amount - txgroup[1].Txn.Fee.Raw,
					},
				}

			expectedFeeSinkData := ledgercore.ToAccountData(balances[testSinkAddr])
			expectedFeeSinkData.MicroAlgos.Raw += txgroup[0].Txn.Fee.Raw
			expectedAcct0Data := ledgercore.ToAccountData(balances[addrs[0]])
			expectedAcct0Data.MicroAlgos.Raw -= txgroup[0].Txn.Fee.Raw
			expectedAcct0Data.TotalAppParams = 1

			expectedBlockHeader := eval.block.BlockHeader
			expectedBasicAppCallDelta := ledgercore.StateDelta{
				Accts: ledgercore.AccountDeltas{
					Accts: []ledgercore.BalanceRecord{
						{
							Addr:        addrs[0],
							AccountData: expectedAcct0Data,
						},
						{
							Addr:        testSinkAddr,
							AccountData: expectedFeeSinkData,
						},
					},
					AppResources: []ledgercore.AppResourceRecord{
						{
							Aidx: basicAppID,
							Addr: addrs[0],
							Params: ledgercore.AppParamsDelta{
								Params: &basics.AppParams{
									ApprovalProgram:   txgroup[0].Txn.ApprovalProgram,
									ClearStateProgram: txgroup[0].Txn.ClearStateProgram,
								},
							},
						},
					},
				},
				Creatables: map[basics.CreatableIndex]ledgercore.ModifiedCreatable{
					basics.CreatableIndex(basicAppID): {
						Ctype:   basics.AppCreatable,
						Created: true,
						Creator: addrs[0],
					},
				},
				Txids: map[transactions.Txid]ledgercore.IncludedTransactions{
					txgroup[0].Txn.ID(): {
						LastValid: txgroup[0].Txn.LastValid,
						Intra:     0,
					},
				},
				Hdr:           &expectedBlockHeader,
				PrevTimestamp: blkHeader.TimeStamp,
			}
			expectedBasicAppCallDelta.Hydrate()

			expectedEvents := []mocktracer.Event{mocktracer.BeforeBlock(eval.block.Round())}
			if testCase.firstTxnBehavior == "approve" {
				err = eval.endOfBlock()
				require.NoError(t, err)

				expectedAcct1Data := ledgercore.AccountData{}
				expectedAcct2Data := ledgercore.ToAccountData(balances[addrs[2]])
				expectedAcct2Data.MicroAlgos.Raw += payTxn.Amount
				expectedAcct3Data := ledgercore.ToAccountData(balances[addrs[3]])
				expectedAcct3Data.MicroAlgos.Raw += expectedPayTxnAD.ClosingAmount.Raw
				expectedFeeSinkData.MicroAlgos.Raw += txgroup[1].Txn.Fee.Raw

				expectedPayTxnDelta := ledgercore.StateDelta{
					Accts: ledgercore.AccountDeltas{
						Accts: []ledgercore.BalanceRecord{
							{
								Addr:        addrs[1],
								AccountData: expectedAcct1Data,
							},
							{
								Addr:        testSinkAddr,
								AccountData: expectedFeeSinkData,
							},
							{
								Addr:        addrs[2],
								AccountData: expectedAcct2Data,
							},
							{
								Addr:        addrs[3],
								AccountData: expectedAcct3Data,
							},
						},
					},
					Txids: map[transactions.Txid]ledgercore.IncludedTransactions{
						txgroup[1].Txn.ID(): {
							LastValid: txgroup[1].Txn.LastValid,
							Intra:     0, // will be incremented once merged
						},
					},
					Hdr:           &expectedBlockHeader,
					PrevTimestamp: blkHeader.TimeStamp,
				}
				expectedPayTxnDelta.Hydrate()

				expectedDelta := mocktracer.MergeStateDeltas(expectedBasicAppCallDelta, expectedPayTxnDelta, scenario.ExpectedStateDelta)

				// If the scenario failed, we expect the failed txn ID to be removed from the group state delta
				if scenario.Outcome != mocktracer.ApprovalOutcome {
					delete(expectedDelta.Txids, txgroup[2].ID())
				}

				expectedEvents = append(expectedEvents, mocktracer.FlattenEvents([][]mocktracer.Event{
					{
						mocktracer.BeforeTxnGroup(3),
						mocktracer.BeforeTxn(protocol.ApplicationCallTx), // start basicAppCallTxn
						mocktracer.BeforeProgram(logic.ModeApp),
					},
					mocktracer.OpcodeEvents(3, false),
					{
						mocktracer.AfterProgram(logic.ModeApp, mocktracer.ProgramResultPass),
						mocktracer.AfterTxn(protocol.ApplicationCallTx, expectedBasicAppCallAD, false), // end basicAppCallTxn
						mocktracer.BeforeTxn(protocol.PaymentTx),                                       // start payTxn
						mocktracer.AfterTxn(protocol.PaymentTx, expectedPayTxnAD, false),               // end payTxn
					},
					scenario.ExpectedEvents,
					{
						mocktracer.AfterTxnGroup(3, &expectedDelta, scenario.Outcome != mocktracer.ApprovalOutcome),
						mocktracer.AfterBlock(eval.block.Round()),
					},
				})...)
			} else {
				// Removed failed txid from expected state delta
				delete(expectedBasicAppCallDelta.Txids, txgroup[0].Txn.ID())

				hasError := testCase.firstTxnBehavior == "error"
				expectedProgramResult := mocktracer.ProgramResultReject
				if hasError {
					expectedProgramResult = mocktracer.ProgramResultError
				}

				// EvalDeltas are removed from failed app call transactions
				expectedBasicAppCallAD.EvalDelta = transactions.EvalDelta{}
				expectedEvents = append(expectedEvents, mocktracer.FlattenEvents([][]mocktracer.Event{
					{
						mocktracer.BeforeTxnGroup(3),
						mocktracer.BeforeTxn(protocol.ApplicationCallTx), // start basicAppCallTxn
						mocktracer.BeforeProgram(logic.ModeApp),
					},
					mocktracer.OpcodeEvents(3, hasError),
					{
						mocktracer.AfterProgram(logic.ModeApp, expectedProgramResult),
						mocktracer.AfterTxn(protocol.ApplicationCallTx, expectedBasicAppCallAD, true), // end basicAppCallTxn
						mocktracer.AfterTxnGroup(3, &expectedBasicAppCallDelta, true),
					},
				})...)
			}
			actualEvents := mocktracer.StripInnerTxnGroupIDsFromEvents(tracer.Events)
			mocktracer.AssertEventsEqual(t, expectedEvents, actualEvents)
		})
	}
}

// BlockEvaluator.workaroundOverspentRewards() fixed a couple issues on testnet.
// This is now part of history and has to be re-created when running catchup on testnet. So, test to ensure it keeps happening.
func TestTestnetFixup(t *testing.T) {
	partitiontest.PartitionTest(t)

	eval := &BlockEvaluator{}
	var rewardPoolBalance ledgercore.AccountData
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

	rewardPoolBalance := ledgercore.ToAccountData(genesisInitState.Accounts[testPoolAddr])
	nextPoolBalance := rewardPoolBalance.MicroAlgos.Raw + poolBonus

	l := newTestLedger(t, bookkeeping.GenesisBalances{
		Balances:    genesisInitState.Accounts,
		FeeSink:     testSinkAddr,
		RewardsPool: testPoolAddr,
	})
	l.blocks[0] = genesisInitState.Block
	l.genesisHash = genesisInitState.GenesisHash

	newBlock := bookkeeping.MakeBlock(genesisInitState.Block.BlockHeader)
	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0, nil)
	require.NoError(t, err)

	// won't work before funding bank
	if poolBonus > 0 {
		_, err = eval.workaroundOverspentRewards(rewardPoolBalance, headerRound)
		require.ErrorContains(t, err, "unable to move funds from testnet bank")
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

type evalTestLedger struct {
	blocks              map[basics.Round]bookkeeping.Block
	roundBalances       map[basics.Round]map[basics.Address]basics.AccountData
	genesisHash         crypto.Digest
	genesisProto        config.ConsensusParams
	genesisProtoVersion protocol.ConsensusVersion
	feeSink             basics.Address
	rewardsPool         basics.Address
	latestTotals        ledgercore.AccountTotals
	tracer              logic.EvalTracer
	boxes               map[string][]byte
}

// newTestLedger creates a in memory Ledger that is as realistic as
// possible.  It has Rewards and FeeSink properly configured.
func newTestLedger(t testing.TB, balances bookkeeping.GenesisBalances) *evalTestLedger {
	l := &evalTestLedger{
		blocks:        make(map[basics.Round]bookkeeping.Block),
		roundBalances: make(map[basics.Round]map[basics.Address]basics.AccountData),
		feeSink:       balances.FeeSink,
		rewardsPool:   balances.RewardsPool,
		tracer:        nil,
		boxes:         make(map[string][]byte),
	}

	protoVersion := protocol.ConsensusFuture
	proto := config.Consensus[protoVersion]

	crypto.RandBytes(l.genesisHash[:])
	genBlock, err := bookkeeping.MakeGenesisBlock(protoVersion,
		balances, "test", l.genesisHash)
	require.NoError(t, err)
	l.roundBalances[0] = balances.Balances
	l.blocks[0] = genBlock

	// calculate the accounts totals.
	var ot basics.OverflowTracker
	for _, acctData := range balances.Balances {
		l.latestTotals.AddAccount(proto.RewardUnit, ledgercore.ToAccountData(acctData), &ot)
	}
	l.genesisProto = proto
	l.genesisProtoVersion = protoVersion

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

	delta, err := Eval(ctx, ledger, blk, true, verifiedTxnCache, executionPool, ledger.tracer)
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
func (ledger *evalTestLedger) StartEvaluator(hdr bookkeeping.BlockHeader, paysetHint, maxTxnBytesPerBlock int, tracer logic.EvalTracer) (*BlockEvaluator, error) {
	return StartEvaluator(ledger, hdr,
		EvaluatorOptions{
			PaysetHint:          paysetHint,
			Validate:            true,
			Generate:            true,
			MaxTxnBytesPerBlock: maxTxnBytesPerBlock,
			Tracer:              tracer,
		})
}

func (ledger *evalTestLedger) FlushCaches() {}

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

// LookupWithoutRewards is like Lookup but is not supposed to apply pending
// rewards up to the requested round rnd.  Here Lookup doesn't do that anyway.
func (ledger *evalTestLedger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, error) {
	ad, err := ledger.Lookup(rnd, addr)
	return ledgercore.ToAccountData(ad), rnd, err
}

func (ledger *evalTestLedger) LookupAgreement(rnd basics.Round, addr basics.Address) (basics.OnlineAccountData, error) {
	ad, _, err := ledger.LookupWithoutRewards(rnd, addr)
	return convertToOnline(ad), err
}

func (ledger *evalTestLedger) GetKnockOfflineCandidates(rnd basics.Round, _ config.ConsensusParams) (map[basics.Address]basics.OnlineAccountData, error) {
	// simulate by returning all online accounts known by the test ledger
	ret := make(map[basics.Address]basics.OnlineAccountData)
	for addr, data := range ledger.roundBalances[rnd] {
		if data.Status == basics.Online && !data.MicroAlgos.IsZero() {
			ret[addr] = basics_testing.OnlineAccountData(data)
		}
	}
	return ret, nil
}

// OnlineCirculation add up the balances of all online accounts in rnd. It
// doesn't remove expired accounts.
func (ledger *evalTestLedger) OnlineCirculation(rnd, voteRound basics.Round) (basics.MicroAlgos, error) {
	circulation := basics.MicroAlgos{}
	for _, data := range ledger.roundBalances[rnd] {
		if data.Status == basics.Online {
			circulation.Raw += data.MicroAlgos.Raw
		}
	}
	return circulation, nil
}

func (ledger *evalTestLedger) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	res := ledgercore.AppResource{}
	ad, ok := ledger.roundBalances[rnd][addr]
	if !ok {
		return res, fmt.Errorf("no such account %s while looking up app", addr.String())
	}
	if params, ok := ad.AppParams[aidx]; ok {
		res.AppParams = &params
	}
	if ls, ok := ad.AppLocalStates[aidx]; ok {
		res.AppLocalState = &ls
	}
	return res, nil
}

func (ledger *evalTestLedger) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	res := ledgercore.AssetResource{}
	ad, ok := ledger.roundBalances[rnd][addr]
	if !ok {
		return res, fmt.Errorf("no such account %s while looking up asset", addr.String())
	}
	if params, ok := ad.AssetParams[aidx]; ok {
		res.AssetParams = &params
	}
	if h, ok := ad.Assets[aidx]; ok {
		res.AssetHolding = &h
	}
	return res, nil
}

func (ledger *evalTestLedger) LookupKv(rnd basics.Round, key string) ([]byte, error) {
	// The test ledger only has one view of the value of a box--no rnd based retrieval is implemented currently
	val, _ := ledger.boxes[key]
	return val, nil
}

// GenesisHash returns the genesis hash for this ledger.
func (ledger *evalTestLedger) GenesisHash() crypto.Digest {
	return ledger.genesisHash
}

// GenesisProto returns the genesis consensus params for this ledger.
func (ledger *evalTestLedger) GenesisProto() config.ConsensusParams {
	return config.Consensus[ledger.genesisProtoVersion]
}

// GenesisProto returns the genesis consensus version for this ledger.
func (ledger *evalTestLedger) GenesisProtoVersion() protocol.ConsensusVersion {
	return ledger.genesisProtoVersion
}

// Latest returns the latest known block round added to the ledger.
func (ledger *evalTestLedger) Latest() basics.Round {
	return basics.Round(len(ledger.blocks)).SubSaturate(1)
}

func (ledger *evalTestLedger) GetStateProofVerificationContext(_ basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	return nil, errors.New("evalTestLedger does not implement GetStateProofVerificationContext")
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
	maps.Copy(newBalances, ledger.roundBalances[vb.Block().Round()-1])

	// update
	deltas := vb.Delta()
	// convert deltas into balance records
	// the code assumes all modified accounts has entries in NewAccts.accts
	// to enforce this fact we call ModifiedAccounts() with a panic as a side effect
	deltas.Accts.ModifiedAccounts()
	for i := 0; i < deltas.Accts.Len(); i++ {
		addr, _ := deltas.Accts.GetByIdx(i) // <-- this assumes resources deltas has addr in accts
		accountData, _ := deltas.Accts.GetBasicsAccountData(addr)
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

func (ledger *evalTestLedger) VotersForStateProof(rnd basics.Round) (*ledgercore.VotersForRound, error) {
	return nil, nil
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
				return &ledgercore.TransactionInLedgerError{Txid: txid, InBlockEvaluator: false}
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
	eval, err := ledger.StartEvaluator(nextHdr, 0, 0, nil)
	require.NoError(t, err)
	return eval
}

// endBlock completes the block being created, returns the ValidatedBlock for inspection
func (ledger *evalTestLedger) endBlock(t testing.TB, eval *BlockEvaluator, proposers ...basics.Address) *ledgercore.ValidatedBlock {
	unfinishedBlock, err := eval.GenerateBlock(proposers)
	require.NoError(t, err)
	// fake agreement's setting of header fields so later validates work.
	seed := committee.Seed{}
	crypto.RandBytes(seed[:])
	validatedBlock := ledgercore.MakeValidatedBlock(unfinishedBlock.UnfinishedBlock().WithProposer(seed, testPoolAddr, true), unfinishedBlock.UnfinishedDeltas())
	err = ledger.AddValidatedBlock(validatedBlock, agreement.Certificate{})
	require.NoError(t, err)
	return &validatedBlock
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

func (l *testCowBaseLedger) GenesisHash() crypto.Digest {
	panic("not implemented")
}

func (l *testCowBaseLedger) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error {
	return errors.New("not implemented")
}

func (l *testCowBaseLedger) LookupWithoutRewards(basics.Round, basics.Address) (ledgercore.AccountData, basics.Round, error) {
	return ledgercore.AccountData{}, basics.Round(0), errors.New("not implemented")
}

func (l *testCowBaseLedger) LookupAgreement(rnd basics.Round, addr basics.Address) (basics.OnlineAccountData, error) {
	return basics.OnlineAccountData{}, errors.New("not implemented")
}

func (l *testCowBaseLedger) GetKnockOfflineCandidates(basics.Round, config.ConsensusParams) (map[basics.Address]basics.OnlineAccountData, error) {
	return nil, errors.New("not implemented")
}

func (l *testCowBaseLedger) OnlineCirculation(rnd, voteRnd basics.Round) (basics.MicroAlgos, error) {
	return basics.MicroAlgos{}, errors.New("not implemented")
}

func (l *testCowBaseLedger) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	return ledgercore.AppResource{}, errors.New("not implemented")
}

func (l *testCowBaseLedger) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	return ledgercore.AssetResource{}, errors.New("not implemented")
}

func (l *testCowBaseLedger) LookupKv(rnd basics.Round, key string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (l *testCowBaseLedger) GetStateProofVerificationContext(_ basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	return nil, errors.New("testCowBaseLedger does not implement GetStateProofVerificationContext")
}

func (l *testCowBaseLedger) GetCreatorForRound(_ basics.Round, cindex basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	res := l.creators[0]
	l.creators = l.creators[1:]
	return res.address, res.exists, nil
}

func TestCowBaseCreatorsCache(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
		creators: map[creatable]foundAddress{},
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
	t.Parallel()

	genesisInitState, addrs, _ := ledgertesting.GenesisWithProto(10, protocol.ConsensusFuture)

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
		crypto.RandBytes(tmp.StateProofID[:])
		crypto.RandBytes(tmp.SelectionID[:])
		crypto.RandBytes(tmp.VoteID[:])
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

	blkEval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0, nil)
	require.NoError(t, err)

	// Advance the evaluator a couple rounds, watching for lack of expiration
	for i := uint64(0); i < uint64(targetRound); i++ {
		vb := l.endBlock(t, blkEval, recvAddr)
		blkEval = l.nextBlock(t)
		for _, acct := range vb.Block().ExpiredParticipationAccounts {
			if acct == recvAddr {
				// won't happen, because recvAddr was proposer
				require.Fail(t, "premature expiration")
			}
		}
	}

	require.Greater(t, uint64(blkEval.Round()), uint64(recvAddrLastValidRound))

	// Make sure we validate our block as well
	blkEval.validate = true

	unfinishedBlock, err := blkEval.GenerateBlock(nil)
	require.NoError(t, err)

	// fake agreement's setting of header fields so later validates work
	validatedBlock := ledgercore.MakeValidatedBlock(unfinishedBlock.UnfinishedBlock().WithProposer(committee.Seed{}, testPoolAddr, true), unfinishedBlock.UnfinishedDeltas())

	expired := false
	for _, acct := range validatedBlock.Block().ExpiredParticipationAccounts {
		if acct == recvAddr {
			expired = true
		}
	}
	require.True(t, expired)

	_, err = Eval(context.Background(), l, validatedBlock.Block(), false, nil, nil, l.tracer)
	require.NoError(t, err)

	acctData, _ := blkEval.state.lookup(recvAddr)

	require.Zero(t, acctData.StateProofID)
	require.Zero(t, acctData.SelectionID)
	require.Zero(t, acctData.VoteID)
	goodBlock := validatedBlock.Block()

	// First validate that it's fine if we dont touch it.
	_, err = Eval(context.Background(), l, goodBlock, true, verify.GetMockedCache(true), nil, l.tracer)
	require.NoError(t, err)

	// Introduce an unknown address to introduce an error
	badBlock := goodBlock
	badBlock.ExpiredParticipationAccounts = append(badBlock.ExpiredParticipationAccounts, basics.Address{1})

	_, err = Eval(context.Background(), l, badBlock, true, verify.GetMockedCache(true), nil, l.tracer)
	require.ErrorContains(t, err, "expiration candidate")

	// Add more than the expected number of accounts
	badBlock = goodBlock
	addressToCopy := badBlock.ExpiredParticipationAccounts[0]
	for i := 0; i < blkEval.proto.MaxProposedExpiredOnlineAccounts+1; i++ {
		badBlock.ExpiredParticipationAccounts = append(badBlock.ExpiredParticipationAccounts, addressToCopy)
	}

	_, err = Eval(context.Background(), l, badBlock, true, verify.GetMockedCache(true), nil, l.tracer)
	require.ErrorContains(t, err, "length of expired accounts")

	// Duplicate an address
	badBlock = goodBlock
	badBlock.ExpiredParticipationAccounts = append(badBlock.ExpiredParticipationAccounts, addressToCopy)

	_, err = Eval(context.Background(), l, badBlock, true, verify.GetMockedCache(true), nil, l.tracer)
	require.ErrorContains(t, err, "duplicate address found")

	badBlock = goodBlock
	// sanity check that bad block is being actually copied and not just the pointer
	_, err = Eval(context.Background(), l, badBlock, true, verify.GetMockedCache(true), nil, l.tracer)
	require.NoError(t, err)
}

type failRoundCowParent struct {
	roundCowBase
}

func (p *failRoundCowParent) lookup(basics.Address) (ledgercore.AccountData, error) {
	return ledgercore.AccountData{}, fmt.Errorf("disk I/O fail (on purpose)")
}

// TestExpiredAccountGenerationWithDiskErr tests edge cases where disk failures can lead to ledger look up failures
func TestExpiredAccountGenerationWithDiskErr(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genesisInitState, addrs, _ := ledgertesting.GenesisWithProto(10, protocol.ConsensusFuture)

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

	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0, nil)
	require.NoError(t, err)

	// Advance the evaluator a couple rounds...
	for i := uint64(0); i < uint64(targetRound); i++ {
		l.endBlock(t, eval)
		eval = l.nextBlock(t)
	}

	eval.validate = true
	eval.generate = false

	eval.block.ExpiredParticipationAccounts = append(eval.block.ExpiredParticipationAccounts, recvAddr)

	err = eval.endOfBlock()
	require.ErrorContains(t, err, "found expiration candidate")

	eval.block.ExpiredParticipationAccounts = []basics.Address{{}}
	eval.state.mods.Accts = ledgercore.AccountDeltas{}
	eval.state.lookupParent = &failRoundCowParent{}
	err = eval.endOfBlock()
	require.ErrorContains(t, err, "disk I/O fail (on purpose)")

	err = eval.resetExpiredOnlineAccountsParticipationKeys()
	require.ErrorContains(t, err, "disk I/O fail (on purpose)")
}

// TestAbsenteeChecks tests that the eval function will correctly mark accounts as absent
func TestAbsenteeChecks(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genesisInitState, addrs, keys := ledgertesting.GenesisWithProto(10, protocol.ConsensusFuture)

	// add 32 more addresses, we can get a suspension by challenge
	for i := 0; i < 32; i++ {
		addrs = append(addrs, basics.Address{byte(i << 3), 0xaa})
	}

	// Set all addrs to online
	for i, addr := range addrs {
		tmp := genesisInitState.Accounts[addr]
		tmp.Status = basics.Online
		crypto.RandBytes(tmp.StateProofID[:])
		crypto.RandBytes(tmp.SelectionID[:])
		crypto.RandBytes(tmp.VoteID[:])
		tmp.IncentiveEligible = true // make suspendable
		tmp.VoteFirstValid = 1
		tmp.VoteLastValid = 1500 // large enough to avoid EXPIRATION, so we can see SUSPENSION
		switch i {
		case 1:
			tmp.LastHeartbeat = 1 // we want addrs[1] to be suspended earlier than others
		case 2:
			tmp.LastProposed = 1 // we want addrs[2] to be suspended earlier than others
		case 3:
			tmp.LastProposed = 1 // we want addrs[3] to be a proposer, and never suspend itself
		case 5:
			tmp.LastHeartbeat = 1 // like addr[1] but !IncentiveEligible, no suspend
			tmp.IncentiveEligible = false
		case 6:
			tmp.LastProposed = 1 // like addr[2] but !IncentiveEligible, no suspend
			tmp.IncentiveEligible = false
		default:
			if i < 10 { // make 0,3,4,7,8,9 unsuspendable
				switch i % 3 {
				case 0:
					tmp.LastProposed = 1200
				case 1:
					tmp.LastHeartbeat = 1200
				case 2:
					tmp.IncentiveEligible = false
				}
			} else {
				// ensure non-zero balance for the new accounts, but a small
				// balance so they will not be absent, just challenged.
				tmp.MicroAlgos = basics.MicroAlgos{Raw: 1_000_000}
				tmp.LastHeartbeat = 1 // non-zero allows suspensions
			}
		}

		genesisInitState.Accounts[addr] = tmp
	}

	// pretend this node is participating on behalf of addrs[3] and addrs[4]
	proposers := []basics.Address{addrs[3], addrs[4]}

	l := newTestLedger(t, bookkeeping.GenesisBalances{
		Balances:    genesisInitState.Accounts,
		FeeSink:     testSinkAddr,
		RewardsPool: testPoolAddr,
	})

	newBlock := bookkeeping.MakeBlock(l.blocks[0].BlockHeader)

	blkEval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0, nil)
	require.NoError(t, err)

	// Advance the evaluator, watching for suspensions as they appear
	challenge := byte(0)
	for i := uint64(0); i < uint64(1200); i++ { // Just before first suspension at 1171
		vb := l.endBlock(t, blkEval, proposers...)
		blkEval = l.nextBlock(t)

		switch vb.Block().Round() {
		case 202: // 2 out of 10 genesis accounts are now absent
			require.Len(t, vb.Block().AbsentParticipationAccounts, 2, addrs)
			require.Contains(t, vb.Block().AbsentParticipationAccounts, addrs[1])
			require.Contains(t, vb.Block().AbsentParticipationAccounts, addrs[2])
		case 1000:
			challenge = vb.Block().BlockHeader.Seed[0]
		default:
			require.Zero(t, vb.Block().AbsentParticipationAccounts, "round %v", vb.Block().Round())
		}
	}
	challenged := basics.Address{(challenge >> 3) << 3, 0xaa}

	pay := func(i int, a basics.Address) transactions.Transaction {
		return transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      addrs[i],
				Fee:         minFee,
				LastValid:   blkEval.Round(),
				GenesisHash: l.GenesisHash(),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: a,
				Amount:   basics.MicroAlgos{Raw: 100_000},
			},
		}
	}

	selfpay := func(i int) transactions.SignedTxn {
		return pay(i, addrs[i]).Sign(keys[i])
	}

	require.NoError(t, blkEval.Transaction(selfpay(0), transactions.ApplyData{}))
	require.NoError(t, blkEval.Transaction(selfpay(1), transactions.ApplyData{}))
	require.NoError(t, blkEval.Transaction(selfpay(2), transactions.ApplyData{}))
	for i := 0; i < 32; i++ {
		require.NoError(t, blkEval.Transaction(pay(0, basics.Address{byte(i << 3), 0xaa}).Sign(keys[0]),
			transactions.ApplyData{}))
	}

	// Make sure we validate our block as well
	blkEval.validate = true

	unfinishedBlock, err := blkEval.GenerateBlock(proposers)
	require.NoError(t, err)

	// fake agreement's setting of header fields so later validates work
	validatedBlock := ledgercore.MakeValidatedBlock(unfinishedBlock.UnfinishedBlock().WithProposer(committee.Seed{}, testPoolAddr, true), unfinishedBlock.UnfinishedDeltas())

	require.Equal(t, basics.Round(1201), validatedBlock.Block().Round())
	require.Empty(t, validatedBlock.Block().ExpiredParticipationAccounts)

	// Of the 32 extra accounts, make sure only the one matching the challenge is suspended
	require.Len(t, validatedBlock.Block().AbsentParticipationAccounts, 1)
	require.Contains(t, validatedBlock.Block().AbsentParticipationAccounts, challenged, challenged.String())
	foundChallenged := false
	for i := byte(0); i < 32; i++ {
		if i == challenge>>3 {
			rnd := validatedBlock.Block().Round()
			ad := basics.Address{i << 3, 0xaa}
			t.Logf("extra account %d %s is challenged, balance rnd %d %d", i, ad,
				rnd, l.roundBalances[rnd][ad].MicroAlgos.Raw)
			require.Equal(t, basics.Address{i << 3, 0xaa}, challenged)
			foundChallenged = true
			continue
		}
		require.NotContains(t, validatedBlock.Block().AbsentParticipationAccounts, basics.Address{i << 3, 0xaa})
	}
	require.True(t, foundChallenged)

	_, err = Eval(context.Background(), l, validatedBlock.Block(), false, nil, nil, l.tracer)
	require.NoError(t, err)

	acctData, _ := blkEval.state.lookup(addrs[0])

	require.NotZero(t, acctData.StateProofID)
	require.NotZero(t, acctData.SelectionID)
	require.NotZero(t, acctData.VoteID)
	goodBlock := validatedBlock.Block()

	// First validate that it's fine if we dont touch it.
	_, err = Eval(context.Background(), l, goodBlock, true, verify.GetMockedCache(true), nil, l.tracer)
	require.NoError(t, err)

	// Introduce an address that shouldn't be suspended
	badBlock := goodBlock
	badBlock.AbsentParticipationAccounts = append(badBlock.AbsentParticipationAccounts, addrs[9])
	_, err = Eval(context.Background(), l, badBlock, true, verify.GetMockedCache(true), nil, l.tracer)
	require.ErrorContains(t, err, "not absent")

	// An account that isn't even online
	badBlock = goodBlock
	badBlock.AbsentParticipationAccounts = append(badBlock.AbsentParticipationAccounts, basics.Address{0x01})
	_, err = Eval(context.Background(), l, badBlock, true, verify.GetMockedCache(true), nil, l.tracer)
	require.ErrorContains(t, err, "not Online")

	// Add more than the expected number of accounts
	badBlock = goodBlock
	addressToCopy := badBlock.AbsentParticipationAccounts[0]
	for i := 0; i < blkEval.proto.MaxProposedExpiredOnlineAccounts+1; i++ {
		badBlock.AbsentParticipationAccounts = append(badBlock.AbsentParticipationAccounts, addressToCopy)
	}

	_, err = Eval(context.Background(), l, badBlock, true, verify.GetMockedCache(true), nil, l.tracer)
	require.ErrorContains(t, err, "length of absent accounts")

	// Duplicate an address
	badBlock = goodBlock
	badBlock.AbsentParticipationAccounts = append(badBlock.AbsentParticipationAccounts, addressToCopy)

	_, err = Eval(context.Background(), l, badBlock, true, verify.GetMockedCache(true), nil, l.tracer)
	require.ErrorContains(t, err, "duplicate address found")

	badBlock = goodBlock
	// sanity check that bad block is being actually copied and not just the pointer
	_, err = Eval(context.Background(), l, badBlock, true, verify.GetMockedCache(true), nil, l.tracer)
	require.NoError(t, err)
}

// TestExpiredAccountGeneration test that expired accounts are added to a block header and validated
func TestExpiredAccountGeneration(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genesisInitState, addrs, _ := ledgertesting.GenesisWithProto(10, protocol.ConsensusFuture)

	sendAddr := addrs[0]
	recvAddr := addrs[1]
	propAddr := addrs[2]
	otherPropAddr := addrs[3] // not expiring, but part of proposer addresses passed to GenerateBlock

	// pretend this node is participating on behalf of addrs[2] and addrs[3]
	proposers := []basics.Address{propAddr, otherPropAddr}

	// the last round that the recvAddr and propAddr are valid for
	testAddrLastValidRound := basics.Round(2)

	// the target round we want to advance the evaluator to
	targetRound := basics.Round(2)

	// Set all to online except the sending address
	for _, addr := range addrs {
		if addr == sendAddr {
			continue
		}
		tmp := genesisInitState.Accounts[addr]

		// make up online account data
		tmp.Status = basics.Online
		tmp.VoteFirstValid = basics.Round(1)
		tmp.VoteLastValid = basics.Round(100)
		tmp.VoteKeyDilution = 0x1234123412341234
		crypto.RandBytes(tmp.SelectionID[:])
		crypto.RandBytes(tmp.VoteID[:])
		crypto.RandBytes(tmp.StateProofID[:])

		genesisInitState.Accounts[addr] = tmp
	}

	// Choose recvAddr and propAddr to have a last valid round less than genesis block round
	for _, addr := range []basics.Address{recvAddr, propAddr} {
		tmp := genesisInitState.Accounts[addr]
		tmp.VoteLastValid = testAddrLastValidRound
		genesisInitState.Accounts[addr] = tmp
	}

	l := newTestLedger(t, bookkeeping.GenesisBalances{
		Balances:    genesisInitState.Accounts,
		FeeSink:     testSinkAddr,
		RewardsPool: testPoolAddr,
		Timestamp:   0,
	})

	newBlock := bookkeeping.MakeBlock(l.blocks[0].BlockHeader)

	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0, nil)
	require.NoError(t, err)

	// Advance the evaluator a couple rounds...
	for i := uint64(0); i < uint64(targetRound); i++ {
		vb := l.endBlock(t, eval)
		eval = l.nextBlock(t)
		require.Empty(t, vb.Block().ExpiredParticipationAccounts)
	}

	require.Greater(t, uint64(eval.Round()), uint64(testAddrLastValidRound))

	// Make sure we validate our block as well
	eval.validate = true

	// GenerateBlock will not mark its own proposer addresses as expired
	unfinishedBlock, err := eval.GenerateBlock(proposers)
	require.NoError(t, err)

	listOfExpiredAccounts := unfinishedBlock.UnfinishedBlock().ParticipationUpdates.ExpiredParticipationAccounts

	require.Len(t, listOfExpiredAccounts, 1)
	require.Equal(t, listOfExpiredAccounts[0], recvAddr)

	recvAcct, err := eval.state.lookup(recvAddr)
	require.NoError(t, err)
	require.Equal(t, basics.Offline, recvAcct.Status)
	require.Zero(t, recvAcct.VoteFirstValid)
	require.Zero(t, recvAcct.VoteLastValid)
	require.Zero(t, recvAcct.VoteKeyDilution)
	require.Zero(t, recvAcct.VoteID)
	require.Zero(t, recvAcct.SelectionID)
	require.Zero(t, recvAcct.StateProofID)

	// propAddr not marked expired
	propAcct, err := eval.state.lookup(propAddr)
	require.NoError(t, err)
	require.Equal(t, basics.Online, propAcct.Status)
	require.NotZero(t, propAcct.VoteFirstValid)
	require.NotZero(t, propAcct.VoteLastValid)
	require.NotZero(t, propAcct.VoteKeyDilution)
	require.NotZero(t, propAcct.VoteID)
	require.NotZero(t, propAcct.SelectionID)
	require.NotZero(t, propAcct.StateProofID)
}

func TestIsAbsent(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := assert.New(t)

	var absent = func(total uint64, acct uint64, last uint64, current uint64) bool {
		return isAbsent(basics.Algos(total), basics.Algos(acct), basics.Round(last), basics.Round(current))
	}
	a.False(absent(1000, 10, 5000, 6000)) // 1% of stake, absent for 1000 rounds
	a.False(absent(1000, 10, 5000, 7000)) // 1% of stake, absent for 2000 rounds
	a.True(absent(1000, 10, 5000, 7001))  // 2001
	a.True(absent(1000, 11, 5000, 7000))  // more acct stake drives percent down, makes it absent
	a.False(absent(1000, 9, 5000, 7001))  // less acct stake
	a.False(absent(1001, 10, 5000, 7001)) // more online stake
	// not absent if never seen
	a.False(absent(1000, 10, 0, 2001))
	a.True(absent(1000, 10, 1, 2002))
}
