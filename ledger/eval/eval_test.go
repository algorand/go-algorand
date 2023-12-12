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

package eval

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/data/bookkeeping"
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
	ad, _ := deltas.Accts.GetBasicsAccountData(addr)
	state := ad.AppParams[1001].GlobalState
	require.Equal(t, basics.TealValue{Type: basics.TealBytesType, Bytes: string(addr[:])}, state["caller"])
	require.Equal(t, basics.TealValue{Type: basics.TealBytesType, Bytes: string(addr[:])}, state["creator"])
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
		testCase := testCase
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
		l.latestTotals.AddAccount(proto, ledgercore.ToAccountData(acctData), &ot)
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

// LookupWithoutRewards is like Lookup but does not apply pending rewards up
// to the requested round rnd.
func (ledger *evalTestLedger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, error) {
	ad := ledger.roundBalances[rnd][addr]
	return ledgercore.ToAccountData(ad), rnd, nil
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
	for k, v := range ledger.roundBalances[vb.Block().Round()-1] {
		newBalances[k] = v
	}

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
		crypto.RandBytes(tmp.StateProofID[:])
		crypto.RandBytes(tmp.SelectionID[:])
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

	_, err = Eval(context.Background(), l, validatedBlock.Block(), false, nil, nil, l.tracer)
	require.NoError(t, err)

	acctData, _ := blkEval.state.lookup(recvAddr)

	require.Equal(t, merklesignature.Verifier{}.Commitment, acctData.StateProofID)
	require.Equal(t, crypto.VRFVerifier{}, acctData.SelectionID)

	badBlock := *validatedBlock

	// First validate that bad block is fine if we dont touch it...
	_, err = Eval(context.Background(), l, badBlock.Block(), true, verify.GetMockedCache(true), nil, l.tracer)
	require.NoError(t, err)

	badBlock = *validatedBlock

	// Introduce an unknown address to introduce an error
	badBlockObj := badBlock.Block()
	badBlockObj.ExpiredParticipationAccounts = append(badBlockObj.ExpiredParticipationAccounts, basics.Address{1})
	badBlock = ledgercore.MakeValidatedBlock(badBlockObj, badBlock.Delta())

	_, err = Eval(context.Background(), l, badBlock.Block(), true, verify.GetMockedCache(true), nil, l.tracer)
	require.Error(t, err)

	badBlock = *validatedBlock

	addressToCopy := badBlock.Block().ExpiredParticipationAccounts[0]

	// Add more than the expected number of accounts
	badBlockObj = badBlock.Block()
	for i := 0; i < blkEval.proto.MaxProposedExpiredOnlineAccounts+1; i++ {
		badBlockObj.ExpiredParticipationAccounts = append(badBlockObj.ExpiredParticipationAccounts, addressToCopy)
	}
	badBlock = ledgercore.MakeValidatedBlock(badBlockObj, badBlock.Delta())

	_, err = Eval(context.Background(), l, badBlock.Block(), true, verify.GetMockedCache(true), nil, l.tracer)
	require.Error(t, err)

	badBlock = *validatedBlock

	// Duplicate an address
	badBlockObj = badBlock.Block()
	badBlockObj.ExpiredParticipationAccounts = append(badBlockObj.ExpiredParticipationAccounts, badBlockObj.ExpiredParticipationAccounts[0])
	badBlock = ledgercore.MakeValidatedBlock(badBlockObj, badBlock.Delta())

	_, err = Eval(context.Background(), l, badBlock.Block(), true, verify.GetMockedCache(true), nil, l.tracer)
	require.Error(t, err)

	badBlock = *validatedBlock
	// sanity check that bad block is being actually copied and not just the pointer
	_, err = Eval(context.Background(), l, badBlock.Block(), true, verify.GetMockedCache(true), nil, l.tracer)
	require.NoError(t, err)

}

type failRoundCowParent struct {
	roundCowBase
}

func (p *failRoundCowParent) lookup(basics.Address) (ledgercore.AccountData, error) {
	return ledgercore.AccountData{}, fmt.Errorf("disk I/O fail (on purpose)")
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

	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0, nil)
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

	eval.block.ExpiredParticipationAccounts = []basics.Address{{}}
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
	require.Equal(t, basics.Offline, recvAcct.Status)
	require.Equal(t, basics.Round(0), recvAcct.VoteFirstValid)
	require.Equal(t, basics.Round(0), recvAcct.VoteLastValid)
	require.Equal(t, uint64(0), recvAcct.VoteKeyDilution)
	require.Equal(t, crypto.OneTimeSignatureVerifier{}, recvAcct.VoteID)
	require.Equal(t, crypto.VRFVerifier{}, recvAcct.SelectionID)
	require.Equal(t, merklesignature.Verifier{}.Commitment, recvAcct.StateProofID)
}
