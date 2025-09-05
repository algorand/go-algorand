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

package mocktracer

import (
	"encoding/hex"
	"fmt"
	"maps"
	"math"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

const programTemplate string = `#pragma version 6
pushbytes "a"
log

%s

itxn_begin
pushint 6 // appl
itxn_field TypeEnum
pushint 0 // NoOp
itxn_field OnCompletion
pushbytes %s
itxn_field ApprovalProgram
pushbytes 0x068101 // #pragma version 6; int 1;
itxn_field ClearStateProgram
itxn_submit

pushbytes "b"
log

%s

itxn_begin
pushint 1 // pay
itxn_field TypeEnum
pushint %d
itxn_field Amount
global CurrentApplicationAddress
itxn_field Receiver
itxn_next
pushint 1 // pay
itxn_field TypeEnum
pushint %d
itxn_field Amount
global CurrentApplicationAddress
itxn_field Receiver
itxn_submit

pushbytes "c"
log

%s`

func fillProgramTemplate(beforeInnersOps, innerApprovalProgram, betweenInnersOps string, innerPay1Amount, innerPay2Amount uint64, afterInnersOps string) string {
	return fmt.Sprintf(programTemplate, beforeInnersOps, innerApprovalProgram, betweenInnersOps, innerPay1Amount, innerPay2Amount, afterInnersOps)
}

// TestScenarioInfo holds arguments used to call a TestScenarioGenerator
type TestScenarioInfo struct {
	CallingTxn     transactions.Transaction
	SenderData     ledgercore.AccountData
	AppAccountData ledgercore.AccountData
	FeeSinkData    ledgercore.AccountData
	FeeSinkAddr    basics.Address
	MinFee         basics.MicroAlgos
	CreatedAppID   basics.AppIndex
	BlockHeader    bookkeeping.BlockHeader
	PrevTimestamp  int64
}

func expectedApplyDataAndStateDelta(info TestScenarioInfo, appCallProgram string, innerProgramBytes []byte) (transactions.ApplyData, ledgercore.StateDelta, ledgercore.StateDelta, ledgercore.StateDelta, ledgercore.StateDelta) {
	expectedInnerAppCall := txntest.Txn{
		Type:   protocol.ApplicationCallTx,
		Sender: info.CreatedAppID.Address(),
		ApprovalProgram: `#pragma version 6
pushbytes "x"
log
pushint 1`,
		ClearStateProgram: `#pragma version 6
pushint 1`,

		FirstValid: info.CallingTxn.FirstValid,
		LastValid:  info.CallingTxn.LastValid,
		Fee:        info.MinFee,
	}
	expectedInnerAppCallAD := transactions.ApplyData{
		ApplicationID: info.CreatedAppID + 1,
		EvalDelta: transactions.EvalDelta{
			GlobalDelta: basics.StateDelta{},
			LocalDeltas: map[uint64]basics.StateDelta{},
			Logs:        []string{"x"},
		},
	}
	expectedInnerPay1 := txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   info.CreatedAppID.Address(),
		Receiver: info.CreatedAppID.Address(),
		Amount:   1,

		FirstValid: info.CallingTxn.FirstValid,
		LastValid:  info.CallingTxn.LastValid,
		Fee:        info.MinFee,
	}
	expectedInnerPay1AD := transactions.ApplyData{}
	expectedInnerPay2 := txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   info.CreatedAppID.Address(),
		Receiver: info.CreatedAppID.Address(),
		Amount:   2,

		FirstValid: info.CallingTxn.FirstValid,
		LastValid:  info.CallingTxn.LastValid,
		Fee:        info.MinFee,
	}
	expectedInnerPay2AD := transactions.ApplyData{}

	expectedAD := transactions.ApplyData{
		ApplicationID: info.CreatedAppID,
		EvalDelta: transactions.EvalDelta{
			GlobalDelta: basics.StateDelta{},
			LocalDeltas: map[uint64]basics.StateDelta{},
			InnerTxns: []transactions.SignedTxnWithAD{
				{
					SignedTxn: expectedInnerAppCall.SignedTxn(),
					ApplyData: expectedInnerAppCallAD,
				},
				{
					SignedTxn: expectedInnerPay1.SignedTxn(),
					ApplyData: expectedInnerPay1AD,
				},
				{
					SignedTxn: expectedInnerPay2.SignedTxn(),
					ApplyData: expectedInnerPay2AD,
				},
			},
			Logs: []string{"a", "b", "c"},
		},
	}

	ops, err := logic.AssembleString(appCallProgram)
	if err != nil {
		panic(err)
	}

	expectedSenderData := info.SenderData
	expectedSenderData.MicroAlgos.Raw -= info.CallingTxn.Fee.Raw
	expectedSenderData.TotalAppParams++
	expectedFeeSinkData := info.FeeSinkData
	expectedFeeSinkData.MicroAlgos.Raw += info.CallingTxn.Fee.Raw

	expectedDeltaCallingTxn := ledgercore.StateDelta{
		Accts: ledgercore.AccountDeltas{
			Accts: []ledgercore.BalanceRecord{
				{
					Addr:        info.CallingTxn.Sender,
					AccountData: expectedSenderData,
				},
				{
					Addr:        info.FeeSinkAddr,
					AccountData: expectedFeeSinkData,
				},
			},
			AppResources: []ledgercore.AppResourceRecord{
				{
					Aidx: info.CreatedAppID,
					Addr: info.CallingTxn.Sender,
					Params: ledgercore.AppParamsDelta{
						Params: &basics.AppParams{
							ApprovalProgram:   ops.Program,
							ClearStateProgram: info.CallingTxn.ClearStateProgram,
							StateSchemas: basics.StateSchemas{
								LocalStateSchema:  info.CallingTxn.LocalStateSchema,
								GlobalStateSchema: info.CallingTxn.GlobalStateSchema,
							},
							ExtraProgramPages: info.CallingTxn.ExtraProgramPages,
						},
					},
				},
			},
		},
		Creatables: map[basics.CreatableIndex]ledgercore.ModifiedCreatable{
			basics.CreatableIndex(info.CreatedAppID): {
				Ctype:   basics.AppCreatable,
				Created: true,
				Creator: info.CallingTxn.Sender,
			},
		},
		Txids: map[transactions.Txid]ledgercore.IncludedTransactions{
			// Cannot call info.CallingTxn.ID() yet, since the txn and its group are not yet final. Instead,
			// use the Txid zero value as a placeholder. It's up to the caller to update this if they need it.
			{}: {
				LastValid: info.CallingTxn.LastValid,
				Intra:     0,
			},
		},
		Hdr:           &info.BlockHeader,
		PrevTimestamp: info.PrevTimestamp,
	}
	expectedDeltaCallingTxn.Hydrate()

	expectedAppAccountData := info.AppAccountData
	expectedAppAccountData.TotalAppParams++
	expectedAppAccountData.MicroAlgos.Raw -= info.MinFee.Raw
	expectedFeeSinkData.MicroAlgos.Raw += info.MinFee.Raw

	expectedDeltaInnerAppCall := ledgercore.StateDelta{
		Accts: ledgercore.AccountDeltas{
			Accts: []ledgercore.BalanceRecord{
				{
					Addr:        info.CreatedAppID.Address(),
					AccountData: expectedAppAccountData,
				},
				{
					Addr:        info.FeeSinkAddr,
					AccountData: expectedFeeSinkData,
				},
			},
			AppResources: []ledgercore.AppResourceRecord{
				{
					Aidx: info.CreatedAppID + 1,
					Addr: info.CreatedAppID.Address(),
					Params: ledgercore.AppParamsDelta{
						Params: &basics.AppParams{
							ApprovalProgram:   innerProgramBytes,
							ClearStateProgram: []byte{0x06, 0x81, 0x01}, // #pragma version 6; int 1;
						},
					},
				},
			},
		},
		Creatables: map[basics.CreatableIndex]ledgercore.ModifiedCreatable{
			basics.CreatableIndex(info.CreatedAppID + 1): {
				Ctype:   basics.AppCreatable,
				Created: true,
				Creator: info.CreatedAppID.Address(),
			},
		},
		Hdr:           &info.BlockHeader,
		PrevTimestamp: info.PrevTimestamp,
	}
	expectedDeltaInnerAppCall.Hydrate()

	expectedAppAccountData.MicroAlgos.Raw -= info.MinFee.Raw
	expectedFeeSinkData.MicroAlgos.Raw += info.MinFee.Raw

	expectedDeltaInnerPay1 := ledgercore.StateDelta{
		Accts: ledgercore.AccountDeltas{
			Accts: []ledgercore.BalanceRecord{
				{
					Addr:        info.CreatedAppID.Address(),
					AccountData: expectedAppAccountData,
				},
				{
					Addr:        info.FeeSinkAddr,
					AccountData: expectedFeeSinkData,
				},
			},
		},
		Hdr:           &info.BlockHeader,
		PrevTimestamp: info.PrevTimestamp,
	}
	expectedDeltaInnerPay1.Hydrate()

	expectedAppAccountData.MicroAlgos.Raw -= info.MinFee.Raw
	expectedFeeSinkData.MicroAlgos.Raw += info.MinFee.Raw

	expectedDeltaInnerPay2 := ledgercore.StateDelta{
		Accts: ledgercore.AccountDeltas{
			Accts: []ledgercore.BalanceRecord{
				{
					Addr:        info.CreatedAppID.Address(),
					AccountData: expectedAppAccountData,
				},
				{
					Addr:        info.FeeSinkAddr,
					AccountData: expectedFeeSinkData,
				},
			},
		},
		Hdr:           &info.BlockHeader,
		PrevTimestamp: info.PrevTimestamp,
	}
	expectedDeltaInnerPay2.Hydrate()

	return expectedAD, expectedDeltaCallingTxn, expectedDeltaInnerAppCall, expectedDeltaInnerPay1, expectedDeltaInnerPay2
}

// TestScenarioOutcome represents an outcome of a TestScenario
type TestScenarioOutcome int

const (
	// ApprovalOutcome indicates the scenario should approve the program
	ApprovalOutcome TestScenarioOutcome = iota
	// RejectionOutcome indicates the scenario should reject the program
	RejectionOutcome
	// ErrorOutcome indicates the scenario should error during the program
	ErrorOutcome
)

// TestScenario represents a testing scenario. See GetTestScenarios for more details.
type TestScenario struct {
	Outcome              TestScenarioOutcome
	Program              string
	ExpectedError        string
	FailedAt             []int
	ExpectedEvents       []Event
	ExpectedSimulationAD transactions.ApplyData
	ExpectedStateDelta   ledgercore.StateDelta
	AppBudgetAdded       int
	AppBudgetConsumed    int
	TxnAppBudgetConsumed []int
}

// TestScenarioGenerator is a function which instantiates a TestScenario
type TestScenarioGenerator func(info TestScenarioInfo) TestScenario

// GetTestScenarios returns scenarios for testing code that invokes a logic.EvalTracer. These
// scenarios are all app calls which invoke inner transactions under various failure conditions.
// The scenarios follow this format:
//
//  1. An app call transaction that spawns inners. They are:
//     a. A basic app call transaction
//     b. A payment transaction [grouped with c]
//     c. A payment transaction [grouped with b]
//
// The scenarios differ by where they fail when attempting to execute that app call. Failures are
// possible during each inner transaction, as well as before all inners, between the two inner
// groups, and after all inners. For app call failures, there are scenarios for both rejection and
// runtime errors, which should invoke tracer hooks slightly differently.
func GetTestScenarios() map[string]TestScenarioGenerator {
	successInnerProgramBytes := []byte{0x06, 0x80, 0x01, 0x78, 0xb0, 0x81, 0x01} // #pragma version 6; pushbytes "x"; log; pushint 1
	successInnerProgram := "0x" + hex.EncodeToString(successInnerProgramBytes)

	noFailureName := "none"
	noFailure := func(info TestScenarioInfo) TestScenario {
		program := fillProgramTemplate("", successInnerProgram, "", 1, 2, "pushint 1")
		expectedAD, expectedDeltaCallingTxn, expectedDeltaInnerAppCall, expectedDeltaInnerPay1, expectedDeltaInnerPay2 := expectedApplyDataAndStateDelta(info, program, successInnerProgramBytes)
		expectedDelta := MergeStateDeltas(expectedDeltaCallingTxn, expectedDeltaInnerAppCall, expectedDeltaInnerPay1, expectedDeltaInnerPay2)

		return TestScenario{
			Outcome:       ApprovalOutcome,
			Program:       program,
			FailedAt:      nil,
			ExpectedError: "", // no error
			ExpectedEvents: FlattenEvents([][]Event{
				{
					BeforeTxn(protocol.ApplicationCallTx),
					BeforeProgram(logic.ModeApp),
				},
				OpcodeEvents(11, false),
				{
					BeforeOpcode(),
					BeforeTxnGroup(1), // start first itxn group
					BeforeTxn(protocol.ApplicationCallTx),
					BeforeProgram(logic.ModeApp),
				},
				OpcodeEvents(3, false),
				{
					AfterProgram(logic.ModeApp, ProgramResultPass),
					AfterTxn(protocol.ApplicationCallTx, expectedAD.EvalDelta.InnerTxns[0].ApplyData, false),
					AfterTxnGroup(1, nil, false), // end first itxn group
					AfterOpcode(false),
				},
				OpcodeEvents(16, false),
				{
					BeforeOpcode(),
					BeforeTxnGroup(2), // start second itxn group
					BeforeTxn(protocol.PaymentTx),
					AfterTxn(protocol.PaymentTx, expectedAD.EvalDelta.InnerTxns[1].ApplyData, false),
					BeforeTxn(protocol.PaymentTx),
					AfterTxn(protocol.PaymentTx, expectedAD.EvalDelta.InnerTxns[2].ApplyData, false),
					AfterTxnGroup(2, nil, false), // end second itxn group
					AfterOpcode(false),
				},
				OpcodeEvents(3, false),
				{
					AfterProgram(logic.ModeApp, ProgramResultPass),
					AfterTxn(protocol.ApplicationCallTx, expectedAD, false),
				},
			}),
			ExpectedSimulationAD: expectedAD,
			ExpectedStateDelta:   expectedDelta,
			AppBudgetAdded:       2100,
			AppBudgetConsumed:    35,
			TxnAppBudgetConsumed: []int{0, 35},
		}
	}

	scenarios := map[string]TestScenarioGenerator{
		noFailureName: noFailure,
	}

	for _, shouldError := range []bool{true, false} {
		failureOps := "pushint 0\nreturn"
		singleFailureOp := "pushint 0"
		failureInnerProgramBytes := []byte{0x06, 0x80, 0x01, 0x78, 0xb0, 0x81, 0x00} // #pragma version 6; pushbytes "x"; log; pushint 0
		failureMessage := "transaction rejected by ApprovalProgram"
		outcome := RejectionOutcome
		programFailingResult := ProgramResultReject
		if shouldError {
			// We could use just the err opcode here, but we want to use two opcodes to maintain
			// trace event consistency with rejections.
			failureOps = "pushint 0\nerr"
			singleFailureOp = "err"
			failureInnerProgramBytes = []byte{0x06, 0x80, 0x01, 0x78, 0xb0, 0x00} // #pragma version 6; pushbytes "x"; log; err
			failureMessage = "err opcode executed"
			outcome = ErrorOutcome
			programFailingResult = ProgramResultError
		}
		failureInnerProgram := "0x" + hex.EncodeToString(failureInnerProgramBytes)

		beforeInnersName := fmt.Sprintf("before inners,error=%t", shouldError)
		beforeInners := func(info TestScenarioInfo) TestScenario {
			program := fillProgramTemplate(failureOps, successInnerProgram, "", 1, 2, "pushint 1")
			expectedAD, expectedDeltaCallingTxn, _, _, _ := expectedApplyDataAndStateDelta(info, program, successInnerProgramBytes)
			expectedDelta := expectedDeltaCallingTxn

			// remove failed txids from delta
			expectedDeltaCallingTxn.Txids = nil

			// EvalDeltas are removed from failed app call transactions
			expectedADNoED := expectedAD
			expectedADNoED.EvalDelta = transactions.EvalDelta{}
			// Only first log happens
			expectedAD.EvalDelta.Logs = expectedAD.EvalDelta.Logs[:1]
			expectedAD.EvalDelta.InnerTxns = nil
			return TestScenario{
				Outcome:       outcome,
				Program:       program,
				ExpectedError: failureMessage,
				FailedAt:      []int{0},
				ExpectedEvents: FlattenEvents([][]Event{
					{
						BeforeTxn(protocol.ApplicationCallTx),
						BeforeProgram(logic.ModeApp),
					},
					OpcodeEvents(4, shouldError),
					{
						AfterProgram(logic.ModeApp, programFailingResult),
						AfterTxn(protocol.ApplicationCallTx, expectedADNoED, true),
					},
				}),
				ExpectedSimulationAD: expectedAD,
				ExpectedStateDelta:   expectedDelta,
				AppBudgetAdded:       700,
				AppBudgetConsumed:    4,
				TxnAppBudgetConsumed: []int{0, 4},
			}
		}
		scenarios[beforeInnersName] = beforeInners

		firstInnerName := fmt.Sprintf("first inner,error=%t", shouldError)
		firstInner := func(info TestScenarioInfo) TestScenario {
			program := fillProgramTemplate("", failureInnerProgram, "", 1, 2, "pushint 1")
			expectedAD, expectedDeltaCallingTxn, _, _, _ := expectedApplyDataAndStateDelta(info, program, failureInnerProgramBytes)
			expectedDelta := expectedDeltaCallingTxn

			// remove failed txids from delta
			expectedDeltaCallingTxn.Txids = nil

			// EvalDeltas are removed from failed app call transactions
			expectedInnerAppCallADNoEvalDelta := expectedAD.EvalDelta.InnerTxns[0].ApplyData
			expectedInnerAppCallADNoEvalDelta.EvalDelta = transactions.EvalDelta{}
			expectedADNoED := expectedAD
			expectedADNoED.EvalDelta = transactions.EvalDelta{}

			// Only first log happens
			expectedAD.EvalDelta.Logs = expectedAD.EvalDelta.Logs[:1]

			expectedAD.EvalDelta.InnerTxns = expectedAD.EvalDelta.InnerTxns[:1]
			expectedAD.EvalDelta.InnerTxns[0].Txn.ApprovalProgram = failureInnerProgramBytes
			return TestScenario{
				Outcome:       outcome,
				Program:       program,
				ExpectedError: failureMessage,
				FailedAt:      []int{0, 0},
				ExpectedEvents: FlattenEvents([][]Event{
					{
						BeforeTxn(protocol.ApplicationCallTx),
						BeforeProgram(logic.ModeApp),
					},
					OpcodeEvents(11, false),
					{
						BeforeOpcode(),
						BeforeTxnGroup(1), // start first itxn group
						BeforeTxn(protocol.ApplicationCallTx),
						BeforeProgram(logic.ModeApp),
					},
					OpcodeEvents(3, shouldError),
					{
						AfterProgram(logic.ModeApp, programFailingResult),
						AfterTxn(protocol.ApplicationCallTx, expectedInnerAppCallADNoEvalDelta, true),
						AfterTxnGroup(1, nil, true), // end first itxn group
						AfterOpcode(true),
						AfterProgram(logic.ModeApp, ProgramResultError),
						AfterTxn(protocol.ApplicationCallTx, expectedADNoED, true),
					},
				}),
				ExpectedSimulationAD: expectedAD,
				ExpectedStateDelta:   expectedDelta,
				AppBudgetAdded:       1400,
				AppBudgetConsumed:    15,
				TxnAppBudgetConsumed: []int{0, 15},
			}
		}
		scenarios[firstInnerName] = firstInner

		betweenInnersName := fmt.Sprintf("between inners,error=%t", shouldError)
		betweenInners := func(info TestScenarioInfo) TestScenario {
			program := fillProgramTemplate("", successInnerProgram, failureOps, 1, 2, "pushint 1")
			expectedAD, expectedDeltaCallingTxn, _, _, _ := expectedApplyDataAndStateDelta(info, program, successInnerProgramBytes)
			expectedDelta := expectedDeltaCallingTxn

			// remove failed txids from delta
			expectedDeltaCallingTxn.Txids = nil

			expectedInnerAppCallAD := expectedAD.EvalDelta.InnerTxns[0].ApplyData

			// EvalDeltas are removed from failed app call transactions
			expectedADNoED := expectedAD
			expectedADNoED.EvalDelta = transactions.EvalDelta{}

			// Only first two logs happen
			expectedAD.EvalDelta.Logs = expectedAD.EvalDelta.Logs[:2]

			expectedAD.EvalDelta.InnerTxns = expectedAD.EvalDelta.InnerTxns[:1]
			return TestScenario{
				Outcome:       outcome,
				Program:       program,
				ExpectedError: failureMessage,
				FailedAt:      []int{0},
				ExpectedEvents: FlattenEvents([][]Event{
					{
						BeforeTxn(protocol.ApplicationCallTx),
						BeforeProgram(logic.ModeApp),
					},
					OpcodeEvents(11, false),
					{
						BeforeOpcode(),
						BeforeTxnGroup(1), // start first itxn group
						BeforeTxn(protocol.ApplicationCallTx),
						BeforeProgram(logic.ModeApp),
					},
					OpcodeEvents(3, false),
					{
						AfterProgram(logic.ModeApp, ProgramResultPass),
						AfterTxn(protocol.ApplicationCallTx, expectedInnerAppCallAD, false),
						AfterTxnGroup(1, nil, false), // end first itxn group
						AfterOpcode(false),
					},
					OpcodeEvents(4, shouldError),
					{
						AfterProgram(logic.ModeApp, programFailingResult),
						AfterTxn(protocol.ApplicationCallTx, expectedADNoED, true),
					},
				}),
				ExpectedSimulationAD: expectedAD,
				ExpectedStateDelta:   expectedDelta,
				AppBudgetAdded:       1400,
				AppBudgetConsumed:    19,
				TxnAppBudgetConsumed: []int{0, 19},
			}
		}
		scenarios[betweenInnersName] = betweenInners

		if shouldError {
			secondInnerName := "second inner"
			secondInner := func(info TestScenarioInfo) TestScenario {
				program := fillProgramTemplate("", successInnerProgram, "", math.MaxUint64, 2, "pushint 1")
				expectedAD, expectedDeltaCallingTxn, _, _, _ := expectedApplyDataAndStateDelta(info, program, successInnerProgramBytes)
				expectedDelta := expectedDeltaCallingTxn

				// remove failed txids from delta
				expectedDeltaCallingTxn.Txids = nil

				expectedInnerAppCallAD := expectedAD.EvalDelta.InnerTxns[0].ApplyData
				expectedInnerPay1AD := expectedAD.EvalDelta.InnerTxns[1].ApplyData

				// EvalDeltas are removed from failed app call transactions
				expectedADNoED := expectedAD
				expectedADNoED.EvalDelta = transactions.EvalDelta{}

				// Only first two logs happen
				expectedAD.EvalDelta.Logs = expectedAD.EvalDelta.Logs[:2]

				expectedAD.EvalDelta.InnerTxns[1].Txn.Amount.Raw = math.MaxUint64
				return TestScenario{
					Outcome:       ErrorOutcome,
					Program:       program,
					ExpectedError: "overspend",
					FailedAt:      []int{0, 1},
					ExpectedEvents: FlattenEvents([][]Event{
						{
							BeforeTxn(protocol.ApplicationCallTx),
							BeforeProgram(logic.ModeApp),
						},
						OpcodeEvents(11, false),
						{
							BeforeOpcode(),
							BeforeTxnGroup(1), // start first itxn group
							BeforeTxn(protocol.ApplicationCallTx),
							BeforeProgram(logic.ModeApp),
						},
						OpcodeEvents(3, false),
						{
							AfterProgram(logic.ModeApp, ProgramResultPass),
							AfterTxn(protocol.ApplicationCallTx, expectedInnerAppCallAD, false),
							AfterTxnGroup(1, nil, false), // end first itxn group
							AfterOpcode(false),
						},
						OpcodeEvents(16, false),
						{
							BeforeOpcode(),
							BeforeTxnGroup(2), // start second itxn group
							BeforeTxn(protocol.PaymentTx),
							AfterTxn(protocol.PaymentTx, expectedInnerPay1AD, true),
							AfterTxnGroup(2, nil, true), // end second itxn group
							AfterOpcode(true),
							AfterProgram(logic.ModeApp, ProgramResultError),
							AfterTxn(protocol.ApplicationCallTx, expectedADNoED, true),
						},
					}),
					ExpectedSimulationAD: expectedAD,
					ExpectedStateDelta:   expectedDelta,
					AppBudgetAdded:       2100,
					AppBudgetConsumed:    32,
					TxnAppBudgetConsumed: []int{0, 32},
				}
			}
			scenarios[secondInnerName] = secondInner

			thirdInnerName := "third inner"
			thirdInner := func(info TestScenarioInfo) TestScenario {
				program := fillProgramTemplate("", successInnerProgram, "", 1, math.MaxUint64, "pushint 1")
				expectedAD, expectedDeltaCallingTxn, _, _, _ := expectedApplyDataAndStateDelta(info, program, successInnerProgramBytes)
				expectedDelta := expectedDeltaCallingTxn

				// remove failed txids from delta
				expectedDeltaCallingTxn.Txids = nil

				expectedInnerAppCallAD := expectedAD.EvalDelta.InnerTxns[0].ApplyData
				expectedInnerPay1AD := expectedAD.EvalDelta.InnerTxns[1].ApplyData
				expectedInnerPay2AD := expectedAD.EvalDelta.InnerTxns[2].ApplyData

				// EvalDeltas are removed from failed app call transactions
				expectedADNoED := expectedAD
				expectedADNoED.EvalDelta = transactions.EvalDelta{}

				// Only first two logs happen
				expectedAD.EvalDelta.Logs = expectedAD.EvalDelta.Logs[:2]

				expectedAD.EvalDelta.InnerTxns[2].Txn.Amount.Raw = math.MaxUint64
				return TestScenario{
					Outcome:       ErrorOutcome,
					Program:       program,
					ExpectedError: "overspend",
					FailedAt:      []int{0, 2},
					ExpectedEvents: FlattenEvents([][]Event{
						{
							BeforeTxn(protocol.ApplicationCallTx),
							BeforeProgram(logic.ModeApp),
						},
						OpcodeEvents(11, false),
						{
							BeforeOpcode(),
							BeforeTxnGroup(1), // start first itxn group
							BeforeTxn(protocol.ApplicationCallTx),
							BeforeProgram(logic.ModeApp),
						},
						OpcodeEvents(3, false),
						{
							AfterProgram(logic.ModeApp, ProgramResultPass),
							AfterTxn(protocol.ApplicationCallTx, expectedInnerAppCallAD, false),
							AfterTxnGroup(1, nil, false), // end first itxn group
							AfterOpcode(false),
						},
						OpcodeEvents(16, false),
						{
							BeforeOpcode(),
							BeforeTxnGroup(2), // start second itxn group
							BeforeTxn(protocol.PaymentTx),
							AfterTxn(protocol.PaymentTx, expectedInnerPay1AD, false),
							BeforeTxn(protocol.PaymentTx),
							AfterTxn(protocol.PaymentTx, expectedInnerPay2AD, true),
							AfterTxnGroup(2, nil, true), // end second itxn group
							AfterOpcode(true),
							AfterProgram(logic.ModeApp, ProgramResultError),
							AfterTxn(protocol.ApplicationCallTx, expectedADNoED, true),
						},
					}),
					ExpectedSimulationAD: expectedAD,
					ExpectedStateDelta:   expectedDelta,
					AppBudgetAdded:       2100,
					AppBudgetConsumed:    32,
					TxnAppBudgetConsumed: []int{0, 32},
				}
			}
			scenarios[thirdInnerName] = thirdInner
		}

		afterInnersName := fmt.Sprintf("after inners,error=%t", shouldError)
		afterInners := func(info TestScenarioInfo) TestScenario {
			program := fillProgramTemplate("", successInnerProgram, "", 1, 2, singleFailureOp)
			expectedAD, expectedDeltaCallingTxn, _, _, _ := expectedApplyDataAndStateDelta(info, program, successInnerProgramBytes)
			expectedDelta := expectedDeltaCallingTxn

			// remove failed txids from delta
			expectedDeltaCallingTxn.Txids = nil

			expectedInnerAppCallAD := expectedAD.EvalDelta.InnerTxns[0].ApplyData
			expectedInnerPay1AD := expectedAD.EvalDelta.InnerTxns[1].ApplyData
			expectedInnerPay2AD := expectedAD.EvalDelta.InnerTxns[2].ApplyData
			// EvalDeltas are removed from failed app call transactions
			expectedADNoED := expectedAD
			expectedADNoED.EvalDelta = transactions.EvalDelta{}
			return TestScenario{
				Outcome:       outcome,
				Program:       program,
				ExpectedError: failureMessage,
				FailedAt:      []int{0},
				ExpectedEvents: FlattenEvents([][]Event{
					{
						BeforeTxn(protocol.ApplicationCallTx),
						BeforeProgram(logic.ModeApp),
					},
					OpcodeEvents(11, false),
					{
						BeforeOpcode(),
						BeforeTxnGroup(1), // start first itxn group
						BeforeTxn(protocol.ApplicationCallTx),
						BeforeProgram(logic.ModeApp),
					},
					OpcodeEvents(3, false),
					{
						AfterProgram(logic.ModeApp, ProgramResultPass),
						AfterTxn(protocol.ApplicationCallTx, expectedInnerAppCallAD, false),
						AfterTxnGroup(1, nil, false), // end first itxn group
						AfterOpcode(false),
					},
					OpcodeEvents(16, false),
					{
						BeforeOpcode(),
						BeforeTxnGroup(2), // start second itxn group
						BeforeTxn(protocol.PaymentTx),
						AfterTxn(protocol.PaymentTx, expectedInnerPay1AD, false),
						BeforeTxn(protocol.PaymentTx),
						AfterTxn(protocol.PaymentTx, expectedInnerPay2AD, false),
						AfterTxnGroup(2, nil, false), // end second itxn group
						AfterOpcode(false),
					},
					OpcodeEvents(3, shouldError),
					{
						AfterProgram(logic.ModeApp, programFailingResult),
						AfterTxn(protocol.ApplicationCallTx, expectedADNoED, true),
					},
				}),
				ExpectedSimulationAD: expectedAD,
				ExpectedStateDelta:   expectedDelta,
				AppBudgetAdded:       2100,
				AppBudgetConsumed:    35,
				TxnAppBudgetConsumed: []int{0, 35},
			}
		}
		scenarios[afterInnersName] = afterInners
	}

	return scenarios
}

func stripInnerTxnGroupIDs(ad *transactions.ApplyData) {
	for i := range ad.EvalDelta.InnerTxns {
		ad.EvalDelta.InnerTxns[i].Txn.Group = crypto.Digest{}
		stripInnerTxnGroupIDs(&ad.EvalDelta.InnerTxns[i].ApplyData)
	}
}

// StripInnerTxnGroupIDsFromEvents removes any inner transaction GroupIDs that are present in the
// TxnApplyData fields of the events.
func StripInnerTxnGroupIDsFromEvents(events []Event) []Event {
	for i := range events {
		stripInnerTxnGroupIDs(&events[i].TxnApplyData)
	}
	return events
}

// MergeStateDeltas merges multiple state deltas into one. The arguments are not modified, but the
// first delta is used to populate non-mergeable fields in the result.
func MergeStateDeltas(deltas ...ledgercore.StateDelta) ledgercore.StateDelta {
	if len(deltas) == 0 {
		return ledgercore.StateDelta{}
	}

	result := ledgercore.StateDelta{
		// copy basic fields from the first delta
		Hdr:            deltas[0].Hdr,
		StateProofNext: deltas[0].StateProofNext,
		PrevTimestamp:  deltas[0].PrevTimestamp,
		Totals:         deltas[0].Totals,

		// initialize structure for later use
		Txids: make(map[transactions.Txid]ledgercore.IncludedTransactions),
	}
	for _, delta := range deltas {
		result.Accts.MergeAccounts(delta.Accts)
		for key, delta := range delta.KvMods {
			result.AddKvMod(key, delta)
		}
		for id, delta := range delta.Creatables {
			result.AddCreatable(id, delta)
		}
		txidBase := uint64(len(result.Txids))
		for txid, includedTx := range delta.Txids {
			includedTx.Intra += txidBase
			result.Txids[txid] = includedTx
		}
		maps.Copy(result.Txleases, delta.Txleases)
	}
	return result
}
