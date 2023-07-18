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

package simulation_test

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/logic/mocktracer"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/simulation"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func uint64ToBytes(num uint64) []byte {
	ibytes := make([]byte, 8)
	binary.BigEndian.PutUint64(ibytes, num)
	return ibytes
}

type simulationTestCase struct {
	input         simulation.Request
	developerAPI  bool
	expected      simulation.Result
	expectedError string
}

func normalizeEvalDeltas(t *testing.T, actual, expected *transactions.EvalDelta) {
	t.Helper()
	for _, evalDelta := range []*transactions.EvalDelta{actual, expected} {
		// The difference between a nil contain and a 0-length one is not meaningful for these tests
		if len(evalDelta.GlobalDelta) == 0 {
			evalDelta.GlobalDelta = nil
		}
		if len(evalDelta.LocalDeltas) == 0 {
			evalDelta.LocalDeltas = nil
		}
	}
	// Use assert instead of require here so that we get a more useful error message later
	assert.Equal(t, len(expected.InnerTxns), len(actual.InnerTxns))
	for innerIndex := range expected.InnerTxns {
		if innerIndex == len(actual.InnerTxns) {
			break
		}
		expectedTxn := &expected.InnerTxns[innerIndex]
		actualTxn := &actual.InnerTxns[innerIndex]
		if expectedTxn.SignedTxn.Txn.Type == "" {
			// Use Type as a marker for whether the transaction was specified or not. If not
			// specified, replace it with the actual inner txn
			expectedTxn.SignedTxn = actualTxn.SignedTxn
		} else if expectedTxn.SignedTxn.Txn.Group.IsZero() {
			// Inner txn IDs are very difficult to calculate, so copy from actual
			expectedTxn.SignedTxn.Txn.Group = actualTxn.SignedTxn.Txn.Group
		}
		normalizeEvalDeltas(t, &actualTxn.EvalDelta, &expectedTxn.EvalDelta)
	}
}

func validateSimulationResult(t *testing.T, result simulation.Result) {
	t.Helper()

	for _, groupResult := range result.TxnGroups {
		if len(groupResult.FailureMessage) != 0 {
			// The only reason for no block is an eval error.
			assert.Nil(t, result.Block)
			return
		}
	}
	require.NotNil(t, result.Block)

	blockGroups, err := result.Block.Block().DecodePaysetGroups()
	require.NoError(t, err)

	if !assert.Equal(t, len(blockGroups), len(result.TxnGroups)) {
		return
	}

	for i, groupResult := range result.TxnGroups {
		if i == len(blockGroups) {
			break
		}
		blockGroup := blockGroups[i]

		if !assert.Equal(t, len(blockGroup), len(groupResult.Txns), "mismatched number of txns in group %d", i) {
			continue
		}

		for j, txnResult := range groupResult.Txns {
			blockTxn := blockGroup[j]
			assert.Equal(t, blockTxn.ApplyData, txnResult.Txn.ApplyData, "transaction %d of group %d has a simulation ApplyData that does not match what appears in a block", i, j)
		}
	}
}

func simulationTest(t *testing.T, f func(env simulationtesting.Environment) simulationTestCase) {
	t.Helper()
	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	testcase := f(env)

	actual, err := simulation.MakeSimulator(env.Ledger, testcase.developerAPI).Simulate(testcase.input)
	require.NoError(t, err)

	validateSimulationResult(t, actual)

	require.Len(t, testcase.expected.TxnGroups, len(testcase.input.TxnGroups), "Test case must expect the same number of transaction groups as its input")

	for i := range testcase.input.TxnGroups {
		for j := range testcase.input.TxnGroups[i] {
			if testcase.expected.TxnGroups[i].Txns[j].Txn.Txn.Type == "" {
				// Use Type as a marker for whether the transaction was specified or not. If not
				// specified, replace it with the input txn
				testcase.expected.TxnGroups[i].Txns[j].Txn.SignedTxn = testcase.input.TxnGroups[i][j]
			}
			normalizeEvalDeltas(t, &actual.TxnGroups[i].Txns[j].Txn.EvalDelta, &testcase.expected.TxnGroups[i].Txns[j].Txn.EvalDelta)
		}
	}

	if len(testcase.expectedError) != 0 {
		require.Contains(t, actual.TxnGroups[0].FailureMessage, testcase.expectedError)
		// if it matched the expected error, copy the actual one so it will pass the equality check below
		testcase.expected.TxnGroups[0].FailureMessage = actual.TxnGroups[0].FailureMessage
	}

	// Do not attempt to compare blocks
	actual.Block = nil
	require.Equal(t, testcase.expected, actual)
}

func TestPayTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("simple", func(t *testing.T) {
		t.Parallel()
		simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
			sender := env.Accounts[0]
			receiver := env.Accounts[1]

			txn := env.TxnInfo.NewTxn(txntest.Txn{
				Type:     protocol.PaymentTx,
				Sender:   sender.Addr,
				Receiver: receiver.Addr,
				Amount:   1_000_000,
			}).Txn().Sign(sender.Sk)

			return simulationTestCase{
				input: simulation.Request{
					TxnGroups: [][]transactions.SignedTxn{{txn}},
				},
				expected: simulation.Result{
					Version:   simulation.ResultLatestVersion,
					LastRound: env.TxnInfo.LatestRound(),
					TxnGroups: []simulation.TxnGroupResult{
						{
							Txns: []simulation.TxnResult{{}},
						},
					},
				},
			}
		})
	})

	t.Run("close to", func(t *testing.T) {
		t.Parallel()
		simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
			sender := env.Accounts[0]
			receiver := env.Accounts[1]
			closeTo := env.Accounts[2]
			amount := uint64(1_000_000)

			txn := env.TxnInfo.NewTxn(txntest.Txn{
				Type:             protocol.PaymentTx,
				Sender:           sender.Addr,
				Receiver:         receiver.Addr,
				Amount:           amount,
				CloseRemainderTo: closeTo.Addr,
			}).Txn().Sign(sender.Sk)

			expectedClosingAmount := sender.AcctData.MicroAlgos.Raw
			expectedClosingAmount -= amount + txn.Txn.Fee.Raw

			return simulationTestCase{
				input: simulation.Request{
					TxnGroups: [][]transactions.SignedTxn{{txn}},
				},
				expected: simulation.Result{
					Version:   simulation.ResultLatestVersion,
					LastRound: env.TxnInfo.LatestRound(),
					TxnGroups: []simulation.TxnGroupResult{
						{
							Txns: []simulation.TxnResult{
								{
									Txn: transactions.SignedTxnWithAD{
										ApplyData: transactions.ApplyData{
											ClosingAmount: basics.MicroAlgos{Raw: expectedClosingAmount},
										},
									},
								},
							},
						},
					},
				},
			}
		})
	})

	t.Run("overspend", func(t *testing.T) {
		t.Parallel()
		simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
			sender := env.Accounts[0]
			receiver := env.Accounts[1]
			amount := sender.AcctData.MicroAlgos.Raw + 100

			txn := env.TxnInfo.NewTxn(txntest.Txn{
				Type:     protocol.PaymentTx,
				Sender:   sender.Addr,
				Receiver: receiver.Addr,
				Amount:   amount,
			}).Txn().Sign(sender.Sk)

			return simulationTestCase{
				input: simulation.Request{
					TxnGroups: [][]transactions.SignedTxn{{txn}},
				},
				expectedError: fmt.Sprintf("tried to spend {%d}", amount),
				expected: simulation.Result{
					Version:   simulation.ResultLatestVersion,
					LastRound: env.TxnInfo.LatestRound(),
					TxnGroups: []simulation.TxnGroupResult{
						{
							Txns:     []simulation.TxnResult{{}},
							FailedAt: simulation.TxnPath{0},
						},
					},
				},
			}
		})
	})
}

func TestIllFormedStackRequest(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	sender := env.Accounts[0]
	futureAppID := basics.AppIndex(1001)

	createTxn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:          protocol.ApplicationCallTx,
		Sender:        sender.Addr,
		ApplicationID: 0,
		ApprovalProgram: `#pragma version 6
txn ApplicationID
bz create
byte "app call"
log
b end
create:
byte "app creation"
log
end:
int 1`,
		ClearStateProgram: `#pragma version 6
int 0`,
	})
	callTxn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:          protocol.ApplicationCallTx,
		Sender:        sender.Addr,
		ApplicationID: futureAppID,
	})

	txntest.Group(&createTxn, &callTxn)

	signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
	signedCallTxn := callTxn.Txn().Sign(sender.Sk)

	simRequest := simulation.Request{
		TxnGroups: [][]transactions.SignedTxn{
			{signedCreateTxn, signedCallTxn},
		},
		TraceConfig: simulation.ExecTraceConfig{
			Enable: false,
			Stack:  true,
		},
	}

	_, err := simulation.MakeSimulator(env.Ledger, true).Simulate(simRequest)
	require.ErrorAs(t, err, &simulation.InvalidRequestError{})
	require.ErrorContains(t, err, "basic trace must be enabled when enabling stack tracing")
}

func TestWrongAuthorizerTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	for _, optionalSigs := range []bool{false, true} {
		optionalSigs := optionalSigs
		t.Run(fmt.Sprintf("optionalSigs=%t", optionalSigs), func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
				sender := env.Accounts[0]
				authority := env.Accounts[1]

				txn := env.TxnInfo.NewTxn(txntest.Txn{
					Type:     protocol.PaymentTx,
					Sender:   sender.Addr,
					Receiver: sender.Addr,
					Amount:   0,
				}).Txn().Sign(authority.Sk)

				if optionalSigs {
					// erase signature
					txn.Sig = crypto.Signature{}
				}

				return simulationTestCase{
					input: simulation.Request{
						TxnGroups:            [][]transactions.SignedTxn{{txn}},
						AllowEmptySignatures: optionalSigs,
					},
					expectedError: fmt.Sprintf("should have been authorized by %s but was actually authorized by %s", sender.Addr, authority.Addr),
					expected: simulation.Result{
						Version:   simulation.ResultLatestVersion,
						LastRound: env.TxnInfo.LatestRound(),
						TxnGroups: []simulation.TxnGroupResult{
							{
								Txns:     []simulation.TxnResult{{}},
								FailedAt: simulation.TxnPath{0},
							},
						},
						EvalOverrides: simulation.ResultEvalOverrides{
							AllowEmptySignatures: optionalSigs,
						},
					},
				}
			})
		})
	}
}

func TestRekey(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]
		authority := env.Accounts[1]

		txn1 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: sender.Addr,
			Amount:   1,
			RekeyTo:  authority.Addr,
		})
		txn2 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: sender.Addr,
			Amount:   2,
		})

		txntest.Group(&txn1, &txn2)

		stxn1 := txn1.Txn().Sign(sender.Sk)
		stxn2 := txn2.Txn().Sign(authority.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{stxn1, stxn2},
				},
			},
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{},
							{},
						},
					},
				},
			},
		}
	})
}

func TestStateProofTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()
	s := simulation.MakeSimulator(env.Ledger, false)

	txgroup := []transactions.SignedTxn{
		env.TxnInfo.NewTxn(txntest.Txn{
			Type: protocol.StateProofTx,
			// No need to fill out StateProofTxnFields, this should fail at signature verification
		}).SignedTxn(),
	}

	_, err := s.Simulate(simulation.Request{TxnGroups: [][]transactions.SignedTxn{txgroup}})
	require.ErrorContains(t, err, "cannot simulate StateProof transactions")
}

func TestSimpleGroupTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()
	s := simulation.MakeSimulator(env.Ledger, false)
	sender1 := env.Accounts[0]
	sender1Balance := env.Accounts[0].AcctData.MicroAlgos
	sender2 := env.Accounts[1]
	sender2Balance := env.Accounts[1].AcctData.MicroAlgos

	// Send money back and forth
	txn1 := env.TxnInfo.NewTxn(txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   sender1.Addr,
		Receiver: sender2.Addr,
		Amount:   1_000_000,
	})
	txn2 := env.TxnInfo.NewTxn(txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   sender2.Addr,
		Receiver: sender1.Addr,
		Amount:   0,
	})

	request := simulation.Request{
		TxnGroups: [][]transactions.SignedTxn{
			{
				txn1.Txn().Sign(sender1.Sk),
				txn2.Txn().Sign(sender2.Sk),
			},
		},
	}

	// Should fail if there is no group parameter
	result, err := s.Simulate(request)
	require.NoError(t, err)
	require.Len(t, result.TxnGroups, 1)
	require.Len(t, result.TxnGroups[0].Txns, 2)
	require.Contains(t, result.TxnGroups[0].FailureMessage, "had zero Group but was submitted in a group of 2")

	// Add group parameter and sign again
	txntest.Group(&txn1, &txn2)
	request.TxnGroups = [][]transactions.SignedTxn{
		{
			txn1.Txn().Sign(sender1.Sk),
			txn2.Txn().Sign(sender2.Sk),
		},
	}

	// Check balances before transaction
	sender1Data, _, err := env.Ledger.LookupWithoutRewards(env.Ledger.Latest(), sender1.Addr)
	require.NoError(t, err)
	require.Equal(t, sender1Balance, sender1Data.MicroAlgos)

	sender2Data, _, err := env.Ledger.LookupWithoutRewards(env.Ledger.Latest(), sender2.Addr)
	require.NoError(t, err)
	require.Equal(t, sender2Balance, sender2Data.MicroAlgos)

	// Should now pass
	result, err = s.Simulate(request)
	require.NoError(t, err)
	require.Len(t, result.TxnGroups, 1)
	require.Len(t, result.TxnGroups[0].Txns, 2)
	require.Zero(t, result.TxnGroups[0].FailureMessage)

	// Confirm balances have not changed
	sender1Data, _, err = env.Ledger.LookupWithoutRewards(env.Ledger.Latest(), sender1.Addr)
	require.NoError(t, err)
	require.Equal(t, sender1Balance, sender1Data.MicroAlgos)

	sender2Data, _, err = env.Ledger.LookupWithoutRewards(env.Ledger.Latest(), sender2.Addr)
	require.NoError(t, err)
	require.Equal(t, sender2Balance, sender2Data.MicroAlgos)
}

func TestLogicSig(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	op, err := logic.AssembleString(`#pragma version 8
arg 0
btoi`)
	require.NoError(t, err)
	program := logic.Program(op.Program)
	lsigAddr := basics.Address(crypto.HashObj(&program))

	testCases := []struct {
		name          string
		arguments     [][]byte
		expectedError string
		cost          uint64
	}{
		{
			name:          "approval",
			arguments:     [][]byte{{1}},
			expectedError: "", // no error
			cost:          2,
		},
		{
			name:          "rejection",
			arguments:     [][]byte{{0}},
			expectedError: "rejected by logic",
			cost:          2,
		},
		{
			name:          "error",
			arguments:     [][]byte{},
			expectedError: "rejected by logic err=cannot load arg[0] of 0",
			cost:          1,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
				sender := env.Accounts[0]

				payTxn := env.TxnInfo.NewTxn(txntest.Txn{
					Type:     protocol.PaymentTx,
					Sender:   sender.Addr,
					Receiver: lsigAddr,
					Amount:   1_000_000,
				})
				appCallTxn := env.TxnInfo.NewTxn(txntest.Txn{
					Type:   protocol.ApplicationCallTx,
					Sender: lsigAddr,
					ApprovalProgram: `#pragma version 8
byte "hello"
log
int 1`,
					ClearStateProgram: `#pragma version 8
int 1`,
				})

				txntest.Group(&payTxn, &appCallTxn)

				signedPayTxn := payTxn.Txn().Sign(sender.Sk)
				signedAppCallTxn := appCallTxn.SignedTxn()
				signedAppCallTxn.Lsig = transactions.LogicSig{
					Logic: program,
					Args:  testCase.arguments,
				}

				expectedSuccess := len(testCase.expectedError) == 0
				var expectedAppCallAD transactions.ApplyData
				expectedFailedAt := simulation.TxnPath{1}
				var AppBudgetConsumed, AppBudgetAdded uint64
				if expectedSuccess {
					expectedAppCallAD = transactions.ApplyData{
						ApplicationID: 1002,
						EvalDelta: transactions.EvalDelta{
							Logs: []string{"hello"},
						},
					}
					expectedFailedAt = nil
					AppBudgetConsumed = 3
					AppBudgetAdded = 700
				}

				return simulationTestCase{
					input: simulation.Request{
						TxnGroups: [][]transactions.SignedTxn{
							{signedPayTxn, signedAppCallTxn},
						},
					},
					expectedError: testCase.expectedError,
					expected: simulation.Result{
						Version:   simulation.ResultLatestVersion,
						LastRound: env.TxnInfo.LatestRound(),
						TxnGroups: []simulation.TxnGroupResult{
							{
								Txns: []simulation.TxnResult{
									{},
									{
										Txn: transactions.SignedTxnWithAD{
											ApplyData: expectedAppCallAD,
										},
										AppBudgetConsumed:      AppBudgetConsumed,
										LogicSigBudgetConsumed: testCase.cost,
									},
								},
								FailedAt:          expectedFailedAt,
								AppBudgetAdded:    AppBudgetAdded,
								AppBudgetConsumed: AppBudgetConsumed,
							},
						},
					},
				}
			})
		})
	}
}

func TestSimpleAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		// Create program and call it
		futureAppID := basics.AppIndex(1001)
		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: 0,
			ApprovalProgram: `#pragma version 6
txn ApplicationID
bz create
byte "app call"
log
b end
create:
byte "app creation"
log
end:
int 1
`,
			ClearStateProgram: `#pragma version 6
int 0
`,
		})
		callTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: futureAppID,
		})

		txntest.Group(&createTxn, &callTxn)

		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
		signedCallTxn := callTxn.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedCreateTxn, signedCallTxn},
				},
			},
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
										EvalDelta: transactions.EvalDelta{
											Logs: []string{"app creation"},
										},
									},
								},
								AppBudgetConsumed: 5,
							},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										EvalDelta: transactions.EvalDelta{
											Logs: []string{"app call"},
										},
									},
								},
								AppBudgetConsumed: 6,
							},
						},
						AppBudgetAdded:    1400,
						AppBudgetConsumed: 11,
					},
				},
			},
		}
	})
}

func TestRejectAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		futureAppID := basics.AppIndex(1001)
		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: 0,
			ApprovalProgram: `#pragma version 6
byte "app creation"
log
int 0
			`,
			ClearStateProgram: `#pragma version 6
int 0
`,
		})
		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{{signedCreateTxn}},
			},
			expectedError: "transaction rejected by ApprovalProgram",
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
										EvalDelta: transactions.EvalDelta{
											Logs: []string{"app creation"},
										},
									},
								},
								AppBudgetConsumed: 3,
							},
						},
						FailedAt:          simulation.TxnPath{0},
						AppBudgetAdded:    700,
						AppBudgetConsumed: 3,
					},
				},
			},
		}
	})
}

func TestErrorAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		futureAppID := basics.AppIndex(1001)
		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: 0,
			ApprovalProgram: `#pragma version 6
byte "app creation"
log
err
			`,
			ClearStateProgram: `#pragma version 6
int 0
`,
		})
		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{{signedCreateTxn}},
			},
			expectedError: "err opcode executed",
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
										EvalDelta: transactions.EvalDelta{
											Logs: []string{"app creation"},
										},
									},
								},
								AppBudgetConsumed: 3,
							},
						},
						FailedAt:          simulation.TxnPath{0},
						AppBudgetAdded:    700,
						AppBudgetConsumed: 3,
					},
				},
			},
		}
	})
}

func TestAppCallOverBudget(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Transaction group has a cost of 4 + 1398
	expensiveAppSource := `#pragma version 6
	txn ApplicationID      // [appId]
	bz end                 // []
` + strings.Repeat(`int 1
	pop
`, 697) + `end:
	int 1`

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		futureAppID := basics.AppIndex(1001)
		// App create with cost 4
		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationID:   0,
			ApprovalProgram: expensiveAppSource,
			ClearStateProgram: `#pragma version 6
int 0
`,
		})
		// App call with cost 1398 - will cause a budget exceeded error,
		// but will only report a cost up to 1396.
		expensiveTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: futureAppID,
		})

		txntest.Group(&createTxn, &expensiveTxn)

		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
		signedExpensiveTxn := expensiveTxn.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedCreateTxn, signedExpensiveTxn},
				},
			},
			expectedError: "dynamic cost budget exceeded",
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
									},
								},
								AppBudgetConsumed: 4,
							},
							{
								AppBudgetConsumed: 1396,
							},
						},
						FailedAt:          simulation.TxnPath{1},
						AppBudgetAdded:    1400,
						AppBudgetConsumed: 1400,
					},
				},
			},
		}
	})
}

func TestAppCallWithExtraBudget(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Transaction group has a cost of 4 + 1404
	expensiveAppSource := `#pragma version 6
	txn ApplicationID      // [appId]
	bz end                 // []
` + strings.Repeat(`int 1; pop;`, 700) + `end:
	int 1`

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		futureAppID := basics.AppIndex(1001)
		// App create with cost 4
		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:              protocol.ApplicationCallTx,
			Sender:            sender.Addr,
			ApplicationID:     0,
			ApprovalProgram:   expensiveAppSource,
			ClearStateProgram: "#pragma version 6\nint 0",
		})
		// Expensive 700 repetition of int 1 and pop total cost 1404
		expensiveTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: futureAppID,
		})

		txntest.Group(&createTxn, &expensiveTxn)

		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
		signedExpensiveTxn := expensiveTxn.Txn().Sign(sender.Sk)
		extraOpcodeBudget := uint64(100)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedCreateTxn, signedExpensiveTxn},
				},
				ExtraOpcodeBudget: extraOpcodeBudget,
			},
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
									},
								},
								AppBudgetConsumed: 4,
							},
							{
								AppBudgetConsumed: 1404,
							},
						},
						AppBudgetAdded:    1500,
						AppBudgetConsumed: 1408,
					},
				},
				EvalOverrides: simulation.ResultEvalOverrides{ExtraOpcodeBudget: extraOpcodeBudget},
			},
		}
	})
}

func TestAppCallWithExtraBudgetReturningPC(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Transaction group has a cost of 4 + 1404
	expensiveAppSource := `#pragma version 6
	txn ApplicationID      // [appId]
	bz end                 // []
` + strings.Repeat(`int 1; pop;`, 700) + `end:
	int 1`

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		futureAppID := basics.AppIndex(1001)
		// App create with cost 4
		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:              protocol.ApplicationCallTx,
			Sender:            sender.Addr,
			ApplicationID:     0,
			ApprovalProgram:   expensiveAppSource,
			ClearStateProgram: "#pragma version 6\nint 1",
		})
		// Expensive 700 repetition of int 1 and pop total cost 1404
		expensiveTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: futureAppID,
		})

		txntest.Group(&createTxn, &expensiveTxn)

		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
		signedExpensiveTxn := expensiveTxn.Txn().Sign(sender.Sk)
		extraOpcodeBudget := uint64(100)

		commonLeadingSteps := []simulation.OpcodeTraceUnit{
			{PC: 1}, {PC: 4}, {PC: 6},
		}

		// Get the first trace
		firstTrace := make([]simulation.OpcodeTraceUnit, len(commonLeadingSteps))
		copy(firstTrace, commonLeadingSteps[:])
		firstTrace = append(firstTrace, simulation.OpcodeTraceUnit{PC: 1409})

		// Get the second trace
		secondTrace := make([]simulation.OpcodeTraceUnit, len(commonLeadingSteps))
		copy(secondTrace, commonLeadingSteps[:])
		for i := 9; i <= 1409; i++ {
			secondTrace = append(secondTrace, simulation.OpcodeTraceUnit{PC: uint64(i)})
		}

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedCreateTxn, signedExpensiveTxn},
				},
				ExtraOpcodeBudget: extraOpcodeBudget,
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
				},
			},
			developerAPI: true,
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
									},
								},
								AppBudgetConsumed: 4,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: firstTrace,
								},
							},
							{
								AppBudgetConsumed: 1404,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: secondTrace,
								},
							},
						},
						AppBudgetAdded:    1500,
						AppBudgetConsumed: 1408,
					},
				},
				EvalOverrides: simulation.ResultEvalOverrides{ExtraOpcodeBudget: extraOpcodeBudget},
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
				},
			},
		}
	})
}

func TestAppCallWithExtraBudgetOverBudget(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Transaction group has a cost of 4 + 1404
	expensiveAppSource := `#pragma version 6
	txn ApplicationID      // [appId]
	bz end                 // []
` + strings.Repeat(`int 1; pop;`, 700) + `end:
	int 1`

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		futureAppID := basics.AppIndex(1001)
		// App create with cost 4
		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:              protocol.ApplicationCallTx,
			Sender:            sender.Addr,
			ApplicationID:     0,
			ApprovalProgram:   expensiveAppSource,
			ClearStateProgram: "#pragma version 6\nint 0",
		})
		// Expensive 700 repetition of int 1 and pop total cost 1404
		expensiveTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: futureAppID,
		})

		txntest.Group(&createTxn, &expensiveTxn)

		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
		signedExpensiveTxn := expensiveTxn.Txn().Sign(sender.Sk)
		// Add a small bit of extra budget, but not enough
		extraBudget := uint64(5)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedCreateTxn, signedExpensiveTxn},
				},
				ExtraOpcodeBudget: extraBudget,
			},
			expectedError: "dynamic cost budget exceeded",
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
									},
								},
								AppBudgetConsumed: 4,
							},
							{
								AppBudgetConsumed: 1401,
							},
						},
						FailedAt:          simulation.TxnPath{1},
						AppBudgetAdded:    1405,
						AppBudgetConsumed: 1405,
					},
				},
				EvalOverrides: simulation.ResultEvalOverrides{ExtraOpcodeBudget: extraBudget},
			},
		}
	})
}

func TestAppCallWithExtraBudgetExceedsInternalLimit(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Transaction group has a cost of 4 + 1404
	expensiveAppSource := `#pragma version 6
	txn ApplicationID      // [appId]
	bz end                 // []
` + strings.Repeat(`int 1; pop;`, 700) + `end:
	int 1`

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()
	s := simulation.MakeSimulator(env.Ledger, false)

	sender := env.Accounts[0]

	futureAppID := basics.AppIndex(1001)
	// App create with cost 4
	createTxn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:              protocol.ApplicationCallTx,
		Sender:            sender.Addr,
		ApplicationID:     0,
		ApprovalProgram:   expensiveAppSource,
		ClearStateProgram: "#pragma version 6\nint 0",
	})
	// Expensive 700 repetition of int 1 and pop total cost 1404
	expensiveTxn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:          protocol.ApplicationCallTx,
		Sender:        sender.Addr,
		ApplicationID: futureAppID,
	})

	txntest.Group(&createTxn, &expensiveTxn)

	signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
	signedExpensiveTxn := expensiveTxn.Txn().Sign(sender.Sk)

	// Add an extra budget that is exceeding simulation.MaxExtraOpcodeBudget
	extraBudget := simulation.MaxExtraOpcodeBudget + 1

	// should error on too high extra budgets
	_, err := s.Simulate(
		simulation.Request{
			TxnGroups:         [][]transactions.SignedTxn{{signedCreateTxn, signedExpensiveTxn}},
			ExtraOpcodeBudget: extraBudget,
		})
	require.ErrorAs(t, err, &simulation.InvalidRequestError{})
	require.ErrorContains(t, err, "extra budget 320001 > simulation extra budget limit 320000")
}

func TestLogicSigOverBudget(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	op, err := logic.AssembleString(`#pragma version 6
` + strings.Repeat(`byte "a"
keccak256
pop
`, 200) + `int 1`)
	require.NoError(t, err)
	program := logic.Program(op.Program)
	lsigAddr := basics.Address(crypto.HashObj(&program))

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		payTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: lsigAddr,
			Amount:   1_000_000,
		})
		appCallTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:   protocol.ApplicationCallTx,
			Sender: lsigAddr,
			ApprovalProgram: `#pragma version 8
byte "hello"
log
int 1`,
			ClearStateProgram: `#pragma version 8
int 1`,
		})

		txntest.Group(&payTxn, &appCallTxn)

		signedPayTxn := payTxn.Txn().Sign(sender.Sk)
		signedAppCallTxn := appCallTxn.SignedTxn()
		signedAppCallTxn.Lsig = transactions.LogicSig{
			Logic: program,
		}

		var expectedAppCallAD transactions.ApplyData
		expectedFailedAt := simulation.TxnPath{1}

		// Opcode cost exceeded, but report current cost of LogicSig before it went over the limit.
		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedPayTxn, signedAppCallTxn},
				},
			},
			expectedError: "dynamic cost budget exceeded",
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: expectedAppCallAD,
								},
								AppBudgetConsumed:      0,
								LogicSigBudgetConsumed: 19934,
							},
						},
						FailedAt:          expectedFailedAt,
						AppBudgetAdded:    0,
						AppBudgetConsumed: 0,
					},
				},
			},
		}
	})
}

func TestAppAtBudget(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Transaction has a cost of 700 and invokes an inner transaction
	exactly700AndCallInner := fmt.Sprintf(`#pragma version 6
pushint 1
cover 0 // This is a noop, just to fix an odd number of ops
%s
itxn_begin
int appl
itxn_field TypeEnum
byte 0x068101
dup
itxn_field ClearStateProgram
itxn_field ApprovalProgram
itxn_submit
`, strings.Repeat(`pushint 1
pop
`, 345))

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		futureAppID := basics.AppIndex(1002)
		// fund outer app
		fund := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: futureAppID.Address(),
			Amount:   401_000,
		})
		// create app
		appCall := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApprovalProgram: exactly700AndCallInner,
			ClearStateProgram: `#pragma version 6
int 1`,
		})

		txntest.Group(&fund, &appCall)

		signedFundTxn := fund.Txn().Sign(sender.Sk)
		signedAppCall := appCall.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedFundTxn, signedAppCall},
				},
			},
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
										EvalDelta: transactions.EvalDelta{
											InnerTxns: []transactions.SignedTxnWithAD{
												{
													ApplyData: transactions.ApplyData{
														ApplicationID: futureAppID + 1,
													},
												},
											},
										},
									},
								},
								AppBudgetConsumed: 701,
							},
						},
						AppBudgetAdded:    1400,
						AppBudgetConsumed: 701,
					},
				},
			},
		}
	})
}

// TestDefaultSignatureCheck tests signature checking when SignaturesOption is NOT enabled.
func TestDefaultSignatureCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()
	s := simulation.MakeSimulator(env.Ledger, false)
	sender := env.Accounts[0]

	stxn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   sender.Addr,
		Receiver: sender.Addr,
		Amount:   0,
	}).SignedTxn()

	// should error on missing signature
	result, err := s.Simulate(simulation.Request{TxnGroups: [][]transactions.SignedTxn{{stxn}}})
	require.NoError(t, err)
	require.Len(t, result.TxnGroups, 1)
	require.Len(t, result.TxnGroups[0].Txns, 1)
	require.Contains(t, result.TxnGroups[0].FailureMessage, "signedtxn has no sig")
	require.Equal(t, result.TxnGroups[0].FailedAt, simulation.TxnPath{0})

	// add signature
	stxn = stxn.Txn.Sign(sender.Sk)

	// should not error now that we have a signature
	result, err = s.Simulate(simulation.Request{TxnGroups: [][]transactions.SignedTxn{{stxn}}})
	require.NoError(t, err)
	require.Len(t, result.TxnGroups, 1)
	require.Len(t, result.TxnGroups[0].Txns, 1)
	require.Zero(t, result.TxnGroups[0].FailureMessage)

	// should error with invalid signature
	stxn.Sig[0] += byte(1) // will wrap if > 255
	result, err = s.Simulate(simulation.Request{TxnGroups: [][]transactions.SignedTxn{{stxn}}})
	require.ErrorAs(t, err, &simulation.InvalidRequestError{})
	require.ErrorContains(t, err, "one signature didn't pass")
}

// TestInvalidTxGroup tests that a transaction group with invalid transactions
// is rejected by the simulator as an InvalidTxGroupError instead of a EvalFailureError.
func TestInvalidTxGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		receiver := env.Accounts[0].Addr

		txn := env.TxnInfo.NewTxn(txntest.Txn{
			Type: protocol.PaymentTx,
			// should error with invalid transaction group error
			Sender:   ledgertesting.PoolAddr(),
			Receiver: receiver,
			Amount:   0,
		}).SignedTxn()

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{{txn}},
			},
			expectedError: "transaction from incentive pool is invalid",
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						FailedAt: simulation.TxnPath{0},
						Txns:     []simulation.TxnResult{{}},
					},
				},
			},
		}
	})
}

// TestLogLimitLiftingInSimulation tests that an app with log calls that exceed limits during normal runtime
// can get through during simulation with AllowMoreLogging activated
func TestLogLimitLiftingInSimulation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	LogTimes := 40
	LogLongLine := strings.Repeat("a", 1050)

	appSourceThatLogsALot := `#pragma version 8
txn NumAppArgs
int 0
==
bnz final
` + strings.Repeat(fmt.Sprintf(`byte "%s"
log
`, LogLongLine), LogTimes) + `final:
int 1`

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]
		receiver := env.Accounts[1]

		futureAppID := basics.AppIndex(1001)

		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:              protocol.ApplicationCallTx,
			Sender:            sender.Addr,
			ApplicationID:     0,
			ApprovalProgram:   appSourceThatLogsALot,
			ClearStateProgram: "#pragma version 8\nint 1",
		})

		callsABunchLogs := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationID:   futureAppID,
			Accounts:        []basics.Address{receiver.Addr},
			ApplicationArgs: [][]byte{[]byte("first-arg")},
		})

		txntest.Group(&createTxn, &callsABunchLogs)

		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
		signedCallsABunchLogs := callsABunchLogs.Txn().Sign(sender.Sk)

		expectedMaxLogCalls, expectedMaxLogSize := uint64(2048), uint64(65536)
		expectedLog := make([]string, LogTimes)
		for i := 0; i < LogTimes; i++ {
			expectedLog[i] = LogLongLine
		}
		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedCreateTxn, signedCallsABunchLogs},
				},
				AllowMoreLogging: true,
			},
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
									},
								},
								AppBudgetConsumed: 6,
							},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										EvalDelta: transactions.EvalDelta{
											Logs: expectedLog,
										},
									},
								},
								AppBudgetConsumed: 86,
							},
						},
						AppBudgetAdded:    1400,
						AppBudgetConsumed: 92,
					},
				},
				EvalOverrides: simulation.ResultEvalOverrides{
					MaxLogCalls: &expectedMaxLogCalls,
					MaxLogSize:  &expectedMaxLogSize,
				},
			},
		}
	})
}

func TestLogSizeExceedWithLiftInSimulation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	LogTimes := 65
	LogLongLine := strings.Repeat("a", 1050)

	appSourceThatLogsALot := `#pragma version 8
txn NumAppArgs
int 0
==
bnz final
` + strings.Repeat(fmt.Sprintf(`byte "%s"
log
`, LogLongLine), LogTimes) + `final:
int 1`

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		futureAppID := basics.AppIndex(1001)

		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:              protocol.ApplicationCallTx,
			Sender:            sender.Addr,
			ApplicationID:     0,
			ApprovalProgram:   appSourceThatLogsALot,
			ClearStateProgram: "#pragma version 8\nint 1",
		})

		callsABunchLogs := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationID:   futureAppID,
			ApplicationArgs: [][]byte{[]byte("first-arg")},
		})

		txntest.Group(&createTxn, &callsABunchLogs)

		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
		signedCallsABunchLogs := callsABunchLogs.Txn().Sign(sender.Sk)

		expectedMaxLogCalls, expectedMaxLogSize := uint64(2048), uint64(65536)
		actualLogTimes := 65536 / len(LogLongLine)
		expectedLog := make([]string, actualLogTimes)
		for i := 0; i < actualLogTimes; i++ {
			expectedLog[i] = LogLongLine
		}
		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedCreateTxn, signedCallsABunchLogs},
				},
				AllowMoreLogging: true,
			},
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						FailedAt: simulation.TxnPath{1},
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
									},
								},
								AppBudgetConsumed: 6,
							},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										EvalDelta: transactions.EvalDelta{
											Logs: expectedLog,
										},
									},
								},
								AppBudgetConsumed: 131,
							},
						},
						AppBudgetAdded:    1400,
						AppBudgetConsumed: 137,
					},
				},
				EvalOverrides: simulation.ResultEvalOverrides{
					MaxLogCalls: &expectedMaxLogCalls,
					MaxLogSize:  &expectedMaxLogSize,
				},
			},
			expectedError: "logic eval error: program logs too large. 66150 bytes >  65536 bytes limit.",
		}
	})
}

// The program is originated from pyteal source for c2c test over betanet:
// https://github.com/ahangsu/c2c-testscript/blob/master/c2c_test/max_depth/app.py
//
// To fully test the PC exposure, we added opt-in and clear-state calls,
// between funding and calling with on-complete deletion.
// The modified version here: https://gist.github.com/ahangsu/7839f558dd36ad7117c0a12fb1dcc63a
const maxDepthTealApproval = `#pragma version 8
txn ApplicationID
int 0
==
bnz main_l6
txn OnCompletion
int OptIn
==
bnz main_l6
txn NumAppArgs
int 1
==
bnz main_l3
err
main_l3:
global CurrentApplicationID
app_params_get AppApprovalProgram
store 1
store 0
global CurrentApplicationID
app_params_get AppClearStateProgram
store 3
store 2
global CurrentApplicationAddress
acct_params_get AcctBalance
store 5
store 4
load 1
assert
load 3
assert
load 5
assert
int 2
txna ApplicationArgs 0
btoi
exp
itob
log
txna ApplicationArgs 0
btoi
int 0
>
bnz main_l5
main_l4:
int 1
return
main_l5:
itxn_begin
  int appl
  itxn_field TypeEnum
  int 0
  itxn_field Fee
  load 0
  itxn_field ApprovalProgram
  load 2
  itxn_field ClearStateProgram
itxn_submit
itxn_begin
  int pay
  itxn_field TypeEnum
  int 0
  itxn_field Fee
  load 4
  int 100000
  -
  itxn_field Amount
  byte "appID"
  gitxn 0 CreatedApplicationID
  itob
  concat
  sha512_256
  itxn_field Receiver
itxn_next
  int appl
  itxn_field TypeEnum
  itxn CreatedApplicationID
  itxn_field ApplicationID
  int 0
  itxn_field Fee
  int OptIn
  itxn_field OnCompletion
itxn_next
  int appl
  itxn_field TypeEnum
  itxn CreatedApplicationID
  itxn_field ApplicationID
  int 0
  itxn_field Fee
  int ClearState
  itxn_field OnCompletion
itxn_next
  int appl
  itxn_field TypeEnum
  txna ApplicationArgs 0
  btoi
  int 1
  -
  itob
  itxn_field ApplicationArgs
  itxn CreatedApplicationID
  itxn_field ApplicationID
  int 0
  itxn_field Fee
  int DeleteApplication
  itxn_field OnCompletion
itxn_submit
b main_l4
main_l6:
int 1
return`

func TestMaxDepthAppWithPCTrace(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]
		futureAppID := basics.AppIndex(1001)

		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:              protocol.ApplicationCallTx,
			Sender:            sender.Addr,
			ApplicationID:     0,
			ApprovalProgram:   maxDepthTealApproval,
			ClearStateProgram: "#pragma version 8\nint 1",
		})

		MaxDepth := 2
		MinBalance := env.TxnInfo.CurrentProtocolParams().MinBalance
		MinFee := env.TxnInfo.CurrentProtocolParams().MinTxnFee

		paymentTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: futureAppID.Address(),
			Amount:   MinBalance * uint64(MaxDepth+1),
		})

		callsMaxDepth := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationID:   futureAppID,
			ApplicationArgs: [][]byte{{byte(MaxDepth)}},
			Fee:             MinFee * uint64(MaxDepth*5+2),
		})

		txntest.Group(&createTxn, &paymentTxn, &callsMaxDepth)

		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
		signedPaymentTxn := paymentTxn.Txn().Sign(sender.Sk)
		signedCallsMaxDepth := callsMaxDepth.Txn().Sign(sender.Sk)

		creationOpcodeTrace := []simulation.OpcodeTraceUnit{
			{PC: 1},
			{PC: 6},
			{PC: 8},
			{PC: 9},
			{PC: 10},
			{PC: 185},
			{PC: 186},
		}

		clearStateOpcodeTrace := []simulation.OpcodeTraceUnit{{PC: 1}}

		recursiveLongOpcodeTrace := []simulation.OpcodeTraceUnit{
			{PC: 1},
			{PC: 6},
			{PC: 8},
			{PC: 9},
			{PC: 10},
			{PC: 13},
			{PC: 15},
			{PC: 16},
			{PC: 17},
			{PC: 20},
			{PC: 22},
			{PC: 23},
			{PC: 24},
			{PC: 28},
			{PC: 30},
			{PC: 32},
			{PC: 34},
			{PC: 36},
			{PC: 38},
			{PC: 40},
			{PC: 42},
			{PC: 44},
			{PC: 46},
			{PC: 48},
			{PC: 50},
			{PC: 52},
			{PC: 54},
			{PC: 55},
			{PC: 57},
			{PC: 58},
			{PC: 60},
			{PC: 61},
			{PC: 63},
			{PC: 66},
			{PC: 67},
			{PC: 68},
			{PC: 69},
			{PC: 70},
			{PC: 73},
			{PC: 74},
			{PC: 75},
			{PC: 76},
			{PC: 81},
			{PC: 82},
			{PC: 83},
			{PC: 85},
			{PC: 86},
			{PC: 88},
			{PC: 90},
			{PC: 92},
			{PC: 94},
			{PC: 96, SpawnedInners: []int{0}},
			{PC: 97},
			{PC: 98},
			{PC: 99},
			{PC: 101},
			{PC: 102},
			{PC: 104},
			{PC: 106},
			{PC: 110},
			{PC: 111},
			{PC: 113},
			{PC: 120},
			{PC: 123},
			{PC: 124},
			{PC: 125},
			{PC: 126},
			{PC: 128},
			{PC: 129},
			{PC: 130},
			{PC: 132},
			{PC: 134},
			{PC: 136},
			{PC: 137},
			{PC: 139},
			{PC: 140},
			{PC: 142},
			{PC: 143},
			{PC: 144},
			{PC: 146},
			{PC: 148},
			{PC: 150},
			{PC: 151},
			{PC: 153},
			{PC: 155},
			{PC: 157},
			{PC: 158},
			{PC: 159},
			{PC: 161},
			{PC: 164},
			{PC: 165},
			{PC: 166},
			{PC: 167},
			{PC: 168},
			{PC: 170},
			{PC: 172},
			{PC: 174},
			{PC: 175},
			{PC: 177},
			{PC: 179},
			{PC: 181, SpawnedInners: []int{1, 2, 3, 4}},
			{PC: 182},
			{PC: 79},
			{PC: 80},
		}

		optInTrace := []simulation.OpcodeTraceUnit{
			{PC: 1},
			{PC: 6},
			{PC: 8},
			{PC: 9},
			{PC: 10},
			{PC: 13},
			{PC: 15},
			{PC: 16},
			{PC: 17},
			{PC: 185},
			{PC: 186},
		}

		finalDepthTrace := []simulation.OpcodeTraceUnit{
			{PC: 1},
			{PC: 6},
			{PC: 8},
			{PC: 9},
			{PC: 10},
			{PC: 13},
			{PC: 15},
			{PC: 16},
			{PC: 17},
			{PC: 20},
			{PC: 22},
			{PC: 23},
			{PC: 24},
			{PC: 28},
			{PC: 30},
			{PC: 32},
			{PC: 34},
			{PC: 36},
			{PC: 38},
			{PC: 40},
			{PC: 42},
			{PC: 44},
			{PC: 46},
			{PC: 48},
			{PC: 50},
			{PC: 52},
			{PC: 54},
			{PC: 55},
			{PC: 57},
			{PC: 58},
			{PC: 60},
			{PC: 61},
			{PC: 63},
			{PC: 66},
			{PC: 67},
			{PC: 68},
			{PC: 69},
			{PC: 70},
			{PC: 73},
			{PC: 74},
			{PC: 75},
			{PC: 76},
			{PC: 79},
			{PC: 80},
		}

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedCreateTxn, signedPaymentTxn, signedCallsMaxDepth},
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
				},
			},
			developerAPI: true,
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{ApplicationID: futureAppID},
								},
								AppBudgetConsumed: 7,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: creationOpcodeTrace,
								},
							},
							{
								Trace: &simulation.TransactionTrace{},
							},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: 0,
										EvalDelta: transactions.EvalDelta{
											Logs: []string{string(uint64ToBytes(1 << MaxDepth))},
											InnerTxns: []transactions.SignedTxnWithAD{
												{
													ApplyData: transactions.ApplyData{ApplicationID: futureAppID + 3},
												},
												{},
												{},
												{},
												{
													ApplyData: transactions.ApplyData{
														EvalDelta: transactions.EvalDelta{
															Logs: []string{string(uint64ToBytes(1 << (MaxDepth - 1)))},
															InnerTxns: []transactions.SignedTxnWithAD{
																{
																	ApplyData: transactions.ApplyData{ApplicationID: futureAppID + 8},
																},
																{},
																{},
																{},
																{
																	ApplyData: transactions.ApplyData{
																		EvalDelta: transactions.EvalDelta{
																			Logs: []string{string(uint64ToBytes(1 << (MaxDepth - 2)))},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
								AppBudgetConsumed: 378,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: recursiveLongOpcodeTrace,
									InnerTraces: []simulation.TransactionTrace{
										{
											ApprovalProgramTrace: creationOpcodeTrace,
										},
										{},
										{
											ApprovalProgramTrace: optInTrace,
										},
										{
											ClearStateProgramTrace: clearStateOpcodeTrace,
										},
										{
											ApprovalProgramTrace: recursiveLongOpcodeTrace,
											InnerTraces: []simulation.TransactionTrace{
												{
													ApprovalProgramTrace: creationOpcodeTrace,
												},
												{},
												{
													ApprovalProgramTrace: optInTrace,
												},
												{
													ClearStateProgramTrace: clearStateOpcodeTrace,
												},
												{
													ApprovalProgramTrace: finalDepthTrace,
												},
											},
										},
									},
								},
							},
						},
						AppBudgetAdded:    4200,
						AppBudgetConsumed: 385,
					},
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
				},
			},
		}
	})
}

func goValuesToTealValues(goValues ...interface{}) []basics.TealValue {
	if len(goValues) == 0 {
		return nil
	}

	boolToUint64 := func(b bool) uint64 {
		if b {
			return 1
		}
		return 0
	}

	modelValues := make([]basics.TealValue, len(goValues))
	for i, goValue := range goValues {
		switch convertedValue := goValue.(type) {
		case []byte:
			modelValues[i] = basics.TealValue{
				Type:  basics.TealBytesType,
				Bytes: string(convertedValue),
			}
		case string:
			modelValues[i] = basics.TealValue{
				Type:  basics.TealBytesType,
				Bytes: string(convertedValue),
			}
		case bool:
			modelValues[i] = basics.TealValue{
				Type: basics.TealUintType,
				Uint: boolToUint64(convertedValue),
			}
		case int:
			modelValues[i] = basics.TealValue{
				Type: basics.TealUintType,
				Uint: uint64(convertedValue),
			}
		case basics.AppIndex:
			modelValues[i] = basics.TealValue{
				Type: basics.TealUintType,
				Uint: uint64(convertedValue),
			}
		case uint64:
			modelValues[i] = basics.TealValue{
				Type: basics.TealUintType,
				Uint: convertedValue,
			}
		default:
			panic("unexpected type inferred from interface{}")
		}
	}
	return modelValues
}

func TestLogicSigPCandStackExposure(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	op, err := logic.AssembleString(`#pragma version 8
` + strings.Repeat(`byte "a"; keccak256; pop
`, 2) + `int 1`)
	require.NoError(t, err)
	program := logic.Program(op.Program)
	lsigAddr := basics.Address(crypto.HashObj(&program))

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		payTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: lsigAddr,
			Amount:   1_000_000,
		})
		appCallTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:   protocol.ApplicationCallTx,
			Sender: lsigAddr,
			ApprovalProgram: `#pragma version 8
byte "hello"; log; int 1`,
			ClearStateProgram: "#pragma version 8\n int 1",
		})

		txntest.Group(&payTxn, &appCallTxn)

		signedPayTxn := payTxn.Txn().Sign(sender.Sk)
		signedAppCallTxn := appCallTxn.SignedTxn()
		signedAppCallTxn.Lsig = transactions.LogicSig{Logic: program}

		keccakBytes := ":\xc2%\x16\x8d\xf5B\x12\xa2\\\x1c\x01\xfd5\xbe\xbf\xea@\x8f\xda\xc2\xe3\x1d\xddo\x80\xa4\xbb\xf9\xa5\xf1\xcb"

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedPayTxn, signedAppCallTxn},
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					Stack:  true,
				},
			},
			developerAPI: true,
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					Stack:  true,
				},
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Trace: &simulation.TransactionTrace{},
							},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: 1002,
										EvalDelta:     transactions.EvalDelta{Logs: []string{"hello"}},
									},
								},
								AppBudgetConsumed:      3,
								LogicSigBudgetConsumed: 266,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
										{
											PC:         1,
											StackAdded: goValuesToTealValues("hello"),
										},
										{
											PC:            8,
											StackPopCount: 1,
										},
										{
											PC:         9,
											StackAdded: goValuesToTealValues(1),
										},
									},
									LogicSigTrace: []simulation.OpcodeTraceUnit{
										{
											PC: 1,
										},
										{
											PC:         5,
											StackAdded: goValuesToTealValues("a"),
										},
										{
											PC:            6,
											StackAdded:    goValuesToTealValues(keccakBytes),
											StackPopCount: 1,
										},
										{
											PC:            7,
											StackPopCount: 1,
										},
										{
											PC:         8,
											StackAdded: goValuesToTealValues("a"),
										},
										{
											PC:            9,
											StackAdded:    goValuesToTealValues(keccakBytes),
											StackPopCount: 1,
										},
										{
											PC:            10,
											StackPopCount: 1,
										},
										{
											PC:         11,
											StackAdded: goValuesToTealValues(1),
										},
									},
								},
							},
						},
						AppBudgetAdded:    700,
						AppBudgetConsumed: 3,
					},
				},
			},
		}
	})
}

func TestFailingLogicSigPCandStack(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	op, err := logic.AssembleString(`#pragma version 8
` + strings.Repeat(`byte "a"; keccak256; pop
`, 2) + `int 0; int 1; -`)
	require.NoError(t, err)
	program := logic.Program(op.Program)
	lsigAddr := basics.Address(crypto.HashObj(&program))

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		payTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: lsigAddr,
			Amount:   1_000_000,
		})
		appCallTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:   protocol.ApplicationCallTx,
			Sender: lsigAddr,
			ApprovalProgram: `#pragma version 8
byte "hello"; log; int 1`,
			ClearStateProgram: "#pragma version 8\n int 1",
		})

		txntest.Group(&payTxn, &appCallTxn)

		signedPayTxn := payTxn.Txn().Sign(sender.Sk)
		signedAppCallTxn := appCallTxn.SignedTxn()
		signedAppCallTxn.Lsig = transactions.LogicSig{Logic: program}

		keccakBytes := ":\xc2%\x16\x8d\xf5B\x12\xa2\\\x1c\x01\xfd5\xbe\xbf\xea@\x8f\xda\xc2\xe3\x1d\xddo\x80\xa4\xbb\xf9\xa5\xf1\xcb"

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedPayTxn, signedAppCallTxn},
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					Stack:  true,
				},
			},
			developerAPI:  true,
			expectedError: "rejected by logic",
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					Stack:  true,
				},
				TxnGroups: []simulation.TxnGroupResult{
					{
						FailedAt: simulation.TxnPath{1},
						Txns: []simulation.TxnResult{
							{},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{},
								},
								LogicSigBudgetConsumed: 268,
								Trace: &simulation.TransactionTrace{
									LogicSigTrace: []simulation.OpcodeTraceUnit{
										{
											PC: 1,
										},
										{
											PC:         5,
											StackAdded: goValuesToTealValues("a"),
										},
										{
											PC:            6,
											StackAdded:    goValuesToTealValues(keccakBytes),
											StackPopCount: 1,
										},
										{
											PC:            7,
											StackPopCount: 1,
										},
										{
											PC:         8,
											StackAdded: goValuesToTealValues("a"),
										},
										{
											PC:            9,
											StackAdded:    goValuesToTealValues(keccakBytes),
											StackPopCount: 1,
										},
										{
											PC:            10,
											StackPopCount: 1,
										},
										{
											PC:         11,
											StackAdded: goValuesToTealValues(0),
										},
										{
											PC:         13,
											StackAdded: goValuesToTealValues(1),
										},
										{
											PC:            15,
											StackPopCount: 2,
										},
									},
								},
							},
						},
					},
				},
			},
		}
	})
}

func TestFailingApp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	op, err := logic.AssembleString(`#pragma version 8
` + strings.Repeat(`byte "a"; keccak256; pop
`, 2) + `int 1`)
	require.NoError(t, err)
	program := logic.Program(op.Program)
	lsigAddr := basics.Address(crypto.HashObj(&program))

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		payTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: lsigAddr,
			Amount:   1_000_000,
		})
		appCallTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:   protocol.ApplicationCallTx,
			Sender: lsigAddr,
			ApprovalProgram: `#pragma version 8
byte "hello"; log; int 0`,
			ClearStateProgram: "#pragma version 8\n int 1",
		})

		txntest.Group(&payTxn, &appCallTxn)

		signedPayTxn := payTxn.Txn().Sign(sender.Sk)
		signedAppCallTxn := appCallTxn.SignedTxn()
		signedAppCallTxn.Lsig = transactions.LogicSig{Logic: program}

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedPayTxn, signedAppCallTxn},
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
				},
			},
			developerAPI:  true,
			expectedError: "rejected by ApprovalProgram",
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
				},
				TxnGroups: []simulation.TxnGroupResult{
					{
						FailedAt: simulation.TxnPath{1},
						Txns: []simulation.TxnResult{
							{
								Trace: &simulation.TransactionTrace{},
							},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: 1002,
										EvalDelta:     transactions.EvalDelta{Logs: []string{"hello"}},
									},
								},
								AppBudgetConsumed:      3,
								LogicSigBudgetConsumed: 266,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
										{PC: 1},
										{PC: 8},
										{PC: 9},
									},
									LogicSigTrace: []simulation.OpcodeTraceUnit{
										{PC: 1},
										{PC: 5},
										{PC: 6},
										{PC: 7},
										{PC: 8},
										{PC: 9},
										{PC: 10},
										{PC: 11},
									},
								},
							},
						},
						AppBudgetAdded:    700,
						AppBudgetConsumed: 3,
					},
				},
			},
		}
	})
}

const FrameBuryDigProgram = `#pragma version 8
txn ApplicationID      // on creation, always approve
bz end

txn NumAppArgs
int 1
==
assert

txn ApplicationArgs 0
btoi
callsub subroutine_manipulating_stack
itob
log
b end

subroutine_manipulating_stack:
  proto 1 1
  int 0                                   // [0]
  dup                                     // [0, 0]
  dupn 4                                  // [0, 0, 0, 0, 0, 0]
  frame_dig -1                            // [0, 0, 0, 0, 0, 0, arg_0]
  frame_bury 0                            // [arg_0, 0, 0, 0, 0, 0]
  dig 5                                   // [arg_0, 0, 0, 0, 0, 0, arg_0]
  cover 5                                 // [arg_0, arg_0, 0, 0, 0, 0, 0]
  frame_dig 0                             // [arg_0, arg_0, 0, 0, 0, 0, 0, arg_0]
  frame_dig 1                             // [arg_0, arg_0, 0, 0, 0, 0, 0, arg_0, arg_0]
  +                                       // [arg_0, arg_0, 0, 0, 0, 0, 0, arg_0 * 2]
  bury 7                                  // [arg_0 * 2, arg_0, 0, 0, 0, 0, 0]
  popn 5                                  // [arg_0 * 2, arg_0]
  uncover 1                               // [arg_0, arg_0 * 2]
  swap                                    // [arg_0 * 2, arg_0]
  +                                       // [arg_0 * 3]
  pushbytess "1!" "5!"                    // [arg_0 * 3, "1!", "5!"]
  pushints 0 2 1 1 5 18446744073709551615 // [arg_0 * 3, "1!", "5!", 0, 2, 1, 1, 5, 18446744073709551615]
  retsub

end:
  int 1
  return
`

func TestFrameBuryDigStackTrace(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		futureAppID := basics.AppIndex(1001)

		applicationArg := 10

		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationID:   0,
			ApprovalProgram: FrameBuryDigProgram,
			ClearStateProgram: `#pragma version 8
int 1`,
		})
		payment := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: futureAppID.Address(),
			Amount:   env.TxnInfo.CurrentProtocolParams().MinBalance,
		})
		callTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationID:   futureAppID,
			ApplicationArgs: [][]byte{{byte(applicationArg)}},
		})
		txntest.Group(&createTxn, &payment, &callTxn)

		signedCreate := createTxn.Txn().Sign(sender.Sk)
		signedPay := payment.Txn().Sign(sender.Sk)
		signedAppCall := callTxn.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedCreate, signedPay, signedAppCall},
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					Stack:  true,
				},
			},
			developerAPI: true,
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					Stack:  true,
				},
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
									},
								},
								AppBudgetConsumed: 5,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
										{
											PC: 1,
										},
										{
											PC:         4,
											StackAdded: goValuesToTealValues(0),
										},
										{
											PC:            6,
											StackPopCount: 1,
										},
										{
											PC:         81,
											StackAdded: goValuesToTealValues(1),
										},
										{
											PC:            82,
											StackAdded:    goValuesToTealValues(1),
											StackPopCount: 1,
										},
									},
								},
							},
							{
								Trace: &simulation.TransactionTrace{},
							},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										EvalDelta: transactions.EvalDelta{
											Logs: []string{
												string(uint64ToBytes(uint64(applicationArg * 3))),
											},
										},
									},
								},
								AppBudgetConsumed: 34,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
										{
											PC: 1,
										},
										{
											PC:         4,
											StackAdded: goValuesToTealValues(futureAppID),
										},
										{
											PC:            6,
											StackPopCount: 1,
										},
										{
											PC:         9,
											StackAdded: goValuesToTealValues(1),
										},
										{
											PC:         11,
											StackAdded: goValuesToTealValues(1),
										},
										{
											PC:            12,
											StackAdded:    goValuesToTealValues(1),
											StackPopCount: 2,
										},
										{
											PC:            13,
											StackPopCount: 1,
										},
										{
											PC:         14,
											StackAdded: goValuesToTealValues([]byte{byte(applicationArg)}),
										},
										{
											PC:            17,
											StackAdded:    goValuesToTealValues(applicationArg),
											StackPopCount: 1,
										},
										// call sub
										{
											PC: 18,
										},
										// proto
										{
											PC: 26,
										},
										{
											PC:         29,
											StackAdded: goValuesToTealValues(0),
										},
										// dup
										{
											PC:            31,
											StackAdded:    goValuesToTealValues(0, 0),
											StackPopCount: 1,
										},
										// dupn 4
										{
											PC:            32,
											StackAdded:    goValuesToTealValues(0, 0, 0, 0, 0),
											StackPopCount: 1,
										},
										// frame_dig -1
										{
											PC:            34,
											StackAdded:    goValuesToTealValues(applicationArg),
											StackPopCount: 0,
										},
										// frame_bury 0
										{
											PC:            36,
											StackAdded:    goValuesToTealValues(applicationArg, 0, 0, 0, 0, 0),
											StackPopCount: 7,
										},
										// dig 5
										{
											PC:            38,
											StackAdded:    goValuesToTealValues(applicationArg),
											StackPopCount: 0,
										},
										// cover 5
										{
											PC:            40,
											StackAdded:    goValuesToTealValues(applicationArg, 0, 0, 0, 0, 0),
											StackPopCount: 6,
										},
										// frame_dig 0
										{
											PC:            42,
											StackAdded:    goValuesToTealValues(applicationArg),
											StackPopCount: 0,
										},
										// frame_dig 1
										{
											PC:            44,
											StackAdded:    goValuesToTealValues(applicationArg),
											StackPopCount: 0,
										},
										// +
										{
											PC:            46,
											StackAdded:    goValuesToTealValues(applicationArg * 2),
											StackPopCount: 2,
										},
										// bury 7
										{
											PC:            47,
											StackAdded:    goValuesToTealValues(applicationArg*2, applicationArg, 0, 0, 0, 0, 0),
											StackPopCount: 8,
										},
										// popn 5
										{
											PC:            49,
											StackPopCount: 5,
										},
										// uncover 1
										{
											PC:            51,
											StackPopCount: 2,
											StackAdded:    goValuesToTealValues(applicationArg, applicationArg*2),
										},
										// swap
										{
											PC:            53,
											StackAdded:    goValuesToTealValues(applicationArg*2, applicationArg),
											StackPopCount: 2,
										},
										// +
										{
											PC:            54,
											StackAdded:    goValuesToTealValues(applicationArg * 3),
											StackPopCount: 2,
										},
										// pushbytess "1!" "5!"
										{
											PC:         55,
											StackAdded: goValuesToTealValues("1!", "5!"),
										},
										// pushints 0 2 1 1 5 18446744073709551615
										{
											PC:         63,
											StackAdded: goValuesToTealValues(0, 2, 1, 1, 5, uint64(math.MaxUint64)),
										},
										// retsub
										{
											PC:            80,
											StackAdded:    goValuesToTealValues(applicationArg * 3),
											StackPopCount: 10,
										},
										// itob
										{
											PC:            21,
											StackAdded:    goValuesToTealValues(uint64ToBytes(uint64(applicationArg) * 3)),
											StackPopCount: 1,
										},
										// log
										{
											PC:            22,
											StackPopCount: 1,
										},
										// b end
										{
											PC: 23,
										},
										// int 1
										{
											PC:         81,
											StackAdded: goValuesToTealValues(1),
										},
										// return
										{
											PC:            82,
											StackAdded:    goValuesToTealValues(1),
											StackPopCount: 1,
										},
									},
								},
							},
						},
						AppBudgetAdded:    1400,
						AppBudgetConsumed: 39,
					},
				},
			},
		}
	})
}

// TestBalanceChangesWithApp sends a payment transaction to a new account and confirms its balance
// within a subsequent app call
func TestBalanceChangesWithApp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]
		senderBalance := sender.AcctData.MicroAlgos.Raw
		sendAmount := senderBalance - 500_000 // Leave 0.5 Algos in the sender account
		receiver := env.Accounts[1]
		receiverBalance := receiver.AcctData.MicroAlgos.Raw

		futureAppID := basics.AppIndex(1001)
		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:   protocol.ApplicationCallTx,
			Sender: sender.Addr,
			ApprovalProgram: `#pragma version 6
txn ApplicationID      // [appId]
bz end                 // []
int 1                  // [1]
balance                // [bal[1]]
itob                   // [itob(bal[1])]
txn ApplicationArgs 0  // [itob(bal[1]), args[0]]
==                     // [itob(bal[1])=?=args[0]]
assert
end:
int 1                  // [1]
`,
			ClearStateProgram: `#pragma version 6
int 1`,
		})
		checkStartingBalanceTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationID:   futureAppID,
			Accounts:        []basics.Address{receiver.Addr},
			ApplicationArgs: [][]byte{uint64ToBytes(receiverBalance)},
		})
		paymentTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: receiver.Addr,
			Amount:   sendAmount,
		})
		checkEndingBalanceTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: futureAppID,
			Accounts:      []basics.Address{receiver.Addr},
			// Receiver's balance should have increased by sendAmount
			ApplicationArgs: [][]byte{uint64ToBytes(receiverBalance + sendAmount)},
		})

		txntest.Group(&createTxn, &checkStartingBalanceTxn, &paymentTxn, &checkEndingBalanceTxn)

		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
		signedCheckStartingBalanceTxn := checkStartingBalanceTxn.Txn().Sign(sender.Sk)
		signedPaymentTxn := paymentTxn.Txn().Sign(sender.Sk)
		signedCheckEndingBalanceTxn := checkEndingBalanceTxn.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{
						signedCreateTxn,
						signedCheckStartingBalanceTxn,
						signedPaymentTxn,
						signedCheckEndingBalanceTxn,
					},
				},
			},
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
									},
								},
								AppBudgetConsumed: 4,
							},
							{
								AppBudgetConsumed: 10,
							},
							{},
							{
								AppBudgetConsumed: 10,
							},
						},
						AppBudgetAdded:    2100,
						AppBudgetConsumed: 24,
					},
				},
			},
		}
	})
}

// TestOptionalSignatures tests that transactions with signatures and without signatures are both
// properly handled when AllowEmptySignatures is enabled.
func TestOptionalSignatures(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	for _, signed := range []bool{true, false} {
		signed := signed
		t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
			simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
				sender := env.Accounts[0]

				txn := env.TxnInfo.NewTxn(txntest.Txn{
					Type:     protocol.PaymentTx,
					Sender:   sender.Addr,
					Receiver: sender.Addr,
					Amount:   1,
				})

				var stxn transactions.SignedTxn
				if signed {
					stxn = txn.Txn().Sign(sender.Sk)
				} else {
					// no signature is included
					stxn = txn.SignedTxn()
				}

				return simulationTestCase{
					input: simulation.Request{
						TxnGroups:            [][]transactions.SignedTxn{{stxn}},
						AllowEmptySignatures: true,
					},
					expected: simulation.Result{
						Version:   simulation.ResultLatestVersion,
						LastRound: env.TxnInfo.LatestRound(),
						TxnGroups: []simulation.TxnGroupResult{
							{
								Txns: []simulation.TxnResult{{}},
							},
						},
						EvalOverrides: simulation.ResultEvalOverrides{
							AllowEmptySignatures: true,
						},
					},
				}
			})
		})
	}
}

// TestOptionalSignaturesIncorrect tests that an incorrect signature still fails when
// AllowEmptySignatures is enabled.
func TestOptionalSignaturesIncorrect(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()
	s := simulation.MakeSimulator(env.Ledger, false)
	sender := env.Accounts[0]

	stxn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   sender.Addr,
		Receiver: sender.Addr,
		Amount:   0,
	}).Txn().Sign(sender.Sk)

	// should error with invalid signature
	stxn.Sig[0] += byte(1) // will wrap if > 255
	_, err := s.Simulate(simulation.Request{TxnGroups: [][]transactions.SignedTxn{{stxn}}})
	require.ErrorAs(t, err, &simulation.InvalidRequestError{})
	require.ErrorContains(t, err, "one signature didn't pass")
}

// TestPartialMissingSignatures tests that a group of transactions with some signatures missing is
// handled properly when AllowEmptySignatures is enabled.
func TestPartialMissingSignatures(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		txn1 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:   protocol.AssetConfigTx,
			Sender: sender.Addr,
			AssetParams: basics.AssetParams{
				Total:    10,
				Decimals: 0,
				Manager:  sender.Addr,
				UnitName: "A",
			},
		})
		txn2 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:   protocol.AssetConfigTx,
			Sender: sender.Addr,
			AssetParams: basics.AssetParams{
				Total:    10,
				Decimals: 0,
				Manager:  sender.Addr,
				UnitName: "B",
			},
		})

		txntest.Group(&txn1, &txn2)

		// add signature to second transaction only
		signedTxn1 := txn1.SignedTxn()
		signedTxn2 := txn2.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedTxn1, signedTxn2},
				},
				AllowEmptySignatures: true,
			},
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ConfigAsset: 1001,
									},
								},
							}, {
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ConfigAsset: 1002,
									},
								},
							},
						},
					},
				},
				EvalOverrides: simulation.ResultEvalOverrides{
					AllowEmptySignatures: true,
				},
			},
		}
	})
}

// TestPooledFeesAcrossSignedAndUnsigned tests that the simulator's transaction group checks
// allow for pooled fees across a mix of signed and unsigned transactions when AllowEmptySignatures is
// enabled.
//
//	Transaction 1 is a signed transaction with not enough fees paid on its own.
//	Transaction 2 is an unsigned transaction with enough fees paid to cover transaction 1.
func TestPooledFeesAcrossSignedAndUnsigned(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender1 := env.Accounts[0]
		sender2 := env.Accounts[1]

		pay1 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender1.Addr,
			Receiver: sender2.Addr,
			Amount:   1_000_000,
			Fee:      env.TxnInfo.CurrentProtocolParams().MinTxnFee - 100,
		})
		pay2 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender2.Addr,
			Receiver: sender1.Addr,
			Amount:   0,
			Fee:      env.TxnInfo.CurrentProtocolParams().MinTxnFee + 100,
		})

		txntest.Group(&pay1, &pay2)

		// sign pay1 only
		signedPay1 := pay1.Txn().Sign(sender1.Sk)
		signedPay2 := pay2.SignedTxn()

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedPay1, signedPay2},
				},
				AllowEmptySignatures: true,
			},
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{}, {},
						},
					},
				},
				EvalOverrides: simulation.ResultEvalOverrides{
					AllowEmptySignatures: true,
				},
			},
		}
	})
}

const logAndFail = `#pragma version 6
byte "message"
log
int 0
`

func makeItxnSubmitToCallInner(t *testing.T, program string) string {
	t.Helper()
	ops, err := logic.AssembleString(program)
	require.NoError(t, err)
	programBytesHex := hex.EncodeToString(ops.Program)
	itxnSubmit := fmt.Sprintf(`byte "starting inner txn"
log

itxn_begin
int appl
itxn_field TypeEnum
int NoOp
itxn_field OnCompletion
byte 0x068101
itxn_field ClearStateProgram
byte 0x%s
itxn_field ApprovalProgram
itxn_submit

byte "finished inner txn"
log
`, programBytesHex)
	return itxnSubmit
}

func wrapCodeWithVersionAndReturn(code string) string {
	return fmt.Sprintf(`#pragma version 6
%s
int 1
return`, code)
}

func makeProgramToCallInner(t *testing.T, program string) string {
	t.Helper()
	itxnSubmitCode := makeItxnSubmitToCallInner(t, program)
	return wrapCodeWithVersionAndReturn(itxnSubmitCode)
}

func TestAppCallInnerTxnApplyDataOnFail(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		singleInnerLogAndFail := makeProgramToCallInner(t, logAndFail)
		nestedInnerLogAndFail := makeProgramToCallInner(t, singleInnerLogAndFail)

		futureOuterAppID := basics.AppIndex(1003)
		futureInnerAppID := futureOuterAppID + 1

		// fund outer app
		pay1 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: futureOuterAppID.Address(),
			Amount:   401_000, // 400_000 min balance plus 1_000 for 1 txn
		})
		// fund inner app
		pay2 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: futureInnerAppID.Address(),
			Amount:   401_000, // 400_000 min balance plus 1_000 for 1 txn
		})
		// create app
		appCall := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationArgs: [][]byte{uint64ToBytes(uint64(1))},
			ApprovalProgram: nestedInnerLogAndFail,
			ClearStateProgram: `#pragma version 6
int 1`,
		})

		txgroup := txntest.Group(&pay1, &pay2, &appCall)

		for i := range txgroup {
			txgroup[i] = txgroup[i].Txn.Sign(sender.Sk)
		}

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{txgroup},
			},
			expectedError: "rejected by ApprovalProgram",
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{},
							{},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureOuterAppID,
										EvalDelta: transactions.EvalDelta{
											Logs: []string{"starting inner txn"},
											InnerTxns: []transactions.SignedTxnWithAD{
												{
													ApplyData: transactions.ApplyData{
														ApplicationID: futureInnerAppID,
														EvalDelta: transactions.EvalDelta{
															Logs: []string{"starting inner txn"},
															InnerTxns: []transactions.SignedTxnWithAD{
																{
																	ApplyData: transactions.ApplyData{
																		ApplicationID: futureInnerAppID + 1,
																		EvalDelta: transactions.EvalDelta{
																			Logs: []string{"message"},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
								AppBudgetConsumed: 27,
							},
						},
						AppBudgetAdded:    2100,
						AppBudgetConsumed: 27,
						FailedAt:          simulation.TxnPath{2, 0, 0},
					},
				},
			},
		}
	})
}

const createAssetCode = `byte "starting asset create"
log

itxn_begin
int acfg
itxn_field TypeEnum
itxn_submit

byte "finished asset create"
log
`

func TestNonAppCallInnerTxnApplyDataOnFail(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		logAndFailItxnCode := makeItxnSubmitToCallInner(t, logAndFail)
		approvalProgram := wrapCodeWithVersionAndReturn(createAssetCode + logAndFailItxnCode)

		futureAppID := basics.AppIndex(1002)

		// fund outer app
		pay1 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: futureAppID.Address(),
			Amount:   401_000, // 400_000 min balance plus 1_000 for 1 txn
		})
		// create app
		appCall := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationArgs: [][]byte{uint64ToBytes(uint64(1))},
			ApprovalProgram: approvalProgram,
			ClearStateProgram: `#pragma version 6
int 1`,
		})

		txgroup := txntest.Group(&pay1, &appCall)

		for i := range txgroup {
			txgroup[i] = txgroup[i].Txn.Sign(sender.Sk)
		}

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{txgroup},
			},
			expectedError: "rejected by ApprovalProgram",
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
										EvalDelta: transactions.EvalDelta{
											Logs: []string{"starting asset create", "finished asset create", "starting inner txn"},
											InnerTxns: []transactions.SignedTxnWithAD{
												{
													ApplyData: transactions.ApplyData{
														ConfigAsset: basics.AssetIndex(futureAppID) + 1,
													},
												},
												{
													ApplyData: transactions.ApplyData{
														ApplicationID: futureAppID + 2,
														EvalDelta: transactions.EvalDelta{
															Logs: []string{"message"},
														},
													},
												},
											},
										},
									},
								},
								AppBudgetConsumed: 23,
							},
						},
						AppBudgetAdded:    2100,
						AppBudgetConsumed: 23,
						FailedAt:          simulation.TxnPath{1, 1},
					},
				},
			},
		}
	})
}

const configAssetCode = `byte "starting asset config"
log

itxn_begin
int acfg
itxn_field TypeEnum
int %d
itxn_field ConfigAsset
itxn_submit

byte "finished asset config"
log
`

func TestInnerTxnNonAppCallFailure(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		futureAppID := basics.AppIndex(1002)
		futureAssetID := basics.AssetIndex(1003)

		// configAssetCode should fail because createAssetCode does not set an asset manager
		approvalProgram := wrapCodeWithVersionAndReturn(createAssetCode + fmt.Sprintf(configAssetCode, futureAssetID))

		// fund outer app
		pay1 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: futureAppID.Address(),
			Amount:   402_000, // 400_000 min balance plus 2_000 for 2 inners
		})
		// create app
		appCall := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationArgs: [][]byte{uint64ToBytes(uint64(1))},
			ApprovalProgram: approvalProgram,
			ClearStateProgram: `#pragma version 6
int 1`,
		})

		txgroup := txntest.Group(&pay1, &appCall)

		for i := range txgroup {
			txgroup[i] = txgroup[i].Txn.Sign(sender.Sk)
		}

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{txgroup},
			},
			expectedError: "logic eval error: this transaction should be issued by the manager",
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
										EvalDelta: transactions.EvalDelta{
											Logs: []string{"starting asset create", "finished asset create", "starting asset config"},
											InnerTxns: []transactions.SignedTxnWithAD{
												{
													ApplyData: transactions.ApplyData{
														ConfigAsset: futureAssetID,
													},
												},
												{},
											},
										},
									},
								},
								AppBudgetConsumed: 17,
							},
						},
						AppBudgetAdded:    2100,
						AppBudgetConsumed: 17,
						FailedAt:          simulation.TxnPath{1, 1},
					},
				},
			},
		}
	})
}

func TestMockTracerScenarios(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	scenarios := mocktracer.GetTestScenarios()

	for name, scenarioFn := range scenarios {
		scenarioFn := scenarioFn
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
				sender := env.Accounts[0]

				futureAppID := basics.AppIndex(1002)
				payTxn := env.TxnInfo.NewTxn(txntest.Txn{
					Type:     protocol.PaymentTx,
					Sender:   sender.Addr,
					Receiver: futureAppID.Address(),
					Amount:   2_000_000,
				})
				appCallTxn := env.TxnInfo.NewTxn(txntest.Txn{
					Type:   protocol.ApplicationCallTx,
					Sender: sender.Addr,
					ClearStateProgram: `#pragma version 6
	int 1`,
				})
				scenario := scenarioFn(mocktracer.TestScenarioInfo{
					CallingTxn:   appCallTxn.Txn(),
					MinFee:       basics.MicroAlgos{Raw: env.TxnInfo.CurrentProtocolParams().MinTxnFee},
					CreatedAppID: futureAppID,
				})
				appCallTxn.ApprovalProgram = scenario.Program

				txntest.Group(&payTxn, &appCallTxn)

				signedPayTxn := payTxn.Txn().Sign(sender.Sk)
				signedAppCallTxn := appCallTxn.Txn().Sign(sender.Sk)

				expectedFailedAt := scenario.FailedAt
				if len(expectedFailedAt) != 0 {
					// The mocktracer scenario txn is second in our group, so add 1 to the top-level index
					expectedFailedAt[0]++
				}
				expected := simulation.Result{
					Version:   simulation.ResultLatestVersion,
					LastRound: env.TxnInfo.LatestRound(),
					TxnGroups: []simulation.TxnGroupResult{
						{
							AppBudgetAdded:    scenario.AppBudgetAdded,
							AppBudgetConsumed: scenario.AppBudgetConsumed,
							FailedAt:          expectedFailedAt,
							Txns: []simulation.TxnResult{
								{
									AppBudgetConsumed: scenario.TxnAppBudgetConsumed[0],
								},
								{
									Txn: transactions.SignedTxnWithAD{
										ApplyData: scenario.ExpectedSimulationAD,
									},
									AppBudgetConsumed: scenario.TxnAppBudgetConsumed[1],
								},
							},
						},
					},
				}

				return simulationTestCase{
					input: simulation.Request{
						TxnGroups: [][]transactions.SignedTxn{
							{signedPayTxn, signedAppCallTxn},
						},
					},
					expectedError: scenario.ExpectedError,
					expected:      expected,
				}
			})
		})
	}
}
