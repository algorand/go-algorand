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

package simulation_test

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/logic/mocktracer"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/simulation"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func uint64ToBytes(num uint64) []byte {
	ibytes := make([]byte, 8)
	binary.BigEndian.PutUint64(ibytes, num)
	return ibytes
}

func bytesToUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
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
		if len(evalDelta.SharedAccts) == 0 {
			evalDelta.SharedAccts = nil
		}
		if len(evalDelta.Logs) == 0 {
			evalDelta.Logs = nil
		}
		if len(evalDelta.InnerTxns) == 0 {
			evalDelta.InnerTxns = nil
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

const ignoreAppBudgetConsumed = math.MaxInt

func simulationTest(t *testing.T, f func(env simulationtesting.Environment) simulationTestCase) {
	t.Helper()
	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	testcase := f(env)

	runSimulationTestCase(t, env, testcase)
}

func runSimulationTestCase(t *testing.T, env simulationtesting.Environment, testcase simulationTestCase) {
	t.Helper()

	actual, err := simulation.MakeSimulator(env.Ledger, testcase.developerAPI).Simulate(testcase.input)
	require.NoError(t, err)

	for i := range actual.TxnGroups {
		if actual.TxnGroups[i].UnnamedResourcesAccessed != nil {
			actual.TxnGroups[i].UnnamedResourcesAccessed.Simplify()
		}
	}

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

			if testcase.expected.TxnGroups[i].Txns[j].AppBudgetConsumed == ignoreAppBudgetConsumed {
				// This test does not care about the app budget consumed. Replace it with the actual value.
				testcase.expected.TxnGroups[i].Txns[j].AppBudgetConsumed = actual.TxnGroups[i].Txns[j].AppBudgetConsumed
			}
		}

		if testcase.expected.TxnGroups[i].AppBudgetConsumed == ignoreAppBudgetConsumed {
			// This test does not care about the app budget consumed. Replace it with the actual value.
			// But let's still ensure it's the sum of budgets consumed in this group.
			var sum int
			for _, txn := range actual.TxnGroups[i].Txns {
				sum += txn.AppBudgetConsumed
			}
			assert.Equal(t, sum, actual.TxnGroups[i].AppBudgetConsumed)
			testcase.expected.TxnGroups[i].AppBudgetConsumed = actual.TxnGroups[i].AppBudgetConsumed
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
		cost          int
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
				var AppBudgetConsumed, AppBudgetAdded int
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

const returnFirstAppArgProgram = `#pragma version 6
byte "counter"
dup
app_global_get
int 1
+
app_global_put

txn ApplicationID
bz end

txn OnCompletion
int OptIn
==
bnz end

txn ApplicationArgs 0
btoi
return

end:
int 1
return`

func TestClearStateRejection(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]
		user := env.Accounts[1]

		appID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
			ApprovalProgram:   returnFirstAppArgProgram,
			ClearStateProgram: returnFirstAppArgProgram,
			GlobalStateSchema: basics.StateSchema{
				NumUint: 1,
			},
		})
		env.OptIntoApp(user.Addr, appID)

		clearStateTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          user.Addr,
			ApplicationID:   appID,
			OnCompletion:    transactions.ClearStateOC,
			ApplicationArgs: [][]byte{{0}},
		})
		otherAppCall := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          user.Addr,
			ApplicationID:   appID,
			ApplicationArgs: [][]byte{{1}},
		})

		txntest.Group(&clearStateTxn, &otherAppCall)

		signedClearStateTxn := clearStateTxn.Txn().Sign(user.Sk)
		signedOtherAppCall := otherAppCall.Txn().Sign(user.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{{signedClearStateTxn, signedOtherAppCall}},
			},
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								// No EvalDelta changes because the clear state failed
								AppBudgetConsumed: 16,
							},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										EvalDelta: transactions.EvalDelta{
											GlobalDelta: basics.StateDelta{
												"counter": {
													Action: basics.SetUintAction,
													Uint:   3,
												},
											},
										},
									},
								},
								AppBudgetConsumed: 16,
							},
						},
						AppBudgetAdded:    1400,
						AppBudgetConsumed: 32,
					},
				},
			},
		}
	})
}

func TestClearStateError(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]
		user := env.Accounts[1]

		appID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
			ApprovalProgram:   returnFirstAppArgProgram,
			ClearStateProgram: returnFirstAppArgProgram,
			GlobalStateSchema: basics.StateSchema{
				NumUint: 1,
			},
		})
		env.OptIntoApp(user.Addr, appID)

		clearStateTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          user.Addr,
			ApplicationID:   appID,
			OnCompletion:    transactions.ClearStateOC,
			ApplicationArgs: [][]byte{}, // No app args, will cause error
		})
		otherAppCall := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          user.Addr,
			ApplicationID:   appID,
			ApplicationArgs: [][]byte{{1}},
		})

		txntest.Group(&clearStateTxn, &otherAppCall)

		signedClearStateTxn := clearStateTxn.Txn().Sign(user.Sk)
		signedOtherAppCall := otherAppCall.Txn().Sign(user.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{{signedClearStateTxn, signedOtherAppCall}},
			},
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								// No EvalDelta changes because the clear state failed
								AppBudgetConsumed: 14,
							},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										EvalDelta: transactions.EvalDelta{
											GlobalDelta: basics.StateDelta{
												"counter": {
													Action: basics.SetUintAction,
													Uint:   3,
												},
											},
										},
									},
								},
								AppBudgetConsumed: 16,
							},
						},
						AppBudgetAdded:    1400,
						AppBudgetConsumed: 30,
					},
				},
			},
		}
	})
}

func TestErrorAfterClearStateError(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]
		user := env.Accounts[1]

		appID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
			ApprovalProgram:   returnFirstAppArgProgram,
			ClearStateProgram: returnFirstAppArgProgram,
			GlobalStateSchema: basics.StateSchema{
				NumUint: 1,
			},
		})
		env.OptIntoApp(user.Addr, appID)

		clearStateTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          user.Addr,
			ApplicationID:   appID,
			OnCompletion:    transactions.ClearStateOC,
			ApplicationArgs: [][]byte{}, // No app args, will cause error
		})
		otherAppCall := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          user.Addr,
			ApplicationID:   appID,
			ApplicationArgs: [][]byte{{0}},
		})

		txntest.Group(&clearStateTxn, &otherAppCall)

		signedClearStateTxn := clearStateTxn.Txn().Sign(user.Sk)
		signedOtherAppCall := otherAppCall.Txn().Sign(user.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{{signedClearStateTxn, signedOtherAppCall}},
			},
			expectedError: "transaction rejected by ApprovalProgram",
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								// No EvalDelta changes because the clear state failed
								AppBudgetConsumed: 14,
							},
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										EvalDelta: transactions.EvalDelta{
											GlobalDelta: basics.StateDelta{
												"counter": {
													Action: basics.SetUintAction,
													Uint:   3,
												},
											},
										},
									},
								},
								AppBudgetConsumed: 16,
							},
						},
						AppBudgetAdded:    1400,
						AppBudgetConsumed: 30,
						FailedAt:          simulation.TxnPath{1},
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
		extraOpcodeBudget := 100

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
		op, err := logic.AssembleString(createTxn.ApprovalProgram.(string))
		require.NoError(t, err)
		approvalHash := crypto.Hash(op.Program)
		// Expensive 700 repetition of int 1 and pop total cost 1404
		expensiveTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: futureAppID,
		})

		txntest.Group(&createTxn, &expensiveTxn)

		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
		signedExpensiveTxn := expensiveTxn.Txn().Sign(sender.Sk)
		extraOpcodeBudget := 100

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
			secondTrace = append(secondTrace, simulation.OpcodeTraceUnit{PC: i})
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
									ApprovalProgramHash:  approvalHash,
								},
							},
							{
								AppBudgetConsumed: 1404,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: secondTrace,
									ApprovalProgramHash:  approvalHash,
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
		extraBudget := 5

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
`, 310) + `int 1`)
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
								LogicSigBudgetConsumed: 39998,
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

func TestStartRound(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()
	s := simulation.MakeSimulator(env.Ledger, false)
	sender := env.Accounts[0]

	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:   protocol.ApplicationCallTx,
		Sender: sender.Addr,
		ApprovalProgram: `#pragma version 8
global Round
itob
log
int 1`,
		ClearStateProgram: `#pragma version 8
int 1`,
	})
	txn.FirstValid = 0
	txn.LastValid = 1000
	stxn := txn.Txn().Sign(sender.Sk)

	for i := uint64(0); i <= env.Config.MaxAcctLookback; i++ {
		// Each of these transactions happens in a separate block
		env.TransferAlgos(sender.Addr, sender.Addr, 0)
	}

	latestRound := env.TxnInfo.LatestHeader.Round

	t.Run("default", func(t *testing.T) {
		// By default, should use latest round
		result, err := s.Simulate(simulation.Request{TxnGroups: [][]transactions.SignedTxn{{stxn}}})
		require.NoError(t, err)
		require.Len(t, result.TxnGroups, 1)
		require.Empty(t, result.TxnGroups[0].FailureMessage)
		require.Len(t, result.TxnGroups[0].Txns, 1)
		require.Len(t, result.TxnGroups[0].Txns[0].Txn.ApplyData.EvalDelta.Logs, 1)
		require.Equal(t, uint64(latestRound+1), bytesToUint64([]byte(result.TxnGroups[0].Txns[0].Txn.ApplyData.EvalDelta.Logs[0])))
	})

	for i := uint64(0); i <= env.Config.MaxAcctLookback; i++ {
		t.Run(fmt.Sprintf("%d rounds before latest", i), func(t *testing.T) {
			result, err := s.Simulate(simulation.Request{Round: latestRound - basics.Round(i), TxnGroups: [][]transactions.SignedTxn{{stxn}}})
			require.NoError(t, err)
			require.Len(t, result.TxnGroups, 1)
			require.Empty(t, result.TxnGroups[0].FailureMessage)
			require.Len(t, result.TxnGroups[0].Txns, 1)
			require.Len(t, result.TxnGroups[0].Txns[0].Txn.ApplyData.EvalDelta.Logs, 1)
			require.Equal(t, uint64(latestRound-basics.Round(i)+1), bytesToUint64([]byte(result.TxnGroups[0].Txns[0].Txn.ApplyData.EvalDelta.Logs[0])))
		})
	}

	t.Run("1 round in the future", func(t *testing.T) {
		_, err := s.Simulate(simulation.Request{Round: latestRound + 1, TxnGroups: [][]transactions.SignedTxn{{stxn}}})
		require.ErrorContains(t, err, fmt.Sprintf("ledger does not have entry %d", latestRound+1))
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

		expectedMaxLogCalls, expectedMaxLogSize := 2048, 65536
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

		expectedMaxLogCalls, expectedMaxLogSize := 2048, 65536
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

		op, err := logic.AssembleString(maxDepthTealApproval)
		require.NoError(t, err)
		approvalProgramBytes := op.Program
		approvalDigest := crypto.Hash(approvalProgramBytes)

		op, err = logic.AssembleString("#pragma version 8\nint 1")
		require.NoError(t, err)
		clearStateProgramBytes := op.Program
		clearStateDigest := crypto.Hash(clearStateProgramBytes)

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
									ApprovalProgramHash:  approvalDigest,
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
									ApprovalProgramHash:  approvalDigest,
									InnerTraces: []simulation.TransactionTrace{
										{
											ApprovalProgramTrace: creationOpcodeTrace,
											ApprovalProgramHash:  approvalDigest,
										},
										{},
										{
											ApprovalProgramTrace: optInTrace,
											ApprovalProgramHash:  approvalDigest,
										},
										{
											ClearStateProgramTrace: clearStateOpcodeTrace,
											ClearStateProgramHash:  clearStateDigest,
										},
										{
											ApprovalProgramTrace: recursiveLongOpcodeTrace,
											ApprovalProgramHash:  approvalDigest,
											InnerTraces: []simulation.TransactionTrace{
												{
													ApprovalProgramTrace: creationOpcodeTrace,
													ApprovalProgramHash:  approvalDigest,
												},
												{},
												{
													ApprovalProgramTrace: optInTrace,
													ApprovalProgramHash:  approvalDigest,
												},
												{
													ClearStateProgramTrace: clearStateOpcodeTrace,
													ClearStateProgramHash:  clearStateDigest,
												},
												{
													ApprovalProgramTrace: finalDepthTrace,
													ApprovalProgramHash:  approvalDigest,
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
	logicHash := crypto.Hash(program)
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

		op, err = logic.AssembleString(appCallTxn.ApprovalProgram.(string))
		require.NoError(t, err)
		approvalHash := crypto.Hash(op.Program)

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
					State:  true,
				},
			},
			developerAPI: true,
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					Stack:  true,
					State:  true,
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
									ApprovalProgramHash: approvalHash,
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
									LogicSigHash: logicHash,
								},
							},
						},
						AppBudgetAdded:    700,
						AppBudgetConsumed: 3,
					},
				},
				InitialStates: &simulation.ResourcesInitialStates{
					AllAppsInitialStates: simulation.AppsInitialStates{},
					CreatedApp:           util.MakeSet(basics.AppIndex(1002)),
				},
			},
		}
	})
}

func TestInvalidLogicSigPCandStack(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	op, err := logic.AssembleString(`#pragma version 8
` + strings.Repeat(`byte "a"; keccak256; pop
`, 2) + `int 0; int 1; -`)
	require.NoError(t, err)
	logicSigProg := logic.Program(op.Program)
	logicSigHash := crypto.Hash(logicSigProg)
	lsigAddr := basics.Address(crypto.HashObj(&logicSigProg))

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
		signedAppCallTxn.Lsig = transactions.LogicSig{Logic: logicSigProg}

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
									LogicSigHash: logicSigHash,
								},
							},
						},
					},
				},
			},
		}
	})
}

func TestInvalidApp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	op, err := logic.AssembleString(`#pragma version 8
` + strings.Repeat(`byte "a"; keccak256; pop
`, 2) + `int 1`)
	require.NoError(t, err)
	logicSigProg := logic.Program(op.Program)
	logicSigHash := crypto.Hash(logicSigProg)
	lsigAddr := basics.Address(crypto.HashObj(&logicSigProg))

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

		approvalOp, err := logic.AssembleString(appCallTxn.ApprovalProgram.(string))
		require.NoError(t, err)
		approvalHash := crypto.Hash(approvalOp.Program)

		txntest.Group(&payTxn, &appCallTxn)

		signedPayTxn := payTxn.Txn().Sign(sender.Sk)
		signedAppCallTxn := appCallTxn.SignedTxn()
		signedAppCallTxn.Lsig = transactions.LogicSig{Logic: logicSigProg}

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
									ApprovalProgramHash: approvalHash,
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
									LogicSigHash: logicSigHash,
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
  store 1                                 // [arg_0 * 3, "1!", "5!", 0, 2, 1, 1, 5]
  load 1                                  // [arg_0 * 3, "1!", "5!", 0, 2, 1, 1, 5, 18446744073709551615]
  stores                                  // [arg_0 * 3, "1!", "5!", 0, 2, 1, 1]
  load 1                                  // [arg_0 * 3, "1!", "5!", 0, 2, 1, 1, 18446744073709551615]
  store 1                                 // [arg_0 * 3, "1!", "5!", 0, 2, 1, 1]
  retsub

end:
  int 1
  return
`

func TestFrameBuryDigStackTrace(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	op, err := logic.AssembleString(FrameBuryDigProgram)
	require.NoError(t, err)
	hash := crypto.Hash(op.Program)

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
					Enable:  true,
					Stack:   true,
					Scratch: true,
				},
			},
			developerAPI: true,
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable:  true,
					Stack:   true,
					Scratch: true,
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
											PC:         90,
											StackAdded: goValuesToTealValues(1),
										},
										{
											PC:            91,
											StackAdded:    goValuesToTealValues(1),
											StackPopCount: 1,
										},
									},
									ApprovalProgramHash: hash,
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
								AppBudgetConsumed: 39,
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
										// store 1
										{
											PC:            80,
											StackPopCount: 1,
											ScratchSlotChanges: []simulation.ScratchChange{
												{
													Slot:     1,
													NewValue: goValuesToTealValues(uint64(math.MaxUint64))[0],
												},
											},
										},
										// load 1
										{
											PC:         82,
											StackAdded: goValuesToTealValues(uint64(math.MaxUint64)),
										},
										// stores
										{
											PC:            84,
											StackPopCount: 2,
											ScratchSlotChanges: []simulation.ScratchChange{
												{
													Slot:     5,
													NewValue: goValuesToTealValues(uint64(math.MaxUint64))[0],
												},
											},
										},
										// load 1
										{
											PC:         85,
											StackAdded: goValuesToTealValues(uint64(math.MaxUint64)),
										},
										// store 1
										{
											PC:            87,
											StackPopCount: 1,
											ScratchSlotChanges: []simulation.ScratchChange{
												{
													Slot:     1,
													NewValue: goValuesToTealValues(uint64(math.MaxUint64))[0],
												},
											},
										},
										// retsub
										{
											PC:            89,
											StackAdded:    goValuesToTealValues(applicationArg * 3),
											StackPopCount: 8,
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
											PC:         90,
											StackAdded: goValuesToTealValues(1),
										},
										// return
										{
											PC:            91,
											StackAdded:    goValuesToTealValues(1),
											StackPopCount: 1,
										},
									},
									ApprovalProgramHash: hash,
								},
							},
						},
						AppBudgetAdded:    1400,
						AppBudgetConsumed: 44,
					},
				},
			},
		}
	})
}

func TestBoxChangeExecTrace(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		futureAppID := basics.AppIndex(1001)
		boxContent := []byte("boxWriteContent")

		boxStateChangeTraceTemplate := func(opName string, units ...simulation.OpcodeTraceUnit) []simulation.OpcodeTraceUnit {
			begin := []simulation.OpcodeTraceUnit{
				{
					PC: 1,
					StackAdded: []basics.TealValue{
						{
							Type: basics.TealUintType,
							Uint: uint64(futureAppID),
						},
					},
				},
				{
					PC:            3,
					StackPopCount: 1,
				},
				{
					PC: 6,
					StackAdded: []basics.TealValue{
						{
							Type:  basics.TealBytesType,
							Bytes: "create",
						},
					},
				},
				{
					PC: 14,
					StackAdded: []basics.TealValue{
						{
							Type:  basics.TealBytesType,
							Bytes: "delete",
						},
					},
				},
				{
					PC: 22,
					StackAdded: []basics.TealValue{
						{
							Type:  basics.TealBytesType,
							Bytes: "read",
						},
					},
				},
				{
					PC: 28,
					StackAdded: []basics.TealValue{
						{
							Type:  basics.TealBytesType,
							Bytes: "write",
						},
					},
				},
				{
					PC: 35,
					StackAdded: []basics.TealValue{
						{
							Type:  basics.TealBytesType,
							Bytes: opName,
						},
					},
				},
				{
					PC:            38,
					StackPopCount: 5,
				},
			}
			end := []simulation.OpcodeTraceUnit{
				{
					PC: 87,
					StackAdded: []basics.TealValue{
						{
							Type: basics.TealUintType,
							Uint: 1,
						},
					},
				},
			}
			result := append(begin, units...)
			result = append(result, end...)
			return result
		}

		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationID:   0,
			ApprovalProgram: fmt.Sprintf(boxTestProgram, 8),
			ClearStateProgram: `#pragma version 8
int 1`,
		})

		op, err := logic.AssembleString(createTxn.ApprovalProgram.(string))
		require.NoError(t, err)
		progHash := crypto.Hash(op.Program)

		payment := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: futureAppID.Address(),
			Amount:   env.TxnInfo.CurrentProtocolParams().MinBalance * 2,
		})
		createBoxTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: futureAppID,
			ApplicationArgs: boxOperation{
				op:         logic.BoxCreateOperation,
				name:       "A",
				createSize: uint64(len(boxContent)),
			}.appArgs(),
			Boxes: []transactions.BoxRef{
				{Name: []byte("A")},
			},
		})
		writeBoxTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: futureAppID,
			ApplicationArgs: boxOperation{
				op:       logic.BoxWriteOperation,
				name:     "A",
				contents: boxContent,
			}.appArgs(),
			Boxes: []transactions.BoxRef{
				{Name: []byte("A")},
			},
		})
		delBoxTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: futureAppID,
			ApplicationArgs: boxOperation{
				op:   logic.BoxDeleteOperation,
				name: "A",
			}.appArgs(),
			Boxes: []transactions.BoxRef{
				{Name: []byte("A")},
			},
		})
		txntest.Group(&createTxn, &payment, &createBoxTxn, &writeBoxTxn, &delBoxTxn)

		signedCreate := createTxn.Txn().Sign(sender.Sk)
		signedPay := payment.Txn().Sign(sender.Sk)
		signedCreateBox := createBoxTxn.Txn().Sign(sender.Sk)
		signedWriteBox := writeBoxTxn.Txn().Sign(sender.Sk)
		signedDelBox := delBoxTxn.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedCreate, signedPay, signedCreateBox, signedWriteBox, signedDelBox},
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable:  true,
					Stack:   true,
					Scratch: true,
					State:   true,
				},
			},
			developerAPI: true,
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable:  true,
					Stack:   true,
					Scratch: true,
					State:   true,
				},
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							// App creation
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
									},
								},
								AppBudgetConsumed: 3,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
										{
											PC: 1,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
												},
											},
										},
										{
											PC:            3,
											StackPopCount: 1,
										},
										{
											PC: 87,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 1,
												},
											},
										},
									},
									ApprovalProgramHash: progHash,
								},
							},
							// Payment
							{
								Trace: &simulation.TransactionTrace{},
							},
							// BoxCreation
							{
								AppBudgetConsumed: 15,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: boxStateChangeTraceTemplate("create",
										simulation.OpcodeTraceUnit{
											PC: 49,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "A",
												},
											},
										},
										simulation.OpcodeTraceUnit{
											PC: 52,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: string(uint64ToBytes(uint64(len(boxContent)))),
												},
											},
										},
										simulation.OpcodeTraceUnit{
											PC: 55,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: uint64(len(boxContent)),
												},
											},
											StackPopCount: 1,
										},
										simulation.OpcodeTraceUnit{
											PC:            56,
											StackPopCount: 2,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 1,
												},
											},
											StateChanges: []simulation.StateOperation{
												{
													AppStateOp: logic.AppStateWrite,
													AppState:   logic.BoxState,
													AppID:      futureAppID,
													Key:        "A",
													NewValue: basics.TealValue{
														Type:  basics.TealBytesType,
														Bytes: string(make([]byte, len(boxContent))),
													},
												},
											},
										},
										simulation.OpcodeTraceUnit{
											PC:            57,
											StackPopCount: 1,
										},
										simulation.OpcodeTraceUnit{
											PC: 58,
										},
									),
									ApprovalProgramHash: progHash,
								},
							},
							// BoxWrite
							{
								AppBudgetConsumed: 13,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: boxStateChangeTraceTemplate("write",
										simulation.OpcodeTraceUnit{
											PC: 78,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "A",
												},
											},
										},
										simulation.OpcodeTraceUnit{
											PC: 81,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
												},
											},
										},
										simulation.OpcodeTraceUnit{
											PC: 83,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: string(boxContent),
												},
											},
										},
										simulation.OpcodeTraceUnit{
											PC:            86,
											StackPopCount: 3,
											StateChanges: []simulation.StateOperation{
												{
													AppStateOp: logic.AppStateWrite,
													AppState:   logic.BoxState,
													AppID:      futureAppID,
													Key:        "A",
													NewValue: basics.TealValue{
														Type:  basics.TealBytesType,
														Bytes: string(boxContent),
													},
												},
											},
										},
									),
									ApprovalProgramHash: progHash,
								},
							},
							// BoxDelete
							{
								AppBudgetConsumed: 13,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: boxStateChangeTraceTemplate("delete",
										simulation.OpcodeTraceUnit{
											PC: 61,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "A",
												},
											},
										},
										simulation.OpcodeTraceUnit{
											PC: 64,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 1,
												},
											},
											StackPopCount: 1,
											StateChanges: []simulation.StateOperation{
												{
													AppStateOp: logic.AppStateDelete,
													AppState:   logic.BoxState,
													AppID:      futureAppID,
													Key:        "A",
												},
											},
										},
										simulation.OpcodeTraceUnit{
											PC:            65,
											StackPopCount: 1,
										},
										simulation.OpcodeTraceUnit{
											PC: 66,
										},
									),
									ApprovalProgramHash: progHash,
								},
							},
						},
						AppBudgetAdded:    2800,
						AppBudgetConsumed: 44,
					},
				},
				InitialStates: &simulation.ResourcesInitialStates{
					AllAppsInitialStates: make(simulation.AppsInitialStates),
					CreatedApp:           util.MakeSet(futureAppID),
				},
			},
		}
	})
}

func TestAppLocalGlobalStateChange(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		approvalProgramSrc := `#pragma version 8
txn ApplicationID
bz end // Do nothing during create

txn OnCompletion
int OptIn
==
bnz end // Always allow optin

byte "local"
byte "global"
txn ApplicationArgs 0
match local global
err // Unknown command

local:
  txn Sender
  byte "local-int-key"
  int 0xcafeb0ba
  app_local_put
  int 0
  byte "local-bytes-key"
  byte "xqcL"
  app_local_put
  b end

global:
  byte "global-int-key"
  int 0xdeadbeef
  app_global_put
  byte "global-bytes-key"
  byte "welt am draht"
  app_global_put
  b end

end:
  int 1
`

		sender := env.Accounts[0]

		createdAppID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
			GlobalStateSchema: basics.StateSchema{NumUint: 1, NumByteSlice: 1},
			LocalStateSchema:  basics.StateSchema{NumUint: 1, NumByteSlice: 1},
			ApprovalProgram:   approvalProgramSrc,
			ClearStateProgram: `#pragma version 8
int 1`,
		})

		op, err := logic.AssembleString(approvalProgramSrc)
		require.NoError(t, err)
		progHash := crypto.Hash(op.Program)

		optIn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			OnCompletion:  transactions.OptInOC,
			Sender:        sender.Addr,
			ApplicationID: createdAppID,
		})

		globalStateCall := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationID:   createdAppID,
			ApplicationArgs: [][]byte{[]byte("global")},
		})

		localStateCall := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationID:   createdAppID,
			ApplicationArgs: [][]byte{[]byte("local")},
		})

		txntest.Group(&optIn, &globalStateCall, &localStateCall)

		signedOptin := optIn.Txn().Sign(sender.Sk)
		signedGlobalStateCall := globalStateCall.Txn().Sign(sender.Sk)
		signedLocalStateCall := localStateCall.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedOptin, signedGlobalStateCall, signedLocalStateCall},
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable:  true,
					Stack:   true,
					Scratch: true,
					State:   true,
				},
			},
			developerAPI: true,
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable:  true,
					Stack:   true,
					Scratch: true,
					State:   true,
				},
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							// Optin
							{
								AppBudgetConsumed: 8,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
										{
											PC: 1,
										},
										{
											PC: 4,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: uint64(createdAppID),
												},
											},
										},
										{
											PC:            6,
											StackPopCount: 1,
										},
										{
											PC: 9,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 1,
												},
											},
										},
										{
											PC: 11,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 1,
												},
											},
										},
										{
											PC: 12,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 1,
												},
											},
											StackPopCount: 2,
										},
										{
											PC:            13,
											StackPopCount: 1,
										},
										{
											PC: 154,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 1,
												},
											},
										},
									},
									ApprovalProgramHash: progHash,
								},
							},
							// Global
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										EvalDelta: transactions.EvalDelta{
											GlobalDelta: basics.StateDelta{
												"global-bytes-key": basics.ValueDelta{
													Bytes:  "welt am draht",
													Action: basics.SetBytesAction,
												},
												"global-int-key": basics.ValueDelta{
													Uint:   0xdeadbeef,
													Action: basics.SetUintAction,
												},
											},
										},
									},
								},
								AppBudgetConsumed: 19,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
										{
											PC: 1,
										},
										{
											PC: 4,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: uint64(createdAppID),
												},
											},
										},
										{
											PC:            6,
											StackPopCount: 1,
										},
										{
											PC: 9,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
												},
											},
										},
										{
											PC: 11,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 1,
												},
											},
										},
										{
											PC: 12,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
												},
											},
											StackPopCount: 2,
										},
										{
											PC:            13,
											StackPopCount: 1,
										},
										{
											PC: 16,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "local",
												},
											},
										},
										{
											PC: 23,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "global",
												},
											},
										},
										{
											PC: 31,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "global",
												},
											},
										},
										{
											PC:            34,
											StackPopCount: 3,
										},
										{
											PC: 94,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "global-int-key",
												},
											},
										},
										{
											PC: 110,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 0xdeadbeef,
												},
											},
										},
										{
											PC: 116,
											StateChanges: []simulation.StateOperation{
												{
													AppStateOp: logic.AppStateWrite,
													AppState:   logic.GlobalState,
													AppID:      createdAppID,
													Key:        "global-int-key",
													NewValue: basics.TealValue{
														Type: basics.TealUintType,
														Uint: 0xdeadbeef,
													},
												},
											},
											StackPopCount: 2,
										},
										{
											PC: 117,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "global-bytes-key",
												},
											},
										},
										{
											PC: 135,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "welt am draht",
												},
											},
										},
										{
											PC:            150,
											StackPopCount: 2,
											StateChanges: []simulation.StateOperation{
												{
													AppStateOp: logic.AppStateWrite,
													AppState:   logic.GlobalState,
													AppID:      createdAppID,
													Key:        "global-bytes-key",
													NewValue: basics.TealValue{
														Type:  basics.TealBytesType,
														Bytes: "welt am draht",
													},
												},
											},
										},
										{PC: 151},
										{
											PC: 154,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 1,
												},
											},
										},
									},
									ApprovalProgramHash: progHash,
								},
							},
							// Local
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										EvalDelta: transactions.EvalDelta{
											LocalDeltas: map[uint64]basics.StateDelta{
												0: {
													"local-bytes-key": basics.ValueDelta{
														Bytes:  "xqcL",
														Action: basics.SetBytesAction,
													},
													"local-int-key": basics.ValueDelta{
														Uint:   0xcafeb0ba,
														Action: basics.SetUintAction,
													},
												},
											},
										},
									},
								},
								AppBudgetConsumed: 21,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
										{
											PC: 1,
										},
										{
											PC: 4,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: uint64(createdAppID),
												},
											},
										},
										{
											PC:            6,
											StackPopCount: 1,
										},
										{
											PC: 9,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
												},
											},
										},
										{
											PC: 11,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 1,
												},
											},
										},
										{
											PC: 12,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
												},
											},
											StackPopCount: 2,
										},
										{
											PC:            13,
											StackPopCount: 1,
										},
										{
											PC: 16,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "local",
												},
											},
										},
										{
											PC: 23,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "global",
												},
											},
										},
										{
											PC: 31,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "local",
												},
											},
										},
										{
											PC:            34,
											StackPopCount: 3,
										},
										{
											PC: 41,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: string(sender.Addr[:]),
												},
											},
										},
										{
											PC: 43,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "local-int-key",
												},
											},
										},
										{
											PC: 58,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 0xcafeb0ba,
												},
											},
										},
										{
											PC: 64,
											StateChanges: []simulation.StateOperation{
												{
													AppStateOp: logic.AppStateWrite,
													AppState:   logic.LocalState,
													AppID:      createdAppID,
													Key:        "local-int-key",
													NewValue: basics.TealValue{
														Type: basics.TealUintType,
														Uint: 0xcafeb0ba,
													},
													Account: sender.Addr,
												},
											},
											StackPopCount: 3,
										},
										{
											PC: 65,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
												},
											},
										},
										{
											PC: 67,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "local-bytes-key",
												},
											},
										},
										{
											PC: 84,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "xqcL",
												},
											},
										},
										{
											PC:            90,
											StackPopCount: 3,
											StateChanges: []simulation.StateOperation{
												{
													AppStateOp: logic.AppStateWrite,
													AppState:   logic.LocalState,
													AppID:      createdAppID,
													Key:        "local-bytes-key",
													NewValue: basics.TealValue{
														Type:  basics.TealBytesType,
														Bytes: "xqcL",
													},
													Account: sender.Addr,
												},
											},
										},
										{PC: 91},
										{
											PC: 154,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 1,
												},
											},
										},
									},
									ApprovalProgramHash: progHash,
								},
							},
						},
						AppBudgetAdded:    2100,
						AppBudgetConsumed: 48,
					},
				},
				InitialStates: &simulation.ResourcesInitialStates{
					AllAppsInitialStates: simulation.AppsInitialStates{
						createdAppID: simulation.SingleAppInitialStates{
							AppLocals:      map[basics.Address]simulation.AppKVPairs{},
							AppGlobals:     simulation.AppKVPairs{},
							AppBoxes:       simulation.AppKVPairs{},
							CreatedGlobals: util.MakeSet("global-bytes-key", "global-int-key"),
							CreatedBoxes:   make(util.Set[string]),
							CreatedLocals: map[basics.Address]util.Set[string]{
								sender.Addr: util.MakeSet("local-bytes-key", "local-int-key"),
							},
						},
					},
					CreatedApp: util.Set[basics.AppIndex]{},
				},
			},
		}
	})
}

func TestAppLocalGlobalStateChangeClearStateRollback(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	for _, shouldError := range []bool{false, true} {
		t.Run(fmt.Sprintf("shouldError=%v", shouldError), func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
				sender := env.Accounts[0]

				approvalProgram := `#pragma version 8
int 1`
				clearStateProgram := `#pragma version 8
byte "global key"
byte "global value"
app_global_put

txn Sender
byte "local key"
byte "local value"
app_local_put
`

				if shouldError {
					clearStateProgram += "err"
				} else {
					clearStateProgram += "int 0"
				}

				createdAppID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
					GlobalStateSchema: basics.StateSchema{NumByteSlice: 1},
					LocalStateSchema:  basics.StateSchema{NumByteSlice: 1},
					ApprovalProgram:   approvalProgram,
					ClearStateProgram: clearStateProgram,
				})

				op, err := logic.AssembleString(clearStateProgram)
				require.NoError(t, err)
				progHash := crypto.Hash(op.Program)

				env.OptIntoApp(sender.Addr, createdAppID)

				clearStateTxn := env.TxnInfo.NewTxn(txntest.Txn{
					Type:          protocol.ApplicationCallTx,
					Sender:        sender.Addr,
					ApplicationID: createdAppID,
					OnCompletion:  transactions.ClearStateOC,
				})

				signedClearStateTxn := clearStateTxn.Txn().Sign(sender.Sk)

				clearStateRollbackError := ""
				clearStateProgramTrace := []simulation.OpcodeTraceUnit{
					{
						PC: 1,
						StackAdded: []basics.TealValue{
							{
								Type:  basics.TealBytesType,
								Bytes: "global key",
							},
						},
					},
					{
						PC: 13,
						StackAdded: []basics.TealValue{
							{
								Type:  basics.TealBytesType,
								Bytes: "global value",
							},
						},
					},
					{
						PC:            27,
						StackPopCount: 2,
						StateChanges: []simulation.StateOperation{
							{
								AppStateOp: logic.AppStateWrite,
								AppState:   logic.GlobalState,
								AppID:      createdAppID,
								Key:        "global key",
								NewValue: basics.TealValue{
									Type:  basics.TealBytesType,
									Bytes: "global value",
								},
							},
						},
					},
					{
						PC: 28,
						StackAdded: []basics.TealValue{
							{
								Type:  basics.TealBytesType,
								Bytes: string(sender.Addr[:]),
							},
						},
					},
					{
						PC: 30,
						StackAdded: []basics.TealValue{
							{
								Type:  basics.TealBytesType,
								Bytes: "local key",
							},
						},
					},
					{
						PC: 41,
						StackAdded: []basics.TealValue{
							{
								Type:  basics.TealBytesType,
								Bytes: "local value",
							},
						},
					},
					{
						PC:            54,
						StackPopCount: 3,
						StateChanges: []simulation.StateOperation{
							{
								AppStateOp: logic.AppStateWrite,
								AppState:   logic.LocalState,
								AppID:      createdAppID,
								Account:    sender.Addr,
								Key:        "local key",
								NewValue: basics.TealValue{
									Type:  basics.TealBytesType,
									Bytes: "local value",
								},
							},
						},
					},
					{
						PC: 55,
						StackAdded: []basics.TealValue{
							{
								Type: basics.TealUintType,
								Uint: 0,
							},
						},
					},
				}

				if shouldError {
					clearStateRollbackError = "err opcode executed"
					clearStateProgramTrace[len(clearStateProgramTrace)-1].StackAdded = nil
				}

				return simulationTestCase{
					input: simulation.Request{
						TxnGroups: [][]transactions.SignedTxn{{signedClearStateTxn}},
						TraceConfig: simulation.ExecTraceConfig{
							Enable:  true,
							Stack:   true,
							Scratch: true,
							State:   true,
						},
					},
					developerAPI: true,
					expected: simulation.Result{
						Version:   simulation.ResultLatestVersion,
						LastRound: env.TxnInfo.LatestRound(),
						TraceConfig: simulation.ExecTraceConfig{
							Enable:  true,
							Stack:   true,
							Scratch: true,
							State:   true,
						},
						TxnGroups: []simulation.TxnGroupResult{
							{
								Txns: []simulation.TxnResult{
									{
										AppBudgetConsumed: 8,
										Trace: &simulation.TransactionTrace{
											ClearStateProgramTrace:  clearStateProgramTrace,
											ClearStateProgramHash:   progHash,
											ClearStateRollback:      true,
											ClearStateRollbackError: clearStateRollbackError,
										},
									},
								},
								AppBudgetAdded:    700,
								AppBudgetConsumed: 8,
							},
						},
						InitialStates: &simulation.ResourcesInitialStates{
							AllAppsInitialStates: simulation.AppsInitialStates{
								createdAppID: {
									AppLocals:  map[basics.Address]simulation.AppKVPairs{},
									AppGlobals: simulation.AppKVPairs{},
									AppBoxes:   simulation.AppKVPairs{},
									// It's fine to leave the keys in "CreatedX" for two reasons:
									// 1. These fields really just mean state was accessed that
									//    didn't exist before, so we shouldn't try to report an
									//    initial value.
									// 2. These values are not included in the REST API, so they are
									//    not going to confuse users.
									CreatedGlobals: util.MakeSet("global key"),
									CreatedBoxes:   make(util.Set[string]),
									CreatedLocals: map[basics.Address]util.Set[string]{
										sender.Addr: util.MakeSet("local key"),
									},
								},
							},
							CreatedApp: util.Set[basics.AppIndex]{},
						},
					},
				}
			})
		})
	}
}

func TestGlobalStateTypeChangeErr(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		sender := env.Accounts[0]

		futureAppID := basics.AppIndex(1001)

		createTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:              protocol.ApplicationCallTx,
			Sender:            sender.Addr,
			ApplicationID:     0,
			GlobalStateSchema: basics.StateSchema{NumUint: 1},
			ApprovalProgram: `#pragma version 8
txn ApplicationID
bz end // Do nothing during create

byte "global-key"
byte "I pretend myself as an uint"
app_global_put

end:
  int 1
`,
			ClearStateProgram: `#pragma version 8
int 1`,
		})

		op, err := logic.AssembleString(createTxn.ApprovalProgram.(string))
		require.NoError(t, err)
		progHash := crypto.Hash(op.Program)

		globalStateCall := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: futureAppID,
		})

		txntest.Group(&createTxn, &globalStateCall)

		signedCreate := createTxn.Txn().Sign(sender.Sk)
		signedGlobalStateCall := globalStateCall.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					{signedCreate, signedGlobalStateCall},
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable:  true,
					Stack:   true,
					Scratch: true,
					State:   true,
				},
			},
			developerAPI:  true,
			expectedError: "store bytes count 1 exceeds schema bytes count 0.",
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable:  true,
					Stack:   true,
					Scratch: true,
					State:   true,
				},
				TxnGroups: []simulation.TxnGroupResult{
					{
						FailedAt: simulation.TxnPath{1},
						Txns: []simulation.TxnResult{
							// App creation
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
									},
								},
								AppBudgetConsumed: 3,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
										{
											PC: 1,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
												},
											},
										},
										{
											PC:            3,
											StackPopCount: 1,
										},
										{
											PC: 48,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: 1,
												},
											},
										},
									},
									ApprovalProgramHash: progHash,
								},
							},
							// Global
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										EvalDelta: transactions.EvalDelta{
											GlobalDelta: basics.StateDelta{
												"global-key": basics.ValueDelta{
													Bytes:  "I pretend myself as an uint",
													Action: basics.SetBytesAction,
												},
											},
										},
									},
								},
								AppBudgetConsumed: 5,
								Trace: &simulation.TransactionTrace{
									ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
										{
											PC: 1,
											StackAdded: []basics.TealValue{
												{
													Type: basics.TealUintType,
													Uint: uint64(futureAppID),
												},
											},
										},
										{
											PC:            3,
											StackPopCount: 1,
										},
										{
											PC: 6,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "global-key",
												},
											},
										},
										{
											PC: 18,
											StackAdded: []basics.TealValue{
												{
													Type:  basics.TealBytesType,
													Bytes: "I pretend myself as an uint",
												},
											},
										},
										{
											PC:            47,
											StackPopCount: 2,
											StateChanges: []simulation.StateOperation{
												{
													AppStateOp: logic.AppStateWrite,
													AppState:   logic.GlobalState,
													AppID:      futureAppID,
													Key:        "global-key",
												},
											},
										},
									},
									ApprovalProgramHash: progHash,
								},
							},
						},
						AppBudgetAdded:    1400,
						AppBudgetConsumed: 8,
					},
				},
				InitialStates: &simulation.ResourcesInitialStates{
					AllAppsInitialStates: make(simulation.AppsInitialStates),
					CreatedApp:           util.MakeSet(futureAppID),
				},
			},
		}
	})
}

type BoxInitialStatesTestCase struct {
	boxOpsForPrepare  []boxOperation
	boxOpsForSimulate []boxOperation
	initialBoxStates  simulation.AppKVPairs
}

func testBoxInitialStatesHelper(t *testing.T, testcase BoxInitialStatesTestCase) {
	t.Helper()

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		proto := env.TxnInfo.CurrentProtocolParams()
		appCreator := env.Accounts[0]

		boxApprovalProgram := fmt.Sprintf(boxTestProgram, 8)
		boxAppID := env.CreateApp(appCreator.Addr, simulationtesting.AppParams{
			ApprovalProgram: boxApprovalProgram,
			ClearStateProgram: `#pragma version 8
int 1`,
		})

		op, err := logic.AssembleString(boxApprovalProgram)
		require.NoError(t, err)
		progHash := crypto.Hash(op.Program)

		transferable := env.Accounts[1].AcctData.MicroAlgos.Raw - proto.MinBalance - proto.MinTxnFee
		env.TransferAlgos(env.Accounts[1].Addr, boxAppID.Address(), transferable)

		for _, boxOp := range testcase.boxOpsForPrepare {
			env.Txn(env.TxnInfo.NewTxn(txntest.Txn{
				Type:            protocol.ApplicationCallTx,
				Sender:          appCreator.Addr,
				ApplicationID:   boxAppID,
				ApplicationArgs: boxOp.appArgs(),
				Boxes:           boxOp.boxRefs(),
			}).SignedTxn())
		}

		boxOpToSimResult := func(boxOp boxOperation) simulation.TxnResult {
			var res simulation.TxnResult
			switch boxOp.op {
			case logic.BoxReadOperation:
				res = simulation.TxnResult{
					AppBudgetConsumed: 14,
					Trace: &simulation.TransactionTrace{
						ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
							{PC: 1},
							{PC: 3},
							{PC: 6},
							{PC: 14},
							{PC: 22},
							{PC: 28},
							{PC: 35},
							{PC: 38},
							{PC: 69},
							{PC: 72},
							{PC: 73},
							{PC: 74},
							{PC: 75},
							{PC: 87},
						},
						ApprovalProgramHash: progHash,
					},
				}
			case logic.BoxWriteOperation:
				res = simulation.TxnResult{
					AppBudgetConsumed: 13,
					Trace: &simulation.TransactionTrace{
						ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
							{PC: 1},
							{PC: 3},
							{PC: 6},
							{PC: 14},
							{PC: 22},
							{PC: 28},
							{PC: 35},
							{PC: 38},
							{PC: 78},
							{PC: 81},
							{PC: 83},
							{
								PC: 86,
								StateChanges: []simulation.StateOperation{
									{
										AppStateOp: logic.AppStateWrite,
										AppState:   logic.BoxState,
										AppID:      boxAppID,
										Key:        boxOp.name,
										NewValue: basics.TealValue{
											Type:  basics.TealBytesType,
											Bytes: string(boxOp.contents),
										},
									},
								},
							},
							{PC: 87},
						},
						ApprovalProgramHash: progHash,
					},
				}
			case logic.BoxCreateOperation:
				res = simulation.TxnResult{
					AppBudgetConsumed: 15,
					Trace: &simulation.TransactionTrace{
						ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
							{PC: 1},
							{PC: 3},
							{PC: 6},
							{PC: 14},
							{PC: 22},
							{PC: 28},
							{PC: 35},
							{PC: 38},
							{PC: 49},
							{PC: 52},
							{PC: 55},
							{
								PC: 56,
								StateChanges: []simulation.StateOperation{
									{
										AppStateOp: logic.AppStateWrite,
										AppState:   logic.BoxState,
										AppID:      boxAppID,
										Key:        boxOp.name,
										NewValue: basics.TealValue{
											Type:  basics.TealBytesType,
											Bytes: string(make([]byte, boxOp.createSize)),
										},
									},
								},
							},
							{PC: 57},
							{PC: 58},
							{PC: 87},
						},
						ApprovalProgramHash: progHash,
					},
				}
			case logic.BoxDeleteOperation:
				res = simulation.TxnResult{
					AppBudgetConsumed: 13,
					Trace: &simulation.TransactionTrace{
						ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
							{PC: 1},
							{PC: 3},
							{PC: 6},
							{PC: 14},
							{PC: 22},
							{PC: 28},
							{PC: 35},
							{PC: 38},
							{PC: 61},
							{
								PC: 64,
								StateChanges: []simulation.StateOperation{
									{
										AppStateOp: logic.AppStateDelete,
										AppState:   logic.BoxState,
										AppID:      boxAppID,
										Key:        boxOp.name,
									},
								},
							},
							{PC: 65},
							{PC: 66},
							{PC: 87},
						},
						ApprovalProgramHash: progHash,
					},
				}
			}
			return res
		}

		txnPtrs := make([]*txntest.Txn, len(testcase.boxOpsForSimulate))
		for i, boxOp := range testcase.boxOpsForSimulate {
			tempTxn := env.TxnInfo.NewTxn(txntest.Txn{
				Type:            protocol.ApplicationCallTx,
				Sender:          appCreator.Addr,
				ApplicationID:   boxAppID,
				ApplicationArgs: boxOp.appArgs(),
				Boxes:           boxOp.boxRefs(),
			})
			txnPtrs[i] = &tempTxn
		}

		txntest.Group(txnPtrs...)
		signedTxns := make([]transactions.SignedTxn, len(testcase.boxOpsForSimulate))
		for i, txn := range txnPtrs {
			signedTxns[i] = txn.Txn().Sign(appCreator.Sk)
		}

		txnResults := make([]simulation.TxnResult, len(testcase.boxOpsForSimulate))
		for i, boxOp := range testcase.boxOpsForSimulate {
			txnResults[i] = boxOpToSimResult(boxOp)
		}
		totalConsumed := 0
		for _, txnResult := range txnResults {
			totalConsumed += txnResult.AppBudgetConsumed
		}

		prepareKeys := make(util.Set[string])
		for _, instruction := range testcase.boxOpsForPrepare {
			if instruction.op != logic.BoxWriteOperation {
				continue
			}
			prepareKeys.Add(instruction.name)
		}
		newlyCreatedGlobalKeySet := make(util.Set[string])
		for _, instruction := range testcase.boxOpsForSimulate {
			if instruction.op != logic.BoxWriteOperation {
				continue
			}
			if prepareKeys.Contains(instruction.name) {
				continue
			}
			newlyCreatedGlobalKeySet.Add(instruction.name)
		}

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					signedTxns,
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					State:  true,
				},
			},
			developerAPI: true,
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					State:  true,
				},
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns:              txnResults,
						AppBudgetAdded:    700 * len(txnResults),
						AppBudgetConsumed: totalConsumed,
					},
				},
				InitialStates: &simulation.ResourcesInitialStates{
					AllAppsInitialStates: simulation.AppsInitialStates{
						boxAppID: simulation.SingleAppInitialStates{
							AppGlobals:     make(simulation.AppKVPairs),
							AppLocals:      map[basics.Address]simulation.AppKVPairs{},
							AppBoxes:       testcase.initialBoxStates,
							CreatedGlobals: make(util.Set[string]),
							CreatedBoxes:   newlyCreatedGlobalKeySet,
							CreatedLocals:  map[basics.Address]util.Set[string]{},
						},
					},
					CreatedApp: util.Set[basics.AppIndex]{},
				},
			},
		}
	})
}

func TestAppInitialBoxStates(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testBoxInitialStatesHelper(t, BoxInitialStatesTestCase{
		boxOpsForPrepare: []boxOperation{
			{
				op:         logic.BoxCreateOperation,
				name:       "A",
				createSize: 21,
			},
			{
				op:       logic.BoxWriteOperation,
				name:     "A",
				contents: []byte("initial box A content"),
			},
		},
		boxOpsForSimulate: []boxOperation{
			{
				op:   logic.BoxReadOperation,
				name: "A",
			},
			{
				op:       logic.BoxWriteOperation,
				name:     "A",
				contents: []byte("box A get overwritten"),
			},
		},
		initialBoxStates: simulation.AppKVPairs{
			"A": {
				Type:  basics.TealBytesType,
				Bytes: "initial box A content",
			},
		},
	})

	testBoxInitialStatesHelper(t, BoxInitialStatesTestCase{
		boxOpsForPrepare: []boxOperation{
			{
				op:         logic.BoxCreateOperation,
				name:       "A",
				createSize: 21,
			},
			{
				op:       logic.BoxWriteOperation,
				name:     "A",
				contents: []byte("initial box A content"),
			},
			{
				op:         logic.BoxCreateOperation,
				name:       "B",
				createSize: 21,
			},
			{
				op:       logic.BoxWriteOperation,
				name:     "B",
				contents: []byte("initial box B content"),
			},
			{
				op:         logic.BoxCreateOperation,
				name:       "C",
				createSize: 21,
			},
			{
				op:       logic.BoxWriteOperation,
				name:     "C",
				contents: []byte("initial box C content"),
			},
		},
		boxOpsForSimulate: []boxOperation{
			{
				op:   logic.BoxDeleteOperation,
				name: "C",
			},
			{
				op:   logic.BoxReadOperation,
				name: "A",
			},
		},
		initialBoxStates: simulation.AppKVPairs{
			"A": {
				Type:  basics.TealBytesType,
				Bytes: "initial box A content",
			},
			"C": {
				Type:  basics.TealBytesType,
				Bytes: "initial box C content",
			},
		},
	})

	testBoxInitialStatesHelper(t, BoxInitialStatesTestCase{
		boxOpsForPrepare: []boxOperation{
			{
				op:         logic.BoxCreateOperation,
				name:       "A",
				createSize: 21,
			},
			{
				op:       logic.BoxWriteOperation,
				name:     "A",
				contents: []byte("initial box A content"),
			},
			{
				op:         logic.BoxCreateOperation,
				name:       "C",
				createSize: 21,
			},
			{
				op:       logic.BoxWriteOperation,
				name:     "C",
				contents: []byte("initial box C content"),
			},
		},
		boxOpsForSimulate: []boxOperation{
			{
				op:         logic.BoxCreateOperation,
				name:       "B",
				createSize: 21,
			},
			{
				op:       logic.BoxWriteOperation,
				name:     "B",
				contents: []byte("initial box B content"),
			},
		},
		initialBoxStates: simulation.AppKVPairs{},
	})
}

func testBoxPutInitialStatesHelper(t *testing.T, testcase BoxInitialStatesTestCase) {
	t.Helper()

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		proto := env.TxnInfo.CurrentProtocolParams()
		appCreator := env.Accounts[0]

		boxApprovalProgram := `#pragma version 8
txn ApplicationID
bz end // Do nothing during create

byte "write"
byte "delete"
txn ApplicationArgs 0
match put del
err // Unknown command

put:
txn ApplicationArgs 1
txn ApplicationArgs 2
box_put
b end

del:
txn ApplicationArgs 1
box_del
assert
b end

end:
int 1
`
		boxAppID := env.CreateApp(appCreator.Addr, simulationtesting.AppParams{
			ApprovalProgram: boxApprovalProgram,
			ClearStateProgram: `#pragma version 8
		int 1`,
		})

		op, err := logic.AssembleString(boxApprovalProgram)
		require.NoError(t, err)
		progHash := crypto.Hash(op.Program)

		transferable := env.Accounts[1].AcctData.MicroAlgos.Raw - proto.MinBalance - proto.MinTxnFee
		env.TransferAlgos(env.Accounts[1].Addr, boxAppID.Address(), transferable)

		for _, boxOp := range testcase.boxOpsForPrepare {
			env.Txn(env.TxnInfo.NewTxn(txntest.Txn{
				Type:            protocol.ApplicationCallTx,
				Sender:          appCreator.Addr,
				ApplicationID:   boxAppID,
				ApplicationArgs: boxOp.appArgs(),
				Boxes:           boxOp.boxRefs(),
			}).SignedTxn())
		}

		boxOpToSimResult := func(boxOp boxOperation) simulation.TxnResult {
			var res simulation.TxnResult
			switch boxOp.op {
			case logic.BoxWriteOperation:
				res = simulation.TxnResult{
					AppBudgetConsumed: 11,
					Trace: &simulation.TransactionTrace{
						ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
							{PC: 1},
							{PC: 3},
							{PC: 6},
							{PC: 13},
							{PC: 21},
							{PC: 24},
							{PC: 31},
							{PC: 34},
							{
								PC: 37,
								StateChanges: []simulation.StateOperation{
									{
										AppStateOp: logic.AppStateWrite,
										AppState:   logic.BoxState,
										AppID:      boxAppID,
										Key:        boxOp.name,
										NewValue: basics.TealValue{
											Type:  basics.TealBytesType,
											Bytes: string(boxOp.contents),
										},
									},
								},
							},
							{PC: 38},
							{PC: 49},
						},
						ApprovalProgramHash: progHash,
					},
				}
			case logic.BoxDeleteOperation:
				res = simulation.TxnResult{
					AppBudgetConsumed: 11,
					Trace: &simulation.TransactionTrace{
						ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
							{PC: 1},
							{PC: 3},
							{PC: 6},
							{PC: 13},
							{PC: 21},
							{PC: 24},
							{PC: 31},
							{PC: 34},
							{PC: 37},
							{PC: 61},
							{
								PC: 64,
								StateChanges: []simulation.StateOperation{
									{
										AppStateOp: logic.AppStateDelete,
										AppState:   logic.BoxState,
										AppID:      boxAppID,
										Key:        boxOp.name,
									},
								},
							},
							{PC: 65},
							{PC: 66},
							{PC: 87},
						},
						ApprovalProgramHash: progHash,
					},
				}
			}
			return res
		}

		txnPtrs := make([]*txntest.Txn, len(testcase.boxOpsForSimulate))
		for i, boxOp := range testcase.boxOpsForSimulate {
			tempTxn := env.TxnInfo.NewTxn(txntest.Txn{
				Type:            protocol.ApplicationCallTx,
				Sender:          appCreator.Addr,
				ApplicationID:   boxAppID,
				ApplicationArgs: boxOp.appArgs(),
				Boxes:           boxOp.boxRefs(),
			})
			txnPtrs[i] = &tempTxn
		}

		txntest.Group(txnPtrs...)
		signedTxns := make([]transactions.SignedTxn, len(testcase.boxOpsForSimulate))
		for i, txn := range txnPtrs {
			signedTxns[i] = txn.Txn().Sign(appCreator.Sk)
		}

		txnResults := make([]simulation.TxnResult, len(testcase.boxOpsForSimulate))
		for i, boxOp := range testcase.boxOpsForSimulate {
			txnResults[i] = boxOpToSimResult(boxOp)
		}
		totalConsumed := 0
		for _, txnResult := range txnResults {
			totalConsumed += txnResult.AppBudgetConsumed
		}

		prepareKeys := make(util.Set[string])
		for _, instruction := range testcase.boxOpsForPrepare {
			if instruction.op != logic.BoxWriteOperation {
				continue
			}
			prepareKeys.Add(instruction.name)
		}
		newlyCreatedGlobalKeySet := make(util.Set[string])
		for _, instruction := range testcase.boxOpsForSimulate {
			if instruction.op != logic.BoxWriteOperation {
				continue
			}
			if prepareKeys.Contains(instruction.name) {
				continue
			}
			newlyCreatedGlobalKeySet.Add(instruction.name)
		}

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					signedTxns,
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					State:  true,
				},
			},
			developerAPI: true,
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					State:  true,
				},
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns:              txnResults,
						AppBudgetAdded:    700 * len(txnResults),
						AppBudgetConsumed: totalConsumed,
					},
				},
				InitialStates: &simulation.ResourcesInitialStates{
					AllAppsInitialStates: simulation.AppsInitialStates{
						boxAppID: simulation.SingleAppInitialStates{
							AppGlobals:     make(simulation.AppKVPairs),
							AppLocals:      map[basics.Address]simulation.AppKVPairs{},
							AppBoxes:       testcase.initialBoxStates,
							CreatedGlobals: make(util.Set[string]),
							CreatedBoxes:   newlyCreatedGlobalKeySet,
							CreatedLocals:  map[basics.Address]util.Set[string]{},
						},
					},
					CreatedApp: util.Set[basics.AppIndex]{},
				},
			},
		}
	})
}

func TestAppInitialBoxStatesAboutBoxPut(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testBoxPutInitialStatesHelper(t, BoxInitialStatesTestCase{
		boxOpsForPrepare: []boxOperation{
			{
				op:       logic.BoxWriteOperation,
				name:     "A",
				contents: []byte("initial box A content"),
			},
		},
		boxOpsForSimulate: []boxOperation{
			{
				op:       logic.BoxWriteOperation,
				name:     "A",
				contents: []byte("box A get overwritten"),
			},
		},
		initialBoxStates: simulation.AppKVPairs{
			"A": {
				Type:  basics.TealBytesType,
				Bytes: "initial box A content",
			},
		},
	})

	testBoxPutInitialStatesHelper(t, BoxInitialStatesTestCase{
		boxOpsForSimulate: []boxOperation{
			{
				op:       logic.BoxWriteOperation,
				name:     "A",
				contents: []byte("box A get overwritten"),
			},
		},
		initialBoxStates: simulation.AppKVPairs{},
	})
}

type GlobalInitialStatesTestCase struct {
	prepareInstruction  [][][]byte
	txnsArgs            [][][]byte
	initialGlobalStates simulation.AppKVPairs
}

func (l GlobalInitialStatesTestCase) toSignedTxns(env simulationtesting.Environment, addr simulationtesting.Account, appID basics.AppIndex) []transactions.SignedTxn {
	txns := make([]*txntest.Txn, len(l.txnsArgs))
	for i, txnArgs := range l.txnsArgs {
		tempTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          addr.Addr,
			ApplicationID:   appID,
			ApplicationArgs: txnArgs,
		})
		txns[i] = &tempTxn
	}
	txntest.Group(txns...)
	signedTxns := make([]transactions.SignedTxn, len(l.txnsArgs))
	for i, txn := range txns {
		signedTxns[i] = txn.Txn().Sign(addr.Sk)
	}
	return signedTxns
}

func testGlobalInitialStatesHelper(t *testing.T, testcase GlobalInitialStatesTestCase) {
	t.Helper()

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		appCreator := env.Accounts[0]

		approvalProgramSrc := `#pragma version 8
txn ApplicationID
bz end // Do nothing during create

byte "put"
byte "del"
txn ApplicationArgs 0
match put del
err // Unknown command

put:
  txn ApplicationArgs 1
  txn ApplicationArgs 2
  app_global_put
  b end

del:
  txn ApplicationArgs 1
  app_global_del
  b end

end:
  int 1
`

		appID := env.CreateApp(appCreator.Addr, simulationtesting.AppParams{
			GlobalStateSchema: basics.StateSchema{NumByteSlice: 8},
			ApprovalProgram:   approvalProgramSrc,
			ClearStateProgram: `#pragma version 8
int 1`,
		})

		op, err := logic.AssembleString(approvalProgramSrc)
		require.NoError(t, err)
		progHash := crypto.Hash(op.Program)

		for _, instruction := range testcase.prepareInstruction {
			txnArgs := [][]byte{[]byte("put")}
			txnArgs = append(txnArgs, instruction...)
			env.Txn(env.TxnInfo.NewTxn(txntest.Txn{
				Sender:          appCreator.Addr,
				Type:            protocol.ApplicationCallTx,
				ApplicationID:   appID,
				ApplicationArgs: txnArgs,
			}).SignedTxn())
		}

		signedTxns := testcase.toSignedTxns(env, appCreator, appID)

		txnArgsToResult := func(txnAppArgs [][]byte) simulation.TxnResult {
			var res simulation.TxnResult
			switch string(txnAppArgs[0]) {
			case "put":
				res = simulation.TxnResult{
					Txn: transactions.SignedTxnWithAD{
						ApplyData: transactions.ApplyData{
							EvalDelta: transactions.EvalDelta{
								GlobalDelta: basics.StateDelta{
									string(txnAppArgs[1]): basics.ValueDelta{
										Bytes:  string(txnAppArgs[2]),
										Action: basics.SetBytesAction,
									},
								},
							},
						},
					},
					AppBudgetConsumed: 11,
					Trace: &simulation.TransactionTrace{
						ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
							{PC: 1},
							{PC: 3},
							{PC: 6},
							{PC: 11},
							{PC: 16},
							{PC: 19},
							{PC: 26},
							{PC: 29},
							{
								PC: 32,
								StateChanges: []simulation.StateOperation{
									{
										AppStateOp: logic.AppStateWrite,
										AppState:   logic.GlobalState,
										AppID:      appID,
										Key:        string(txnAppArgs[1]),
										NewValue: basics.TealValue{
											Type:  basics.TealBytesType,
											Bytes: string(txnAppArgs[2]),
										},
									},
								},
							},
							{PC: 33},
							{PC: 43},
						},
						ApprovalProgramHash: progHash,
					},
				}
			case "del":
				res = simulation.TxnResult{
					Txn: transactions.SignedTxnWithAD{
						ApplyData: transactions.ApplyData{
							EvalDelta: transactions.EvalDelta{
								GlobalDelta: basics.StateDelta{
									string(txnAppArgs[1]): basics.ValueDelta{
										Action: basics.DeleteAction,
									},
								},
							},
						},
					},
					AppBudgetConsumed: 10,
					Trace: &simulation.TransactionTrace{
						ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
							{PC: 1},
							{PC: 3},
							{PC: 6},
							{PC: 11},
							{PC: 16},
							{PC: 19},
							{PC: 36},
							{
								PC: 39,
								StateChanges: []simulation.StateOperation{
									{
										AppStateOp: logic.AppStateDelete,
										AppState:   logic.GlobalState,
										AppID:      appID,
										Key:        string(txnAppArgs[1]),
									},
								},
							},
							{PC: 40},
							{PC: 43},
						},
						ApprovalProgramHash: progHash,
					},
				}
			default:
			}
			return res
		}
		txnResults := make([]simulation.TxnResult, len(testcase.txnsArgs))
		for i, txnArgs := range testcase.txnsArgs {
			txnResults[i] = txnArgsToResult(txnArgs)
		}

		prepareKeys := make(util.Set[string])
		for _, instruction := range testcase.prepareInstruction {
			prepareKeys.Add(string(instruction[0]))
		}
		newlyCreatedGlobalKeySet := make(util.Set[string])
		for _, txnArgs := range testcase.txnsArgs {
			if string(txnArgs[0]) != "put" {
				continue
			}
			if prepareKeys.Contains(string(txnArgs[1])) {
				continue
			}
			newlyCreatedGlobalKeySet.Add(string(txnArgs[1]))
		}

		totalConsumed := 0
		for _, txnResult := range txnResults {
			totalConsumed += txnResult.AppBudgetConsumed
		}

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					signedTxns,
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					State:  true,
				},
			},
			developerAPI: true,
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					State:  true,
				},
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns:              txnResults,
						AppBudgetAdded:    700 * len(txnResults),
						AppBudgetConsumed: totalConsumed,
					},
				},
				InitialStates: &simulation.ResourcesInitialStates{
					AllAppsInitialStates: simulation.AppsInitialStates{
						appID: simulation.SingleAppInitialStates{
							AppGlobals:     testcase.initialGlobalStates,
							AppLocals:      map[basics.Address]simulation.AppKVPairs{},
							AppBoxes:       make(simulation.AppKVPairs),
							CreatedGlobals: newlyCreatedGlobalKeySet,
							CreatedBoxes:   make(util.Set[string]),
							CreatedLocals:  map[basics.Address]util.Set[string]{},
						},
					},
					CreatedApp: make(util.Set[basics.AppIndex]),
				},
			},
		}
	})
}

func TestAppInitialGlobalStates(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testGlobalInitialStatesHelper(t,
		GlobalInitialStatesTestCase{
			txnsArgs: [][][]byte{
				{
					[]byte("put"), []byte("A"), []byte("content A"),
				},
				{
					[]byte("del"), []byte("A"),
				},
			},
			initialGlobalStates: simulation.AppKVPairs{},
		},
	)

	testGlobalInitialStatesHelper(t,
		GlobalInitialStatesTestCase{
			prepareInstruction: [][][]byte{
				{
					[]byte("A"), []byte("initial content A"),
				},
			},
			txnsArgs: [][][]byte{
				{
					[]byte("put"), []byte("A"), []byte("content A"),
				},
				{
					[]byte("del"), []byte("A"),
				},
			},
			initialGlobalStates: simulation.AppKVPairs{
				"A": basics.TealValue{
					Type:  basics.TealBytesType,
					Bytes: "initial content A",
				},
			},
		},
	)
}

type LocalStateOperation struct {
	addressIndex uint64
	appArgs      [][]byte
}

type LocalInitialStatesTestCase struct {
	prepareInstructions  []LocalStateOperation
	simulateInstructions []LocalStateOperation
	initialLocalStates   map[uint64]simulation.AppKVPairs
}

func (testcase LocalInitialStatesTestCase) toSignedTxns(env simulationtesting.Environment, appID basics.AppIndex) []transactions.SignedTxn {
	txns := make([]*txntest.Txn, len(testcase.simulateInstructions))
	for i, instruction := range testcase.simulateInstructions {
		tempTxn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          env.Accounts[instruction.addressIndex].Addr,
			ApplicationID:   appID,
			ApplicationArgs: instruction.appArgs,
		})
		txns[i] = &tempTxn
	}
	txntest.Group(txns...)
	signedTxns := make([]transactions.SignedTxn, len(testcase.simulateInstructions))
	for i, txn := range txns {
		signedTxns[i] = txn.Txn().Sign(env.Accounts[testcase.simulateInstructions[i].addressIndex].Sk)
	}
	return signedTxns
}

func testLocalInitialStatesHelper(t *testing.T, testcase LocalInitialStatesTestCase) {
	t.Helper()

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		appCreator := env.Accounts[0]

		approvalProgramSrc := `#pragma version 8
txn ApplicationID
bz end // Do nothing during create

txn OnCompletion
int OptIn
==
bnz end // Always allow optin

byte "put"
byte "get"
byte "del"

txn ApplicationArgs 0
match put get del
err // Unknown command

put:
  txn Sender            // account
  txn ApplicationArgs 1 // key
  txn ApplicationArgs 2 // local state content
  app_local_put
  b end

get:
  txn Sender            // account
  txn ApplicationArgs 1 // key
  app_local_get
  pop
  b end

del:
  txn Sender            // account
  txn ApplicationArgs 1 // key
  app_local_del
  b end

end:
  int 1
`

		appID := env.CreateApp(appCreator.Addr, simulationtesting.AppParams{
			LocalStateSchema: basics.StateSchema{NumByteSlice: 8},
			ApprovalProgram:  approvalProgramSrc,
			ClearStateProgram: `#pragma version 8
int 1`,
		})

		op, err := logic.AssembleString(approvalProgramSrc)
		require.NoError(t, err)
		progHash := crypto.Hash(op.Program)

		for _, acct := range env.Accounts[2:] {
			env.Txn(env.TxnInfo.NewTxn(txntest.Txn{
				Sender:        acct.Addr,
				Type:          protocol.ApplicationCallTx,
				ApplicationID: appID,
				OnCompletion:  transactions.OptInOC,
			}).SignedTxn())
		}

		for _, instruction := range testcase.prepareInstructions {
			env.Txn(env.TxnInfo.NewTxn(txntest.Txn{
				Sender:          env.Accounts[instruction.addressIndex].Addr,
				Type:            protocol.ApplicationCallTx,
				ApplicationID:   appID,
				ApplicationArgs: instruction.appArgs,
			}).SignedTxn())
		}

		signedTxns := testcase.toSignedTxns(env, appID)

		txnArgsToResult := func(instruction LocalStateOperation) simulation.TxnResult {
			var res simulation.TxnResult
			switch string(instruction.appArgs[0]) {
			case "put":
				res = simulation.TxnResult{
					Txn: transactions.SignedTxnWithAD{
						ApplyData: transactions.ApplyData{
							EvalDelta: transactions.EvalDelta{
								LocalDeltas: map[uint64]basics.StateDelta{
									0: {
										string(instruction.appArgs[1]): basics.ValueDelta{
											Bytes:  string(instruction.appArgs[2]),
											Action: basics.SetBytesAction,
										},
									},
								},
							},
						},
					},
					AppBudgetConsumed: 18,
					Trace: &simulation.TransactionTrace{
						ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
							{PC: 1},
							{PC: 4},
							{PC: 6},
							{PC: 9},
							{PC: 11},
							{PC: 12},
							{PC: 13},
							{PC: 16},
							{PC: 21},
							{PC: 26},
							{PC: 31},
							{PC: 34},
							{PC: 43},
							{PC: 45},
							{PC: 48},
							{
								PC: 51,
								StateChanges: []simulation.StateOperation{
									{
										AppStateOp: logic.AppStateWrite,
										AppState:   logic.LocalState,
										AppID:      appID,
										Key:        string(instruction.appArgs[1]),
										NewValue: basics.TealValue{
											Type:  basics.TealBytesType,
											Bytes: string(instruction.appArgs[2]),
										},
										Account: env.Accounts[instruction.addressIndex].Addr,
									},
								},
							},
							{PC: 52},
							{PC: 74},
						},
						ApprovalProgramHash: progHash,
					},
				}
			case "del":
				res = simulation.TxnResult{
					Txn: transactions.SignedTxnWithAD{
						ApplyData: transactions.ApplyData{
							EvalDelta: transactions.EvalDelta{
								LocalDeltas: map[uint64]basics.StateDelta{
									0: {
										string(instruction.appArgs[1]): basics.ValueDelta{
											Action: basics.DeleteAction,
										},
									},
								},
							},
						},
					},
					AppBudgetConsumed: 17,
					Trace: &simulation.TransactionTrace{
						ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
							{PC: 1},
							{PC: 4},
							{PC: 6},
							{PC: 9},
							{PC: 11},
							{PC: 12},
							{PC: 13},
							{PC: 16},
							{PC: 21},
							{PC: 26},
							{PC: 31},
							{PC: 34},
							{PC: 65},
							{PC: 67},
							{
								PC: 70,
								StateChanges: []simulation.StateOperation{
									{
										AppStateOp: logic.AppStateDelete,
										AppState:   logic.LocalState,
										AppID:      appID,
										Key:        string(instruction.appArgs[1]),
										Account:    env.Accounts[instruction.addressIndex].Addr,
									},
								},
							},
							{PC: 71},
							{PC: 74},
						},
						ApprovalProgramHash: progHash,
					},
				}
			case "get":
				res = simulation.TxnResult{
					AppBudgetConsumed: 18,
					Trace: &simulation.TransactionTrace{
						ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
							{PC: 1},
							{PC: 4},
							{PC: 6},
							{PC: 9},
							{PC: 11},
							{PC: 12},
							{PC: 13},
							{PC: 16},
							{PC: 21},
							{PC: 26},
							{PC: 31},
							{PC: 34},
							{PC: 55},
							{PC: 57},
							{PC: 60},
							{PC: 61},
							{PC: 62},
							{PC: 74},
						},
						ApprovalProgramHash: progHash,
					},
				}
			default:
			}
			return res
		}
		txnResults := make([]simulation.TxnResult, len(testcase.simulateInstructions))
		for i, txnArgs := range testcase.simulateInstructions {
			txnResults[i] = txnArgsToResult(txnArgs)
		}

		prepareInitialStates := make(map[basics.Address]util.Set[string])
		for _, instruction := range testcase.prepareInstructions {
			if prepareInitialStates[env.Accounts[instruction.addressIndex].Addr] == nil {
				prepareInitialStates[env.Accounts[instruction.addressIndex].Addr] = make(util.Set[string])
			}
			prepareInitialStates[env.Accounts[instruction.addressIndex].Addr].Add(string(instruction.appArgs[1]))
		}

		newlyCreatedLocalStates := make(map[basics.Address]util.Set[string])
		for _, instruction := range testcase.simulateInstructions {
			if string(instruction.appArgs[0]) != "put" {
				continue
			}
			acctAddress := env.Accounts[instruction.addressIndex].Addr
			if prepareInitialStates[acctAddress] != nil && prepareInitialStates[acctAddress].Contains(string(instruction.appArgs[1])) {
				continue
			}
			if newlyCreatedLocalStates[acctAddress] == nil {
				newlyCreatedLocalStates[acctAddress] = make(util.Set[string])
			}
			newlyCreatedLocalStates[acctAddress].Add(string(instruction.appArgs[1]))
		}

		totalConsumed := 0
		for _, txnResult := range txnResults {
			totalConsumed += txnResult.AppBudgetConsumed
		}

		expectedInitialLocalStates := make(map[basics.Address]simulation.AppKVPairs)
		for addrID, kvPair := range testcase.initialLocalStates {
			expectedInitialLocalStates[env.Accounts[addrID].Addr] = kvPair
		}

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					signedTxns,
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					State:  true,
				},
			},
			developerAPI: true,
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					State:  true,
				},
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns:              txnResults,
						AppBudgetAdded:    700 * len(txnResults),
						AppBudgetConsumed: totalConsumed,
					},
				},
				InitialStates: &simulation.ResourcesInitialStates{
					AllAppsInitialStates: simulation.AppsInitialStates{
						appID: simulation.SingleAppInitialStates{
							AppGlobals:     make(simulation.AppKVPairs),
							AppLocals:      expectedInitialLocalStates,
							AppBoxes:       make(simulation.AppKVPairs),
							CreatedGlobals: make(util.Set[string]),
							CreatedLocals:  newlyCreatedLocalStates,
							CreatedBoxes:   make(util.Set[string]),
						},
					},
					CreatedApp: make(util.Set[basics.AppIndex]),
				},
			},
		}
	})
}

func TestLocalInitialStates(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testLocalInitialStatesHelper(t, LocalInitialStatesTestCase{
		prepareInstructions: []LocalStateOperation{},
		simulateInstructions: []LocalStateOperation{
			{
				addressIndex: 2,
				appArgs: [][]byte{
					[]byte("put"), []byte("key"), []byte("value"),
				},
			},
		},
		initialLocalStates: map[uint64]simulation.AppKVPairs{},
	})

	testLocalInitialStatesHelper(t, LocalInitialStatesTestCase{
		prepareInstructions: []LocalStateOperation{
			{
				addressIndex: 2,
				appArgs: [][]byte{
					[]byte("put"), []byte("key"), []byte("value"),
				},
			},
		},
		simulateInstructions: []LocalStateOperation{
			{
				addressIndex: 2,
				appArgs: [][]byte{
					[]byte("put"), []byte("key"), []byte("new-value"),
				},
			},
			{
				addressIndex: 2,
				appArgs: [][]byte{
					[]byte("get"), []byte("key"),
				},
			},
			{
				addressIndex: 2,
				appArgs: [][]byte{
					[]byte("del"), []byte("key"),
				},
			},
		},
		initialLocalStates: map[uint64]simulation.AppKVPairs{
			2: {
				"key": basics.TealValue{
					Type:  basics.TealBytesType,
					Bytes: "value",
				},
			},
		},
	})
}

func TestInitialStatesGetEx(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
		appCreator := env.Accounts[0]

		approvalProgramSrc := `#pragma version 8
txn ApplicationID
bz end // Do nothing during create

txn OnCompletion
int OptIn
==
bnz end // Always allow optin

byte "put"
byte "local_put"
byte "del"
txn ApplicationArgs 0
match put local_put del
err // Unknown command

put:
  txn ApplicationArgs 1
  txn ApplicationArgs 2
  app_global_put
  b end

local_put:
  txn Sender
  txn ApplicationArgs 1
  txn ApplicationArgs 2
  app_local_put
  b end

del:
  txn ApplicationArgs 1
  app_global_del
  b end

end:
  int 1
`

		appIDWithStates := env.CreateApp(appCreator.Addr, simulationtesting.AppParams{
			GlobalStateSchema: basics.StateSchema{NumByteSlice: 8},
			LocalStateSchema:  basics.StateSchema{NumByteSlice: 8},
			ApprovalProgram:   approvalProgramSrc,
			ClearStateProgram: `#pragma version 8
int 1`,
		})

		env.Txn(env.TxnInfo.NewTxn(txntest.Txn{
			Sender:        appCreator.Addr,
			Type:          protocol.ApplicationCallTx,
			ApplicationID: appIDWithStates,
			OnCompletion:  transactions.OptInOC,
		}).SignedTxn())

		prepareSteps := [][][]byte{
			{
				[]byte("put"), []byte("A"), []byte("initial content A"),
			},
			{
				[]byte("local_put"), []byte("B"), []byte("initial content B"),
			},
		}

		for _, txnArgs := range prepareSteps {
			env.Txn(env.TxnInfo.NewTxn(txntest.Txn{
				Sender:          appCreator.Addr,
				Type:            protocol.ApplicationCallTx,
				ApplicationID:   appIDWithStates,
				ApplicationArgs: txnArgs,
			}).SignedTxn())
		}

		// The application to read another app
		approvalProgramSrc = `#pragma version 8
txn ApplicationID
bz end // Do nothing during create

byte "read_global"
byte "read_local"
txn ApplicationArgs 0
match read_global read_local
err // Unknown command

read_global:
  txn ApplicationArgs 1 // AppID
  btoi
  txn ApplicationArgs 2 // GlobalKey
  app_global_get_ex
  assert
  pop
  b end

read_local:
  txn Sender
  txn ApplicationArgs 1 // AppID
  btoi
  txn ApplicationArgs 2 // LocalKey
  app_local_get_ex
  assert
  pop
  b end

end:
int 1
`
		appIDReadingStates := env.CreateApp(appCreator.Addr, simulationtesting.AppParams{
			ApprovalProgram: approvalProgramSrc,
			ClearStateProgram: `#pragma version 8
int 1`,
		})

		op, err := logic.AssembleString(approvalProgramSrc)
		require.NoError(t, err)
		progHash := crypto.Hash(op.Program)

		txns := make([]*txntest.Txn, 2)
		tmpTxn0 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        appCreator.Addr,
			ApplicationID: appIDReadingStates,
			ApplicationArgs: [][]byte{
				[]byte("read_global"),
				uint64ToBytes(uint64(appIDWithStates)),
				[]byte("A"),
			},
			ForeignApps: []basics.AppIndex{appIDWithStates},
		})
		txns[0] = &tmpTxn0
		tmpTxn1 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        appCreator.Addr,
			ApplicationID: appIDReadingStates,
			ApplicationArgs: [][]byte{
				[]byte("read_local"),
				uint64ToBytes(uint64(appIDWithStates)),
				[]byte("B"),
			},
			ForeignApps: []basics.AppIndex{appIDWithStates},
			Note:        []byte("bla"),
		})
		txns[1] = &tmpTxn1
		txntest.Group(txns...)
		signedTxns := make([]transactions.SignedTxn, len(txns))
		for i, txn := range txns {
			signedTxns[i] = txn.Txn().Sign(appCreator.Sk)
		}

		// now construct app calls for global local get ex
		txnResults := []simulation.TxnResult{
			{
				AppBudgetConsumed: 14,
				Trace: &simulation.TransactionTrace{
					ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
						{PC: 1},
						{PC: 3},
						{PC: 6},
						{PC: 19},
						{PC: 31},
						{PC: 34},
						{PC: 41},
						{PC: 44},
						{PC: 45},
						{PC: 48},
						{PC: 49},
						{PC: 50},
						{PC: 51},
						{PC: 69},
					},
					ApprovalProgramHash: progHash,
				},
			},
			{
				AppBudgetConsumed: 15,
				Trace: &simulation.TransactionTrace{
					ApprovalProgramTrace: []simulation.OpcodeTraceUnit{
						{PC: 1},
						{PC: 3},
						{PC: 6},
						{PC: 19},
						{PC: 31},
						{PC: 34},
						{PC: 54},
						{PC: 56},
						{PC: 59},
						{PC: 60},
						{PC: 63},
						{PC: 64},
						{PC: 65},
						{PC: 66},
						{PC: 69},
					},
					ApprovalProgramHash: progHash,
				},
			},
		}

		totalConsumed := 0
		for _, txnResult := range txnResults {
			totalConsumed += txnResult.AppBudgetConsumed
		}

		return simulationTestCase{
			input: simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{
					signedTxns,
				},
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					State:  true,
				},
			},
			developerAPI: true,
			expected: simulation.Result{
				Version:   simulation.ResultLatestVersion,
				LastRound: env.TxnInfo.LatestRound(),
				TraceConfig: simulation.ExecTraceConfig{
					Enable: true,
					State:  true,
				},
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns:              txnResults,
						AppBudgetAdded:    700 * len(txnResults),
						AppBudgetConsumed: totalConsumed,
					},
				},
				InitialStates: &simulation.ResourcesInitialStates{
					AllAppsInitialStates: simulation.AppsInitialStates{
						appIDWithStates: simulation.SingleAppInitialStates{
							AppGlobals: simulation.AppKVPairs{
								"A": basics.TealValue{
									Type:  basics.TealBytesType,
									Bytes: "initial content A",
								},
							},
							AppLocals: map[basics.Address]simulation.AppKVPairs{
								appCreator.Addr: {
									"B": basics.TealValue{
										Type:  basics.TealBytesType,
										Bytes: "initial content B",
									},
								},
							},
							AppBoxes:       make(simulation.AppKVPairs),
							CreatedGlobals: make(util.Set[string]),
							CreatedBoxes:   make(util.Set[string]),
							CreatedLocals:  map[basics.Address]util.Set[string]{},
						},
					},
					CreatedApp: make(util.Set[basics.AppIndex]),
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

func TestAppCallInnerTxnApplyDataOnErr(t *testing.T) {
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

func TestNonAppCallInnerTxnApplyDataOnErr(t *testing.T) {
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

func TestInnerTxnNonAppCallErr(t *testing.T) {
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
			expectedError: "this transaction should be issued by the manager",
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

// TestUnnamedResources tests that app calls can access resources that they otherwise should not be
// able to if AllowUnnamedResources is enabled. Additional tests follow for special cases.
func TestUnnamedResources(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// Start with directRefEnabledVersion (4), since prior to that all restricted references had to
	// be indexes into the foreign arrays, meaning we can't test the unnamed case.
	for v := 4; v <= logic.LogicVersion; v++ {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
				sender := env.Accounts[0]

				otherAccount := env.Accounts[1]
				otherAccountAuthAddr := env.Accounts[2].Addr
				env.Rekey(otherAccount.Addr, otherAccountAuthAddr)

				assetCreator := env.Accounts[2].Addr
				assetID := env.CreateAsset(assetCreator, basics.AssetParams{Total: 100})

				assetHolder := env.Accounts[3].Addr
				env.OptIntoAsset(assetHolder, assetID)
				env.TransferAsset(assetCreator, assetHolder, assetID, 1)

				otherAppCreator := env.Accounts[4].Addr
				otherAppID := env.CreateApp(otherAppCreator, simulationtesting.AppParams{
					// Using version 8 because this is the highest version where we check that
					// cross-products of resources are available.
					ApprovalProgram:   "#pragma version 8\nint 1",
					ClearStateProgram: "#pragma version 8\nint 1",
				})

				otherAppUser := env.Accounts[5].Addr
				env.OptIntoApp(otherAppUser, otherAppID)

				proto := env.TxnInfo.CurrentProtocolParams()
				if v > int(proto.LogicSigVersion) {
					t.Skip("not testing in unsupported proto")
				}
				expectedUnnamedResourceGroupAssignment := &simulation.ResourceTracker{
					MaxAccounts:               proto.MaxTxGroupSize * (proto.MaxAppTxnAccounts + proto.MaxAppTxnForeignApps),
					MaxAssets:                 proto.MaxTxGroupSize * proto.MaxAppTxnForeignAssets,
					MaxApps:                   proto.MaxTxGroupSize * proto.MaxAppTxnForeignApps,
					MaxBoxes:                  proto.MaxTxGroupSize * proto.MaxAppBoxReferences,
					MaxTotalRefs:              proto.MaxTxGroupSize * proto.MaxAppTotalTxnReferences,
					MaxCrossProductReferences: proto.MaxTxGroupSize * proto.MaxAppTxnForeignApps * (proto.MaxAppTxnForeignApps + 2),
				}
				var expectedUnnamedResourceTxnAssignment *simulation.ResourceTracker
				var expectedResources *simulation.ResourceTracker
				if v < 9 {
					// no shared resources
					expectedUnnamedResourceTxnAssignment = &simulation.ResourceTracker{
						MaxAccounts:  proto.MaxAppTxnAccounts + proto.MaxAppTxnForeignApps,
						MaxAssets:    proto.MaxAppTxnForeignAssets,
						MaxApps:      proto.MaxAppTxnForeignApps,
						MaxBoxes:     proto.MaxAppBoxReferences,
						MaxTotalRefs: proto.MaxAppTotalTxnReferences,
					}
					expectedResources = expectedUnnamedResourceTxnAssignment
				} else {
					// shared resources
					expectedResources = expectedUnnamedResourceGroupAssignment
				}

				var innerCount int

				program := fmt.Sprintf("#pragma version %d\n", v)

				// Do nothing during create
				program += "txn ApplicationID; bz end;"

				// Account access
				program += fmt.Sprintf("addr %s; balance; int %d; <; assert;", otherAccount.Addr, otherAccount.AcctData.MicroAlgos.Raw)
				if v >= 6 { // acct_params_get introduced
					program += fmt.Sprintf("addr %s; acct_params_get AcctAuthAddr; assert; addr %s; ==; assert;", otherAccount.Addr, otherAccountAuthAddr)
				}
				if v >= 5 { // inner txns introduced
					program += fmt.Sprintf("itxn_begin; int pay; itxn_field TypeEnum; addr %s; itxn_field Receiver; itxn_submit;", otherAccount.Addr)
					innerCount++
				}
				expectedResources.Accounts = map[basics.Address]struct{}{
					otherAccount.Addr: {},
				}

				// Asset params access
				program += fmt.Sprintf("int %d; asset_params_get AssetTotal; assert; int 100; ==; assert;", assetID)
				if v >= 5 { // AssetCreator field introduced
					program += fmt.Sprintf("int %d; asset_params_get AssetCreator; assert; addr %s; ==; assert;", assetID, assetCreator)
				}
				expectedResources.Assets = map[basics.AssetIndex]struct{}{
					assetID: {},
				}

				// Asset holding access
				program += fmt.Sprintf("txn Sender; int %d; asset_holding_get AssetBalance; !; assert; !; assert;", assetID)
				program += fmt.Sprintf("addr %s; int %d; asset_holding_get AssetBalance; assert; int 99; ==; assert;", assetCreator, assetID)
				program += fmt.Sprintf("addr %s; int %d; asset_holding_get AssetBalance; assert; int 1; ==; assert;", assetHolder, assetID)
				if v >= 5 { // inner txns introduced
					program += fmt.Sprintf("itxn_begin; int axfer; itxn_field TypeEnum; int %d; itxn_field XferAsset; itxn_submit;", assetID)
					innerCount++
				}
				expectedResources.Accounts[assetCreator] = struct{}{}
				expectedResources.Accounts[assetHolder] = struct{}{}
				if v >= 9 {
					expectedUnnamedResourceGroupAssignment.AssetHoldings = map[ledgercore.AccountAsset]struct{}{
						{Address: sender.Addr, Asset: assetID}:      {},
						{Address: assetCreator, Asset: assetID}:     {},
						{Address: assetHolder, Asset: assetID}:      {},
						{Address: basics.Address{}, Asset: assetID}: {},
					}
				}

				// App params access
				program += fmt.Sprintf("int %d; byte 0x01; app_global_get_ex; !; assert; !; assert;", otherAppID)
				if v >= 5 { // app_params_get introduced
					program += fmt.Sprintf("int %d; app_params_get AppCreator; assert; addr %s; ==; assert;", otherAppID, otherAppCreator)
				}
				expectedResources.Apps = map[basics.AppIndex]struct{}{
					otherAppID: {},
				}

				// App local access
				program += fmt.Sprintf("txn Sender; int %d; app_opted_in; !; assert;", otherAppID)
				program += fmt.Sprintf("addr %s; int %d; app_opted_in; assert;", otherAppUser, otherAppID)
				program += fmt.Sprintf("addr %s; int %d; byte 0x01; app_local_get_ex; !; assert; !; assert;", otherAppUser, otherAppID)
				if v >= 6 { // contract to contract itxn calls introduced
					program += fmt.Sprintf("itxn_begin; int appl; itxn_field TypeEnum; int %d; itxn_field ApplicationID; itxn_submit;", otherAppID)
					innerCount++
				}
				expectedResources.Accounts[otherAppUser] = struct{}{}
				if v >= 9 {
					expectedUnnamedResourceGroupAssignment.AppLocals = map[ledgercore.AccountApp]struct{}{
						{Address: sender.Addr, App: otherAppID}:      {},
						{Address: otherAppUser, App: otherAppID}:     {},
						{Address: basics.Address{}, App: otherAppID}: {},
					}
				}

				// Box access
				if v >= 8 { // boxes introduced
					program += `byte "A"; int 64; box_create; assert;`
					program += `byte "B"; box_len; !; assert; !; assert;`
					expectedUnnamedResourceGroupAssignment.Boxes = map[basics.BoxRef]simulation.BoxStat{
						{App: 0, Name: "A"}: {},
						{App: 0, Name: "B"}: {},
					}
				}

				program += "end: int 1"

				testAppID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
					ApprovalProgram:   program,
					ClearStateProgram: fmt.Sprintf("#pragma version %d\n int 1", v),
				})

				// Fund the app to cover inner txn fees and min balance increases
				env.TransferAlgos(sender.Addr, testAppID.Address(), 1_000_000)

				var holdingsToFix []ledgercore.AccountAsset
				for holding := range expectedUnnamedResourceGroupAssignment.AssetHoldings {
					if holding.Address.IsZero() {
						// replace with app address
						holdingsToFix = append(holdingsToFix, holding)
					}
				}
				for _, holding := range holdingsToFix {
					delete(expectedUnnamedResourceGroupAssignment.AssetHoldings, holding)
					holding.Address = testAppID.Address()
					expectedUnnamedResourceGroupAssignment.AssetHoldings[holding] = struct{}{}
				}
				var localsToFix []ledgercore.AccountApp
				for local := range expectedUnnamedResourceGroupAssignment.AppLocals {
					if local.Address.IsZero() {
						// replace with app address
						localsToFix = append(localsToFix, local)
					}
				}
				for _, local := range localsToFix {
					delete(expectedUnnamedResourceGroupAssignment.AppLocals, local)
					local.Address = testAppID.Address()
					expectedUnnamedResourceGroupAssignment.AppLocals[local] = struct{}{}
				}
				var boxesToFix []basics.BoxRef
				for box := range expectedUnnamedResourceGroupAssignment.Boxes {
					if box.App == 0 {
						// replace with app ID
						boxesToFix = append(boxesToFix, box)
					}
				}
				for _, box := range boxesToFix {
					value := expectedUnnamedResourceGroupAssignment.Boxes[box]
					delete(expectedUnnamedResourceGroupAssignment.Boxes, box)
					box.App = testAppID
					expectedUnnamedResourceGroupAssignment.Boxes[box] = value
				}

				txn := env.TxnInfo.NewTxn(txntest.Txn{
					Type:          protocol.ApplicationCallTx,
					Sender:        sender.Addr,
					ApplicationID: testAppID,
				})
				stxn := txn.Txn().Sign(sender.Sk)

				if expectedUnnamedResourceTxnAssignment != nil {
					localAccounts := len(expectedUnnamedResourceTxnAssignment.Accounts)
					localAssets := len(expectedUnnamedResourceTxnAssignment.Assets)
					localApps := len(expectedUnnamedResourceTxnAssignment.Apps)
					// Skip boxes, they are global only
					expectedUnnamedResourceGroupAssignment.MaxAccounts -= localAccounts + localApps
					expectedUnnamedResourceGroupAssignment.MaxAssets -= localAssets
					expectedUnnamedResourceGroupAssignment.MaxApps -= localApps
					expectedUnnamedResourceGroupAssignment.MaxTotalRefs -= localAccounts + localAssets + localApps

					if !expectedUnnamedResourceTxnAssignment.HasResources() {
						expectedUnnamedResourceTxnAssignment = nil
					}
				}

				if !expectedUnnamedResourceGroupAssignment.HasResources() {
					expectedUnnamedResourceGroupAssignment = nil
				}

				return simulationTestCase{
					input: simulation.Request{
						TxnGroups:             [][]transactions.SignedTxn{{stxn}},
						AllowUnnamedResources: true,
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
												EvalDelta: transactions.EvalDelta{
													InnerTxns: make([]transactions.SignedTxnWithAD, innerCount),
												},
											},
										},
										AppBudgetConsumed:        ignoreAppBudgetConsumed,
										UnnamedResourcesAccessed: expectedUnnamedResourceTxnAssignment,
									},
								},
								AppBudgetAdded:           700 + 700*innerCount,
								AppBudgetConsumed:        ignoreAppBudgetConsumed,
								UnnamedResourcesAccessed: expectedUnnamedResourceGroupAssignment,
							},
						},
						EvalOverrides: simulation.ResultEvalOverrides{
							AllowUnnamedResources: true,
						},
					},
				}
			})
		})
	}
}

// TestUnnamedResourcesAccountLocalWrite tests app call behavior when writing to an account's local
// state they otherwise shouldn't have access to if AllowUnnamedResources is enabled.
func TestUnnamedResourcesAccountLocalWrite(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// Start with directRefEnabledVersion (4), since prior to that all restricted references had to
	// be indexes into the foreign arrays, meaning we can't test the unnamed case.
	for v := 4; v <= logic.LogicVersion; v++ {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
				sender := env.Accounts[0]
				testAppUser := env.Accounts[1].Addr

				proto := env.TxnInfo.CurrentProtocolParams()
				if v > int(proto.LogicSigVersion) {
					t.Skip("not testing in unsupported proto")
				}

				program := fmt.Sprintf(`#pragma version %d
txn ApplicationID
!
txn OnCompletion
int OptIn
==
||
bnz end // Do nothing during create or opt in

// App local write to an account we shouldn't be able to
addr %s
byte "key"
byte "value"
app_local_put

end:
int 1
`, v, testAppUser)

				testAppID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
					ApprovalProgram:   program,
					ClearStateProgram: fmt.Sprintf("#pragma version %d\n int 1", v),
					LocalStateSchema: basics.StateSchema{
						NumByteSlice: 1,
					},
				})

				env.OptIntoApp(testAppUser, testAppID)

				txn := env.TxnInfo.NewTxn(txntest.Txn{
					Type:          protocol.ApplicationCallTx,
					Sender:        sender.Addr,
					ApplicationID: testAppID,
				})
				stxn := txn.Txn().Sign(sender.Sk)

				expectedUnnamedResourceAssignment := &simulation.ResourceTracker{
					MaxAccounts:               proto.MaxTxGroupSize * (proto.MaxAppTxnAccounts + proto.MaxAppTxnForeignApps),
					MaxAssets:                 proto.MaxTxGroupSize * proto.MaxAppTxnForeignAssets,
					MaxApps:                   proto.MaxTxGroupSize * proto.MaxAppTxnForeignApps,
					MaxBoxes:                  proto.MaxTxGroupSize * proto.MaxAppBoxReferences,
					MaxTotalRefs:              proto.MaxTxGroupSize * proto.MaxAppTotalTxnReferences,
					MaxCrossProductReferences: proto.MaxTxGroupSize * proto.MaxAppTxnForeignApps * (proto.MaxAppTxnForeignApps + 2),
				}
				var expectedUnnamedResourceTxnAssignment *simulation.ResourceTracker

				var expectedEvalDelta transactions.EvalDelta
				var expectedError string
				var expectedFailedAt simulation.TxnPath
				// Can write to accounts outside of foreign array in sharedResourcesVersion (9), but not before then
				if v >= 9 {
					expectedEvalDelta = transactions.EvalDelta{
						SharedAccts: []basics.Address{testAppUser},
						LocalDeltas: map[uint64]basics.StateDelta{
							1: {
								"key": basics.ValueDelta{
									Action: basics.SetBytesAction,
									Bytes:  "value",
								},
							},
						},
					}
					expectedUnnamedResourceAssignment.Accounts = map[basics.Address]struct{}{
						testAppUser: {},
					}
					expectedUnnamedResourceAssignment.AppLocals = map[ledgercore.AccountApp]struct{}{
						{Address: testAppUser, App: testAppID}: {},
					}
				} else {
					expectedError = fmt.Sprintf("logic eval error: invalid Account reference for mutation %s", testAppUser)
					expectedFailedAt = simulation.TxnPath{0}
					expectedUnnamedResourceTxnAssignment = &simulation.ResourceTracker{
						MaxAccounts:  proto.MaxAppTxnAccounts + proto.MaxAppTxnForeignApps,
						MaxAssets:    proto.MaxAppTxnForeignAssets,
						MaxApps:      proto.MaxAppTxnForeignApps,
						MaxBoxes:     proto.MaxAppBoxReferences,
						MaxTotalRefs: proto.MaxAppTotalTxnReferences,
						Accounts: map[basics.Address]struct{}{
							testAppUser: {},
						},
					}
					expectedUnnamedResourceAssignment.MaxAccounts--
					expectedUnnamedResourceAssignment.MaxTotalRefs--
				}

				if expectedUnnamedResourceTxnAssignment != nil && !expectedUnnamedResourceTxnAssignment.HasResources() {
					expectedUnnamedResourceTxnAssignment = nil
				}

				if !expectedUnnamedResourceAssignment.HasResources() {
					expectedUnnamedResourceAssignment = nil
				}

				return simulationTestCase{
					input: simulation.Request{
						TxnGroups:             [][]transactions.SignedTxn{{stxn}},
						AllowUnnamedResources: true,
					},
					expectedError: expectedError,
					expected: simulation.Result{
						Version:   simulation.ResultLatestVersion,
						LastRound: env.TxnInfo.LatestRound(),
						TxnGroups: []simulation.TxnGroupResult{
							{
								Txns: []simulation.TxnResult{
									{
										Txn: transactions.SignedTxnWithAD{
											ApplyData: transactions.ApplyData{
												EvalDelta: expectedEvalDelta,
											},
										},
										AppBudgetConsumed:        ignoreAppBudgetConsumed,
										UnnamedResourcesAccessed: expectedUnnamedResourceTxnAssignment,
									},
								},
								FailedAt:                 expectedFailedAt,
								AppBudgetAdded:           700,
								AppBudgetConsumed:        ignoreAppBudgetConsumed,
								UnnamedResourcesAccessed: expectedUnnamedResourceAssignment,
							},
						},
						EvalOverrides: simulation.ResultEvalOverrides{
							AllowUnnamedResources: true,
						},
					},
				}
			})
		})
	}
}

// TestUnnamedResourcesCreatedAppsAndAssets tests cross-product availability for newly created apps
// and assets.
func TestUnnamedResourcesCreatedAppsAndAssets(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// Start with v9, since that's when we first track cross-product references indepdently.
	for v := 9; v <= logic.LogicVersion; v++ {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
				proto := env.TxnInfo.CurrentProtocolParams()
				if v > int(proto.LogicSigVersion) {
					t.Skip("not testing in unsupported proto")
				}

				sender := env.Accounts[0]
				otherResourceCreator := env.Accounts[1]
				otherAccount := env.Accounts[2].Addr

				otherAssetID := env.CreateAsset(otherResourceCreator.Addr, basics.AssetParams{Total: 100})
				otherAppID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
					ApprovalProgram:   fmt.Sprintf("#pragma version %d\n int 1", v),
					ClearStateProgram: fmt.Sprintf("#pragma version %d\n int 1", v),
				})

				program := fmt.Sprintf(`#pragma version %d
txn ApplicationID
bz end // Do nothing during create

gtxn 0 CreatedAssetID
store 0 // new asset

gtxn 1 CreatedApplicationID
dup
store 1 // new app
app_params_get AppAddress
assert
store 2 // new app account

addr %s
store 10 // other account

int %d
store 11 // other asset

int %d
store 12 // other app

// Asset holding lookup for newly created asset
load 10
load 0
asset_holding_get AssetBalance
!
assert
!
assert

// App local lookup for newly created app
load 10
load 1
app_opted_in
!
assert

// Asset holding lookup for newly created app account
load 2
load 11
asset_holding_get AssetBalance
!
assert
!
assert

// App local lookup for newly created app account
load 2
load 12
app_opted_in
!
assert

end:
int 1
`, v, otherAccount, otherAssetID, otherAppID)

				testAppID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
					ApprovalProgram:   program,
					ClearStateProgram: fmt.Sprintf("#pragma version %d\n int 1", v),
				})

				assetCreateTxn := env.TxnInfo.NewTxn(txntest.Txn{
					Type:   protocol.AssetConfigTx,
					Sender: otherResourceCreator.Addr,
					AssetParams: basics.AssetParams{
						Total: 1,
					},
				})
				appCreateTxn := env.TxnInfo.NewTxn(txntest.Txn{
					Type:              protocol.ApplicationCallTx,
					Sender:            otherResourceCreator.Addr,
					ApprovalProgram:   fmt.Sprintf("#pragma version %d\n int 1", v),
					ClearStateProgram: fmt.Sprintf("#pragma version %d\n int 1", v),
				})
				appCallTxn := env.TxnInfo.NewTxn(txntest.Txn{
					Type:          protocol.ApplicationCallTx,
					Sender:        sender.Addr,
					ApplicationID: testAppID,
				})
				txntest.Group(&assetCreateTxn, &appCreateTxn, &appCallTxn)
				assetCreateStxn := assetCreateTxn.Txn().Sign(otherResourceCreator.Sk)
				appCreateStxn := appCreateTxn.Txn().Sign(otherResourceCreator.Sk)
				appCallStxn := appCallTxn.Txn().Sign(sender.Sk)

				expectedUnnamedResourceAssignment := simulation.ResourceTracker{
					MaxAccounts:  (proto.MaxTxGroupSize - 1) * (proto.MaxAppTxnAccounts + proto.MaxAppTxnForeignApps),
					MaxAssets:    (proto.MaxTxGroupSize - 1) * proto.MaxAppTxnForeignAssets,
					MaxApps:      (proto.MaxTxGroupSize - 1) * proto.MaxAppTxnForeignApps,
					MaxBoxes:     (proto.MaxTxGroupSize - 1) * proto.MaxAppBoxReferences,
					MaxTotalRefs: (proto.MaxTxGroupSize - 1) * proto.MaxAppTotalTxnReferences,

					Accounts: map[basics.Address]struct{}{
						otherAccount: {},
					},
					Assets: map[basics.AssetIndex]struct{}{
						otherAssetID: {},
					},
					Apps: map[basics.AppIndex]struct{}{
						otherAppID: {},
					},
					MaxCrossProductReferences: (proto.MaxTxGroupSize - 1) * proto.MaxAppTxnForeignApps * (proto.MaxAppTxnForeignApps + 2),
					// These should remain nil, since cross-product references for newly created
					// resources should not be counted against the group's resource limits.
					AssetHoldings: nil,
					AppLocals:     nil,
				}

				return simulationTestCase{
					input: simulation.Request{
						TxnGroups: [][]transactions.SignedTxn{
							{assetCreateStxn, appCreateStxn, appCallStxn},
						},
						AllowUnnamedResources: true,
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
												ConfigAsset: basics.AssetIndex(testAppID) + 1,
											},
										},
									},
									{
										Txn: transactions.SignedTxnWithAD{
											ApplyData: transactions.ApplyData{
												ApplicationID: testAppID + 2,
											},
										},
										AppBudgetConsumed: ignoreAppBudgetConsumed,
									},
									{
										AppBudgetConsumed: ignoreAppBudgetConsumed,
									},
								},
								AppBudgetAdded:           1400,
								AppBudgetConsumed:        ignoreAppBudgetConsumed,
								UnnamedResourcesAccessed: &expectedUnnamedResourceAssignment,
							},
						},
						EvalOverrides: simulation.ResultEvalOverrides{
							AllowUnnamedResources: true,
						},
					},
				}
			})
		})
	}
}

const verPragma = "#pragma version %d\n"

const bailOnCreate = `
txn ApplicationID
bz end
`

const mainBoxTestProgram = `
byte "create"
byte "delete"
byte "read"
byte "write"
txn ApplicationArgs 0
match create delete read write
err // Unknown command

create:
txn ApplicationArgs 1
txn ApplicationArgs 2
btoi
box_create
assert
b end

delete:
txn ApplicationArgs 1
box_del
assert
b end

read:
txn ApplicationArgs 1
box_get
pop
pop
b end

write:
txn ApplicationArgs 1
int 0
txn ApplicationArgs 2
box_replace

end:
int 1
`

// boxTestProgram executes the operations defined by boxOperation
const boxTestProgram = verPragma + bailOnCreate + mainBoxTestProgram

// boxDuringCreateProgram will even try to operate during the app creation.
const boxDuringCreateProgram = verPragma + mainBoxTestProgram

// boxOperation is used to describe something we want done to a box. A
// transaction doing it will be created and run in a test.
type boxOperation struct {
	op            logic.BoxOperation
	name          string
	createSize    uint64
	contents      []byte
	otherRefCount int
	withBoxRefs   int  // Add this many box refs to the generated transaction
	duringCreate  bool // If true, instantiate `boxDuringCreateProgram` to execute the op
}

func (o boxOperation) appArgs() [][]byte {
	switch o.op {
	case logic.BoxCreateOperation:
		return [][]byte{
			[]byte("create"),
			[]byte(o.name),
			uint64ToBytes(o.createSize),
		}
	case logic.BoxReadOperation:
		return [][]byte{
			[]byte("read"),
			[]byte(o.name),
		}
	case logic.BoxWriteOperation:
		return [][]byte{
			[]byte("write"),
			[]byte(o.name),
			o.contents,
		}
	case logic.BoxDeleteOperation:
		return [][]byte{
			[]byte("delete"),
			[]byte(o.name),
		}
	default:
		panic(fmt.Sprintf("unknown box operation: %v", o.op))
	}
}

func (o boxOperation) boxRefs() []transactions.BoxRef {
	return []transactions.BoxRef{{Name: []byte(o.name)}}
}

type boxTestResult struct {
	Boxes           map[basics.BoxRef]uint64 // maps observed boxes to their size when read
	NumEmptyBoxRefs int

	FailureMessage string
	FailingIndex   int
}

// testUnnamedBoxOperations creates a group with one transaction per boxOp,
// calling `app` with arguments meant to effect the boxOps.  The results must
// match `expected`.
func testUnnamedBoxOperations(t *testing.T, env simulationtesting.Environment, app basics.AppIndex, boxOps []boxOperation, expected boxTestResult) {
	t.Helper()

	maxGroupSize := env.TxnInfo.CurrentProtocolParams().MaxTxGroupSize
	require.LessOrEqual(t, len(boxOps), maxGroupSize)

	otherAssets := 0
	boxRefs := 0
	txns := make([]*txntest.Txn, maxGroupSize)
	for i, op := range boxOps {
		txn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          env.Accounts[0].Addr,
			ApplicationID:   app,
			ApplicationArgs: op.appArgs(),
			ForeignAssets:   make([]basics.AssetIndex, op.otherRefCount),
			Boxes:           slices.Repeat(op.boxRefs(), op.withBoxRefs),
			Note:            []byte{byte(i)}, // Make each txn unique
		})
		if op.duringCreate {
			txn.ApplicationID = 0
			v := env.TxnInfo.CurrentProtocolParams().LogicSigVersion
			txn.ApprovalProgram = fmt.Sprintf(boxDuringCreateProgram, v)
			txn.ClearStateProgram = fmt.Sprintf("#pragma version %d\n int 1", v)
		}
		txns[i] = &txn
		otherAssets += op.otherRefCount
		boxRefs += op.withBoxRefs
	}
	for i := len(boxOps); i < maxGroupSize; i++ {
		// Fill out the rest of the group with non-app transactions. This reduces the amount of
		// unnamed global resources available.
		txn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   env.Accounts[0].Addr,
			Receiver: env.Accounts[0].Addr,
			Note:     []byte{byte(i)}, // Make each txn unique
		})
		txns[i] = &txn
	}
	txntest.Group(txns...)
	stxns := make([]transactions.SignedTxn, len(txns))
	for i, txn := range txns {
		stxns[i] = txn.Txn().Sign(env.Accounts[0].Sk)
	}

	expectedTxnResults := make([]simulation.TxnResult, len(stxns))
	for i := range expectedTxnResults {
		expectedTxnResults[i].AppBudgetConsumed = ignoreAppBudgetConsumed
		if i < len(boxOps) && boxOps[i].duringCreate {
			// 1007 here is because of the number of transactions we used to
			// setup the env.  See explanation in: TestUnnamedResourcesBoxIOBudget
			expectedTxnResults[i].Txn.ApplyData.ApplicationID = 1007 + basics.AppIndex(i)
		}
	}

	var failedAt simulation.TxnPath
	if expected.FailureMessage != "" {
		failedAt = simulation.TxnPath{expected.FailingIndex}
	}

	proto := env.TxnInfo.CurrentProtocolParams()
	expectedUnnamedResources := &simulation.ResourceTracker{
		MaxAccounts:  len(boxOps) * (proto.MaxAppTxnAccounts + proto.MaxAppTxnForeignApps),
		MaxAssets:    len(boxOps)*proto.MaxAppTxnForeignAssets - otherAssets,
		MaxApps:      len(boxOps) * proto.MaxAppTxnForeignApps,
		MaxBoxes:     len(boxOps)*proto.MaxAppBoxReferences - boxRefs,
		MaxTotalRefs: len(boxOps)*proto.MaxAppTotalTxnReferences - otherAssets - boxRefs,

		NumEmptyBoxRefs: expected.NumEmptyBoxRefs,

		MaxCrossProductReferences: len(boxOps) * proto.MaxAppTxnForeignApps * (proto.MaxAppTxnForeignApps + 2),
	}
	if expected.Boxes != nil {
		expectedUnnamedResources.Boxes = make(map[basics.BoxRef]simulation.BoxStat, len(expected.Boxes))
		for key, size := range expected.Boxes {
			expectedUnnamedResources.Boxes[key] = simulation.BoxStat{ReadSize: size}
		}
	}

	if !expectedUnnamedResources.HasResources() {
		expectedUnnamedResources = nil
	}

	testCase := simulationTestCase{
		input: simulation.Request{
			TxnGroups:             [][]transactions.SignedTxn{stxns},
			AllowUnnamedResources: true,
		},
		expectedError: expected.FailureMessage,
		expected: simulation.Result{
			Version:   simulation.ResultLatestVersion,
			LastRound: env.TxnInfo.LatestRound(),
			TxnGroups: []simulation.TxnGroupResult{
				{
					Txns:                     expectedTxnResults,
					AppBudgetAdded:           700 * len(boxOps),
					AppBudgetConsumed:        ignoreAppBudgetConsumed,
					UnnamedResourcesAccessed: expectedUnnamedResources,
					FailedAt:                 failedAt,
				},
			},
			EvalOverrides: simulation.ResultEvalOverrides{
				AllowUnnamedResources: true,
			},
		},
	}
	runSimulationTestCase(t, env, testCase)
}

// TestUnnamedResourcesBoxIOBudget tests that the box IO budgets behave properly when
// AllowUnnamedResources is enabled. It does us no good if you can reference unnamed boxes, but the
// IO budget is still restricted based on the predeclared foreign box array.
func TestUnnamedResourcesBoxIOBudget(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// Boxes introduced in v8
	for v := 8; v <= logic.LogicVersion; v++ {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			t.Parallel()
			env := simulationtesting.PrepareSimulatorTest(t)
			defer env.Close()

			proto := env.TxnInfo.CurrentProtocolParams()
			if v > int(proto.LogicSigVersion) {
				t.Skip("not testing in unsupported proto")
			}

			sender := env.Accounts[0]

			appID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
				ApprovalProgram:   fmt.Sprintf(boxTestProgram, v),
				ClearStateProgram: fmt.Sprintf("#pragma version %d\n int 1", v),
			})

			// MBR is needed for boxes.
			transferable := env.Accounts[1].AcctData.MicroAlgos.Raw - proto.MinBalance - 2*proto.MinTxnFee
			env.TransferAlgos(env.Accounts[1].Addr, appID.Address(), transferable/2)
			// we're also going to make new boxes in a new app, which will be
			// the sixth txns after the appID creation (because of two
			// TrsnaferAlgos and 3 env.Txn, below)
			env.TransferAlgos(env.Accounts[1].Addr, (appID + 6).Address(), transferable/2)

			// Set up boxes A, B, C for testing.
			// A is a box with a size of exactly BytesPerBoxReference
			env.Txn(env.TxnInfo.NewTxn(txntest.Txn{
				Type:          protocol.ApplicationCallTx,
				Sender:        sender.Addr,
				ApplicationID: appID,
				ApplicationArgs: [][]byte{
					[]byte("create"),
					[]byte("A"),
					uint64ToBytes(proto.BytesPerBoxReference),
				},
				Boxes: []transactions.BoxRef{{Name: []byte("A")}},
			}).SignedTxn())
			// B is a box with a size of 1
			env.Txn(env.TxnInfo.NewTxn(txntest.Txn{
				Type:          protocol.ApplicationCallTx,
				Sender:        sender.Addr,
				ApplicationID: appID,
				ApplicationArgs: [][]byte{
					[]byte("create"),
					[]byte("B"),
					uint64ToBytes(1),
				},
				Boxes: []transactions.BoxRef{{Name: []byte("B")}},
			}).SignedTxn())
			// C is a box with a size of 2 * BytesPerBoxReference - 1
			env.Txn(env.TxnInfo.NewTxn(txntest.Txn{
				Type:          protocol.ApplicationCallTx,
				Sender:        sender.Addr,
				ApplicationID: appID,
				ApplicationArgs: [][]byte{
					[]byte("create"),
					[]byte("C"),
					uint64ToBytes(2*proto.BytesPerBoxReference - 1),
				},
				Boxes: []transactions.BoxRef{{Name: []byte("C")}, {}},
			}).SignedTxn())

			testBoxOps := func(boxOps []boxOperation, expected boxTestResult) {
				t.Helper()
				testUnnamedBoxOperations(t, env, appID, boxOps, expected)
			}

			// Each test below will run against the environment we just set up. They will each run
			// in separate simulations, so we can reuse the same environment and not have to worry
			// about the effects of one test interfering with another.

			// Reading existing boxes
			testBoxOps([]boxOperation{
				{op: logic.BoxReadOperation, name: "A"},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "A"}: proto.BytesPerBoxReference,
				},
			})
			testBoxOps([]boxOperation{
				{op: logic.BoxReadOperation, name: "B"},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "B"}: 1,
				},
			})
			testBoxOps([]boxOperation{
				{op: logic.BoxReadOperation, name: "C"},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "C"}: 2*proto.BytesPerBoxReference - 1,
				},
				// We need an additional empty box ref because the size of C exceeds BytesPerBoxReference
				NumEmptyBoxRefs: 1,
			})
			testBoxOps([]boxOperation{
				{op: logic.BoxReadOperation, name: "C", withBoxRefs: 1},
			}, boxTestResult{
				// We need an additional empty box ref because the size of C exceeds BytesPerBoxReference
				NumEmptyBoxRefs: 1,
			})
			testBoxOps([]boxOperation{
				{op: logic.BoxReadOperation, name: "A"},
				{op: logic.BoxReadOperation, name: "B"},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "A"}: proto.BytesPerBoxReference,
					{App: appID, Name: "B"}: 1,
				},
			})
			testBoxOps([]boxOperation{
				{op: logic.BoxReadOperation, name: "A"},
				{op: logic.BoxReadOperation, name: "C"},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "A"}: proto.BytesPerBoxReference,
					{App: appID, Name: "C"}: 2*proto.BytesPerBoxReference - 1,
				},
				NumEmptyBoxRefs: 1,
			})
			testBoxOps([]boxOperation{
				{op: logic.BoxReadOperation, name: "A"},
				{op: logic.BoxReadOperation, name: "B"},
				{op: logic.BoxReadOperation, name: "C"},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "A"}: proto.BytesPerBoxReference,
					{App: appID, Name: "B"}: 1,
					{App: appID, Name: "C"}: 2*proto.BytesPerBoxReference - 1,
				},
				// No empty box refs needed because we have perfectly reached 3 * BytesPerBoxReference
			})

			// non-existent box
			testBoxOps([]boxOperation{
				{op: logic.BoxReadOperation, name: "Q"},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "Q"}: 0,
				},
			})

			// Creating new boxes
			testBoxOps([]boxOperation{
				{op: logic.BoxCreateOperation, name: "D", createSize: proto.BytesPerBoxReference},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "D"}: 0,
				},
			})
			testBoxOps([]boxOperation{
				{op: logic.BoxCreateOperation, name: "D", createSize: proto.BytesPerBoxReference + 1},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "D"}: 0,
				},
				NumEmptyBoxRefs: 1,
			})
			testBoxOps([]boxOperation{
				{op: logic.BoxCreateOperation, name: "D", createSize: proto.BytesPerBoxReference * 3},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "D"}: 0,
				},
				NumEmptyBoxRefs: 2,
			})
			testBoxOps([]boxOperation{
				{op: logic.BoxCreateOperation, name: "D", createSize: 1},
				{op: logic.BoxCreateOperation, name: "E", createSize: 1},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "D"}: 0,
					{App: appID, Name: "E"}: 0,
				},
			})

			// Try to read during a new app create. These boxes _can't_ exist, so no need for extra read quota
			testBoxOps([]boxOperation{
				{op: logic.BoxReadOperation, name: "X", duringCreate: true},
			}, boxTestResult{
				NumEmptyBoxRefs: 1,
			})
			testBoxOps([]boxOperation{
				{op: logic.BoxReadOperation, name: "X", duringCreate: true},
				{op: logic.BoxReadOperation, name: "Y", duringCreate: true},
			}, boxTestResult{
				NumEmptyBoxRefs: 2,
			})
			// now try to create, which can cause enough dirty bytes to require empty refs
			testBoxOps([]boxOperation{
				{op: logic.BoxCreateOperation, name: "small", createSize: proto.BytesPerBoxReference, duringCreate: true},
			}, boxTestResult{
				NumEmptyBoxRefs: 1,
			})
			testBoxOps([]boxOperation{
				{op: logic.BoxCreateOperation, name: "big", createSize: proto.BytesPerBoxReference + 1, duringCreate: true},
			}, boxTestResult{
				NumEmptyBoxRefs: 2,
			})

			// Creating new boxes and reading existing ones
			testBoxOps([]boxOperation{
				{op: logic.BoxCreateOperation, name: "D", createSize: proto.BytesPerBoxReference + 2},
				{op: logic.BoxReadOperation, name: "A"},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "D"}: 0,
					{App: appID, Name: "A"}: proto.BytesPerBoxReference,
				},
				// Since we never write to A, its write budget can cover the extra bytes from writing D,
				// so no extra refs needed.
			})
			testBoxOps([]boxOperation{
				{op: logic.BoxReadOperation, name: "A"},
				{op: logic.BoxCreateOperation, name: "D", createSize: proto.BytesPerBoxReference + 2},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "D"}: 0,
					{App: appID, Name: "A"}: proto.BytesPerBoxReference,
				},
				// The same is true in reverse.
			})

			// Writing to new boxes and existing boxes
			testBoxOps([]boxOperation{
				{op: logic.BoxCreateOperation, name: "D", createSize: proto.BytesPerBoxReference + 2},
				{op: logic.BoxWriteOperation, name: "A", contents: []byte{1}},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "D"}: 0,
					{App: appID, Name: "A"}: proto.BytesPerBoxReference,
				},
				NumEmptyBoxRefs: 1,
			})
			testBoxOps([]boxOperation{
				{op: logic.BoxCreateOperation, name: "D", createSize: proto.BytesPerBoxReference + 2},
				{op: logic.BoxWriteOperation, name: "B", contents: []byte{1}},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "D"}: 0,
					{App: appID, Name: "B"}: 1,
				},
				// Expect 0 empty box refs because the additional box ref from B can cover the extra bytes
				// from writing D
			})

			// Writing then deleting
			testBoxOps([]boxOperation{
				{op: logic.BoxCreateOperation, name: "D", createSize: 4 * proto.BytesPerBoxReference},
				{op: logic.BoxDeleteOperation, name: "D"},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "D"}: 0,
				},
				// Still need 3 empty box refs because we went over the write budget before deletion.
				NumEmptyBoxRefs: 3,
			})

			// Writing, deleting, then reading
			testBoxOps([]boxOperation{
				{op: logic.BoxCreateOperation, name: "D", createSize: 4 * proto.BytesPerBoxReference},
				{op: logic.BoxDeleteOperation, name: "D"},
				{op: logic.BoxReadOperation, name: "C"},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "D"}: 0,
					{App: appID, Name: "C"}: 2*proto.BytesPerBoxReference - 1,
				},
				// 1 extra ref from writing D can be used to cover the extra bytes from reading C,
				// but the other refs must remain.
				NumEmptyBoxRefs: 2,
			})

			// Testing limits

			// Exactly at read budget
			testBoxOps([]boxOperation{
				{
					op:            logic.BoxReadOperation,
					name:          "A",
					otherRefCount: proto.MaxAppBoxReferences - 1,
				},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "A"}: proto.BytesPerBoxReference,
				},
			})

			// Over read budget
			testBoxOps([]boxOperation{
				{
					op:            logic.BoxReadOperation,
					name:          "C",
					otherRefCount: proto.MaxAppBoxReferences - 1,
				},
			}, boxTestResult{
				FailureMessage: fmt.Sprintf("logic eval error: invalid Box reference %#x", "C"),
				FailingIndex:   0,
			})

			// Very close to read budget, but writing another box should still be allowed
			testBoxOps([]boxOperation{
				{
					op:            logic.BoxReadOperation,
					name:          "C",
					otherRefCount: proto.MaxAppBoxReferences - 2,
				},
				{
					op:            logic.BoxCreateOperation,
					name:          "X",
					createSize:    2 * proto.BytesPerBoxReference,
					otherRefCount: proto.MaxAppBoxReferences,
				},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "C"}: 2*proto.BytesPerBoxReference - 1,
					{App: appID, Name: "X"}: 0,
				},
			})

			// Exactly at write budget
			testBoxOps([]boxOperation{
				{
					op:            logic.BoxCreateOperation,
					name:          "X",
					createSize:    proto.BytesPerBoxReference,
					otherRefCount: proto.MaxAppBoxReferences - 1,
				},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "X"}: 0,
				},
			})

			// Over write budget
			testBoxOps([]boxOperation{
				{
					op:            logic.BoxCreateOperation,
					name:          "X",
					createSize:    proto.BytesPerBoxReference + 1,
					otherRefCount: proto.MaxAppBoxReferences - 1,
				},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "X"}: 0,
				},
				FailureMessage: fmt.Sprintf("logic eval error: write budget (%d) exceeded %d", proto.BytesPerBoxReference, proto.BytesPerBoxReference+1),
				FailingIndex:   0,
			})

			// Exactly at write budget, but reading another box should still be allowed
			testBoxOps([]boxOperation{
				{
					op:            logic.BoxCreateOperation,
					name:          "X",
					createSize:    2 * proto.BytesPerBoxReference,
					otherRefCount: proto.MaxAppBoxReferences - 2,
				},
				{
					op:            logic.BoxReadOperation,
					name:          "A",
					otherRefCount: proto.MaxAppBoxReferences,
				},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "X"}: 0,
					{App: appID, Name: "A"}: proto.BytesPerBoxReference,
				},
			})

			// No more refs available
			testBoxOps([]boxOperation{
				{
					op:            logic.BoxReadOperation,
					name:          "A",
					otherRefCount: proto.MaxAppBoxReferences - 1,
				},
				{
					op:            logic.BoxReadOperation,
					name:          "B",
					otherRefCount: proto.MaxAppBoxReferences,
				},
			}, boxTestResult{
				Boxes: map[basics.BoxRef]uint64{
					{App: appID, Name: "A"}: proto.BytesPerBoxReference,
				},
				FailureMessage: fmt.Sprintf("logic eval error: invalid Box reference %#x", "B"),
				FailingIndex:   1,
			})
		})
	}
}

const resourceLimitsTestProgramBase = `#pragma version %d
txn ApplicationID
bz end // Do nothing during create

// Scratch slots:
// 0 - loop counter
// 1 - resource type
// 2 - cross-product app/asset ID
// 3 - cross-product accounts

loop:
load 0
txn NumAppArgs
<
bz loop_end
load 0
txnas ApplicationArgs
dup

extract 1 0
swap

int 0
getbyte

store 1
load 1
bz account
load 1
int 1
==
bnz asset
load 1
int 2
==
bnz app
load 1
int 3
==
bnz box
load 1
int 4
==
bnz asset_holding
load 1
int 5
==
bnz app_local
err

account:
balance
assert
b loop_step

asset:
btoi
asset_params_get AssetTotal
assert
assert
b loop_step

app:
btoi
byte 0x01
app_global_get_ex
!
assert
!
assert
b loop_step

box:
%s
b loop_step

asset_holding:
dup
int 0
extract_uint64
store 2
extract 8 0
store 3
asset_holding_loop:
load 3
len
bz asset_holding_loop_end
txn Note
load 3
dup
extract 1 0
store 3
int 0
getbyte
int 32
*
int 32
extract
load 2
asset_holding_get AssetBalance
!
assert
!
assert
b asset_holding_loop
asset_holding_loop_end:
b loop_step

app_local:
dup
int 0
extract_uint64
store 2
extract 8 0
store 3
app_local_loop:
load 3
len
bz app_local_loop_end
txn Note
load 3
dup
extract 1 0
store 3
int 0
getbyte
int 32
*
int 32
extract
load 2
app_opted_in
!
assert
b app_local_loop
app_local_loop_end:

loop_step:
load 0
int 1
+
store 0
b loop
loop_end:

end:
int 1
`

func resourceLimitsTestProgram(version int) string {
	var boxCode string
	if version >= 8 {
		// Boxes available
		boxCode = "box_len; !; assert; !; assert"
	} else {
		boxCode = "err"
	}
	return fmt.Sprintf(resourceLimitsTestProgramBase, version, boxCode)
}

type unnamedResourceArgument struct {
	account              basics.Address
	asset                basics.AssetIndex
	app                  basics.AppIndex
	box                  string
	assetHoldingAccounts []basics.Address
	appLocalAccounts     []basics.Address

	limitExceeded bool
}

type unnamedResourceArguments []unnamedResourceArgument

func (resources unnamedResourceArguments) markLimitExceeded() unnamedResourceArguments {
	modified := slices.Clone(resources)
	modified[len(modified)-1].limitExceeded = true
	return modified
}

func (resources unnamedResourceArguments) addAccounts(accounts ...basics.Address) unnamedResourceArguments {
	modified := slices.Clone(resources)
	for _, account := range accounts {
		modified = append(modified, unnamedResourceArgument{account: account})
	}
	return modified
}

func (resources unnamedResourceArguments) addAssets(assets ...basics.AssetIndex) unnamedResourceArguments {
	modified := slices.Clone(resources)
	for _, asset := range assets {
		modified = append(modified, unnamedResourceArgument{asset: asset})
	}
	return modified
}

func (resources unnamedResourceArguments) addApps(apps ...basics.AppIndex) unnamedResourceArguments {
	modified := slices.Clone(resources)
	for _, app := range apps {
		modified = append(modified, unnamedResourceArgument{app: app})
	}
	return modified
}

func (resources unnamedResourceArguments) addBoxes(boxes ...string) unnamedResourceArguments {
	modified := slices.Clone(resources)
	for _, box := range boxes {
		modified = append(modified, unnamedResourceArgument{box: box})
	}
	return modified
}

func (resources unnamedResourceArguments) addAssetHoldings(asset basics.AssetIndex, accounts ...basics.Address) unnamedResourceArguments {
	modified := slices.Clone(resources)
	modified = append(modified, unnamedResourceArgument{asset: asset, assetHoldingAccounts: accounts})
	return modified
}

func (resources unnamedResourceArguments) addAppLocals(app basics.AppIndex, accounts ...basics.Address) unnamedResourceArguments {
	modified := slices.Clone(resources)
	modified = append(modified, unnamedResourceArgument{app: app, appLocalAccounts: accounts})
	return modified
}

func (resources unnamedResourceArguments) accounts() []basics.Address {
	var accounts []basics.Address
	for i := range resources {
		if resources[i].limitExceeded {
			break
		}
		if !resources[i].account.IsZero() {
			accounts = append(accounts, resources[i].account)
		}
		// accounts = append(accounts, resources[i].assetHoldingAccounts...)
		// accounts = append(accounts, resources[i].appLocalAccounts...)
	}
	return accounts
}

func (resources unnamedResourceArguments) assets() []basics.AssetIndex {
	var assets []basics.AssetIndex
	for i := range resources {
		if resources[i].limitExceeded {
			break
		}
		if resources[i].asset != 0 {
			assets = append(assets, resources[i].asset)
		}
	}
	return assets
}

func (resources unnamedResourceArguments) apps() []basics.AppIndex {
	var apps []basics.AppIndex
	for i := range resources {
		if resources[i].limitExceeded {
			break
		}
		if resources[i].app != 0 {
			apps = append(apps, resources[i].app)
		}
	}
	return apps
}

func (resources unnamedResourceArguments) boxes() []string {
	var boxes []string
	for i := range resources {
		if resources[i].limitExceeded {
			break
		}
		if resources[i].box != "" {
			boxes = append(boxes, resources[i].box)
		}
	}
	return boxes
}

func (resources unnamedResourceArguments) assetHoldings() []ledgercore.AccountAsset {
	var assetHoldings []ledgercore.AccountAsset
	for i := range resources {
		if resources[i].limitExceeded {
			break
		}
		for _, account := range resources[i].assetHoldingAccounts {
			assetHoldings = append(assetHoldings, ledgercore.AccountAsset{
				Address: account,
				Asset:   resources[i].asset,
			})
		}
	}
	return assetHoldings
}

func (resources unnamedResourceArguments) appLocals() []ledgercore.AccountApp {
	var appLocals []ledgercore.AccountApp
	for i := range resources {
		if resources[i].limitExceeded {
			break
		}
		for _, account := range resources[i].appLocalAccounts {
			appLocals = append(appLocals, ledgercore.AccountApp{
				Address: account,
				App:     resources[i].app,
			})
		}
	}
	return appLocals
}

func (resources unnamedResourceArguments) addToTxn(txn *txntest.Txn) {
	encodedArgs := make([][]byte, len(resources))
	crossProductAccounts := make(map[basics.Address]int)
	var crossProductAccountsOrder []basics.Address
	for i, resource := range resources {
		switch {
		case len(resource.assetHoldingAccounts) != 0:
			encoding := make([]byte, 1+8+len(resource.assetHoldingAccounts))
			encoding[0] = 4
			copy(encoding[1:9], uint64ToBytes(uint64(resource.asset)))
			for j, account := range resource.assetHoldingAccounts {
				accountIndex, ok := crossProductAccounts[account]
				if !ok {
					accountIndex = len(crossProductAccounts)
					crossProductAccounts[account] = accountIndex
					crossProductAccountsOrder = append(crossProductAccountsOrder, account)
				}
				encoding[9+j] = byte(accountIndex)
			}
			encodedArgs[i] = encoding
		case len(resource.appLocalAccounts) != 0:
			encoding := make([]byte, 1+8+len(resource.appLocalAccounts))
			encoding[0] = 5
			copy(encoding[1:9], uint64ToBytes(uint64(resource.app)))
			for j, account := range resource.appLocalAccounts {
				accountIndex, ok := crossProductAccounts[account]
				if !ok {
					accountIndex = len(crossProductAccounts)
					crossProductAccounts[account] = accountIndex
					crossProductAccountsOrder = append(crossProductAccountsOrder, account)
				}
				encoding[9+j] = byte(accountIndex)
			}
			encodedArgs[i] = encoding
		case !resource.account.IsZero():
			encodedArgs[i] = append([]byte{0}, resource.account[:]...)
		case resource.asset != 0:
			encodedArgs[i] = append([]byte{1}, uint64ToBytes(uint64(resource.asset))...)
		case resource.app != 0:
			encodedArgs[i] = append([]byte{2}, uint64ToBytes(uint64(resource.app))...)
		case resource.box != "":
			encodedArgs[i] = append([]byte{3}, []byte(resource.box)...)
		default:
			panic(fmt.Sprintf("empty resource at index %d", i))
		}
	}
	txn.ApplicationArgs = encodedArgs
	txn.Note = make([]byte, 32*len(crossProductAccountsOrder))
	for i, account := range crossProductAccountsOrder {
		copy(txn.Note[32*i:], account[:])
	}
}

func mapWithKeys[K comparable, V any](keys []K, defaultValue V) map[K]V {
	if keys == nil {
		return nil
	}

	m := make(map[K]V, len(keys))
	for _, k := range keys {
		m[k] = defaultValue
	}
	return m
}

func boxNamesToRefs(app basics.AppIndex, names []string) []basics.BoxRef {
	if names == nil {
		return nil
	}

	refs := make([]basics.BoxRef, len(names))
	for i, name := range names {
		refs[i] = basics.BoxRef{
			App:  app,
			Name: name,
		}
	}
	return refs
}

func testUnnamedResourceLimits(t *testing.T, env simulationtesting.Environment, appVersion int, app basics.AppIndex, resources unnamedResourceArguments, otherTxns []txntest.Txn, extraBudget int, expectedError string) {
	t.Helper()
	maxGroupSize := env.TxnInfo.CurrentProtocolParams().MaxTxGroupSize
	txns := make([]*txntest.Txn, maxGroupSize)
	appCall := env.TxnInfo.NewTxn(txntest.Txn{
		Type:          protocol.ApplicationCallTx,
		Sender:        env.Accounts[0].Addr,
		ApplicationID: app,
	})
	resources.addToTxn(&appCall)
	txns[0] = &appCall
	for i := range otherTxns {
		txn := env.TxnInfo.NewTxn(otherTxns[i])
		txns[i+1] = &txn
	}
	for i := 1 + len(otherTxns); i < maxGroupSize; i++ {
		// Fill out the rest of the group with non-app transactions. This reduces the amount of
		// unnamed global resources available.
		txn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   env.Accounts[0].Addr,
			Receiver: env.Accounts[0].Addr,
			Note:     []byte{byte(i)}, // Make each txn unique
		})
		txns[i] = &txn
	}
	txntest.Group(txns...)
	stxns := make([]transactions.SignedTxn, len(txns))
	for i, txn := range txns {
		stxns[i] = txn.Txn().Sign(env.Accounts[0].Sk)
	}

	expectedTxnResults := make([]simulation.TxnResult, len(stxns))
	for i := range expectedTxnResults {
		expectedTxnResults[i].AppBudgetConsumed = ignoreAppBudgetConsumed
	}

	var failedAt simulation.TxnPath
	if expectedError != "" {
		failedAt = simulation.TxnPath{0}
	}

	proto := env.TxnInfo.CurrentProtocolParams()

	expectedGroupResources := &simulation.ResourceTracker{
		MaxAccounts:  proto.MaxAppTxnAccounts + proto.MaxAppTxnForeignApps,
		MaxAssets:    proto.MaxAppTxnForeignAssets,
		MaxApps:      proto.MaxAppTxnForeignApps,
		MaxBoxes:     proto.MaxAppBoxReferences,
		MaxTotalRefs: proto.MaxAppTotalTxnReferences,

		Boxes: mapWithKeys(boxNamesToRefs(app, resources.boxes()), simulation.BoxStat{}),

		MaxCrossProductReferences: proto.MaxAppTxnForeignApps * (proto.MaxAppTxnForeignApps + 2),
	}
	expectedAccounts := mapWithKeys(resources.accounts(), struct{}{})
	// If present, delete the sender, since it's accessible normally.
	delete(expectedAccounts, env.Accounts[0].Addr)
	if len(expectedAccounts) == 0 {
		expectedAccounts = nil
	}
	expectedAssets := mapWithKeys(resources.assets(), struct{}{})
	for _, txn := range otherTxns {
		delete(expectedAssets, txn.XferAsset)
	}
	if len(expectedAssets) == 0 {
		expectedAssets = nil
	}
	expectedApps := mapWithKeys(resources.apps(), struct{}{})
	delete(expectedApps, app)
	if len(expectedApps) == 0 {
		expectedApps = nil
	}
	if appVersion < 9 {
		// No shared resources
		localResources := simulation.ResourceTracker{
			MaxAccounts:  proto.MaxAppTxnAccounts + proto.MaxAppTxnForeignApps,
			MaxAssets:    proto.MaxAppTxnForeignAssets,
			MaxApps:      proto.MaxAppTxnForeignApps,
			MaxBoxes:     proto.MaxAppBoxReferences,
			MaxTotalRefs: proto.MaxAppTotalTxnReferences,

			Accounts: expectedAccounts,
			Assets:   expectedAssets,
			Apps:     expectedApps,
		}
		expectedGroupResources.MaxAccounts -= len(localResources.Accounts) + len(localResources.Apps)
		expectedGroupResources.MaxAssets -= len(localResources.Assets)
		expectedGroupResources.MaxApps -= len(localResources.Apps)
		expectedGroupResources.MaxTotalRefs -= len(localResources.Accounts) + len(localResources.Assets) + len(localResources.Apps)
		if localResources.HasResources() {
			expectedTxnResults[0].UnnamedResourcesAccessed = &localResources
		}
	} else {
		// Shared resources
		expectedGroupResources.Accounts = expectedAccounts
		expectedGroupResources.Assets = expectedAssets
		expectedGroupResources.Apps = expectedApps
		expectedGroupResources.AssetHoldings = mapWithKeys(resources.assetHoldings(), struct{}{})
		expectedGroupResources.AppLocals = mapWithKeys(resources.appLocals(), struct{}{})
	}

	if !expectedGroupResources.HasResources() {
		expectedGroupResources = nil
	}

	testCase := simulationTestCase{
		input: simulation.Request{
			TxnGroups:             [][]transactions.SignedTxn{stxns},
			AllowUnnamedResources: true,
			ExtraOpcodeBudget:     extraBudget,
		},
		expectedError: expectedError,
		expected: simulation.Result{
			Version:   simulation.ResultLatestVersion,
			LastRound: env.TxnInfo.LatestRound(),
			TxnGroups: []simulation.TxnGroupResult{
				{
					Txns:                     expectedTxnResults,
					AppBudgetAdded:           700 + extraBudget,
					AppBudgetConsumed:        ignoreAppBudgetConsumed,
					UnnamedResourcesAccessed: expectedGroupResources,
					FailedAt:                 failedAt,
				},
			},
			EvalOverrides: simulation.ResultEvalOverrides{
				AllowUnnamedResources: true,
				ExtraOpcodeBudget:     extraBudget,
			},
		},
	}
	runSimulationTestCase(t, env, testCase)
}

func TestUnnamedResourcesLimits(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// Start with v5, since that introduces the `txnas` opcode, needed for dynamic indexing into app
	// args array.
	for v := 5; v <= logic.LogicVersion; v++ {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			t.Parallel()
			env := simulationtesting.PrepareSimulatorTest(t)
			defer env.Close()

			proto := env.TxnInfo.CurrentProtocolParams()
			if v > int(proto.LogicSigVersion) {
				t.Skip("not testing in unsupported proto")
				return
			}

			sender := env.Accounts[0]
			otherAccounts := make([]basics.Address, len(env.Accounts)-1)
			for i := range otherAccounts {
				otherAccounts[i] = env.Accounts[i+1].Addr
			}

			assetCreator := env.Accounts[1].Addr
			assets := make([]basics.AssetIndex, proto.MaxAppTxnForeignAssets+1)
			for i := range assets {
				assets[i] = env.CreateAsset(assetCreator, basics.AssetParams{Total: 100})
			}

			otherAppCreator := env.Accounts[1].Addr
			otherApps := make([]basics.AppIndex, proto.MaxAppTxnForeignApps+1)
			for i := range otherApps {
				otherApps[i] = env.CreateApp(otherAppCreator, simulationtesting.AppParams{
					// The program version here doesn't matter
					ApprovalProgram:   "#pragma version 8\nint 1",
					ClearStateProgram: "#pragma version 8\nint 1",
				})
			}

			boxes := make([]string, proto.MaxAppBoxReferences+1)
			for i := range boxes {
				boxes[i] = fmt.Sprintf("box%d", i)
			}

			appID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
				ApprovalProgram:   resourceLimitsTestProgram(v),
				ClearStateProgram: fmt.Sprintf("#pragma version %d\n int 1", v),
			})

			testResourceAccess := func(resources unnamedResourceArguments, extra ...string) {
				t.Helper()
				var expectedError string
				if len(extra) != 0 {
					expectedError = extra[0]
				}
				testUnnamedResourceLimits(t, env, v, appID, resources, nil, 0, expectedError)
			}

			// Each test below will run against the environment we just set up. They will each run
			// in separate simulations, so we can reuse the same environment and not have to worry
			// about the effects of one test interfering with another.

			// Exactly at account limit
			testResourceAccess(
				unnamedResourceArguments{}.addAccounts(otherAccounts[:proto.MaxAppTotalTxnReferences]...),
			)
			// Over account limit
			testResourceAccess(
				unnamedResourceArguments{}.
					addAccounts(otherAccounts[:proto.MaxAppTotalTxnReferences+1]...).
					markLimitExceeded(),
				fmt.Sprintf("logic eval error: unavailable Account %s", otherAccounts[proto.MaxAppTotalTxnReferences]),
			)

			// Exactly at asset limit
			testResourceAccess(
				unnamedResourceArguments{}.addAssets(assets[:proto.MaxAppTxnForeignAssets]...),
			)
			// Over asset limit
			testResourceAccess(
				unnamedResourceArguments{}.
					addAssets(assets[:proto.MaxAppTxnForeignAssets+1]...).
					markLimitExceeded(),
				fmt.Sprintf("logic eval error: unavailable Asset %d", assets[proto.MaxAppTxnForeignAssets]),
			)

			// Exactly at app limit
			testResourceAccess(
				unnamedResourceArguments{}.addApps(otherApps[:proto.MaxAppTxnForeignApps]...),
			)
			// Over app limit
			testResourceAccess(
				unnamedResourceArguments{}.
					addApps(otherApps[:proto.MaxAppTxnForeignApps+1]...).
					markLimitExceeded(),
				fmt.Sprintf("logic eval error: unavailable App %d", otherApps[proto.MaxAppTxnForeignApps]),
			)

			if v >= 8 {
				// Exactly at box limit
				testResourceAccess(
					unnamedResourceArguments{}.addBoxes(boxes[:proto.MaxAppBoxReferences]...),
				)
				// Over box limit
				testResourceAccess(
					unnamedResourceArguments{}.
						addBoxes(boxes[:proto.MaxAppBoxReferences+1]...).
						markLimitExceeded(),
					fmt.Sprintf("logic eval error: invalid Box reference %#x", boxes[proto.MaxAppBoxReferences]),
				)
			}

			numResourceTypes := 3 // accounts, assets, apps
			if v >= 8 {
				numResourceTypes++ // boxes
			}
			var atLimit unnamedResourceArguments
			for i := 0; i < proto.MaxAppTotalTxnReferences; i++ {
				switch i % numResourceTypes {
				case 0:
					atLimit = atLimit.addAccounts(otherAccounts[i/numResourceTypes])
				case 1:
					atLimit = atLimit.addAssets(assets[i/numResourceTypes])
				case 2:
					atLimit = atLimit.addApps(otherApps[i/numResourceTypes])
				case 3:
					atLimit = atLimit.addBoxes(boxes[i/numResourceTypes])
				default:
					panic(fmt.Sprintf("i=%d, numResourceTypes=%d", i, numResourceTypes))
				}
			}
			// Exactly at limit for total references
			testResourceAccess(atLimit)

			// Adding 1 more of any is over the limit
			testResourceAccess(
				atLimit.addAccounts(otherAccounts[len(otherAccounts)-1]).markLimitExceeded(),
				fmt.Sprintf("logic eval error: unavailable Account %s", otherAccounts[len(otherAccounts)-1]),
			)
			testResourceAccess(
				atLimit.addAssets(assets[len(assets)-1]).markLimitExceeded(),
				fmt.Sprintf("logic eval error: unavailable Asset %d", assets[len(assets)-1]),
			)
			testResourceAccess(
				atLimit.addApps(otherApps[len(otherApps)-1]).markLimitExceeded(),
				fmt.Sprintf("logic eval error: unavailable App %d", otherApps[len(otherApps)-1]),
			)
			if v >= 8 {
				testResourceAccess(
					atLimit.addBoxes(boxes[len(boxes)-1]).markLimitExceeded(),
					fmt.Sprintf("logic eval error: invalid Box reference %#x", boxes[len(boxes)-1]),
				)
			}
		})
	}
}

// PROBLEM: for newly created assets/apps (and app accounts), cross-product refs with unnamed resources
// SHOULD NOT count against the cross product limit. This is because just including the other resource
// anywhere in the group is enough to grant access.

func excludingIndex[S []V, V any](slice S, index int) S {
	if index == 0 {
		return slice[1:]
	}
	if index == len(slice)-1 {
		return slice[:len(slice)-1]
	}
	return append(slices.Clone(slice[:index]), slice[index+1:]...)
}

func TestUnnamedResourcesCrossProductLimits(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// Start with v9, since that's when we first track cross-product references indepdently.
	for v := 9; v <= logic.LogicVersion; v++ {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			t.Parallel()
			env := simulationtesting.PrepareSimulatorTest(t)
			defer env.Close()

			proto := env.TxnInfo.CurrentProtocolParams()
			if v > int(proto.LogicSigVersion) {
				t.Skip("not testing in unsupported proto")
				return
			}

			sender := env.Accounts[0]
			otherAccounts := make([]basics.Address, proto.MaxTxGroupSize)
			for i := range otherAccounts {
				otherAccounts[i][0] = byte(i + 1)
			}

			assets := make([]basics.AssetIndex, proto.MaxTxGroupSize-1)
			for i := range assets {
				assets[i] = env.CreateAsset(sender.Addr, basics.AssetParams{Total: 100})
			}

			otherApps := make([]basics.AppIndex, proto.MaxAppTxnForeignApps)
			for i := range otherApps {
				otherApps[i] = env.CreateApp(sender.Addr, simulationtesting.AppParams{
					// The program version here doesn't matter
					ApprovalProgram:   "#pragma version 8\nint 1",
					ClearStateProgram: "#pragma version 8\nint 1",
				})
			}
			otherAppAccounts := make([]basics.Address, len(otherApps))
			for i := range otherAppAccounts {
				otherAppAccounts[i] = otherApps[i].Address()
			}

			appID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
				ApprovalProgram:   resourceLimitsTestProgram(v),
				ClearStateProgram: fmt.Sprintf("#pragma version %d\n int 1", v),
			})

			otherAccounts[len(otherAccounts)-1] = appID.Address()

			assetFillingTxns := make([]txntest.Txn, proto.MaxTxGroupSize-1)
			for i := range assetFillingTxns {
				assetFillingTxns[i] = txntest.Txn{
					Type:          protocol.AssetTransferTx,
					XferAsset:     assets[i],
					Sender:        sender.Addr,
					AssetReceiver: otherAccounts[i],
				}
			}

			testResourceAccess := func(resources unnamedResourceArguments, extra ...string) {
				t.Helper()
				var expectedError string
				if len(extra) != 0 {
					expectedError = extra[0]
				}
				testUnnamedResourceLimits(t, env, v, appID, resources, assetFillingTxns, 2000, expectedError)
			}

			// Each test below will run against the environment we just set up. They will each run
			// in separate simulations, so we can reuse the same environment and not have to worry
			// about the effects of one test interfering with another.

			maxCrossProducts := proto.MaxAppTxnForeignApps * (proto.MaxAppTxnForeignApps + 2)

			var atAssetHoldingLimit unnamedResourceArguments
			var assetHoldingLimitIndex int
			for i := range assets {
				accounts := excludingIndex(otherAccounts, i)
				end := false
				if (i+1)*(proto.MaxTxGroupSize-1) >= maxCrossProducts {
					remaining := maxCrossProducts - i*(proto.MaxTxGroupSize-1)
					accounts = accounts[:remaining]
					assetHoldingLimitIndex = i + 1
					end = true
				}
				atAssetHoldingLimit = atAssetHoldingLimit.addAssetHoldings(assets[i], accounts...)
				if end {
					break
				}
			}

			var atAppLocalLimit unnamedResourceArguments
			for i := range otherApps {
				accounts := []basics.Address{sender.Addr, appID.Address()}
				accounts = append(accounts, excludingIndex(otherAppAccounts, i)...)
				atAppLocalLimit = atAppLocalLimit.addAppLocals(otherApps[i], accounts...)
			}
			atAppLocalLimit = atAppLocalLimit.addAppLocals(appID, otherAppAccounts...)

			// Hitting the limit with a combined number of asset holdings and app locals. We reuse
			// most of atAppLocalLimit, but remove the last app locals and replace them with asset
			// holdings.
			atCombinedLimit := atAppLocalLimit[:len(atAppLocalLimit)-1]
			atCombinedLimit = atCombinedLimit.addAssetHoldings(assets[0], otherAccounts[1:proto.MaxAppTxnForeignApps+1]...)

			// Exactly at asset holding limit
			testResourceAccess(atAssetHoldingLimit)

			// Exactly at app local limit
			testResourceAccess(atAppLocalLimit)

			// Exactly at total cross-product limit with both resource types
			testResourceAccess(atCombinedLimit)

			// Over asset holding limit
			testResourceAccess(
				atAssetHoldingLimit.
					addAssetHoldings(assets[assetHoldingLimitIndex], otherAccounts[0]).
					markLimitExceeded(),
				fmt.Sprintf("logic eval error: unavailable Holding %d+%s", assets[assetHoldingLimitIndex], otherAccounts[0]),
			)

			// Over app local limit
			testResourceAccess(
				atAppLocalLimit.
					addAppLocals(appID, otherAccounts[0]).
					markLimitExceeded(),
				fmt.Sprintf("logic eval error: unavailable Local State %d+%s", appID, otherAccounts[0]),
			)

			// Over total cross-product limit with asset holding
			testResourceAccess(
				atCombinedLimit.
					addAssetHoldings(assets[1], otherAccounts[0]).
					markLimitExceeded(),
				fmt.Sprintf("logic eval error: unavailable Holding %d+%s", assets[1], otherAccounts[0]),
			)

			// Over total cross-product limit with app local
			testResourceAccess(
				atCombinedLimit.
					addAppLocals(appID, otherAccounts[0]).
					markLimitExceeded(),
				fmt.Sprintf("logic eval error: unavailable Local State %d+%s", appID, otherAccounts[0]),
			)
		})
	}
}

func TestFixSigners(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("AllowEmptySignatures=false", func(t *testing.T) {
		t.Parallel()
		env := simulationtesting.PrepareSimulatorTest(t)
		defer env.Close()

		sender := env.Accounts[0]

		txn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: sender.Addr,
		}).SignedTxn()

		simRequest := simulation.Request{
			TxnGroups: [][]transactions.SignedTxn{
				{txn},
			},
			AllowEmptySignatures: false,
			FixSigners:           true,
		}

		_, err := simulation.MakeSimulator(env.Ledger, false).Simulate(simRequest)
		require.ErrorAs(t, err, &simulation.InvalidRequestError{})
		require.ErrorContains(t, err, "FixSigners requires AllowEmptySignatures to be enabled")
	})

	type testInputs struct {
		txgroup        []transactions.SignedTxn
		sender         simulationtesting.Account
		other          simulationtesting.Account
		innerRekeyAddr basics.Address
	}

	makeTestInputs := func(env *simulationtesting.Environment) testInputs {
		sender := env.Accounts[0]
		other := env.Accounts[1]

		innerRekeyAddr := env.Accounts[2].Addr
		innerProgram := fmt.Sprintf(`#pragma version 9
		txn ApplicationID
		bz end

		// Rekey to the the innerRekeyAddr
		itxn_begin
		int pay
		itxn_field TypeEnum
		txn ApplicationArgs 0
		itxn_field Sender
		addr %s
		itxn_field RekeyTo
		itxn_submit

		end:
		int 1
		`, innerRekeyAddr)

		innerAppID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
			ApprovalProgram:   innerProgram,
			ClearStateProgram: "#pragma version 9\nint 1",
		})

		outerProgram := fmt.Sprintf(`#pragma version 9
		txn ApplicationID
		bz end

		// Rekey to inner app
		itxn_begin
		int pay
		itxn_field TypeEnum
		txn ApplicationArgs 0
		itxn_field Sender
		addr %s
		itxn_field RekeyTo
		itxn_submit

		// Call inner app
		itxn_begin
		int appl
		itxn_field TypeEnum
		int %d
		itxn_field ApplicationID
		txn ApplicationArgs 0
		itxn_field ApplicationArgs
		itxn_submit

		end:
		int 1`, innerAppID.Address(), innerAppID)

		appID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
			ApprovalProgram:   outerProgram,
			ClearStateProgram: "#pragma version 9\nint 1",
		})

		env.TransferAlgos(sender.Addr, appID.Address(), 1_000_000)

		// rekey to EOA
		pay0 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: sender.Addr,
			RekeyTo:  other.Addr,
		})
		// rekey to outer app, which rekeys to inner app, which rekeys to another app
		pay1 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: sender.Addr,
			RekeyTo:  appID.Address(),
		})
		// app rekeys to random address
		appCall := env.TxnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          other.Addr,
			ApplicationID:   appID,
			ApplicationArgs: [][]byte{sender.Addr[:]},
			ForeignApps:     []basics.AppIndex{innerAppID},
		})
		// rekey back to sender (original address)
		pay2 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: sender.Addr,
			RekeyTo:  sender.Addr,
		})
		// send txn from sender
		pay3 := env.TxnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: sender.Addr,
		})

		txgroup := txntest.Group(&pay0, &pay1, &appCall, &pay2, &pay3)

		return testInputs{
			txgroup:        txgroup,
			sender:         sender,
			other:          other,
			innerRekeyAddr: innerRekeyAddr,
		}
	}

	// Convenience function for getting the expected app call result. This is a function instead of
	// a variable because it's used by multiple tests, and the expected result is modified with the
	// input transactions before comparison by each test.
	expectedAppCallResultFn := func() simulation.TxnResult {
		return simulation.TxnResult{
			AppBudgetConsumed: ignoreAppBudgetConsumed,
			Txn: transactions.SignedTxnWithAD{
				ApplyData: transactions.ApplyData{
					EvalDelta: transactions.EvalDelta{
						InnerTxns: []transactions.SignedTxnWithAD{
							{},
							{
								ApplyData: transactions.ApplyData{
									EvalDelta: transactions.EvalDelta{
										InnerTxns: []transactions.SignedTxnWithAD{
											{},
										},
									},
								},
							},
						},
					},
				},
			},
		}
	}

	t.Run("no signatures", func(t *testing.T) {
		t.Parallel()
		simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
			inputs := makeTestInputs(&env)

			// Do not sign any of the transactions

			return simulationTestCase{
				input: simulation.Request{
					TxnGroups:            [][]transactions.SignedTxn{inputs.txgroup},
					AllowEmptySignatures: true,
					FixSigners:           true,
				},
				expected: simulation.Result{
					Version:   simulation.ResultLatestVersion,
					LastRound: env.TxnInfo.LatestRound(),
					EvalOverrides: simulation.ResultEvalOverrides{
						AllowEmptySignatures: true,
						FixSigners:           true,
					},
					TxnGroups: []simulation.TxnGroupResult{
						{
							Txns: []simulation.TxnResult{
								{}, // pay0
								{ // pay1
									FixedSigner: inputs.other.Addr,
								},
								// appCall
								expectedAppCallResultFn(),
								{ // pay2
									FixedSigner: inputs.innerRekeyAddr,
								},
								{}, // pay3
							},
							AppBudgetConsumed: ignoreAppBudgetConsumed,
							AppBudgetAdded:    2800,
						},
					},
				},
			}
		})
	})

	t.Run("sign pay after outer rekey", func(t *testing.T) {
		t.Parallel()
		simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
			inputs := makeTestInputs(&env)

			// Sign txn 1, payment after the outer rekey, with the wrong AuthAddr. This renders the
			// group invalid, since the AuthAddr will not be corrected if a signature is provided.
			inputs.txgroup[1] = inputs.txgroup[1].Txn.Sign(inputs.sender.Sk)

			return simulationTestCase{
				input: simulation.Request{
					TxnGroups:            [][]transactions.SignedTxn{inputs.txgroup},
					AllowEmptySignatures: true,
					FixSigners:           true,
				},
				expectedError: fmt.Sprintf("should have been authorized by %s but was actually authorized by %s", inputs.other.Addr, inputs.sender.Addr),
				expected: simulation.Result{
					Version:   simulation.ResultLatestVersion,
					LastRound: env.TxnInfo.LatestRound(),
					EvalOverrides: simulation.ResultEvalOverrides{
						AllowEmptySignatures: true,
						FixSigners:           true,
					},
					TxnGroups: []simulation.TxnGroupResult{
						{
							FailedAt: simulation.TxnPath{1},
							Txns: []simulation.TxnResult{
								{}, // pay0
								{}, // pay1, does NOT contain FixedSigner
								{}, // appCall
								{}, // pay2
								{}, // pay3
							},
							AppBudgetConsumed: 0,
							// This is here even though we don't make it to the app call because
							// pooled app budget is determined before the group is evaluated.
							AppBudgetAdded: 700,
						},
					},
				},
			}
		})
	})

	t.Run("sign pay after inner rekey", func(t *testing.T) {
		t.Parallel()
		simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
			inputs := makeTestInputs(&env)

			// Sign txn 3, payment after the inner rekey, with the wrong AuthAddr. This renders the
			// group invalid, since the AuthAddr will not be corrected if a signature is provided.
			inputs.txgroup[3] = inputs.txgroup[3].Txn.Sign(inputs.other.Sk)

			return simulationTestCase{
				input: simulation.Request{
					TxnGroups:            [][]transactions.SignedTxn{inputs.txgroup},
					AllowEmptySignatures: true,
					FixSigners:           true,
				},
				expectedError: fmt.Sprintf("should have been authorized by %s but was actually authorized by %s", inputs.innerRekeyAddr, inputs.other.Addr),
				expected: simulation.Result{
					Version:   simulation.ResultLatestVersion,
					LastRound: env.TxnInfo.LatestRound(),
					EvalOverrides: simulation.ResultEvalOverrides{
						AllowEmptySignatures: true,
						FixSigners:           true,
					},
					TxnGroups: []simulation.TxnGroupResult{
						{
							FailedAt: simulation.TxnPath{3},
							Txns: []simulation.TxnResult{
								{}, // pay0
								{ // pay1
									FixedSigner: inputs.other.Addr,
								},
								// appCall
								expectedAppCallResultFn(),
								{}, // pay2, does NOT contained FixedSigner
								{}, // pay3
							},
							AppBudgetConsumed: ignoreAppBudgetConsumed,
							AppBudgetAdded:    2800,
						},
					},
				},
			}
		})
	})

	// Edge case tests below

	t.Run("sender account is empty", func(t *testing.T) {
		t.Parallel()
		simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
			sender := env.Accounts[0]

			appID := env.CreateApp(sender.Addr, simulationtesting.AppParams{
				ApprovalProgram:   "#pragma version 9\nint 1",
				ClearStateProgram: "#pragma version 9\nint 1",
			})

			var noBalanceAccount1 basics.Address
			crypto.RandBytes(noBalanceAccount1[:])

			var noBalanceAccount2 basics.Address
			crypto.RandBytes(noBalanceAccount2[:])

			noBalPay1 := env.TxnInfo.NewTxn(txntest.Txn{
				Type:     protocol.PaymentTx,
				Sender:   noBalanceAccount1,
				Receiver: noBalanceAccount1,
				Fee:      0,
				Note:     []byte{1},
			})
			appCall := env.TxnInfo.NewTxn(txntest.Txn{
				Type:          protocol.ApplicationCallTx,
				Sender:        sender.Addr,
				ApplicationID: appID,
				Fee:           env.TxnInfo.CurrentProtocolParams().MinTxnFee * 3,
			})
			noBalPay2 := env.TxnInfo.NewTxn(txntest.Txn{
				Type:     protocol.PaymentTx,
				Sender:   noBalanceAccount2,
				Receiver: noBalanceAccount2,
				Fee:      0,
				Note:     []byte{2},
			})
			txgroup := txntest.Group(&noBalPay1, &appCall, &noBalPay2)

			// Testing that our ledger lookup of accounts to retreive their AuthAddr does not crash
			// and burn when the account is empty.

			return simulationTestCase{
				input: simulation.Request{
					TxnGroups:            [][]transactions.SignedTxn{txgroup},
					AllowEmptySignatures: true,
					FixSigners:           true,
				},
				expected: simulation.Result{
					Version:   simulation.ResultLatestVersion,
					LastRound: env.TxnInfo.LatestRound(),
					EvalOverrides: simulation.ResultEvalOverrides{
						AllowEmptySignatures: true,
						FixSigners:           true,
					},
					TxnGroups: []simulation.TxnGroupResult{
						{
							Txns: []simulation.TxnResult{
								{}, // noBalPay1
								{ // appCall
									AppBudgetConsumed: ignoreAppBudgetConsumed,
								},
								{}, // noBalPay2
							},
							AppBudgetAdded:    700,
							AppBudgetConsumed: ignoreAppBudgetConsumed,
						},
					},
				},
			}
		})
	})

	t.Run("fixed AuthAddr is sender address", func(t *testing.T) {
		t.Parallel()
		simulationTest(t, func(env simulationtesting.Environment) simulationTestCase {
			acct0 := env.Accounts[0]
			acct1 := env.Accounts[1]
			acct2 := env.Accounts[2]

			appID := env.CreateApp(acct0.Addr, simulationtesting.AppParams{
				ApprovalProgram:   "#pragma version 9\nint 1",
				ClearStateProgram: "#pragma version 9\nint 1",
			})

			pay1 := env.TxnInfo.NewTxn(txntest.Txn{
				Type:     protocol.PaymentTx,
				Sender:   acct1.Addr,
				Receiver: acct1.Addr,
				Note:     []byte{1},
			})
			appCall := env.TxnInfo.NewTxn(txntest.Txn{
				Type:          protocol.ApplicationCallTx,
				Sender:        acct0.Addr,
				ApplicationID: appID,
			})
			pay2 := env.TxnInfo.NewTxn(txntest.Txn{
				Type:     protocol.PaymentTx,
				Sender:   acct1.Addr,
				Receiver: acct1.Addr,
				Note:     []byte{2},
			})
			txgroup := txntest.Group(&pay1, &appCall, &pay2)

			txgroup[0].AuthAddr = acct2.Addr
			txgroup[2].AuthAddr = acct2.Addr

			return simulationTestCase{
				input: simulation.Request{
					TxnGroups:            [][]transactions.SignedTxn{txgroup},
					AllowEmptySignatures: true,
					FixSigners:           true,
				},
				expected: simulation.Result{
					Version:   simulation.ResultLatestVersion,
					LastRound: env.TxnInfo.LatestRound(),
					EvalOverrides: simulation.ResultEvalOverrides{
						AllowEmptySignatures: true,
						FixSigners:           true,
					},
					TxnGroups: []simulation.TxnGroupResult{
						{
							Txns: []simulation.TxnResult{
								{ // pay1
									FixedSigner: acct1.Addr,
								},
								{ // appCall
									AppBudgetConsumed: ignoreAppBudgetConsumed,
								},
								{ // pay2
									FixedSigner: acct1.Addr,
								},
							},
							AppBudgetAdded:    700,
							AppBudgetConsumed: ignoreAppBudgetConsumed,
						},
					},
				},
			}
		})
	})
}
