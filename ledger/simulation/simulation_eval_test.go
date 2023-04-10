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

// attachGroupID calculates and assigns the ID for a transaction group.
// Mutates the group directly.
func attachGroupID(txns []transactions.SignedTxn) {
	txgroup := transactions.TxGroup{
		TxGroupHashes: make([]crypto.Digest, len(txns)),
	}
	for i, txn := range txns {
		txn.Txn.Group = crypto.Digest{}
		txgroup.TxGroupHashes[i] = crypto.Digest(txn.ID())
	}
	group := crypto.HashObj(txgroup)

	for i := range txns {
		txns[i].Txn.Header.Group = group
	}
}

func uint64ToBytes(num uint64) []byte {
	ibytes := make([]byte, 8)
	binary.BigEndian.PutUint64(ibytes, num)
	return ibytes
}

type simulationTestCase struct {
	input         []transactions.SignedTxn
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

	shouldHaveBlock := true
	if !result.WouldSucceed {
		// WouldSucceed might be false because of missing signatures, in which case a block would
		// still be generated. The only reason for no block would be an eval error.
		for _, groupResult := range result.TxnGroups {
			if len(groupResult.FailureMessage) != 0 {
				shouldHaveBlock = false
				break
			}
		}
	}
	if !shouldHaveBlock {
		assert.Nil(t, result.Block)
		return
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

func simulationTest(t *testing.T, f func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase) {
	t.Helper()
	l, accounts, txnInfo := simulationtesting.PrepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l, simulation.SimulatorConfig{})

	testcase := f(accounts, txnInfo)

	actual, err := s.Simulate(testcase.input)
	require.NoError(t, err)

	validateSimulationResult(t, actual)

	require.Len(t, testcase.expected.TxnGroups, 1, "Test case must expect a single txn group")
	require.Len(t, testcase.expected.TxnGroups[0].Txns, len(testcase.input), "Test case expected a different number of transactions than its input")

	for i, inputTxn := range testcase.input {
		if testcase.expected.TxnGroups[0].Txns[i].Txn.Txn.Type == "" {
			// Use Type as a marker for whether the transaction was specified or not. If not
			// specified, replace it with the input txn
			testcase.expected.TxnGroups[0].Txns[i].Txn.SignedTxn = inputTxn
		}
		normalizeEvalDeltas(t, &actual.TxnGroups[0].Txns[i].Txn.EvalDelta, &testcase.expected.TxnGroups[0].Txns[i].Txn.EvalDelta)
	}

	if len(testcase.expectedError) != 0 {
		require.Contains(t, actual.TxnGroups[0].FailureMessage, testcase.expectedError)
		require.False(t, testcase.expected.WouldSucceed, "Test case WouldSucceed value is not consistent with expected failure")
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
		for _, signed := range []bool{true, false} {
			signed := signed
			t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
				t.Parallel()
				simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
					sender := accounts[0]
					receiver := accounts[1]

					txn := txnInfo.NewTxn(txntest.Txn{
						Type:     protocol.PaymentTx,
						Sender:   sender.Addr,
						Receiver: receiver.Addr,
						Amount:   1_000_000,
					}).SignedTxn()

					if signed {
						txn = txn.Txn.Sign(sender.Sk)
					}

					return simulationTestCase{
						input: []transactions.SignedTxn{txn},
						expected: simulation.Result{
							Version:   1,
							LastRound: txnInfo.LatestRound(),
							TxnGroups: []simulation.TxnGroupResult{
								{
									Txns: []simulation.TxnResult{
										{
											MissingSignature: !signed,
										},
									},
								},
							},
							WouldSucceed: signed,
							MaxLogCalls:  32,
							MaxLogSize:   1024,
						},
					}
				})
			})
		}
	})

	t.Run("close to", func(t *testing.T) {
		t.Parallel()
		for _, signed := range []bool{true, false} {
			signed := signed
			t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
				t.Parallel()
				simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
					sender := accounts[0]
					receiver := accounts[1]
					closeTo := accounts[2]
					amount := uint64(1_000_000)

					txn := txnInfo.NewTxn(txntest.Txn{
						Type:             protocol.PaymentTx,
						Sender:           sender.Addr,
						Receiver:         receiver.Addr,
						Amount:           amount,
						CloseRemainderTo: closeTo.Addr,
					}).SignedTxn()

					if signed {
						txn = txn.Txn.Sign(sender.Sk)
					}

					expectedClosingAmount := sender.AcctData.MicroAlgos.Raw
					expectedClosingAmount -= amount + txn.Txn.Fee.Raw

					return simulationTestCase{
						input: []transactions.SignedTxn{txn},
						expected: simulation.Result{
							Version:   1,
							LastRound: txnInfo.LatestRound(),
							TxnGroups: []simulation.TxnGroupResult{
								{
									Txns: []simulation.TxnResult{
										{
											Txn: transactions.SignedTxnWithAD{
												ApplyData: transactions.ApplyData{
													ClosingAmount: basics.MicroAlgos{Raw: expectedClosingAmount},
												},
											},
											MissingSignature: !signed,
										},
									},
								},
							},
							WouldSucceed: signed,
							MaxLogSize:   1024,
							MaxLogCalls:  32,
						},
					}
				})
			})
		}
	})

	t.Run("overspend", func(t *testing.T) {
		t.Parallel()
		for _, signed := range []bool{true, false} {
			signed := signed
			t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
				t.Parallel()
				simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
					sender := accounts[0]
					receiver := accounts[1]
					amount := sender.AcctData.MicroAlgos.Raw + 100

					txn := txnInfo.NewTxn(txntest.Txn{
						Type:     protocol.PaymentTx,
						Sender:   sender.Addr,
						Receiver: receiver.Addr,
						Amount:   amount,
					}).SignedTxn()

					if signed {
						txn = txn.Txn.Sign(sender.Sk)
					}

					return simulationTestCase{
						input:         []transactions.SignedTxn{txn},
						expectedError: fmt.Sprintf("tried to spend {%d}", amount),
						expected: simulation.Result{
							Version:   1,
							LastRound: txnInfo.LatestRound(),
							TxnGroups: []simulation.TxnGroupResult{
								{
									Txns: []simulation.TxnResult{
										{
											MissingSignature: !signed,
										},
									},
									FailedAt: simulation.TxnPath{0},
								},
							},
							WouldSucceed: false,
							MaxLogSize:   1024,
							MaxLogCalls:  32,
						},
					}
				})
			})
		}
	})
}

func TestWrongAuthorizerTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, signed := range []bool{true, false} {
		signed := signed
		t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
				sender := accounts[0]
				authority := accounts[1]

				txn := txnInfo.NewTxn(txntest.Txn{
					Type:     protocol.PaymentTx,
					Sender:   sender.Addr,
					Receiver: sender.Addr,
					Amount:   0,
				})

				var stxn transactions.SignedTxn
				if signed {
					stxn = txn.Txn().Sign(authority.Sk)
				} else {
					stxn = txn.SignedTxn()
					stxn.AuthAddr = authority.Addr
				}

				return simulationTestCase{
					input:         []transactions.SignedTxn{stxn},
					expectedError: fmt.Sprintf("should have been authorized by %s but was actually authorized by %s", sender.Addr, authority.Addr),
					expected: simulation.Result{
						Version:   1,
						LastRound: txnInfo.LatestRound(),
						TxnGroups: []simulation.TxnGroupResult{
							{
								Txns: []simulation.TxnResult{
									{
										MissingSignature: !signed,
									},
								},
								FailedAt: simulation.TxnPath{0},
							},
						},
						WouldSucceed: false,
						MaxLogSize:   1024,
						MaxLogCalls:  32,
					},
				}
			})
		})
	}
}

func TestRekey(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, signed := range []bool{true, false} {
		signed := signed
		t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
				sender := accounts[0]
				authority := accounts[1]

				txn1 := txnInfo.NewTxn(txntest.Txn{
					Type:     protocol.PaymentTx,
					Sender:   sender.Addr,
					Receiver: sender.Addr,
					Amount:   1,
					RekeyTo:  authority.Addr,
				})
				txn2 := txnInfo.NewTxn(txntest.Txn{
					Type:     protocol.PaymentTx,
					Sender:   sender.Addr,
					Receiver: sender.Addr,
					Amount:   2,
				})

				txntest.Group(&txn1, &txn2)

				var stxn1 transactions.SignedTxn
				var stxn2 transactions.SignedTxn
				if signed {
					stxn1 = txn1.Txn().Sign(sender.Sk)
					stxn2 = txn2.Txn().Sign(authority.Sk)
				} else {
					stxn1 = txn1.SignedTxn()
					stxn2 = txn2.SignedTxn()
					stxn2.AuthAddr = authority.Addr
				}
				return simulationTestCase{
					input: []transactions.SignedTxn{stxn1, stxn2},
					expected: simulation.Result{
						Version:   1,
						LastRound: txnInfo.LatestRound(),
						TxnGroups: []simulation.TxnGroupResult{
							{
								Txns: []simulation.TxnResult{
									{
										MissingSignature: !signed,
									},
									{
										MissingSignature: !signed,
									},
								},
							},
						},
						WouldSucceed: signed,
						MaxLogSize:   1024,
						MaxLogCalls:  32,
					},
				}
			})
		})
	}
}

func TestStateProofTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, _, txnInfo := simulationtesting.PrepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l, simulation.SimulatorConfig{})

	txgroup := []transactions.SignedTxn{
		txnInfo.NewTxn(txntest.Txn{
			Type: protocol.StateProofTx,
			// No need to fill out StateProofTxnFields, this should fail at signature verification
		}).SignedTxn(),
	}

	_, err := s.Simulate(txgroup)
	require.ErrorContains(t, err, "cannot simulate StateProof transactions")
}

func TestSimpleGroupTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, txnInfo := simulationtesting.PrepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l, simulation.SimulatorConfig{})
	sender1 := accounts[0].Addr
	sender1Balance := accounts[0].AcctData.MicroAlgos
	sender2 := accounts[1].Addr
	sender2Balance := accounts[1].AcctData.MicroAlgos

	// Send money back and forth
	txgroup := []transactions.SignedTxn{
		txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender1,
			Receiver: sender2,
			Amount:   1_000_000,
		}).SignedTxn(),
		txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender2,
			Receiver: sender1,
			Amount:   0,
		}).SignedTxn(),
	}

	// Should fail if there is no group parameter
	result, err := s.Simulate(txgroup)
	require.NoError(t, err)
	require.False(t, result.WouldSucceed)
	require.Len(t, result.TxnGroups, 1)
	require.Len(t, result.TxnGroups[0].Txns, 2)
	require.Contains(t, result.TxnGroups[0].FailureMessage, "had zero Group but was submitted in a group of 2")

	// Add group parameter
	attachGroupID(txgroup)

	// Check balances before transaction
	sender1Data, _, err := l.LookupWithoutRewards(l.Latest(), sender1)
	require.NoError(t, err)
	require.Equal(t, sender1Balance, sender1Data.MicroAlgos)

	sender2Data, _, err := l.LookupWithoutRewards(l.Latest(), sender2)
	require.NoError(t, err)
	require.Equal(t, sender2Balance, sender2Data.MicroAlgos)

	// Should now pass
	result, err = s.Simulate(txgroup)
	require.NoError(t, err)
	require.False(t, result.WouldSucceed)
	require.Len(t, result.TxnGroups, 1)
	require.Len(t, result.TxnGroups[0].Txns, 2)
	require.Zero(t, result.TxnGroups[0].FailureMessage)

	// Confirm balances have not changed
	sender1Data, _, err = l.LookupWithoutRewards(l.Latest(), sender1)
	require.NoError(t, err)
	require.Equal(t, sender1Balance, sender1Data.MicroAlgos)

	sender2Data, _, err = l.LookupWithoutRewards(l.Latest(), sender2)
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
			simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
				sender := accounts[0]

				payTxn := txnInfo.NewTxn(txntest.Txn{
					Type:     protocol.PaymentTx,
					Sender:   sender.Addr,
					Receiver: lsigAddr,
					Amount:   1_000_000,
				})
				appCallTxn := txnInfo.NewTxn(txntest.Txn{
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
						ApplicationID: 2,
						EvalDelta: transactions.EvalDelta{
							Logs: []string{"hello"},
						},
					}
					expectedFailedAt = nil
					AppBudgetConsumed = 3
					AppBudgetAdded = 700
				}

				return simulationTestCase{
					input:         []transactions.SignedTxn{signedPayTxn, signedAppCallTxn},
					expectedError: testCase.expectedError,
					expected: simulation.Result{
						Version:   1,
						LastRound: txnInfo.LatestRound(),
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
						WouldSucceed: expectedSuccess,
						MaxLogSize:   1024,
						MaxLogCalls:  32,
					},
				}
			})
		})
	}
}

func TestSimpleAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, signed := range []bool{true, false} {
		signed := signed
		t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
				sender := accounts[0]

				// Create program and call it
				futureAppID := basics.AppIndex(1)
				createTxn := txnInfo.NewTxn(txntest.Txn{
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
				callTxn := txnInfo.NewTxn(txntest.Txn{
					Type:          protocol.ApplicationCallTx,
					Sender:        sender.Addr,
					ApplicationID: futureAppID,
				})

				txntest.Group(&createTxn, &callTxn)

				signedCreateTxn := createTxn.SignedTxn()
				signedCallTxn := callTxn.SignedTxn()

				if signed {
					signedCreateTxn = signedCreateTxn.Txn.Sign(sender.Sk)
					signedCallTxn = signedCallTxn.Txn.Sign(sender.Sk)
				}

				return simulationTestCase{
					input: []transactions.SignedTxn{signedCreateTxn, signedCallTxn},
					expected: simulation.Result{
						Version:   1,
						LastRound: txnInfo.LatestRound(),
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
										MissingSignature:  !signed,
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
										MissingSignature:  !signed,
										AppBudgetConsumed: 6,
									},
								},
								AppBudgetAdded:    1400,
								AppBudgetConsumed: 11,
							},
						},
						WouldSucceed: signed,
						MaxLogCalls:  32,
						MaxLogSize:   1024,
					},
				}
			})
		})
	}
}

func TestRejectAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, signed := range []bool{true, false} {
		signed := signed
		t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
				sender := accounts[0]

				futureAppID := basics.AppIndex(1)
				createTxn := txnInfo.NewTxn(txntest.Txn{
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

				signedCreateTxn := createTxn.SignedTxn()

				if signed {
					signedCreateTxn = createTxn.Txn().Sign(sender.Sk)
				}

				return simulationTestCase{
					input:         []transactions.SignedTxn{signedCreateTxn},
					expectedError: "transaction rejected by ApprovalProgram",
					expected: simulation.Result{
						Version:   1,
						LastRound: txnInfo.LatestRound(),
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
										MissingSignature:  !signed,
										AppBudgetConsumed: 3,
									},
								},
								FailedAt:          simulation.TxnPath{0},
								AppBudgetAdded:    700,
								AppBudgetConsumed: 3,
							},
						},
						WouldSucceed: false,
						MaxLogSize:   1024,
						MaxLogCalls:  32,
					},
				}
			})
		})
	}
}

func TestErrorAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, signed := range []bool{true, false} {
		signed := signed
		t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
				sender := accounts[0]

				futureAppID := basics.AppIndex(1)
				createTxn := txnInfo.NewTxn(txntest.Txn{
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

				signedCreateTxn := createTxn.SignedTxn()

				if signed {
					signedCreateTxn = createTxn.Txn().Sign(sender.Sk)
				}

				return simulationTestCase{
					input:         []transactions.SignedTxn{signedCreateTxn},
					expectedError: "err opcode executed",
					expected: simulation.Result{
						Version:   1,
						LastRound: txnInfo.LatestRound(),
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
										MissingSignature:  !signed,
										AppBudgetConsumed: 3,
									},
								},
								FailedAt:          simulation.TxnPath{0},
								AppBudgetAdded:    700,
								AppBudgetConsumed: 3,
							},
						},
						WouldSucceed: false,
						MaxLogSize:   1024,
						MaxLogCalls:  32,
					},
				}
			})
		})
	}
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

	simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
		sender := accounts[0]
		receiver := accounts[1]

		futureAppID := basics.AppIndex(1)
		// App create with cost 4
		createTxn := txnInfo.NewTxn(txntest.Txn{
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
		expensiveTxn := txnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: futureAppID,
			Accounts:      []basics.Address{receiver.Addr},
		})

		txntest.Group(&createTxn, &expensiveTxn)

		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
		signedExpensiveTxn := expensiveTxn.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input:         []transactions.SignedTxn{signedCreateTxn, signedExpensiveTxn},
			expectedError: "dynamic cost budget exceeded",
			expected: simulation.Result{
				Version:   1,
				LastRound: txnInfo.LatestRound(),
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
				WouldSucceed: false,
				MaxLogSize:   1024,
				MaxLogCalls:  32,
			},
		}
	})
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

	simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
		sender := accounts[0]

		payTxn := txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: lsigAddr,
			Amount:   1_000_000,
		})
		appCallTxn := txnInfo.NewTxn(txntest.Txn{
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
			input:         []transactions.SignedTxn{signedPayTxn, signedAppCallTxn},
			expectedError: "dynamic cost budget exceeded",
			expected: simulation.Result{
				Version:   1,
				LastRound: txnInfo.LatestRound(),
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
				WouldSucceed: false,
				MaxLogSize:   1024,
				MaxLogCalls:  32,
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

	simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
		sender := accounts[0]

		futureAppID := basics.AppIndex(2)
		// fund outer app
		fund := txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: futureAppID.Address(),
			Amount:   401_000,
		})
		// create app
		appCall := txnInfo.NewTxn(txntest.Txn{
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
			input: []transactions.SignedTxn{signedFundTxn, signedAppCall},
			expected: simulation.Result{
				Version:   1,
				LastRound: txnInfo.LatestRound(),
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
				WouldSucceed: true,
				MaxLogSize:   1024,
				MaxLogCalls:  32,
			},
		}
	})
}

func TestSignatureCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, txnInfo := simulationtesting.PrepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l, simulation.SimulatorConfig{})
	sender := accounts[0].Addr

	txgroup := []transactions.SignedTxn{
		txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender,
			Receiver: sender,
			Amount:   0,
		}).SignedTxn(),
	}

	// should catch missing signature
	result, err := s.Simulate(txgroup)
	require.NoError(t, err)
	require.False(t, result.WouldSucceed)
	require.Len(t, result.TxnGroups, 1)
	require.Len(t, result.TxnGroups[0].Txns, 1)
	require.True(t, result.TxnGroups[0].Txns[0].MissingSignature)
	require.Zero(t, result.TxnGroups[0].FailureMessage)

	// add signature
	signatureSecrets := accounts[0].Sk
	txgroup[0] = txgroup[0].Txn.Sign(signatureSecrets)

	// should not error now that we have a signature
	result, err = s.Simulate(txgroup)
	require.NoError(t, err)
	require.True(t, result.WouldSucceed)
	require.Len(t, result.TxnGroups, 1)
	require.Len(t, result.TxnGroups[0].Txns, 1)
	require.False(t, result.TxnGroups[0].Txns[0].MissingSignature)
	require.Zero(t, result.TxnGroups[0].FailureMessage)

	// should error with invalid signature
	txgroup[0].Sig[0] += byte(1) // will wrap if > 255
	result, err = s.Simulate(txgroup)
	require.ErrorAs(t, err, &simulation.InvalidTxGroupError{})
	require.ErrorContains(t, err, "one signature didn't pass")
}

// TestInvalidTxGroup tests that a transaction group with invalid transactions
// is rejected by the simulator as an InvalidTxGroupError instead of a EvalFailureError.
func TestInvalidTxGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, txnInfo := simulationtesting.PrepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l, simulation.SimulatorConfig{})
	receiver := accounts[0].Addr

	txgroup := []transactions.SignedTxn{
		txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   ledgertesting.PoolAddr(),
			Receiver: receiver,
			Amount:   0,
		}).SignedTxn(),
	}

	// should error with invalid transaction group error
	_, err := s.Simulate(txgroup)
	require.ErrorAs(t, err, &simulation.InvalidTxGroupError{})
	require.ErrorContains(t, err, "transaction from incentive pool is invalid")
}

// TestBalanceChangesWithApp sends a payment transaction to a new account and confirms its balance
// within a subsequent app call
func TestBalanceChangesWithApp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, signed := range []bool{true, false} {
		signed := signed
		t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
				sender := accounts[0]
				senderBalance := sender.AcctData.MicroAlgos.Raw
				sendAmount := senderBalance - 500_000 // Leave 0.5 Algos in the sender account
				receiver := accounts[1]
				receiverBalance := receiver.AcctData.MicroAlgos.Raw

				futureAppID := basics.AppIndex(1)
				createTxn := txnInfo.NewTxn(txntest.Txn{
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
				checkStartingBalanceTxn := txnInfo.NewTxn(txntest.Txn{
					Type:            protocol.ApplicationCallTx,
					Sender:          sender.Addr,
					ApplicationID:   futureAppID,
					Accounts:        []basics.Address{receiver.Addr},
					ApplicationArgs: [][]byte{uint64ToBytes(receiverBalance)},
				})
				paymentTxn := txnInfo.NewTxn(txntest.Txn{
					Type:     protocol.PaymentTx,
					Sender:   sender.Addr,
					Receiver: receiver.Addr,
					Amount:   sendAmount,
				})
				checkEndingBalanceTxn := txnInfo.NewTxn(txntest.Txn{
					Type:          protocol.ApplicationCallTx,
					Sender:        sender.Addr,
					ApplicationID: futureAppID,
					Accounts:      []basics.Address{receiver.Addr},
					// Receiver's balance should have increased by sendAmount
					ApplicationArgs: [][]byte{uint64ToBytes(receiverBalance + sendAmount)},
				})

				txntest.Group(&createTxn, &checkStartingBalanceTxn, &paymentTxn, &checkEndingBalanceTxn)

				signedCreateTxn := createTxn.SignedTxn()
				signedCheckStartingBalanceTxn := checkStartingBalanceTxn.SignedTxn()
				signedPaymentTxn := paymentTxn.SignedTxn()
				signedCheckEndingBalanceTxn := checkEndingBalanceTxn.SignedTxn()

				if signed {
					signedCreateTxn = createTxn.Txn().Sign(sender.Sk)
					signedCheckStartingBalanceTxn = checkStartingBalanceTxn.Txn().Sign(sender.Sk)
					signedPaymentTxn = paymentTxn.Txn().Sign(sender.Sk)
					signedCheckEndingBalanceTxn = checkEndingBalanceTxn.Txn().Sign(sender.Sk)
				}

				return simulationTestCase{
					input: []transactions.SignedTxn{
						signedCreateTxn,
						signedCheckStartingBalanceTxn,
						signedPaymentTxn,
						signedCheckEndingBalanceTxn,
					},
					expected: simulation.Result{
						Version:   1,
						LastRound: txnInfo.LatestRound(),
						TxnGroups: []simulation.TxnGroupResult{
							{
								Txns: []simulation.TxnResult{
									{
										Txn: transactions.SignedTxnWithAD{
											ApplyData: transactions.ApplyData{
												ApplicationID: futureAppID,
											},
										},
										MissingSignature:  !signed,
										AppBudgetConsumed: 4,
									},
									{
										MissingSignature:  !signed,
										AppBudgetConsumed: 10,
									},
									{
										MissingSignature: !signed,
									},
									{
										MissingSignature:  !signed,
										AppBudgetConsumed: 10,
									},
								},
								AppBudgetAdded:    2100,
								AppBudgetConsumed: 24,
							},
						},
						WouldSucceed: signed,
						MaxLogSize:   1024,
						MaxLogCalls:  32,
					},
				}
			})
		})
	}
}

func TestPartialMissingSignatures(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
		sender := accounts[0]

		txn1 := txnInfo.NewTxn(txntest.Txn{
			Type:   protocol.AssetConfigTx,
			Sender: sender.Addr,
			AssetParams: basics.AssetParams{
				Total:    10,
				Decimals: 0,
				Manager:  sender.Addr,
				UnitName: "A",
			},
		})
		txn2 := txnInfo.NewTxn(txntest.Txn{
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
			input: []transactions.SignedTxn{signedTxn1, signedTxn2},
			expected: simulation.Result{
				Version:   1,
				LastRound: txnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								MissingSignature: true,
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ConfigAsset: 1,
									},
								},
							}, {
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ConfigAsset: 2,
									},
								},
							},
						},
					},
				},
				WouldSucceed: false,
				MaxLogSize:   1024,
				MaxLogCalls:  32,
			},
		}
	})
}

// TestPooledFeesAcrossSignedAndUnsigned tests that the simulator's transaction group checks
// allow for pooled fees across a mix of signed and unsigned transactions.
// Transaction 1 is a signed transaction with not enough fees paid on its own.
// Transaction 2 is an unsigned transaction with enough fees paid to cover transaction 1.
func TestPooledFeesAcrossSignedAndUnsigned(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
		sender1 := accounts[0]
		sender2 := accounts[1]

		pay1 := txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender1.Addr,
			Receiver: sender2.Addr,
			Amount:   1_000_000,
			Fee:      txnInfo.CurrentProtocolParams().MinTxnFee - 100,
		})
		pay2 := txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender2.Addr,
			Receiver: sender1.Addr,
			Amount:   0,
			Fee:      txnInfo.CurrentProtocolParams().MinTxnFee + 100,
		})

		txntest.Group(&pay1, &pay2)

		// sign pay1 only
		signedPay1 := pay1.Txn().Sign(sender1.Sk)
		signedPay2 := pay2.SignedTxn()

		return simulationTestCase{
			input: []transactions.SignedTxn{signedPay1, signedPay2},
			expected: simulation.Result{
				Version:   1,
				LastRound: txnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{}, {
								MissingSignature: true,
							},
						},
					},
				},
				WouldSucceed: false,
				MaxLogSize:   1024,
				MaxLogCalls:  32,
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

	simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
		sender := accounts[0]

		singleInnerLogAndFail := makeProgramToCallInner(t, logAndFail)
		nestedInnerLogAndFail := makeProgramToCallInner(t, singleInnerLogAndFail)

		// fund outer app
		pay1 := txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: basics.AppIndex(3).Address(),
			Amount:   401_000, // 400_000 min balance plus 1_000 for 1 txn
		})
		// fund inner app
		pay2 := txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: basics.AppIndex(4).Address(),
			Amount:   401_000, // 400_000 min balance plus 1_000 for 1 txn
		})
		// create app
		appCall := txnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationArgs: [][]byte{uint64ToBytes(uint64(1))},
			ApprovalProgram: nestedInnerLogAndFail,
			ClearStateProgram: `#pragma version 6
int 1`,
		})

		txgroup := txntest.Group(&pay1, &pay2, &appCall)

		return simulationTestCase{
			input:         txgroup,
			expectedError: "rejected by ApprovalProgram",
			expected: simulation.Result{
				Version:   1,
				LastRound: txnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								MissingSignature: true,
							}, {
								MissingSignature: true,
							}, {
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: 3,
										EvalDelta: transactions.EvalDelta{
											Logs: []string{"starting inner txn"},
											InnerTxns: []transactions.SignedTxnWithAD{
												{
													ApplyData: transactions.ApplyData{
														ApplicationID: 4,
														EvalDelta: transactions.EvalDelta{
															Logs: []string{"starting inner txn"},
															InnerTxns: []transactions.SignedTxnWithAD{
																{
																	ApplyData: transactions.ApplyData{
																		ApplicationID: 5,
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
								MissingSignature:  true,
							},
						},
						AppBudgetAdded:    2100,
						AppBudgetConsumed: 27,
						FailedAt:          simulation.TxnPath{2, 0, 0},
					},
				},
				WouldSucceed: false,
				MaxLogSize:   1024,
				MaxLogCalls:  32,
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

	simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
		sender := accounts[0]

		logAndFailItxnCode := makeItxnSubmitToCallInner(t, logAndFail)
		approvalProgram := wrapCodeWithVersionAndReturn(createAssetCode + logAndFailItxnCode)

		// fund outer app
		pay1 := txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: basics.AppIndex(2).Address(),
			Amount:   401_000, // 400_000 min balance plus 1_000 for 1 txn
		})
		// create app
		appCall := txnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationArgs: [][]byte{uint64ToBytes(uint64(1))},
			ApprovalProgram: approvalProgram,
			ClearStateProgram: `#pragma version 6
int 1`,
		})

		txgroup := txntest.Group(&pay1, &appCall)

		return simulationTestCase{
			input:         txgroup,
			expectedError: "rejected by ApprovalProgram",
			expected: simulation.Result{
				Version:   1,
				LastRound: txnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								MissingSignature: true,
							}, {
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: 2,
										EvalDelta: transactions.EvalDelta{
											Logs: []string{"starting asset create", "finished asset create", "starting inner txn"},
											InnerTxns: []transactions.SignedTxnWithAD{
												{
													ApplyData: transactions.ApplyData{
														ConfigAsset: 3,
													},
												},
												{
													ApplyData: transactions.ApplyData{
														ApplicationID: 4,
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
								MissingSignature:  true,
							},
						},
						AppBudgetAdded:    2100,
						AppBudgetConsumed: 23,
						FailedAt:          simulation.TxnPath{1, 1},
					},
				},
				WouldSucceed: false,
				MaxLogSize:   1024,
				MaxLogCalls:  32,
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

	simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
		sender := accounts[0]

		// configAssetCode should fail because createAssetCode does not set an asset manager
		approvalProgram := wrapCodeWithVersionAndReturn(createAssetCode + fmt.Sprintf(configAssetCode, 3))

		// fund outer app
		pay1 := txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: basics.AppIndex(2).Address(),
			Amount:   402_000, // 400_000 min balance plus 2_000 for 2 inners
		})
		// create app
		appCall := txnInfo.NewTxn(txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          sender.Addr,
			ApplicationArgs: [][]byte{uint64ToBytes(uint64(1))},
			ApprovalProgram: approvalProgram,
			ClearStateProgram: `#pragma version 6
int 1`,
		})

		txgroup := txntest.Group(&pay1, &appCall)

		return simulationTestCase{
			input:         txgroup,
			expectedError: "logic eval error: this transaction should be issued by the manager",
			expected: simulation.Result{
				Version:   1,
				LastRound: txnInfo.LatestRound(),
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								MissingSignature: true,
							}, {
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: 2,
										EvalDelta: transactions.EvalDelta{
											Logs: []string{"starting asset create", "finished asset create", "starting asset config"},
											InnerTxns: []transactions.SignedTxnWithAD{
												{
													ApplyData: transactions.ApplyData{
														ConfigAsset: 3,
													},
												},
												{},
											},
										},
									},
								},
								AppBudgetConsumed: 17,
								MissingSignature:  true,
							},
						},
						AppBudgetAdded:    2100,
						AppBudgetConsumed: 17,
						FailedAt:          simulation.TxnPath{1, 1},
					},
				},
				WouldSucceed: false,
				MaxLogSize:   1024,
				MaxLogCalls:  32,
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
			simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
				sender := accounts[0]

				futureAppID := basics.AppIndex(2)
				payTxn := txnInfo.NewTxn(txntest.Txn{
					Type:     protocol.PaymentTx,
					Sender:   sender.Addr,
					Receiver: futureAppID.Address(),
					Amount:   2_000_000,
				})
				appCallTxn := txnInfo.NewTxn(txntest.Txn{
					Type:   protocol.ApplicationCallTx,
					Sender: sender.Addr,
					ClearStateProgram: `#pragma version 6
	int 1`,
				})
				scenario := scenarioFn(mocktracer.TestScenarioInfo{
					CallingTxn:   appCallTxn.Txn(),
					MinFee:       basics.MicroAlgos{Raw: txnInfo.CurrentProtocolParams().MinTxnFee},
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
					Version:   1,
					LastRound: txnInfo.LatestRound(),
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
					WouldSucceed: scenario.Outcome == mocktracer.ApprovalOutcome,
					MaxLogCalls:  32,
					MaxLogSize:   1024,
				}

				return simulationTestCase{
					input:         []transactions.SignedTxn{signedPayTxn, signedAppCallTxn},
					expectedError: scenario.ExpectedError,
					expected:      expected,
				}
			})
		})
	}
}
