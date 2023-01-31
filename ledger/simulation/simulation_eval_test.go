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
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/libgoal"

	"github.com/algorand/go-algorand/ledger/simulation"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func makeTestClient() libgoal.Client {
	c, err := libgoal.MakeClientFromConfig(libgoal.ClientConfig{
		AlgodDataDir: "NO_DIR",
	}, libgoal.DynamicClient)
	if err != nil {
		panic(err)
	}

	return c
}

// Attach group ID to a transaction group. Mutates the group directly.
func attachGroupID(txgroup []transactions.SignedTxn) error {
	txnArray := make([]transactions.Transaction, len(txgroup))
	for i, txn := range txgroup {
		txnArray[i] = txn.Txn
	}

	client := makeTestClient()
	groupID, err := client.GroupID(txnArray)
	if err != nil {
		return err
	}

	for i := range txgroup {
		txgroup[i].Txn.Header.Group = groupID
	}

	return nil
}

func uint64ToBytes(num uint64) []byte {
	ibytes := make([]byte, 8)
	binary.BigEndian.PutUint64(ibytes, num)
	return ibytes
}

// ==============================
// > Simulation Tests
// ==============================

type simulationTestCase struct {
	input         []transactions.SignedTxn
	expected      simulation.Result
	expectedError string
}

func normalizeEvalDeltas(t *testing.T, actual, expected *transactions.EvalDelta) {
	for _, evalDelta := range []*transactions.EvalDelta{actual, expected} {
		if len(evalDelta.GlobalDelta) == 0 {
			evalDelta.GlobalDelta = nil
		}
		if len(evalDelta.LocalDeltas) == 0 {
			evalDelta.LocalDeltas = nil
		}
	}
	require.Equal(t, len(expected.InnerTxns), len(actual.InnerTxns))
	for innerIndex := range expected.InnerTxns {
		if expected.InnerTxns[innerIndex].SignedTxn.Txn.Type == "" {
			// Use Type as a marker for whether the transaction was specified or not. If not
			// specified, replace it with the actual inner txn
			expected.InnerTxns[innerIndex].SignedTxn = actual.InnerTxns[innerIndex].SignedTxn
		}
		normalizeEvalDeltas(t, &actual.InnerTxns[innerIndex].EvalDelta, &expected.InnerTxns[innerIndex].EvalDelta)
	}
}

func simulationTest(t *testing.T, f func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase) {
	t.Helper()
	l, accounts, txnInfo := simulationtesting.PrepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)

	testcase := f(accounts, txnInfo)

	actual, err := s.Simulate(testcase.input)
	require.NoError(t, err)

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

	require.Equal(t, testcase.expected, actual)
}

// > Simulate Without Debugger

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
							Version: 1,
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
							Version: 1,
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
							Version: 1,
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
						},
					}
				})
			})
		}
	})
}

func TestAuthAddrTxn(t *testing.T) {
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
				}).SignedTxn()
				txn.AuthAddr = authority.Addr

				if signed {
					txn = txn.Txn.Sign(authority.Sk)
				}

				return simulationTestCase{
					input:         []transactions.SignedTxn{txn},
					expectedError: fmt.Sprintf("should have been authorized by %s but was actually authorized by %s", sender.Addr, authority.Addr),
					expected: simulation.Result{
						Version: 1,
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
	s := simulation.MakeSimulator(l)

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
	s := simulation.MakeSimulator(l)
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
	err = attachGroupID(txgroup)
	require.NoError(t, err)

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
						Version: 1,
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
										MissingSignature: !signed,
									},
									{
										Txn: transactions.SignedTxnWithAD{
											ApplyData: transactions.ApplyData{
												EvalDelta: transactions.EvalDelta{
													Logs: []string{"app call"},
												},
											},
										},
										MissingSignature: !signed,
									},
								},
							},
						},
						WouldSucceed: signed,
					},
				}
			})
		})
	}
}

func TestRejectAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
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
		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input:         []transactions.SignedTxn{signedCreateTxn},
			expectedError: "transaction rejected by ApprovalProgram",
			expected: simulation.Result{
				Version: 1,
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
							},
						},
						FailedAt: simulation.TxnPath{0},
					},
				},
				WouldSucceed: false,
			},
		}
	})
}

func TestErrorAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
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
		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input:         []transactions.SignedTxn{signedCreateTxn},
			expectedError: "err opcode executed",
			expected: simulation.Result{
				Version: 1,
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
							},
						},
						FailedAt: simulation.TxnPath{0},
					},
				},
				WouldSucceed: false,
			},
		}
	})
}

func TestSignatureCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, txnInfo := simulationtesting.PrepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
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
	s := simulation.MakeSimulator(l)
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
	b end
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

		signedCreateTxn := createTxn.Txn().Sign(sender.Sk)
		signedCheckStartingBalanceTxn := checkStartingBalanceTxn.Txn().Sign(sender.Sk)
		signedPaymentTxn := paymentTxn.Txn().Sign(sender.Sk)
		signedCheckEndingBalanceTxn := checkEndingBalanceTxn.Txn().Sign(sender.Sk)

		return simulationTestCase{
			input: []transactions.SignedTxn{
				signedCreateTxn,
				signedCheckStartingBalanceTxn,
				signedPaymentTxn,
				signedCheckEndingBalanceTxn,
			},
			expected: simulation.Result{
				Version: 1,
				TxnGroups: []simulation.TxnGroupResult{
					{
						Txns: []simulation.TxnResult{
							{
								Txn: transactions.SignedTxnWithAD{
									ApplyData: transactions.ApplyData{
										ApplicationID: futureAppID,
									},
								},
							},
							{},
							{},
							{},
						},
					},
				},
				WouldSucceed: true,
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
				Version: 1,
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
			},
		}
	})
}

func TestSimulateFailureInformation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Test FailedAt for each program failure
	for i := 0; i < 3; i++ {
		i := i
		t.Run(fmt.Sprintf("i=%d", i), func(t *testing.T) {
			t.Parallel()
			simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
				sender := accounts[0]

				// The loop variable i indicates which inner transaction will fail.
				// TODO: explain the setup for this test more
				// TODO: additional failure conditions would be in the top-level app call before/between/after inners

				futureAppID := basics.AppIndex(2)
				fundApp := txnInfo.NewTxn(txntest.Txn{
					Type:     protocol.PaymentTx,
					Sender:   sender.Addr,
					Receiver: futureAppID.Address(),
					Amount:   403_000, // 400_000 min balance plus 3_000 for 3 txns
				})
				createApp := txnInfo.NewTxn(txntest.Txn{
					Type:            protocol.ApplicationCallTx,
					Sender:          sender.Addr,
					ApplicationID:   0,
					ApplicationArgs: [][]byte{uint64ToBytes(uint64(3 - i))},
					ApprovalProgram: `#pragma version 6
int 3                             // [index(3)]
prepare_txn:
	itxn_begin                    // [index]
	int appl                      // [index, appl]
	itxn_field TypeEnum           // [index]
	int NoOp                      // [index, NoOp]
	itxn_field OnCompletion       // [index]
	byte 0x068101                 // [index, 0x068101]
	itxn_field ClearStateProgram  // [index]
app_arg_check:
    // #pragma version 6; int 1;
	byte 0x068101                 // [index, 0x068101]
	// #pragma version 6; int 0;
	byte 0x068100                 // [index, 0x068101, 0x068100]
	dig 2                         // [index, 0x068101, 0x068100, index]
	txn ApplicationArgs 0         // [index, 0x068101, 0x068100, index, args[0]]
	btoi                          // [index, 0x068101, 0x068100, index, btoi(args[0])]
	==                            // [index, 0x068101, 0x068100, index=?=btoi(args[0])]
	select                        // [index, index==btoi(args[0]) ? 0x068100 : 0x068101]
	itxn_field ApprovalProgram    // [index]
	itxn_submit                   // [index]
decrement_and_loop:
	int 1                         // [index, 1]
	-                             // [index - 1]
	dup                           // [index - 1, index - 1]
	bnz prepare_txn               // [index - 1]
pop                               // []
int 1                             // [1]
`,
					ClearStateProgram: `#pragma version 6
int 1`,
				})

				txntest.Group(&fundApp, &createApp)

				signedFundApp := fundApp.Txn().Sign(sender.Sk)
				signedCreateApp := createApp.Txn().Sign(sender.Sk)

				var expectedInnerTxns []transactions.SignedTxnWithAD
				for innerIndex := 0; innerIndex <= i; innerIndex++ {
					innerTxn := transactions.SignedTxnWithAD{
						SignedTxn: txnInfo.InnerTxn(signedFundApp, txntest.Txn{
							Type:              protocol.ApplicationCallTx,
							Sender:            futureAppID.Address(),
							ApprovalProgram:   []byte{0x06, 0x81, 0x01},
							ClearStateProgram: []byte{0x06, 0x81, 0x01},
						}).SignedTxn(),
						ApplyData: transactions.ApplyData{
							ApplicationID: futureAppID + basics.AppIndex(innerIndex+1),
						},
					}
					if innerIndex == i {
						innerTxn.SignedTxn.Txn.ApprovalProgram = []byte{0x06, 0x81, 0x00}
					}
					expectedInnerTxns = append(expectedInnerTxns, innerTxn)
				}

				return simulationTestCase{
					input:         []transactions.SignedTxn{signedFundApp, signedCreateApp},
					expectedError: "rejected by ApprovalProgram",
					expected: simulation.Result{
						Version: 1,
						TxnGroups: []simulation.TxnGroupResult{
							{
								Txns: []simulation.TxnResult{
									{}, {
										Txn: transactions.SignedTxnWithAD{
											ApplyData: transactions.ApplyData{
												ApplicationID: futureAppID,
												EvalDelta: transactions.EvalDelta{
													InnerTxns: expectedInnerTxns,
												},
											},
										},
									},
								},
								FailedAt: simulation.TxnPath{1, uint64(i)},
							},
						},
						WouldSucceed: false,
					},
				}
			})
		})
	}
}

func TestSimulatePartialMissingSignatures(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, txnInfo := simulationtesting.PrepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0]
	senderBalance := accounts[0].AcctData.MicroAlgos

	txn1 := txnInfo.NewTxn(txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   sender.Addr,
		Receiver: sender.Addr,
		Amount:   senderBalance.Raw - 1000,
	})
	txn2 := txnInfo.NewTxn(txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   sender.Addr,
		Receiver: sender.Addr,
		Amount:   senderBalance.Raw - 2000,
	})

	txntest.Group(&txn1, &txn2)

	// add signature to second transaction only
	signedTxn1 := txn1.SignedTxn()
	signedTxn2 := txn2.Txn().Sign(sender.Sk)

	result, err := s.Simulate([]transactions.SignedTxn{signedTxn1, signedTxn2})
	require.NoError(t, err)
	require.Len(t, result.TxnGroups, 1)
	require.Len(t, result.TxnGroups[0].Txns, 2)
	require.Empty(t, result.TxnGroups[0].FailureMessage)
	require.False(t, result.WouldSucceed)
	require.True(t, result.TxnGroups[0].Txns[0].MissingSignature)
	require.False(t, result.TxnGroups[0].Txns[1].MissingSignature)
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
itxn_submit`, programBytesHex)
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

func TestSimulateAccessInnerTxnApplyDataOnFail(t *testing.T) {
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
			Amount:   401_000, // 400000 min balance plus 1000 for 1 txn
		})
		// fund inner app
		pay2 := txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: basics.AppIndex(4).Address(),
			Amount:   401_000, // 400000 min balance plus 1000 for 1 txn
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
				Version: 1,
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
								MissingSignature: true,
							},
						},
						FailedAt: simulation.TxnPath{2, 0, 0},
					},
				},
				WouldSucceed: false,
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
`

func TestSimulateAccessInnerTxnNonAppCallApplyDataOnFail(t *testing.T) {
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
			Amount:   401_000, // 400000 min balance plus 1000 for 1 txn
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
				Version: 1,
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
											Logs: []string{"starting asset create", "starting inner txn"},
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
								MissingSignature: true,
							},
						},
						FailedAt: simulation.TxnPath{1, 1},
					},
				},
				WouldSucceed: false,
			},
		}
	})
}

const invalidCreateAssetCode = `byte "starting invalid asset create"
log
itxn_begin
int acfg
itxn_field TypeEnum
int 2
itxn_field ConfigAssetDefaultFrozen
itxn_submit
`

func TestSimulateAccessInnerTxnWithNonAppCallsFailure(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	simulationTest(t, func(accounts []simulationtesting.Account, txnInfo simulationtesting.TxnInfo) simulationTestCase {
		sender := accounts[0]

		approvalProgram := wrapCodeWithVersionAndReturn(createAssetCode + invalidCreateAssetCode)

		// fund outer app
		pay1 := txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender.Addr,
			Receiver: basics.AppIndex(2).Address(),
			Amount:   402_000, // 400000 min balance plus 2000 for 2 inners
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
			expectedError: "boolean is neither 1 nor 0",
			expected: simulation.Result{
				Version: 1,
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
											Logs: []string{"starting asset create", "starting invalid asset create"},
											InnerTxns: []transactions.SignedTxnWithAD{
												{
													ApplyData: transactions.ApplyData{
														ConfigAsset: 3,
													},
												},
											},
										},
									},
								},
								MissingSignature: true,
							},
						},
						FailedAt: simulation.TxnPath{1},
					},
				},
				WouldSucceed: false,
			},
		}
	})
}
