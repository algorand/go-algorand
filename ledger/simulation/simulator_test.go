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

package simulation_test

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"

	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/internal"
	"github.com/algorand/go-algorand/ledger/simulation"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// ==============================
// > Simulation Test Helpers
// ==============================

type account struct {
	addr     basics.Address
	sk       *crypto.SignatureSecrets
	acctData basics.AccountData
}

func prepareSimulatorTest(t *testing.T) (l *data.Ledger, accounts []account, makeTxnHeader func(sender basics.Address) transactions.Header) {
	genesisInitState, keys := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)

	// Prepare ledger
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)
	realLedger, err := ledger.OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err, "could not open ledger")

	l = &data.Ledger{Ledger: realLedger}
	require.NotNil(t, l)

	// Reformat accounts
	accounts = make([]account, len(keys)-2) // -2 for pool and sink accounts
	i := 0
	for addr, key := range keys {
		if addr == ledgertesting.PoolAddr() || addr == ledgertesting.SinkAddr() {
			continue
		}

		acctData := genesisInitState.Accounts[addr]
		accounts[i] = account{addr, key, acctData}
		i++
	}

	// txn header generator
	hdr, err := l.BlockHdr(l.Latest())
	require.NoError(t, err)
	makeTxnHeader = func(sender basics.Address) transactions.Header {
		return transactions.Header{
			Fee:         basics.MicroAlgos{Raw: 1000},
			FirstValid:  hdr.Round,
			GenesisID:   hdr.GenesisID,
			GenesisHash: hdr.GenesisHash,
			LastValid:   hdr.Round + basics.Round(1000),
			Note:        []byte{240, 134, 38, 55, 197, 14, 142, 132},
			Sender:      sender,
		}
	}

	return
}

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
// > Sanity Tests
// ==============================

// We want to be careful that the Algod ledger does not move on to another round
// so we confirm here that all ledger methods which implicitly access the current round
// are overriden within the `simulatorLedger`.
func TestNonOverridenDataLedgerMethodsUseRoundParamter(t *testing.T) {
	l, _, _ := prepareSimulatorTest(t)

	// methods overriden by `simulatorLedger``
	overridenMethods := []string{
		"Latest",
		"LookupLatest",
	}

	// methods that don't use a round number
	excludedMethods := []string{
		"GenesisHash",
		"GenesisProto",
		"LatestTotals",
	}

	methodIsSkipped := func(methodName string) bool {
		for _, overridenMethod := range overridenMethods {
			if overridenMethod == methodName {
				return true
			}
		}
		for _, excludedMethod := range excludedMethods {
			if excludedMethod == methodName {
				return true
			}
		}
		return false
	}

	methodExistsInEvalLedger := func(methodName string) bool {
		evalLedgerType := reflect.TypeOf((*internal.LedgerForEvaluator)(nil)).Elem()
		for i := 0; i < evalLedgerType.NumMethod(); i++ {
			if evalLedgerType.Method(i).Name == methodName {
				return true
			}
		}
		return false
	}

	methodHasRoundParameter := func(methodType reflect.Type) bool {
		for i := 0; i < methodType.NumIn(); i++ {
			if methodType.In(i) == reflect.TypeOf(basics.Round(0)) {
				return true
			}
		}
		return false
	}

	ledgerType := reflect.TypeOf(l)
	for i := 0; i < ledgerType.NumMethod(); i++ {
		method := ledgerType.Method(i)
		if methodExistsInEvalLedger(method.Name) && !methodIsSkipped(method.Name) {
			require.True(t, methodHasRoundParameter(method.Type), "method %s has no round parameter", method.Name)
		}
	}
}

// ==============================
// > Simulation Tests
// ==============================

// > Simulate Without Debugger

func TestPayTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0].addr

	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: makeTxnHeader(sender),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender,
					Amount:   basics.MicroAlgos{Raw: 0},
				},
			},
		},
	}

	_, _, err := s.Simulate(txgroup)
	require.NoError(t, err)
}

func TestOverspendPayTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0].addr
	senderBalance := accounts[0].acctData.MicroAlgos
	amount := senderBalance.Raw + 100

	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: makeTxnHeader(sender),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender,
					Amount:   basics.MicroAlgos{Raw: amount}, // overspend
				},
			},
		},
	}

	_, _, err := s.Simulate(txgroup)
	require.ErrorAs(t, err, &simulation.EvalFailureError{})
	require.ErrorContains(t, err, fmt.Sprintf("tried to spend {%d}", amount))
}

func TestSimpleGroupTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender1 := accounts[0].addr
	sender1Balance := accounts[0].acctData.MicroAlgos
	sender2 := accounts[1].addr
	sender2Balance := accounts[1].acctData.MicroAlgos

	// Send money back and forth
	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: makeTxnHeader(sender1),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender2,
					Amount:   basics.MicroAlgos{Raw: 1000000},
				},
			},
		},
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: makeTxnHeader(sender2),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender1,
					Amount:   basics.MicroAlgos{Raw: 0},
				},
			},
		},
	}

	// Should fail if there is no group parameter
	_, _, err := s.Simulate(txgroup)
	require.ErrorAs(t, err, &simulation.EvalFailureError{})
	require.ErrorContains(t, err, "had zero Group but was submitted in a group of 2")

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
	_, _, err = s.Simulate(txgroup)
	require.NoError(t, err)

	// Confirm balances have not changed
	sender1Data, _, err = l.LookupWithoutRewards(l.Latest(), sender1)
	require.NoError(t, err)
	require.Equal(t, sender1Balance, sender1Data.MicroAlgos)

	sender2Data, _, err = l.LookupWithoutRewards(l.Latest(), sender2)
	require.NoError(t, err)
	require.Equal(t, sender2Balance, sender2Data.MicroAlgos)
}

const trivialAVMProgram = `#pragma version 6
int 1`
const rejectAVMProgram = `#pragma version 6
int 0`

func TestSimpleAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0].addr

	// Compile AVM program
	ops, err := logic.AssembleString(trivialAVMProgram)
	require.NoError(t, err, ops.Errors)
	prog := ops.Program

	// Create program and call it
	futureAppID := 1
	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: makeTxnHeader(sender),
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID:     0,
					ApprovalProgram:   prog,
					ClearStateProgram: prog,
					LocalStateSchema: basics.StateSchema{
						NumUint:      0,
						NumByteSlice: 0,
					},
					GlobalStateSchema: basics.StateSchema{
						NumUint:      0,
						NumByteSlice: 0,
					},
				},
			},
		},
		{
			Txn: transactions.Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: makeTxnHeader(sender),
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID: basics.AppIndex(futureAppID),
				},
			},
		},
	}

	err = attachGroupID(txgroup)
	require.NoError(t, err)

	_, _, err = s.Simulate(txgroup)
	require.NoError(t, err)
}

func TestRejectAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0].addr

	// Compile AVM program
	ops, err := logic.AssembleString(rejectAVMProgram)
	require.NoError(t, err, ops.Errors)
	prog := ops.Program

	// Create program and call it
	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: makeTxnHeader(sender),
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID:     0,
					ApprovalProgram:   prog,
					ClearStateProgram: prog,
					LocalStateSchema: basics.StateSchema{
						NumUint:      0,
						NumByteSlice: 0,
					},
					GlobalStateSchema: basics.StateSchema{
						NumUint:      0,
						NumByteSlice: 0,
					},
				},
			},
		},
	}

	err = attachGroupID(txgroup)
	require.NoError(t, err)

	_, _, err = s.Simulate(txgroup)
	require.ErrorAs(t, err, &simulation.EvalFailureError{})
	require.ErrorContains(t, err, "transaction rejected by ApprovalProgram")
}

func TestSignatureCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0].addr

	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: makeTxnHeader(sender),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender,
					Amount:   basics.MicroAlgos{Raw: 0},
				},
			},
		},
	}

	// should error without a signature
	_, missingSignatures, err := s.Simulate(txgroup)
	require.NoError(t, err)
	require.True(t, missingSignatures)

	// add signature
	signatureSecrets := accounts[0].sk
	txgroup[0] = txgroup[0].Txn.Sign(signatureSecrets)

	// should not error now that we have a signature
	_, missingSignatures, err = s.Simulate(txgroup)
	require.NoError(t, err)
	require.False(t, missingSignatures)

	// should error with invalid signature
	txgroup[0].Sig[0] += byte(1) // will wrap if > 255
	_, _, err = s.Simulate(txgroup)
	require.ErrorAs(t, err, &simulation.InvalidTxGroupError{})
	require.ErrorContains(t, err, "one signature didn't pass")
}

// TestInvalidTxGroup tests that a transaction group with invalid transactions
// is rejected by the simulator as an InvalidTxGroupError instead of a EvalFailureError.
func TestInvalidTxGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	receiver := accounts[0].addr

	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.PaymentTx,
				// invalid sender
				Header: makeTxnHeader(ledgertesting.PoolAddr()),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: receiver,
					Amount:   basics.MicroAlgos{Raw: 0},
				},
			},
		},
	}

	// should error with invalid transaction group error
	_, _, err := s.Simulate(txgroup)
	require.ErrorAs(t, err, &simulation.InvalidTxGroupError{})
	require.ErrorContains(t, err, "transaction from incentive pool is invalid")
}

const accountBalanceCheckProgram = `#pragma version 6
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
`

func TestBalanceChangesWithApp(t *testing.T) {
	// Send a payment transaction to a new account and confirm its balance within an app call
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0].addr
	senderBalance := accounts[0].acctData.MicroAlgos.Raw
	sendAmount := senderBalance - 500000
	receiver := accounts[1].addr
	receiverBalance := accounts[1].acctData.MicroAlgos.Raw

	// Compile approval program
	ops, err := logic.AssembleString(accountBalanceCheckProgram)
	require.NoError(t, err, ops.Errors)
	approvalProg := ops.Program

	// Compile clear program
	ops, err = logic.AssembleString(trivialAVMProgram)
	require.NoError(t, err, ops.Errors)
	clearStateProg := ops.Program

	futureAppID := 1
	txgroup := []transactions.SignedTxn{
		// create app
		{
			Txn: transactions.Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: makeTxnHeader(sender),
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID:     0,
					ApprovalProgram:   approvalProg,
					ClearStateProgram: clearStateProg,
					LocalStateSchema: basics.StateSchema{
						NumUint:      0,
						NumByteSlice: 0,
					},
					GlobalStateSchema: basics.StateSchema{
						NumUint:      0,
						NumByteSlice: 0,
					},
				},
			},
		},
		// check balance
		{
			Txn: transactions.Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: makeTxnHeader(sender),
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID:   basics.AppIndex(futureAppID),
					Accounts:        []basics.Address{receiver},
					ApplicationArgs: [][]byte{uint64ToBytes(receiverBalance)},
				},
			},
		},
		// send payment
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: makeTxnHeader(sender),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: receiver,
					Amount:   basics.MicroAlgos{Raw: sendAmount},
				},
			},
		},
		// check balance changed
		{
			Txn: transactions.Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: makeTxnHeader(sender),
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID:   basics.AppIndex(futureAppID),
					Accounts:        []basics.Address{receiver},
					ApplicationArgs: [][]byte{uint64ToBytes(receiverBalance + sendAmount)},
				},
			},
		},
	}

	err = attachGroupID(txgroup)
	require.NoError(t, err)

	_, _, err = s.Simulate(txgroup)
	require.NoError(t, err)
}

// TestBalanceChangesWithApp tests that the simulator's transaction group checks
// allow for pooled fees across a mix of signed and unsigned transactions.
// Transaction 1 is a signed transaction with not enough fees paid on its own.
// Transaction 2 is an unsigned transaction with enough fees paid to cover transaction 1.
func TestPooledFeesAcrossSignedAndUnsigned(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender1 := accounts[0].addr
	sender2 := accounts[1].addr

	txnHeader1 := makeTxnHeader(sender1)
	txnHeader2 := makeTxnHeader(sender2)
	txnHeader1.Fee = basics.MicroAlgos{Raw: txnHeader1.Fee.Raw - 100}
	txnHeader2.Fee = basics.MicroAlgos{Raw: txnHeader2.Fee.Raw + 100}

	// Send money back and forth
	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: txnHeader1,
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender2,
					Amount:   basics.MicroAlgos{Raw: 1000000},
				},
			},
		},
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: txnHeader2,
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender1,
					Amount:   basics.MicroAlgos{Raw: 0},
				},
			},
		},
	}

	err := attachGroupID(txgroup)
	require.NoError(t, err)

	// add signature to txn 1
	signatureSecrets := accounts[0].sk
	txgroup[0] = txgroup[0].Txn.Sign(signatureSecrets)

	_, _, err = s.Simulate(txgroup)
	require.NoError(t, err)
}

// > Simulate With Debugger

type simpleDebugger struct {
	beforeTxnCalls int
	afterTxnCalls  int
}

func (d *simpleDebugger) BeforeTxn(ep *logic.EvalParams, groupIndex int) error {
	d.beforeTxnCalls++
	return nil
}
func (d *simpleDebugger) AfterTxn(ep *logic.EvalParams, groupIndex int) error {
	d.afterTxnCalls++
	return nil
}

// TestSimulateWithDebugger is a simple test to ensure that the debugger hooks are called. More
// complicated tests are in the logic/debugger_test.go file.
func TestSimulateWithDebugger(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0].addr
	senderBalance := accounts[0].acctData.MicroAlgos
	amount := senderBalance.Raw - 10000

	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: makeTxnHeader(sender),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender,
					Amount:   basics.MicroAlgos{Raw: amount},
				},
			},
		},
	}

	debugger := simpleDebugger{0, 0}
	_, _, err := s.SimulateWithDebugger(txgroup, &debugger)
	require.NoError(t, err)
	require.Equal(t, 1, debugger.beforeTxnCalls)
	require.Equal(t, 1, debugger.afterTxnCalls)
}

// > Detailed Simulate

const logProgram = `#pragma version 6
byte "message"
log
int 1`

func TestDetailedSimulateResultLogs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0].addr

	// Compile approval program
	ops, err := logic.AssembleString(logProgram)
	require.NoError(t, err, ops.Errors)
	approvalProg := ops.Program

	// Compile clear program
	ops, err = logic.AssembleString(trivialAVMProgram)
	require.NoError(t, err, ops.Errors)
	clearStateProg := ops.Program

	txgroup := []transactions.SignedTxn{
		// create app
		{
			Txn: transactions.Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: makeTxnHeader(sender),
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID:     0,
					ApprovalProgram:   approvalProg,
					ClearStateProgram: clearStateProg,
					LocalStateSchema: basics.StateSchema{
						NumUint:      0,
						NumByteSlice: 0,
					},
					GlobalStateSchema: basics.StateSchema{
						NumUint:      0,
						NumByteSlice: 0,
					},
				},
			},
		},
	}

	txgroup[0] = txgroup[0].Txn.Sign(accounts[0].sk)

	result, err := s.DetailedSimulate(txgroup)
	require.NoError(t, err)
	require.True(t, result.WouldSucceed)
	require.Equal(t, 1, len(result.TxnGroups))
	require.Equal(t, 1, len(result.TxnGroups[0].Txns))

	actualTxnWithAD := result.TxnGroups[0].Txns[0].Txn
	require.Equal(t, protocol.ApplicationCallTx, actualTxnWithAD.Txn.Type)
	require.NotEmpty(t, actualTxnWithAD.ApplyData)
	require.Len(t, actualTxnWithAD.ApplyData.EvalDelta.Logs, 1)
	require.Equal(t, "message", actualTxnWithAD.ApplyData.EvalDelta.Logs[0])
}

const plannedFailureProgram = `#pragma version 6
int 3                           // [index(3)]
prepare_txn:
	itxn_begin                    // [index]
	int appl                      // [index, appl]
	itxn_field TypeEnum           // [index]
	int NoOp                      // [index, NoOp]
	itxn_field OnCompletion       // [index]
	byte 0x068101                 // [index, 0x068101]
	itxn_field ClearStateProgram  // [index]
app_arg_check:
	dup													  // [index, index]
	txn ApplicationArgs 0         // [index, index, args[0]]
	btoi                          // [index, index, btoi(args[0])]
	==                            // [index, index=?=btoi(args[0])]
	bnz reject_approval_program   // [index]
pass_approval_program:
	byte 0x068101                 // [index, 0x068101]. 0x068101 is #pragma version 6; int 1;
	b submit_and_loop             // [index, 0x068101]
reject_approval_program:
	byte 0x068100                 // [index, 0x068100]. 0x068100 is #pragma version 6; int 0;
	b submit_and_loop             // [index, 0x068100]
submit_and_loop:
	itxn_field ApprovalProgram    // [index]
	itxn_submit                   // [index]
decrement_and_loop:
	int 1                         // [index, 1]
	-                             // [index - 1]
	dup                           // [index - 1, index - 1]
	bnz prepare_txn               // [index - 1]
pop                             // []
int 1                           // [1]
`

func TestDetailedSimulateFailureInformation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Set up simulator
	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0].addr

	// Compile approval program
	ops, err := logic.AssembleString(plannedFailureProgram)
	require.NoError(t, err, ops.Errors)
	approvalProg := ops.Program

	// Compile clear program
	ops, err = logic.AssembleString(trivialAVMProgram)
	require.NoError(t, err, ops.Errors)
	clearStateProg := ops.Program

	// Test FailedAt for each program failure
	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			txgroup := []transactions.SignedTxn{
				// fund app
				{
					Txn: transactions.Transaction{
						Type:   protocol.PaymentTx,
						Header: makeTxnHeader(sender),
						PaymentTxnFields: transactions.PaymentTxnFields{
							Receiver: basics.AppIndex(2).Address(),
							Amount:   basics.MicroAlgos{Raw: 403000}, // 400000 min balance plus 3000 for 3 txns
						},
					},
				},
				// create app
				{
					Txn: transactions.Transaction{
						Type:   protocol.ApplicationCallTx,
						Header: makeTxnHeader(sender),
						ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
							ApplicationID:     0,
							ApplicationArgs:   [][]byte{uint64ToBytes(uint64(3 - i))},
							ApprovalProgram:   approvalProg,
							ClearStateProgram: clearStateProg,
							LocalStateSchema: basics.StateSchema{
								NumUint:      0,
								NumByteSlice: 0,
							},
							GlobalStateSchema: basics.StateSchema{
								NumUint:      0,
								NumByteSlice: 0,
							},
						},
					},
				},
			}

			err = attachGroupID(txgroup)
			require.NoError(t, err)

			result, err := s.DetailedSimulate(txgroup)
			require.NoError(t, err)
			require.False(t, result.WouldSucceed)
			require.Contains(t, result.TxnGroups[0].FailureMessage, "rejected by ApprovalProgram")
			require.Equal(t, simulation.TxnPath{1, uint64(i)}, result.TxnGroups[0].FailedAt)
		})
	}
}

func TestDetailedSimulateMissingSignatures(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0].addr
	senderBalance := accounts[0].acctData.MicroAlgos

	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: makeTxnHeader(sender),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender,
					Amount:   basics.MicroAlgos{Raw: senderBalance.Raw - 1000},
				},
			},
		},
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: makeTxnHeader(sender),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender,
					Amount:   basics.MicroAlgos{Raw: senderBalance.Raw - 2000},
				},
			},
		},
	}

	err := attachGroupID(txgroup)
	require.NoError(t, err)

	// add signature to second transaction
	signatureSecrets := accounts[0].sk
	txgroup[1] = txgroup[1].Txn.Sign(signatureSecrets)

	result, err := s.DetailedSimulate(txgroup)
	require.NoError(t, err)
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

func makeProgramToCallInner(program string) (string, error) {
	ops, err := logic.AssembleString(program)
	if err != nil {
		return "", err
	}
	programBytesHex := hex.EncodeToString(ops.Program)
	outerProgram := fmt.Sprintf(`#pragma version 6
byte "starting inner txn"
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
int 1
`, programBytesHex)

	return outerProgram, nil
}

func TestDetailedSimulateAccessInnerTxnApplyDataOnFail(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Set up simulator
	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0].addr

	// Compile approval program
	singleInnerLogAndFail, err := makeProgramToCallInner(logAndFail)
	require.NoError(t, err)
	nestedInnerLogAndFail, err := makeProgramToCallInner(singleInnerLogAndFail)
	require.NoError(t, err)
	ops, err := logic.AssembleString(nestedInnerLogAndFail)
	require.NoError(t, err, ops.Errors)
	approvalProg := ops.Program

	// Compile clear program
	ops, err = logic.AssembleString(trivialAVMProgram)
	require.NoError(t, err, ops.Errors)
	clearStateProg := ops.Program

	txgroup := []transactions.SignedTxn{
		// fund outer app
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: makeTxnHeader(sender),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: basics.AppIndex(3).Address(),
					Amount:   basics.MicroAlgos{Raw: 401000}, // 400000 min balance plus 1000 for 1 txn
				},
			},
		},
		// fund inner app
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: makeTxnHeader(sender),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: basics.AppIndex(4).Address(),
					Amount:   basics.MicroAlgos{Raw: 401000}, // 400000 min balance plus 1000 for 1 txn
				},
			},
		},
		// create app
		{
			Txn: transactions.Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: makeTxnHeader(sender),
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID:     0,
					ApplicationArgs:   [][]byte{uint64ToBytes(uint64(1))},
					ApprovalProgram:   approvalProg,
					ClearStateProgram: clearStateProg,
					LocalStateSchema: basics.StateSchema{
						NumUint:      0,
						NumByteSlice: 0,
					},
					GlobalStateSchema: basics.StateSchema{
						NumUint:      0,
						NumByteSlice: 0,
					},
				},
			},
		},
	}

	err = attachGroupID(txgroup)
	require.NoError(t, err)

	result, err := s.DetailedSimulate(txgroup)
	require.NoError(t, err)
	require.False(t, result.WouldSucceed)
	txnGroup := result.TxnGroups[0]
	require.Contains(t, txnGroup.FailureMessage, "rejected by ApprovalProgram")
	require.Equal(t, simulation.TxnPath{2, 0, 0}, txnGroup.FailedAt)

	// Check that inner transaction ApplyData is accessible
	outerAppEvalDelta := txnGroup.Txns[2].Txn.ApplyData.EvalDelta
	middleAppEvalDelta := outerAppEvalDelta.InnerTxns[0].ApplyData.EvalDelta
	innerAppEvalDelta := middleAppEvalDelta.InnerTxns[0].ApplyData.EvalDelta
	require.Equal(t, "starting inner txn", outerAppEvalDelta.Logs[0])
	require.Equal(t, "starting inner txn", middleAppEvalDelta.Logs[0])
	require.Equal(t, "message", innerAppEvalDelta.Logs[0])
}
