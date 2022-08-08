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
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	. "github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger"
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
// > Simulation Tests
// ==============================

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

	result, err := s.Simulate(txgroup)
	require.NoError(t, err)
	require.Empty(t, result.FailureMessage)
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

	result, err := s.Simulate(txgroup)
	require.NoError(t, err)
	require.Contains(t, result.FailureMessage, fmt.Sprintf("tried to spend {%d}", amount))
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
	result, err := s.Simulate(txgroup)
	require.NoError(t, err)
	require.Contains(t, result.FailureMessage, "had zero Group but was submitted in a group of 2")

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
	require.Empty(t, result.FailureMessage)

	// Confirm balances have not changed
	sender1Data, _, err = l.LookupWithoutRewards(l.Latest(), sender1)
	require.NoError(t, err)
	require.Equal(t, sender1Balance, sender1Data.MicroAlgos)

	sender2Data, _, err = l.LookupWithoutRewards(l.Latest(), sender2)
	require.NoError(t, err)
	require.Equal(t, sender2Balance, sender2Data.MicroAlgos)
}

const trivialAVMProgram = `#pragma version 2
int 1`
const rejectAVMProgram = `#pragma version 2
int 0`

func TestSimpleAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0].addr

	// Compile AVM program
	ops, err := AssembleString(trivialAVMProgram)
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

	result, err := s.Simulate(txgroup)
	require.NoError(t, err)
	require.Empty(t, result.FailureMessage)
}

func TestRejectAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := prepareSimulatorTest(t)
	defer l.Close()
	s := simulation.MakeSimulator(l)
	sender := accounts[0].addr

	// Compile AVM program
	ops, err := AssembleString(rejectAVMProgram)
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

	result, err := s.Simulate(txgroup)
	require.NoError(t, err)
	require.Contains(t, result.FailureMessage, "transaction rejected by ApprovalProgram")
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
	result, err := s.Simulate(txgroup)
	require.NoError(t, err)
	require.Empty(t, result.FailureMessage)
	require.True(t, result.MissingSignatures)

	// add signature
	signatureSecrets := accounts[0].sk
	txgroup[0] = txgroup[0].Txn.Sign(signatureSecrets)

	// should not error now that we have a signature
	result, err = s.Simulate(txgroup)
	require.NoError(t, err)
	require.Empty(t, result.FailureMessage)
	require.False(t, result.MissingSignatures)

	// should error with invalid signature
	txgroup[0].Sig[0] += byte(1) // will wrap if > 255
	result, err = s.Simulate(txgroup)
	require.ErrorAs(t, err, &simulation.InvalidTxGroupError{})
	require.ErrorContains(t, err, "one signature didn't pass")
}

// TestInvalidTxGroup tests that a transaction group with invalid transactions
// is rejected by the simulator as an error instead of a failure message.
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
	_, err := s.Simulate(txgroup)
	require.ErrorAs(t, err, &simulation.InvalidTxGroupError{})
	require.ErrorContains(t, err, "transaction from incentive pool is invalid")
}

const accountBalanceCheckProgram = `#pragma version 4
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
	ops, err := AssembleString(accountBalanceCheckProgram)
	require.NoError(t, err, ops.Errors)
	approvalProg := ops.Program

	// Compile clear program
	ops, err = AssembleString(trivialAVMProgram)
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

	result, err := s.Simulate(txgroup)
	require.NoError(t, err)
	require.Empty(t, result.FailureMessage)
}
