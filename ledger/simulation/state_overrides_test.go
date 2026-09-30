// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/avm-abi/apps"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/simulation"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func balanceOverride(addr basics.Address, microAlgos uint64) simulation.StateOverrides {
	return simulation.StateOverrides{
		Accounts: map[basics.Address]simulation.AccountOverride{
			addr: {Balance: &basics.MicroAlgos{Raw: microAlgos}},
		},
	}
}

func TestStateOverrideBalanceFundsNewAccount(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	senderSk := crypto.GenerateSignatureSecrets(seed)
	sender := basics.Address(senderSk.SignatureVerifier)
	receiver := env.Accounts[1]

	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   sender,
		Receiver: receiver.Addr,
		Amount:   1_000_000,
	}).Txn().Sign(senderSk)

	s := simulation.MakeSimulator(env.Ledger, false)

	// Without the override, the unfunded sender cannot pay
	result, err := s.Simulate(simulation.Request{TxnGroups: [][]transactions.SignedTxn{{txn}}})
	require.NoError(t, err)
	require.Contains(t, result.TxnGroups[0].FailureMessage, "overspend")

	const overrideBalance = 10_000_000
	result, err = s.Simulate(simulation.Request{
		TxnGroups:      [][]transactions.SignedTxn{{txn}},
		StateOverrides: balanceOverride(sender, overrideBalance),
	})
	require.NoError(t, err)
	require.Empty(t, result.TxnGroups[0].FailureMessage)

	delta := result.Block.Delta()
	senderData, ok := delta.Accts.GetData(sender)
	require.True(t, ok)
	require.Equal(t, overrideBalance-txn.Txn.Amount.Raw-txn.Txn.Fee.Raw, senderData.MicroAlgos.Raw)

	receiverData, ok := delta.Accts.GetData(receiver.Addr)
	require.True(t, ok)
	require.Equal(t, receiver.AcctData.MicroAlgos.Raw+txn.Txn.Amount.Raw, receiverData.MicroAlgos.Raw)

	// The real ledger is unaffected
	acct, _, _, err := env.Ledger.LookupAccount(env.Ledger.Latest(), sender)
	require.NoError(t, err)
	require.Zero(t, acct.MicroAlgos.Raw)
}

func TestStateOverrideBalanceDecrease(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	sender := env.Accounts[0]
	receiver := env.Accounts[1]

	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   sender.Addr,
		Receiver: receiver.Addr,
		Amount:   1_000_000,
	}).Txn().Sign(sender.Sk)

	result, err := simulation.MakeSimulator(env.Ledger, false).Simulate(simulation.Request{
		TxnGroups:      [][]transactions.SignedTxn{{txn}},
		StateOverrides: balanceOverride(sender.Addr, 500_000),
	})
	require.NoError(t, err)
	require.Contains(t, result.TxnGroups[0].FailureMessage, "overspend")
	require.Equal(t, simulation.TxnPath{0}, result.TxnGroups[0].FailedAt)
}

func TestStateOverrideBalanceVisibleToAVM(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	sender := env.Accounts[0]
	const overrideBalance = 123_456_789

	fee := env.TxnInfo.CurrentProtocolParams().MinTxnFee
	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:   protocol.ApplicationCallTx,
		Sender: sender.Addr,
		// The fee has already been deducted when the program runs
		ApprovalProgram: fmt.Sprintf(`#pragma version 8
txn Sender
balance
int %d
==`, overrideBalance-fee),
		ClearStateProgram: `#pragma version 8
int 1`,
	}).Txn().Sign(sender.Sk)

	s := simulation.MakeSimulator(env.Ledger, false)

	result, err := s.Simulate(simulation.Request{TxnGroups: [][]transactions.SignedTxn{{txn}}})
	require.NoError(t, err)
	require.Contains(t, result.TxnGroups[0].FailureMessage, "rejected by ApprovalProgram")

	result, err = s.Simulate(simulation.Request{
		TxnGroups:      [][]transactions.SignedTxn{{txn}},
		StateOverrides: balanceOverride(sender.Addr, overrideBalance),
	})
	require.NoError(t, err)
	require.Empty(t, result.TxnGroups[0].FailureMessage)
}

func assemble(t *testing.T, source string) []byte {
	t.Helper()
	ops, err := logic.AssembleString(source)
	require.NoError(t, err)
	return ops.Program
}

func TestStateOverrideCreateApp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	creator := env.Accounts[0]
	caller := env.Accounts[1]
	proto := env.TxnInfo.CurrentProtocolParams()

	// Advance the txn counter so there is an unused ID available for the new app
	env.TransferAlgos(creator.Addr, caller.Addr, 1)
	aidx := basics.AppIndex(env.TxnInfo.LatestHeader.TxnCounter)
	globalSchema := basics.StateSchema{NumUint: 1, NumByteSlice: 1}

	// The creator's minimum balance includes the new app, and the app account's includes its box
	creatorData, _, err := env.Ledger.LookupWithoutRewards(env.Ledger.Latest(), creator.Addr)
	require.NoError(t, err)
	creatorData.TotalAppParams++
	creatorData.TotalAppSchema = creatorData.TotalAppSchema.AddSchema(globalSchema)
	creatorMinBalance := creatorData.MinBalance(&proto).Raw
	appAcctMinBalance := ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{TotalBoxes: 1, TotalBoxBytes: uint64(len("box") + len("boxval"))},
	}.MinBalance(&proto).Raw

	approval := assemble(t, fmt.Sprintf(`#pragma version 8
global CurrentApplicationID
app_params_get AppCreator
assert
addr %[1]s
==
assert

byte "counter"
app_global_get
int 41
==
assert

byte "name"
app_global_get
byte "hello"
==
assert

byte "box"
box_get
assert
byte "boxval"
==
assert

addr %[1]s
min_balance
int %[2]d
==
assert

global CurrentApplicationAddress
min_balance
int %[3]d
==
assert

byte "counter"
int 42
app_global_put

byte "box"
byte "newval"
box_put

int 1`, creator.Addr, creatorMinBalance, appAcctMinBalance))
	clear := assemble(t, "#pragma version 8\nint 1")

	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:          protocol.ApplicationCallTx,
		Sender:        caller.Addr,
		ApplicationID: aidx,
		Accounts:      []basics.Address{creator.Addr},
		Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("box")}},
	}).Txn().Sign(caller.Sk)

	s := simulation.MakeSimulator(env.Ledger, false)

	// Without the override, the app does not exist
	result, err := s.Simulate(simulation.Request{TxnGroups: [][]transactions.SignedTxn{{txn}}})
	require.NoError(t, err)
	require.NotEmpty(t, result.TxnGroups[0].FailureMessage)

	result, err = s.Simulate(simulation.Request{
		TxnGroups: [][]transactions.SignedTxn{{txn}},
		StateOverrides: simulation.StateOverrides{
			Accounts: map[basics.Address]simulation.AccountOverride{
				aidx.Address(): {Balance: &basics.MicroAlgos{Raw: appAcctMinBalance}},
			},
			Apps: map[basics.AppIndex]simulation.AppOverride{
				aidx: {
					Creator:           creator.Addr,
					ApprovalProgram:   approval,
					ClearStateProgram: clear,
					GlobalStateSchema: &globalSchema,
					GlobalState: basics.TealKeyValue{
						"counter": {Type: basics.TealUintType, Uint: 41},
						"name":    {Type: basics.TealBytesType, Bytes: "hello"},
					},
					Boxes: map[string][]byte{"box": []byte("boxval")},
				},
			},
		},
	})
	require.NoError(t, err)
	require.Empty(t, result.TxnGroups[0].FailureMessage)

	evalDelta := result.TxnGroups[0].Txns[0].Txn.EvalDelta
	require.Equal(t, basics.StateDelta{
		"counter": {Action: basics.SetUintAction, Uint: 42},
	}, evalDelta.GlobalDelta)
	boxKey := apps.MakeBoxKey(uint64(aidx), "box")
	require.Equal(t, []byte("newval"), result.Block.Delta().KvMods[boxKey].Data)

	// The real ledger is unaffected
	_, exists, err := env.Ledger.GetCreatorForRound(env.Ledger.Latest(), basics.CreatableIndex(aidx), basics.AppCreatable)
	require.NoError(t, err)
	require.False(t, exists)
	value, err := env.Ledger.LookupKv(env.Ledger.Latest(), boxKey)
	require.NoError(t, err)
	require.Nil(t, value)
}

func TestStateOverrideExistingApp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	creator := env.Accounts[0]
	aidx := env.CreateApp(creator.Addr, simulationtesting.AppParams{
		ApprovalProgram: `#pragma version 8
txn ApplicationID
bz end

byte "x"
app_global_get
int 7
==
assert

byte "b"
box_get
assert
byte "v"
==
assert

byte "b"
box_del
assert

end:
int 1`,
		ClearStateProgram: "#pragma version 8\nint 1",
		GlobalStateSchema: basics.StateSchema{NumUint: 1},
	})

	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:          protocol.ApplicationCallTx,
		Sender:        creator.Addr,
		ApplicationID: aidx,
		Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("b")}},
	}).Txn().Sign(creator.Sk)

	s := simulation.MakeSimulator(env.Ledger, false)

	result, err := s.Simulate(simulation.Request{TxnGroups: [][]transactions.SignedTxn{{txn}}})
	require.NoError(t, err)
	require.Contains(t, result.TxnGroups[0].FailureMessage, "assert failed")

	result, err = s.Simulate(simulation.Request{
		TxnGroups: [][]transactions.SignedTxn{{txn}},
		StateOverrides: simulation.StateOverrides{
			Accounts: map[basics.Address]simulation.AccountOverride{
				aidx.Address(): {Balance: &basics.MicroAlgos{Raw: 1_000_000}},
			},
			Apps: map[basics.AppIndex]simulation.AppOverride{
				aidx: {
					GlobalState: basics.TealKeyValue{"x": {Type: basics.TealUintType, Uint: 7}},
					Boxes:       map[string][]byte{"b": []byte("v")},
				},
			},
		},
	})
	require.NoError(t, err)
	require.Empty(t, result.TxnGroups[0].FailureMessage)

	// Deleting the overridden box releases the box bookkeeping it added to the app account
	appAcct, ok := result.Block.Delta().Accts.GetData(aidx.Address())
	require.True(t, ok)
	require.Zero(t, appAcct.TotalBoxes)
	require.Zero(t, appAcct.TotalBoxBytes)
}

func TestStateOverrideAppValidation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	creator := env.Accounts[0]
	other := env.Accounts[1]
	aidx := env.CreateApp(creator.Addr, simulationtesting.AppParams{
		ApprovalProgram:   "#pragma version 8\nint 1",
		ClearStateProgram: "#pragma version 8\nint 1",
		GlobalStateSchema: basics.StateSchema{NumUint: 1},
	})
	// Advance the txn counter so there is an unused ID available for a new app
	env.TransferAlgos(creator.Addr, other.Addr, 1)
	newAidx := basics.AppIndex(env.TxnInfo.LatestHeader.TxnCounter)
	program := assemble(t, "#pragma version 8\nint 1")

	txn := env.TxnInfo.NewTxn(txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   creator.Addr,
		Receiver: other.Addr,
	}).Txn().Sign(creator.Sk)

	testCases := []struct {
		name          string
		aidx          basics.AppIndex
		override      simulation.AppOverride
		expectedError string
	}{
		{
			name:          "zero app ID",
			aidx:          0,
			override:      simulation.AppOverride{Creator: creator.Addr, ApprovalProgram: program, ClearStateProgram: program},
			expectedError: "app ID must be non-zero",
		},
		{
			name:          "new app ID just above txn counter",
			aidx:          newAidx + 1,
			override:      simulation.AppOverride{Creator: creator.Addr, ApprovalProgram: program, ClearStateProgram: program},
			expectedError: "which may be assigned during simulation",
		},
		{
			name:          "new app ID at end of reserved range",
			aidx:          newAidx + 1000,
			override:      simulation.AppOverride{Creator: creator.Addr, ApprovalProgram: program, ClearStateProgram: program},
			expectedError: "which may be assigned during simulation",
		},
		{
			name:          "app ID above MaxInt64",
			aidx:          math.MaxInt64 + 1,
			override:      simulation.AppOverride{Creator: creator.Addr, ApprovalProgram: program, ClearStateProgram: program},
			expectedError: "exceeds maximum",
		},
		{
			name:          "new app without creator",
			aidx:          newAidx,
			override:      simulation.AppOverride{ApprovalProgram: program, ClearStateProgram: program},
			expectedError: "creator is required",
		},
		{
			name:          "new app without programs",
			aidx:          newAidx,
			override:      simulation.AppOverride{Creator: creator.Addr},
			expectedError: "approval and clear state programs are required",
		},
		{
			name:          "change creator",
			aidx:          aidx,
			override:      simulation.AppOverride{Creator: other.Addr},
			expectedError: "cannot be changed",
		},
		{
			name: "global state exceeds schema",
			aidx: aidx,
			override: simulation.AppOverride{GlobalState: basics.TealKeyValue{
				"a": {Type: basics.TealUintType, Uint: 1},
				"b": {Type: basics.TealUintType, Uint: 2},
			}},
			expectedError: "exceeds global schema",
		},
		{
			name: "global value too long",
			aidx: aidx,
			override: simulation.AppOverride{
				GlobalStateSchema: &basics.StateSchema{NumByteSlice: 1},
				GlobalState: basics.TealKeyValue{
					"a": {Type: basics.TealBytesType, Bytes: string(make([]byte, 200))},
				},
			},
			expectedError: "exceeds maximum",
		},
		{
			name:          "empty box name",
			aidx:          aidx,
			override:      simulation.AppOverride{Boxes: map[string][]byte{"": nil}},
			expectedError: "box name length 0",
		},
	}

	s := simulation.MakeSimulator(env.Ledger, false)

	for _, validAidx := range []basics.AppIndex{newAidx, newAidx + 1001, math.MaxInt64} {
		result, err := s.Simulate(simulation.Request{
			TxnGroups: [][]transactions.SignedTxn{{txn}},
			StateOverrides: simulation.StateOverrides{
				Apps: map[basics.AppIndex]simulation.AppOverride{
					validAidx: {Creator: creator.Addr, ApprovalProgram: program, ClearStateProgram: program},
				},
			},
		})
		require.NoError(t, err, "app ID %d", validAidx)
		require.Empty(t, result.TxnGroups[0].FailureMessage, "app ID %d", validAidx)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Simulate(simulation.Request{
				TxnGroups: [][]transactions.SignedTxn{{txn}},
				StateOverrides: simulation.StateOverrides{
					Apps: map[basics.AppIndex]simulation.AppOverride{tc.aidx: tc.override},
				},
			})
			require.ErrorAs(t, err, &simulation.InvalidRequestError{})
			require.ErrorContains(t, err, tc.expectedError)
		})
	}
}
