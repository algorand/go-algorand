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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
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
