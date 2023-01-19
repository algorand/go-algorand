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

package simulation

import (
	"testing"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic/mocktracer"
	"github.com/algorand/go-algorand/data/txntest"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// TestSimulateWithTrace is a simple test to ensure that the debugger hooks are called. More
// complicated tests are in the logic/tracer_test.go file.
func TestSimulateWithTrace(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, txnInfo := simulationtesting.PrepareSimulatorTest(t)
	defer l.Close()
	s := MakeSimulator(l)
	sender := accounts[0].Addr
	senderBalance := accounts[0].AcctData.MicroAlgos
	amount := senderBalance.Raw - 10000

	txgroup := []transactions.SignedTxn{
		txnInfo.NewTxn(txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   sender,
			Receiver: sender,
			Amount:   amount,
		}).SignedTxn(),
	}

	mockTracer := &mocktracer.Tracer{}
	block, _, err := s.simulateWithTracer(txgroup, mockTracer)
	require.NoError(t, err)

	payset := block.Block().Payset
	require.Len(t, payset, 1)

	expectedEvents := []mocktracer.Event{
		mocktracer.BeforeTxnGroup(1),
		mocktracer.BeforeTxn(protocol.PaymentTx),
		mocktracer.AfterTxn(protocol.PaymentTx, payset[0].ApplyData),
		mocktracer.AfterTxnGroup(1),
	}
	require.Equal(t, expectedEvents, mockTracer.Events)
}
