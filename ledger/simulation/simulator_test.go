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
	"reflect"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/logic/mocktracer"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/eval"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// We want to be careful that the Algod ledger does not move on to another round
// so we confirm here that all ledger methods which implicitly access the current round
// are overriden within the `simulatorLedger`.
func TestNonOverridenDataLedgerMethodsUseRoundParameter(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, _, _ := simulationtesting.PrepareSimulatorTest(t)

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
		"FlushCaches",
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
		evalLedgerType := reflect.TypeOf((*eval.LedgerForEvaluator)(nil)).Elem()
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

// TestSimulateWithTrace is a simple test to ensure that the debugger hooks are called. More
// complicated tests are in data/transactions/logic/tracer_test.go
func TestSimulateWithTrace(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, txnInfo := simulationtesting.PrepareSimulatorTest(t)
	defer l.Close()
	s := MakeSimulator(l)
	sender := accounts[0]

	op, err := logic.AssembleString(`#pragma version 8
int 1`)
	require.NoError(t, err)
	program := logic.Program(op.Program)
	lsigAddr := basics.Address(crypto.HashObj(&program))

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
int 1`,
		ClearStateProgram: `#pragma version 8
int 1`,
	})

	txntest.Group(&payTxn, &appCallTxn)

	signedPayTxn := payTxn.Txn().Sign(sender.Sk)
	signedAppCallTxn := appCallTxn.SignedTxn()
	signedAppCallTxn.Lsig.Logic = program

	txgroup := []transactions.SignedTxn{signedPayTxn, signedAppCallTxn}

	mockTracer := &mocktracer.Tracer{}
	block, _, err := s.simulateWithTracer(txgroup, mockTracer)
	require.NoError(t, err)

	payset := block.Block().Payset
	require.Len(t, payset, 2)

	expectedEvents := []mocktracer.Event{
		// LogicSig evaluation
		mocktracer.BeforeProgram(logic.ModeSig),
		mocktracer.BeforeOpcode(),
		mocktracer.AfterOpcode(false),
		mocktracer.AfterProgram(logic.ModeSig, false),
		// Txn evaluation
		mocktracer.BeforeTxnGroup(2),
		mocktracer.BeforeTxn(protocol.PaymentTx),
		mocktracer.AfterTxn(protocol.PaymentTx, payset[0].ApplyData, nil, false),
		mocktracer.BeforeTxn(protocol.ApplicationCallTx),
		mocktracer.BeforeProgram(logic.ModeApp),
		mocktracer.BeforeOpcode(),
		mocktracer.AfterOpcode(false),
		mocktracer.AfterProgram(logic.ModeApp, false),
		mocktracer.AfterTxn(protocol.ApplicationCallTx, payset[1].ApplyData, nil, false),
		mocktracer.AfterTxnGroup(2, nil, false),
	}
	require.Equal(t, expectedEvents, mockTracer.Events)
}
