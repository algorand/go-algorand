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
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/logic/mocktracer"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// We want to be careful that the Algod ledger does not move on to another round
// so we confirm here that all ledger methods which implicitly access the current round
// are overriden within the `simulatorLedger`.
func TestNonOverridenDataLedgerMethodsUseRoundParameter(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	env := simulationtesting.PrepareSimulatorTest(t)

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

	ledgerType := reflect.TypeOf(env.Ledger)
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

	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Ledger.Close()
	s := MakeSimulator(env.Ledger)
	sender := env.Accounts[0]

	op, err := logic.AssembleString(`#pragma version 8
int 1`)
	require.NoError(t, err)
	program := logic.Program(op.Program)
	lsigAddr := basics.Address(crypto.HashObj(&program))

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

	evalBlock := block.Block()
	require.Len(t, evalBlock.Payset, 2)

	expectedSenderData := ledgercore.ToAccountData(sender.AcctData)
	expectedSenderData.MicroAlgos.Raw -= signedPayTxn.Txn.Amount.Raw + signedPayTxn.Txn.Fee.Raw
	expectedLsigData := ledgercore.AccountData{}
	expectedLsigData.MicroAlgos.Raw += signedPayTxn.Txn.Amount.Raw - signedAppCallTxn.Txn.Fee.Raw
	expectedLsigData.TotalAppParams = 1
	expectedFeeSinkData := ledgercore.ToAccountData(env.FeeSinkAccount.AcctData)
	expectedFeeSinkData.MicroAlgos.Raw += signedPayTxn.Txn.Fee.Raw + signedAppCallTxn.Txn.Fee.Raw

	expectedAppID := evalBlock.Payset[1].ApplyData.ApplicationID
	expectedAppParams := ledgercore.AppParamsDelta{
		Params: &basics.AppParams{
			ApprovalProgram:   signedAppCallTxn.Txn.ApprovalProgram,
			ClearStateProgram: signedAppCallTxn.Txn.ClearStateProgram,
		},
	}

	// Cannot use evalBlock directly because the tracer is called before many block details are finalized
	expectedBlockHeader := bookkeeping.MakeBlock(env.TxnInfo.LatestHeader).BlockHeader
	expectedBlockHeader.TimeStamp = evalBlock.TimeStamp
	expectedBlockHeader.RewardsRate = evalBlock.RewardsRate
	expectedBlockHeader.RewardsResidue = evalBlock.RewardsResidue

	expectedDelta := ledgercore.MakeStateDelta(&expectedBlockHeader, env.TxnInfo.LatestHeader.TimeStamp, 0, 0)
	expectedDelta.Accts.Upsert(sender.Addr, expectedSenderData)
	expectedDelta.Accts.Upsert(env.FeeSinkAccount.Addr, expectedFeeSinkData)
	expectedDelta.Accts.Upsert(lsigAddr, expectedLsigData)
	expectedDelta.Accts.UpsertAppResource(lsigAddr, expectedAppID, expectedAppParams, ledgercore.AppLocalStateDelta{})
	expectedDelta.AddCreatable(basics.CreatableIndex(expectedAppID), ledgercore.ModifiedCreatable{
		Ctype:   basics.AppCreatable,
		Created: true,
		Creator: lsigAddr,
	})
	expectedDelta.Txids[signedPayTxn.Txn.ID()] = ledgercore.IncludedTransactions{
		LastValid: signedPayTxn.Txn.LastValid,
		Intra:     0,
	}
	expectedDelta.Txids[signedAppCallTxn.Txn.ID()] = ledgercore.IncludedTransactions{
		LastValid: signedAppCallTxn.Txn.LastValid,
		Intra:     1,
	}

	expectedEvents := []mocktracer.Event{
		// LogicSig evaluation
		mocktracer.BeforeProgram(logic.ModeSig),
		mocktracer.BeforeOpcode(),
		mocktracer.AfterOpcode(false),
		mocktracer.AfterProgram(logic.ModeSig, false),
		// Txn evaluation
		mocktracer.BeforeBlock(block.Block().Round()),
		mocktracer.BeforeTxnGroup(2),
		mocktracer.BeforeTxn(protocol.PaymentTx),
		mocktracer.AfterTxn(protocol.PaymentTx, evalBlock.Payset[0].ApplyData, nil, false),
		mocktracer.BeforeTxn(protocol.ApplicationCallTx),
		mocktracer.BeforeProgram(logic.ModeApp),
		mocktracer.BeforeOpcode(),
		mocktracer.AfterOpcode(false),
		mocktracer.AfterProgram(logic.ModeApp, false),
		mocktracer.AfterTxn(protocol.ApplicationCallTx, evalBlock.Payset[1].ApplyData, nil, false),
		mocktracer.AfterTxnGroup(2, &expectedDelta, false),
		//Block evaluation
		mocktracer.AfterBlock(block.Block().Round()),
	}
	actualEvents := mockTracer.Events

	// Dehydrate deltas for better comparison
	for i := range expectedEvents {
		if expectedEvents[i].Deltas != nil {
			expectedEvents[i].Deltas.Dehydrate()
		}
	}
	for i := range actualEvents {
		if actualEvents[i].Deltas != nil {
			actualEvents[i].Deltas.Dehydrate()
		}
	}

	// These extra checks are not necessary for correctness, but they provide more targeted information on failure
	if assert.Equal(t, len(expectedEvents), len(actualEvents)) {
		for i := range expectedEvents {
			jsonExpectedDelta := protocol.EncodeJSONStrict(expectedEvents[i].Deltas)
			jsonActualDelta := protocol.EncodeJSONStrict(actualEvents[i].Deltas)
			assert.Equal(t, expectedEvents[i].Deltas, actualEvents[i].Deltas, "StateDelta disagreement: i=%d, event type: (%v,%v)\n\nexpected: %s\n\nactual: %s", i, expectedEvents[i].Type, actualEvents[i].Type, jsonExpectedDelta, jsonActualDelta)
		}
	}

	require.Equal(t, expectedEvents, actualEvents)
}
