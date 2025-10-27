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

package simulation

import (
	"reflect"
	"slices"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
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
	"github.com/stretchr/testify/require"
)

// We want to be careful that the Algod ledger does not move on to another round
// so we confirm here that all ledger methods which implicitly access the current round
// are overridden within the `simulatorLedger`.
func TestNonOverridenDataLedgerMethodsUseRoundParameter(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// methods overridden by `simulatorLedger``
	overriddenMethods := []string{
		"Latest",
		"LookupLatest",
		"LatestTotals",
	}

	// methods that don't use a round number
	excludedMethods := []string{
		"GenesisHash",
		"GenesisProto",
		"FlushCaches",
	}

	methodIsSkipped := func(methodName string) bool {
		if slices.Contains(overriddenMethods, methodName) {
			return true
		}
		return slices.Contains(excludedMethods, methodName)
	}

	methodExistsInEvalLedger := func(methodName string) bool {
		evalLedgerType := reflect.TypeFor[eval.LedgerForEvaluator]()
		for i := 0; i < evalLedgerType.NumMethod(); i++ {
			if evalLedgerType.Method(i).Name == methodName {
				return true
			}
		}
		return false
	}

	methodHasRoundParameter := func(methodType reflect.Type) bool {
		for i := 0; i < methodType.NumIn(); i++ {
			if methodType.In(i) == reflect.TypeFor[basics.Round]() {
				return true
			}
		}
		return false
	}

	ledgerType := reflect.TypeFor[*data.Ledger]()
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
	defer env.Close()
	s := MakeSimulator(env.Ledger, false)
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
	s.ledger.start = s.ledger.Ledger.Latest() // Set starting round for simulation
	block, err := s.simulateWithTracer(transactions.WrapSignedTxnsWithAD(txgroup), mockTracer, ResultEvalOverrides{})
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
	expectedBlockHeader.RewardsLevel = evalBlock.RewardsLevel
	expectedBlockHeader.RewardsResidue = evalBlock.RewardsResidue
	expectedBlockHeader.RewardsRate = evalBlock.RewardsRate
	expectedBlockHeader.RewardsRecalculationRound = evalBlock.RewardsRecalculationRound

	expectedDelta := ledgercore.StateDelta{
		Accts: ledgercore.AccountDeltas{
			Accts: []ledgercore.BalanceRecord{
				{
					Addr:        sender.Addr,
					AccountData: expectedSenderData,
				},
				{
					Addr:        env.FeeSinkAccount.Addr,
					AccountData: expectedFeeSinkData,
				},
				{
					Addr:        lsigAddr,
					AccountData: expectedLsigData,
				},
			},
			AppResources: []ledgercore.AppResourceRecord{
				{
					Aidx:   expectedAppID,
					Addr:   lsigAddr,
					Params: expectedAppParams,
				},
			},
		},
		Creatables: map[basics.CreatableIndex]ledgercore.ModifiedCreatable{
			basics.CreatableIndex(expectedAppID): {
				Ctype:   basics.AppCreatable,
				Created: true,
				Creator: lsigAddr,
			},
		},
		Txids: map[transactions.Txid]ledgercore.IncludedTransactions{
			signedPayTxn.Txn.ID(): {
				LastValid: signedPayTxn.Txn.LastValid,
				Intra:     0,
			},
			signedAppCallTxn.Txn.ID(): {
				LastValid: signedAppCallTxn.Txn.LastValid,
				Intra:     1,
			},
		},
		Hdr:           &expectedBlockHeader,
		PrevTimestamp: env.TxnInfo.LatestHeader.TimeStamp,
	}

	expectedEvents := []mocktracer.Event{
		// LogicSig evaluation
		mocktracer.BeforeProgram(logic.ModeSig),
		mocktracer.BeforeOpcode(),
		mocktracer.AfterOpcode(false),
		mocktracer.AfterProgram(logic.ModeSig, mocktracer.ProgramResultPass),
		// Txn evaluation
		mocktracer.BeforeBlock(block.Block().Round()),
		mocktracer.BeforeTxnGroup(2),
		mocktracer.BeforeTxn(protocol.PaymentTx),
		mocktracer.AfterTxn(protocol.PaymentTx, evalBlock.Payset[0].ApplyData, false),
		mocktracer.BeforeTxn(protocol.ApplicationCallTx),
		mocktracer.BeforeProgram(logic.ModeApp),
		mocktracer.BeforeOpcode(),
		mocktracer.AfterOpcode(false),
		mocktracer.AfterProgram(logic.ModeApp, mocktracer.ProgramResultPass),
		mocktracer.AfterTxn(protocol.ApplicationCallTx, evalBlock.Payset[1].ApplyData, false),
		mocktracer.AfterTxnGroup(2, &expectedDelta, false),
		//Block evaluation
		mocktracer.AfterBlock(block.Block().Round()),
	}
	mocktracer.AssertEventsEqual(t, expectedEvents, mockTracer.Events)
}
