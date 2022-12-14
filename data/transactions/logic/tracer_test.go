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

package logic

import (
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// byte 0x068101 is `#pragma version 6; int 1;`
const innerTxnTestProgram string = `itxn_begin
int appl
itxn_field TypeEnum
int NoOp
itxn_field OnCompletion
byte 0x068101
dup
itxn_field ApprovalProgram
itxn_field ClearStateProgram
itxn_submit

itxn_begin
int pay
itxn_field TypeEnum
int 1
itxn_field Amount
global CurrentApplicationAddress
itxn_field Receiver
itxn_next
int pay
itxn_field TypeEnum
int 2
itxn_field Amount
global CurrentApplicationAddress
itxn_field Receiver
itxn_submit

int 1
`

// can't use mocktracer.Tracer because the import would be circular
type testEvalTracer struct {
	beforeTxnCalls int
	afterTxnCalls  int

	beforeProgramCalls int
	afterProgramCalls  int
	programModes       []RunMode

	beforeOpcodeCalls int
	afterOpcodeCalls  int

	beforeInnerTxnGroupCalls int
	afterInnerTxnGroupCalls  int
}

func (t *testEvalTracer) BeforeTxn(ep *EvalParams, groupIndex int) {
	t.beforeTxnCalls++
}

func (t *testEvalTracer) AfterTxn(ep *EvalParams, groupIndex int, ad transactions.ApplyData) {
	t.afterTxnCalls++
}

func (t *testEvalTracer) BeforeProgram(cx *EvalContext) {
	t.beforeProgramCalls++
	t.programModes = append(t.programModes, cx.RunMode())
}

func (t *testEvalTracer) AfterProgram(cx *EvalContext, evalError error) {
	t.afterProgramCalls++
}

func (t *testEvalTracer) BeforeOpcode(cx *EvalContext) {
	t.beforeOpcodeCalls++
}

func (t *testEvalTracer) AfterOpcode(cx *EvalContext, evalError error) {
	t.afterOpcodeCalls++
}

func (t *testEvalTracer) BeforeInnerTxnGroup(ep *EvalParams) {
	t.beforeInnerTxnGroupCalls++
}

func (t *testEvalTracer) AfterInnerTxnGroup(ep *EvalParams) {
	t.afterInnerTxnGroupCalls++
}

func TestEvalWithTracer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("logicsig", func(t *testing.T) {
		t.Parallel()
		testTracer := testEvalTracer{}
		ep := defaultEvalParams()
		ep.Tracer = &testTracer
		testLogic(t, debuggerTestProgram, AssemblerMaxVersion, ep)

		// these should not be called because beforeTxn and afterTxn hooks
		// are called within ledger evaluation, not logic.
		require.Zero(t, testTracer.beforeTxnCalls)
		require.Zero(t, testTracer.afterTxnCalls)

		require.Equal(t, 1, testTracer.beforeProgramCalls)
		require.Equal(t, 1, testTracer.afterProgramCalls)
		require.Equal(t, []RunMode{ModeSig}, testTracer.programModes)

		require.Equal(t, 35, testTracer.beforeOpcodeCalls)
		require.Equal(t, testTracer.beforeOpcodeCalls, testTracer.afterOpcodeCalls)

		require.Zero(t, testTracer.beforeInnerTxnGroupCalls)
		require.Zero(t, testTracer.afterInnerTxnGroupCalls)
	})

	t.Run("simple app", func(t *testing.T) {
		t.Parallel()
		testTracer := testEvalTracer{}
		ep := defaultEvalParams()
		ep.Tracer = &testTracer
		testApp(t, debuggerTestProgram, ep)

		// these should not be called because beforeTxn and afterTxn hooks
		// are called within ledger evaluation, not logic.
		require.Zero(t, testTracer.beforeTxnCalls)
		require.Zero(t, testTracer.afterTxnCalls)

		require.Equal(t, 1, testTracer.beforeProgramCalls)
		require.Equal(t, 1, testTracer.afterProgramCalls)
		require.Equal(t, []RunMode{ModeApp}, testTracer.programModes)

		require.Equal(t, 35, testTracer.beforeOpcodeCalls)
		require.Equal(t, testTracer.beforeOpcodeCalls, testTracer.afterOpcodeCalls)

		require.Zero(t, testTracer.beforeInnerTxnGroupCalls)
		require.Zero(t, testTracer.afterInnerTxnGroupCalls)
	})

	t.Run("app with inner txns", func(t *testing.T) {
		t.Parallel()
		testTracer := testEvalTracer{}
		ep, tx, ledger := MakeSampleEnv()

		// Establish 888 as the app id, and fund it.
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(basics.AppIndex(888).Address(), 200000)

		ep.Tracer = &testTracer
		testApp(t, innerTxnTestProgram, ep)

		// only called for the inner transaction in this test, not the top-level one
		require.Equal(t, 3, testTracer.beforeTxnCalls)
		require.Equal(t, 3, testTracer.afterTxnCalls)

		require.Equal(t, 2, testTracer.beforeProgramCalls)
		require.Equal(t, 2, testTracer.afterProgramCalls)
		require.Equal(t, []RunMode{ModeApp, ModeApp}, testTracer.programModes)

		appCallTealOps := 27
		innerAppCallTealOps := 1
		require.Equal(t, appCallTealOps+innerAppCallTealOps, testTracer.beforeOpcodeCalls)
		require.Equal(t, testTracer.beforeOpcodeCalls, testTracer.afterOpcodeCalls)

		// two groups of inner transactions were issued
		require.Equal(t, 2, testTracer.beforeInnerTxnGroupCalls)
		require.Equal(t, 2, testTracer.afterInnerTxnGroupCalls)
	})
}
