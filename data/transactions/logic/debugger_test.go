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
int 1
`

type testDbgHook struct {
	beforeTxnCalls int
	afterTxnCalls  int

	beforeLogicEvalCalls int
	afterLogicEvalCalls  int

	beforeTealOpCalls int
	afterTealOpCalls  int

	beforeInnerTxnGroupCalls int
	afterInnerTxnGroupCalls  int
}

func (d *testDbgHook) BeforeTxn(ep *EvalParams, groupIndex int) error {
	d.beforeTxnCalls++
	return nil
}

func (d *testDbgHook) AfterTxn(ep *EvalParams, groupIndex int) error {
	d.afterTxnCalls++
	return nil
}

func (d *testDbgHook) BeforeLogicEval(cx *EvalContext) error {
	d.beforeLogicEvalCalls++
	return nil
}

func (d *testDbgHook) AfterLogicEval(cx *EvalContext, evalError error) error {
	d.afterLogicEvalCalls++
	return nil
}

func (d *testDbgHook) BeforeTealOp(cx *EvalContext) error {
	d.beforeTealOpCalls++
	return nil
}

func (d *testDbgHook) AfterTealOp(cx *EvalContext, evalError error) error {
	d.afterTealOpCalls++
	return nil
}

func (d *testDbgHook) BeforeInnerTxnGroup(ep *EvalParams) error {
	d.beforeInnerTxnGroupCalls++
	return nil
}

func (d *testDbgHook) AfterInnerTxnGroup(ep *EvalParams) error {
	d.afterInnerTxnGroupCalls++
	return nil
}

func TestDebuggerHook(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("logicsig", func(t *testing.T) {
		t.Parallel()
		testDbg := testDbgHook{}
		ep := defaultEvalParams(nil)
		ep.Debugger = &testDbg
		testLogic(t, legacyDebuggerTestProgram, AssemblerMaxVersion, ep)

		// these should not be called because beforeTxn and afterTxn hooks
		// are called within ledger evaluation, not logic.
		require.Zero(t, testDbg.beforeTxnCalls)
		require.Zero(t, testDbg.afterTxnCalls)

		require.Equal(t, 1, testDbg.beforeLogicEvalCalls)
		require.Equal(t, 1, testDbg.afterLogicEvalCalls)

		require.Equal(t, 35, testDbg.beforeTealOpCalls)
		require.Equal(t, testDbg.beforeTealOpCalls, testDbg.afterTealOpCalls)

		require.Zero(t, testDbg.beforeInnerTxnGroupCalls)
		require.Zero(t, testDbg.afterInnerTxnGroupCalls)
	})

	t.Run("simple app", func(t *testing.T) {
		t.Parallel()
		testDbg := testDbgHook{}
		ep := defaultEvalParams(nil)
		ep.Debugger = &testDbg
		testApp(t, legacyDebuggerTestProgram, ep)

		// these should not be called because beforeTxn and afterTxn hooks
		// are called within ledger evaluation, not logic.
		require.Zero(t, testDbg.beforeTxnCalls)
		require.Zero(t, testDbg.afterTxnCalls)

		require.Equal(t, 1, testDbg.beforeLogicEvalCalls)
		require.Equal(t, 1, testDbg.afterLogicEvalCalls)

		require.Equal(t, 35, testDbg.beforeTealOpCalls)
		require.Equal(t, testDbg.beforeTealOpCalls, testDbg.afterTealOpCalls)

		require.Zero(t, testDbg.beforeInnerTxnGroupCalls)
		require.Zero(t, testDbg.afterInnerTxnGroupCalls)
	})

	t.Run("app with inner txns", func(t *testing.T) {
		t.Parallel()
		testDbg := testDbgHook{}
		ep, tx, ledger := MakeSampleEnv()

		// Establish 888 as the app id, and fund it.
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(basics.AppIndex(888).Address(), 200000)

		ep.Debugger = &testDbg
		testApp(t, innerTxnTestProgram, ep)

		// called for the inner transaction, not the top-level one
		require.Equal(t, 1, testDbg.beforeTxnCalls)
		require.Equal(t, 1, testDbg.afterTxnCalls)

		require.Equal(t, 2, testDbg.beforeLogicEvalCalls)
		require.Equal(t, 2, testDbg.afterLogicEvalCalls)

		appCallTealOps := 11
		innerAppCallTealOps := 1
		require.Equal(t, appCallTealOps+innerAppCallTealOps, testDbg.beforeTealOpCalls)
		require.Equal(t, testDbg.beforeTealOpCalls, testDbg.afterTealOpCalls)

		require.Equal(t, 1, testDbg.beforeInnerTxnGroupCalls)
		require.Equal(t, 1, testDbg.afterInnerTxnGroupCalls)
	})
}
