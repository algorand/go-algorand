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
	beforeLogicSigEvalCalls  int
	afterLogicSigEvalCalls   int
	beforeTxnCalls           int
	beforeAppEvalCalls       int
	beforeTealOpCalls        int
	beforeInnerTxnGroupCalls int
	afterInnerTxnGroupCalls  int
	afterTealOpCalls         int
	afterAppEvalCalls        int
	afterTxnCalls            int
	state                    *DebugState
}

func (d *testDbgHook) BeforeLogicSigEval(state *DebugState) error {
	d.beforeLogicSigEvalCalls++
	d.state = state
	return nil
}

func (d *testDbgHook) AfterLogicSigEval(state *DebugState) error {
	d.afterLogicSigEvalCalls++
	d.state = state
	return nil
}

func (d *testDbgHook) BeforeTxn(ep *EvalParams, groupIndex int) error {
	d.beforeTxnCalls++
	d.state = ep.caller.debugState
	return nil
}

func (d *testDbgHook) BeforeAppEval(state *DebugState) error {
	d.beforeAppEvalCalls++
	d.state = state
	return nil
}

func (d *testDbgHook) BeforeTealOp(state *DebugState) error {
	d.beforeTealOpCalls++
	d.state = state
	return nil
}

func (d *testDbgHook) BeforeInnerTxnGroup(ep *EvalParams) error {
	d.beforeInnerTxnGroupCalls++
	d.state = ep.caller.debugState
	return nil
}

func (d *testDbgHook) AfterInnerTxnGroup(ep *EvalParams) error {
	d.afterInnerTxnGroupCalls++
	d.state = ep.caller.debugState
	return nil
}

func (d *testDbgHook) AfterTealOp(state *DebugState) error {
	d.afterTealOpCalls++
	d.state = state
	return nil
}

func (d *testDbgHook) AfterAppEval(state *DebugState) error {
	d.afterAppEvalCalls++
	d.state = state
	return nil
}

func (d *testDbgHook) AfterTxn(ep *EvalParams, groupIndex int) error {
	d.afterTxnCalls++
	d.state = ep.caller.debugState
	return nil
}

func TestDebuggerHook(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testDbg := testDbgHook{}
	ep := defaultEvalParams(nil)
	ep.Debugger = &testDbg
	testApp(t, legacyDebuggerTestProgram, ep)

	// these should not be called because beforeTxn and afterTxn hooks
	// are called within ledger evaluation, not logic.
	require.Equal(t, 0, testDbg.beforeTxnCalls)
	require.Equal(t, 0, testDbg.afterTxnCalls)

	require.Equal(t, 0, testDbg.beforeLogicSigEvalCalls)
	require.Equal(t, 0, testDbg.afterLogicSigEvalCalls)

	require.Equal(t, 1, testDbg.beforeAppEvalCalls)
	require.Equal(t, 1, testDbg.afterAppEvalCalls)

	require.Greater(t, testDbg.beforeTealOpCalls, 1)
	require.Greater(t, testDbg.afterTealOpCalls, 1)
	require.Equal(t, testDbg.beforeTealOpCalls, testDbg.afterTealOpCalls)

	require.Zero(t, testDbg.beforeInnerTxnGroupCalls)
	require.Zero(t, testDbg.afterInnerTxnGroupCalls)

	require.Len(t, testDbg.state.Stack, 1)
}

func TestDebuggerHooksLogicSig(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testDbg := testDbgHook{}
	ep := defaultEvalParams(nil)
	ep.Debugger = &testDbg
	testLogic(t, legacyDebuggerTestProgram, AssemblerMaxVersion, ep)

	// these should not be called because beforeTxn and afterTxn hooks
	// are called within ledger evaluation, not logic.
	require.Equal(t, 0, testDbg.beforeTxnCalls)
	require.Equal(t, 0, testDbg.afterTxnCalls)

	require.Equal(t, 1, testDbg.beforeLogicSigEvalCalls)
	require.Equal(t, 1, testDbg.afterLogicSigEvalCalls)

	require.Equal(t, 0, testDbg.beforeAppEvalCalls)
	require.Equal(t, 0, testDbg.afterAppEvalCalls)

	require.Greater(t, testDbg.beforeTealOpCalls, 1)
	require.Greater(t, testDbg.afterTealOpCalls, 1)
	require.Equal(t, testDbg.beforeTealOpCalls, testDbg.afterTealOpCalls)

	require.Zero(t, testDbg.beforeInnerTxnGroupCalls)
	require.Zero(t, testDbg.afterInnerTxnGroupCalls)

	require.Len(t, testDbg.state.Stack, 1)
}

func TestDebuggerHookInnerTxns(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testDbg := testDbgHook{}
	ep, tx, ledger := MakeSampleEnv()

	// Establish 888 as the app id, and fund it.
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(basics.AppIndex(888).Address(), 200000)

	ep.Debugger = &testDbg
	testApp(t, innerTxnTestProgram, ep)

	require.Equal(t, testDbg.beforeAppEvalCalls, 2)
	require.Equal(t, testDbg.afterAppEvalCalls, 2)

	appCallTealOps := 11
	innerAppCallTealOps := 1
	require.Equal(t, testDbg.beforeTealOpCalls, appCallTealOps+innerAppCallTealOps)
	require.Equal(t, testDbg.beforeTealOpCalls, testDbg.afterTealOpCalls)

	require.Equal(t, 1, testDbg.beforeInnerTxnGroupCalls)
	require.Equal(t, 1, testDbg.afterInnerTxnGroupCalls)

	require.Len(t, testDbg.state.Stack, 1)
}
