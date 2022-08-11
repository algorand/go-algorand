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
	"encoding/base64"
	"os"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

var testProgram string = `intcblock 0 1 1 1 1 5 100
bytecblock 0x414c474f 0x1337 0x2001 0xdeadbeef 0x70077007
bytec 0
sha256
keccak256
sha512_256
len
intc_0
+
intc_1
-
intc_2
/
intc_3
*
intc 4
<
intc_1
>
intc_1
<=
intc_1
>=
intc_1
&&
intc_1
||
bytec_1
bytec_2
!=
bytec_3
bytec 4
!=
&&
&&
`

// byte 0x068101 is `#pragma version 6; int 1;`
var innerTxnTestProgram string = `itxn_begin
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

func TestWebDebuggerManual(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	debugURL := os.Getenv("TEAL_DEBUGGER_URL")
	if len(debugURL) == 0 {
		t.Skip("this must be run manually")
	}

	ep, tx, _ := makeSampleEnv()
	ep.TxnGroup[0].Lsig.Args = [][]byte{
		tx.Sender[:],
		tx.Receiver[:],
		tx.CloseRemainderTo[:],
		tx.VotePK[:],
		tx.SelectionPK[:],
		tx.Note,
	}
	ep.Debugger = &WebDebuggerHook{URL: debugURL}
	testLogic(t, testProgram, AssemblerMaxVersion, ep)
}

type testDbgHook struct {
	beforeAppEvalCalls  int
	beforeTealOpCalls   int
	beforeInnerTxnCalls int
	afterInnerTxnCalls  int
	afterTealOpCalls    int
	afterAppEvalCalls   int
	state               *DebugState
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

func (d *testDbgHook) BeforeInnerTxn(ep *EvalParams) error {
	d.beforeInnerTxnCalls++
	d.state = ep.caller.debugState
	return nil
}

func (d *testDbgHook) AfterInnerTxn(ep *EvalParams) error {
	d.afterInnerTxnCalls++
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

func TestDebuggerHook(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testDbg := testDbgHook{}
	ep := defaultEvalParams(nil)
	ep.Debugger = &testDbg
	testLogic(t, testProgram, AssemblerMaxVersion, ep)

	require.Equal(t, 1, testDbg.beforeAppEvalCalls)
	require.Equal(t, 1, testDbg.afterAppEvalCalls)

	require.Greater(t, testDbg.beforeTealOpCalls, 1)
	require.Greater(t, testDbg.afterTealOpCalls, 1)
	require.Equal(t, testDbg.beforeTealOpCalls, testDbg.afterTealOpCalls)

	require.Zero(t, testDbg.beforeInnerTxnCalls)
	require.Zero(t, testDbg.afterInnerTxnCalls)

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

	require.Equal(t, 1, testDbg.beforeInnerTxnCalls)
	require.Equal(t, 1, testDbg.afterInnerTxnCalls)

	require.Len(t, testDbg.state.Stack, 1)
}

func TestLineToPC(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	dState := DebugState{
		Disassembly: "abc\ndef\nghi",
		PCOffset:    []PCOffset{{PC: 1, Offset: 4}, {PC: 2, Offset: 8}, {PC: 3, Offset: 12}},
	}
	pc := dState.LineToPC(0)
	require.Equal(t, 0, pc)

	pc = dState.LineToPC(1)
	require.Equal(t, 1, pc)

	pc = dState.LineToPC(2)
	require.Equal(t, 2, pc)

	pc = dState.LineToPC(3)
	require.Equal(t, 3, pc)

	pc = dState.LineToPC(4)
	require.Equal(t, 0, pc)

	pc = dState.LineToPC(-1)
	require.Equal(t, 0, pc)

	pc = dState.LineToPC(0x7fffffff)
	require.Equal(t, 0, pc)

	dState.PCOffset = []PCOffset{}
	pc = dState.LineToPC(1)
	require.Equal(t, 0, pc)

	dState.PCOffset = []PCOffset{{PC: 1, Offset: 0}}
	pc = dState.LineToPC(1)
	require.Equal(t, 0, pc)
}

func TestValueDeltaToValueDelta(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	vDelta := basics.ValueDelta{
		Action: basics.SetUintAction,
		Bytes:  "some string",
		Uint:   uint64(0xffffffff),
	}
	ans := valueDeltaToValueDelta(&vDelta)
	require.Equal(t, vDelta.Action, ans.Action)
	require.NotEqual(t, vDelta.Bytes, ans.Bytes)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte(vDelta.Bytes)), ans.Bytes)
	require.Equal(t, vDelta.Uint, ans.Uint)
}

var testCallStackProgram string = `intcblock 1
callsub label1
intc_0
label1:
callsub label2
label2:
intc_0
`

func TestParseCallstack(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	expectedCallFrames := []CallFrame{
		{
			FrameLine: 1,
			LabelName: "label1",
		},
		{
			FrameLine: 4,
			LabelName: "label2",
		},
	}

	dState := DebugState{
		Disassembly: testCallStackProgram,
		PCOffset:    []PCOffset{{PC: 1, Offset: 18}, {PC: 4, Offset: 30}, {PC: 7, Offset: 45}, {PC: 8, Offset: 65}, {PC: 11, Offset: 88}},
	}
	callstack := []int{4, 8}

	cfs := dState.parseCallstack(callstack)
	require.Equal(t, expectedCallFrames, cfs)
}

func TestCallStackUpdate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	expectedCallFrames := []CallFrame{
		{
			FrameLine: 2,
			LabelName: "label1",
		},
		{
			FrameLine: 5,
			LabelName: "label2",
		},
	}

	testDbg := testDbgHook{}
	ep := defaultEvalParams(nil)
	ep.Debugger = &testDbg
	testLogic(t, testCallStackProgram, AssemblerMaxVersion, ep)

	require.Equal(t, 1, testDbg.beforeAppEvalCalls)
	require.Equal(t, 1, testDbg.afterAppEvalCalls)
	require.Greater(t, testDbg.beforeTealOpCalls, 1)
	require.Len(t, testDbg.state.Stack, 1)
	require.Equal(t, testDbg.state.CallStack, expectedCallFrames)
}
