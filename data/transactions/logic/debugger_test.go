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

package logic

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

const debuggerTestProgram string = `intcblock 0 1 1 1 1 5 100
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

func TestWebDebuggerManual(t *testing.T) { //nolint:paralleltest // Manual test
	partitiontest.PartitionTest(t)

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
	ep.Tracer = MakeEvalTracerDebuggerAdaptor(&WebDebugger{URL: debugURL})
	testLogic(t, debuggerTestProgram, AssemblerMaxVersion, ep)
}

type testDebugger struct {
	register int
	update   int
	complete int
	state    *DebugState
}

func (d *testDebugger) Register(state *DebugState) {
	d.register++
	d.state = state
}

func (d *testDebugger) Update(state *DebugState) {
	d.update++
	d.state = state
}

func (d *testDebugger) Complete(state *DebugState) {
	d.complete++
	d.state = state
}

func TestDebuggerProgramEval(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("logicsig", func(t *testing.T) {
		t.Parallel()
		testDbg := testDebugger{}
		ep := defaultEvalParams()
		ep.Tracer = MakeEvalTracerDebuggerAdaptor(&testDbg)
		testLogic(t, debuggerTestProgram, AssemblerMaxVersion, ep)

		require.Equal(t, 1, testDbg.register)
		require.Equal(t, 1, testDbg.complete)
		require.Equal(t, 35, testDbg.update)
		require.Len(t, testDbg.state.Stack, 1)
	})

	t.Run("simple app", func(t *testing.T) {
		t.Parallel()
		testDbg := testDebugger{}
		ep := defaultEvalParams()
		ep.Tracer = MakeEvalTracerDebuggerAdaptor(&testDbg)
		testApp(t, debuggerTestProgram, ep)

		require.Equal(t, 1, testDbg.register)
		require.Equal(t, 1, testDbg.complete)
		require.Equal(t, 35, testDbg.update)
		require.Len(t, testDbg.state.Stack, 1)
	})

	t.Run("app with inner txns", func(t *testing.T) {
		t.Parallel()
		testDbg := testDebugger{}
		ep, tx, ledger := MakeSampleEnv()

		// Establish 888 as the app id, and fund it.
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(basics.AppIndex(888).Address(), 200000)

		ep.Tracer = MakeEvalTracerDebuggerAdaptor(&testDbg)
		testApp(t, innerTxnTestProgram, ep)

		require.Equal(t, 1, testDbg.register)
		require.Equal(t, 1, testDbg.complete)
		require.Equal(t, 27, testDbg.update)
		require.Len(t, testDbg.state.Stack, 1)
	})
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
	callstack := []frame{{retpc: 4}, {retpc: 8}}

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

	testDbg := testDebugger{}
	ep := defaultEvalParams()
	ep.Tracer = MakeEvalTracerDebuggerAdaptor(&testDbg)
	testLogic(t, testCallStackProgram, AssemblerMaxVersion, ep)

	require.Equal(t, 1, testDbg.register)
	require.Equal(t, 1, testDbg.complete)
	require.Greater(t, testDbg.update, 1)
	require.Len(t, testDbg.state.Stack, 1)
	require.Equal(t, testDbg.state.CallStack, expectedCallFrames)
}
