// Copyright (C) 2019-2024 Algorand, Inc.
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

package logic_test

import (
	"os"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	. "github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/logic/mocktracer"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

const debuggerTestProgramApprove string = `intcblock 0 1 1 1 1 5 100
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
const debuggerTestProgramReject string = debuggerTestProgramApprove + "!"
const debuggerTestProgramError string = debuggerTestProgramApprove + "err"
const debuggerTestProgramPanic string = debuggerTestProgramApprove + "panic"

func TestWebDebuggerManual(t *testing.T) { //nolint:paralleltest // Manual test
	partitiontest.PartitionTest(t)

	debugURL := os.Getenv("TEAL_DEBUGGER_URL")
	if len(debugURL) == 0 {
		t.Skip("this must be run manually")
	}

	ep, tx, _ := MakeSampleEnv()
	ep.TxnGroup[0].Lsig.Args = [][]byte{
		tx.Sender[:],
		tx.Receiver[:],
		tx.CloseRemainderTo[:],
		tx.VotePK[:],
		tx.SelectionPK[:],
		tx.Note,
	}
	ep.Tracer = MakeEvalTracerDebuggerAdaptor(&WebDebugger{URL: debugURL})
	TestLogic(t, debuggerTestProgramApprove, AssemblerMaxVersion, ep)
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

var debuggerTestCases = []struct {
	name             string
	program          string
	evalProblems     []string
	expectedRegister int
	expectedUpdate   int
	expectedComplete int
	expectedStack    []basics.TealValue
}{
	{
		name:             "approve",
		program:          debuggerTestProgramApprove,
		expectedRegister: 1,
		expectedUpdate:   35,
		expectedComplete: 1,
		expectedStack: []basics.TealValue{
			{
				Type: basics.TealUintType,
				Uint: 1,
			},
		},
	},
	{
		name:             "reject",
		program:          debuggerTestProgramReject,
		evalProblems:     []string{"REJECT"},
		expectedRegister: 1,
		expectedUpdate:   36,
		expectedComplete: 1,
		expectedStack: []basics.TealValue{
			{
				Type: basics.TealUintType,
				Uint: 0,
			},
		},
	},
	{
		name:             "error",
		program:          debuggerTestProgramError,
		evalProblems:     []string{"err opcode executed"},
		expectedRegister: 1,
		expectedUpdate:   36,
		expectedComplete: 1,
		expectedStack: []basics.TealValue{
			{
				Type: basics.TealUintType,
				Uint: 1,
			},
		},
	},
}

func TestDebuggerLogicSigEval(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	for _, testCase := range debuggerTestCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			testDbg := testDebugger{}
			ep := DefaultSigParams()
			ep.Tracer = MakeEvalTracerDebuggerAdaptor(&testDbg)
			TestLogic(t, testCase.program, AssemblerMaxVersion, ep, testCase.evalProblems...)

			require.Equal(t, testCase.expectedRegister, testDbg.register)
			require.Equal(t, testCase.expectedComplete, testDbg.complete)
			require.Equal(t, testCase.expectedUpdate, testDbg.update)
			require.Equal(t, testCase.expectedStack, testDbg.state.Stack)
		})
	}
}

func TestDebuggerTopLeveLAppEval(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	for _, testCase := range debuggerTestCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			testDbg := testDebugger{}
			ep := DefaultAppParams()
			ep.Tracer = MakeEvalTracerDebuggerAdaptor(&testDbg)
			TestApp(t, testCase.program, ep, testCase.evalProblems...)

			require.Equal(t, testCase.expectedRegister, testDbg.register)
			require.Equal(t, testCase.expectedComplete, testDbg.complete)
			require.Equal(t, testCase.expectedUpdate, testDbg.update)
			require.Equal(t, testCase.expectedStack, testDbg.state.Stack)
		})
	}
}

func TestDebuggerInnerAppEval(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	scenarios := mocktracer.GetTestScenarios()
	for scenarioName, makeScenario := range scenarios {
		scenarioName := scenarioName
		makeScenario := makeScenario
		t.Run(scenarioName, func(t *testing.T) {
			t.Parallel()
			testDbg := testDebugger{}
			ep, tx, ledger := MakeSampleEnv()

			// Establish 888 as the app id, and fund it.
			ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
			ledger.NewAccount(basics.AppIndex(888).Address(), 200_000)

			scenario := makeScenario(mocktracer.TestScenarioInfo{
				CallingTxn:   *tx,
				CreatedAppID: basics.AppIndex(888),
			})

			var evalProblems []string
			switch scenario.Outcome {
			case mocktracer.RejectionOutcome:
				evalProblems = []string{"REJECT"}
			case mocktracer.ErrorOutcome:
				if scenario.ExpectedError == "overspend" {
					// the logic test ledger uses this error instead
					evalProblems = []string{"insufficient balance"}
				} else {
					evalProblems = []string{scenario.ExpectedError}
				}
			}

			ep.Tracer = MakeEvalTracerDebuggerAdaptor(&testDbg)
			ops := TestProg(t, scenario.Program, AssemblerNoVersion)
			TestAppBytes(t, ops.Program, ep, evalProblems...)

			require.Equal(t, 1, testDbg.register)
			require.Equal(t, 1, testDbg.complete)

			var expectedUpdateCount int
			expectedStack := []basics.TealValue{}
			switch {
			case scenarioName == "none":
				expectedUpdateCount = 32
				expectedStack = []basics.TealValue{{Type: basics.TealUintType, Uint: 1}}
			case strings.HasPrefix(scenarioName, "before inners"):
				expectedUpdateCount = 4
				expectedStack = []basics.TealValue{{Type: basics.TealUintType}}
			case strings.HasPrefix(scenarioName, "first inner"):
				expectedUpdateCount = 12
			case strings.HasPrefix(scenarioName, "between inners"):
				expectedUpdateCount = 16
				expectedStack = []basics.TealValue{{Type: basics.TealUintType}}
			case scenarioName == "second inner":
				expectedUpdateCount = 29
			case scenarioName == "third inner":
				expectedUpdateCount = 29
			case strings.HasPrefix(scenarioName, "after inners"):
				expectedUpdateCount = 32
				if scenario.Outcome == mocktracer.RejectionOutcome {
					expectedStack = []basics.TealValue{{Type: basics.TealUintType}}
				}
			}

			require.Equal(t, expectedUpdateCount, testDbg.update)
			require.Equal(t, expectedStack, testDbg.state.Stack)
		})
	}
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
	ep := DefaultSigParams()
	ep.Tracer = MakeEvalTracerDebuggerAdaptor(&testDbg)
	TestLogic(t, TestCallStackProgram, AssemblerMaxVersion, ep)

	require.Equal(t, 1, testDbg.register)
	require.Equal(t, 1, testDbg.complete)
	require.Greater(t, testDbg.update, 1)
	require.Len(t, testDbg.state.Stack, 1)
	require.Equal(t, testDbg.state.CallStack, expectedCallFrames)
}
