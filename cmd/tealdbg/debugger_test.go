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

package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type testDbgAdapter struct {
	debugger      Control
	notifications chan Notification

	started    bool
	ended      bool
	eventCount int

	done chan struct{}

	t *testing.T
}

func makeTestDbgAdapter(t *testing.T) (d *testDbgAdapter) {
	d = new(testDbgAdapter)
	d.done = make(chan struct{})
	d.t = t
	return d
}

func (d *testDbgAdapter) WaitForCompletion() {
	<-d.done
}

func (d *testDbgAdapter) SessionStarted(_ string, debugger Control, ch chan Notification) {
	d.debugger = debugger
	d.notifications = ch

	go d.eventLoop()

	d.started = true
}

func (d *testDbgAdapter) SessionEnded(_ string) {
	d.ended = true
}

func (d *testDbgAdapter) URL() string {
	return ""
}

func (d *testDbgAdapter) eventLoop() {
	for {
		select {
		case n := <-d.notifications:
			d.eventCount++
			if n.Event == "completed" {
				d.done <- struct{}{}
				return
			}
			if n.Event == "registered" {
				require.NotNil(d.t, n.DebugState.Globals)
				require.NotNil(d.t, n.DebugState.Scratch)
				require.NotEmpty(d.t, n.DebugState.Disassembly)
				require.NotEmpty(d.t, n.DebugState.ExecID)
				err := d.debugger.SetBreakpoint(n.DebugState.Line + 1)
				require.NoError(d.t, err)
			}
			d.debugger.Resume()
		}
	}
}

func TestDebuggerSimple(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto := config.Consensus[protocol.ConsensusV18]
	require.Greater(t, proto.LogicSigVersion, uint64(0))
	debugger := MakeDebugger()

	da := makeTestDbgAdapter(t)
	debugger.AddAdapter(da)

	ops, err := logic.AssembleStringWithVersion("int 0; int 1; +", 1)
	require.NoError(t, err)
	txn := transactions.SignedTxn{}
	txn.Lsig.Logic = ops.Program

	ep := logic.NewSigEvalParams([]transactions.SignedTxn{txn}, &proto, logic.NoHeaderLedger{})
	ep.Tracer = logic.MakeEvalTracerDebuggerAdaptor(debugger)

	_, err = logic.EvalSignature(0, ep)
	require.NoError(t, err)

	da.WaitForCompletion()

	require.True(t, da.started)
	require.True(t, da.ended)
	require.Equal(t, 3, da.eventCount) // register, update, complete
}

func createSessionFromSource(t *testing.T, program string) *session {
	source := fmt.Sprintf(program, logic.LogicVersion)
	ops, err := logic.AssembleStringWithVersion(source, logic.LogicVersion)
	require.NoError(t, err)
	disassembly, err := logic.Disassemble(ops.Program)
	require.NoError(t, err)

	// create a sample disassembly line to pc mapping
	// this simple source is similar to disassembly except intcblock at the beginning
	pcOffset := make(map[int]int, len(ops.OffsetToSource))
	for pc, location := range ops.OffsetToSource {
		pcOffset[location.Line+1] = pc
	}

	s := makeSession(disassembly, 0)
	s.source = source
	s.programName = "test"
	s.offsetToSource = ops.OffsetToSource
	s.pcOffset = pcOffset

	return s
}

func TestSession(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	s := createSessionFromSource(t, "#pragma version %d\nint 1\ndup\n+\n")
	err := s.SetBreakpoint(2)
	require.NoError(t, err)

	ackCount := 0
	done := make(chan struct{})
	ackFunc := func() {
		<-s.acknowledged
		ackCount++
		done <- struct{}{}
	}
	go ackFunc()

	s.Resume()
	<-done
	require.Equal(t, map[int]struct{}{2: {}}, s.debugConfig.ActiveBreak)
	require.Equal(t, breakpoint{true, true}, s.breakpoints[2])
	require.Equal(t, true, s.debugConfig.isBreak(2, len(s.callStack)))
	require.Equal(t, 1, ackCount)

	s.SetBreakpointsActive(false)
	require.Equal(t, breakpoint{true, false}, s.breakpoints[2])

	s.SetBreakpointsActive(true)
	require.Equal(t, breakpoint{true, true}, s.breakpoints[2])

	err = s.RemoveBreakpoint(2)
	require.NoError(t, err)
	require.Equal(t, breakpoint{false, false}, s.breakpoints[2])

	go ackFunc()

	s.Step()
	<-done

	require.Equal(t, true, s.debugConfig.StepBreak)
	require.Equal(t, 2, ackCount)

	data, err := s.GetSourceMap()
	require.NoError(t, err)
	require.Greater(t, len(data), 0)

	name, data := s.GetSource()
	require.NotEmpty(t, name)
	require.Greater(t, len(data), 0)
}

// Tests control functions for stepping over subroutines and checks
// that call stack is inspected correctly.
func TestCallStackControl(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	newTestCase := func() (*session, chan struct{}, func(), *int) {
		s := createSessionFromSource(t, "#pragma version %d\nlab1:\nint 1\ncallsub lab1\ndup\n+\n")

		ackCount := 0
		done := make(chan struct{})
		ackFunc := func() {
			ackCount++
			<-s.acknowledged
			done <- struct{}{}

		}

		return s, done, ackFunc, &ackCount
	}

	cases := map[string]func(*testing.T){
		"Check that step over on callsub line returns correct callstack depth": func(t *testing.T) {
			s, done, ackFunc, ackCount := newTestCase()
			s.setCallStack([]logic.CallFrame{{FrameLine: 2, LabelName: "lab1"}})
			initialStackDepth := len(s.callStack)
			s.line.Store(3)

			go ackFunc()
			s.StepOver()
			<-done

			require.Equal(t, map[int]struct{}{4: {}}, s.debugConfig.ActiveBreak)
			require.Equal(t, breakpoint{true, true}, s.breakpoints[4])

			require.Equal(t, false, s.debugConfig.NoBreak)
			require.Equal(t, false, s.debugConfig.StepBreak)
			require.Equal(t, true, s.debugConfig.StepOutOver)

			require.Equal(t, 1, *ackCount)
			require.Equal(t, initialStackDepth, len(s.callStack))
		},
		"Breakpoint should not trigger at the wrong call stack height": func(t *testing.T) {
			s, done, ackFunc, ackCount := newTestCase()

			s.setCallStack([]logic.CallFrame{{FrameLine: 2, LabelName: "lab1"}})
			s.line.Store(3)

			go ackFunc()
			s.StepOver()
			<-done

			s.setCallStack([]logic.CallFrame{
				{FrameLine: 2, LabelName: "lab1"},
				{FrameLine: 2, LabelName: "lab1"},
			})
			require.Equal(t, false, s.debugConfig.isBreak(4, len(s.callStack)))

			s.setCallStack([]logic.CallFrame{
				{FrameLine: 2, LabelName: "lab1"},
			})
			require.Equal(t, true, s.debugConfig.isBreak(4, len(s.callStack)))
			require.Equal(t, 1, *ackCount)
		},
		"Check step over on a non callsub line breaks at next line": func(t *testing.T) {
			s, done, ackFunc, ackCount := newTestCase()

			s.line.Store(4)

			go ackFunc()
			s.StepOver()
			<-done

			require.Equal(t, false, s.debugConfig.NoBreak)
			require.Equal(t, true, s.debugConfig.StepBreak)
			require.Equal(t, false, s.debugConfig.StepOutOver)

			require.Equal(t, 1, *ackCount)
			require.Equal(t, 0, len(s.callStack))
		},
		"Check that step out when call stack depth is 1 sets breakpoint to the line after frame": func(t *testing.T) {
			s, done, ackFunc, ackCount := newTestCase()

			s.setCallStack([]logic.CallFrame{{FrameLine: 2, LabelName: "lab1"}})
			s.line.Store(4)

			go ackFunc()
			s.StepOut()
			<-done

			require.Equal(t, map[int]struct{}{3: {}}, s.debugConfig.ActiveBreak)
			require.Equal(t, breakpoint{true, true}, s.breakpoints[3])
			require.Equal(t, true, s.debugConfig.isBreak(3, len(s.callStack)-1))

			require.Equal(t, false, s.debugConfig.NoBreak)
			require.Equal(t, false, s.debugConfig.StepBreak)
			require.Equal(t, true, s.debugConfig.StepOutOver)

			require.Equal(t, 1, *ackCount)
			require.Equal(t, 1, len(s.callStack))
		},
		"Check that step out when call stack depth is 0 sets NoBreak to true": func(t *testing.T) {
			s, done, ackFunc, ackCount := newTestCase()

			s.setCallStack(nil)
			s.line.Store(3)

			go ackFunc()
			s.StepOut()
			<-done

			require.Equal(t, true, s.debugConfig.NoBreak)
			require.Equal(t, false, s.debugConfig.StepBreak)
			require.Equal(t, false, s.debugConfig.StepOutOver)

			require.Equal(t, 1, *ackCount)
			require.Equal(t, 0, len(s.callStack))
		},
		"Check that resume keeps track of every breakpoint": func(t *testing.T) {
			s, done, ackFunc, ackCount := newTestCase()

			s.line.Store(3)
			err := s.RemoveBreakpoint(3)
			require.NoError(t, err)
			require.Equal(t, breakpoint{false, false}, s.breakpoints[2])
			err = s.SetBreakpoint(2)
			require.NoError(t, err)
			err = s.SetBreakpoint(4)
			require.NoError(t, err)

			go ackFunc()
			s.Resume()
			<-done

			require.Equal(t, map[int]struct{}{2: {}, 4: {}}, s.debugConfig.ActiveBreak)
			require.Equal(t, breakpoint{true, true}, s.breakpoints[2])
			require.Equal(t, breakpoint{true, true}, s.breakpoints[4])
			require.Equal(t, true, s.debugConfig.isBreak(2, len(s.callStack)))
			require.Equal(t, false, s.debugConfig.isBreak(3, len(s.callStack)))
			require.Equal(t, true, s.debugConfig.isBreak(4, len(s.callStack)))

			require.Equal(t, false, s.debugConfig.NoBreak)
			require.Equal(t, false, s.debugConfig.StepBreak)
			require.Equal(t, false, s.debugConfig.StepOutOver)

			require.Equal(t, 1, *ackCount)
			require.Equal(t, 0, len(s.callStack))
		},
	}

	// nolint:paralleltest // Linter is not following formulation of subtests.
	for name, f := range cases {
		t.Run(name, f)
	}
}

func TestSourceMaps(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	s := createSessionFromSource(t, "#pragma version %d\nint 1\n")

	// Source and source map checks
	data, err := s.GetSourceMap()
	require.NoError(t, err)
	require.Greater(t, len(data), 0)

	name, data := s.GetSource()
	require.NotEmpty(t, name)
	require.Greater(t, len(data), 0)
}
