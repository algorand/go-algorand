// Copyright (C) 2019-2020 Algorand, Inc.
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

func (d *testDbgAdapter) SessionStarted(sid string, debugger Control, ch chan Notification) {
	d.debugger = debugger
	d.notifications = ch

	go d.eventLoop()

	d.started = true
}

func (d *testDbgAdapter) SessionEnded(sid string) {
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
				d.debugger.SetBreakpoint(n.DebugState.Line + 1)
			}
			d.debugger.Resume()
		}
	}
}

func TestDebuggerSimple(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusV18]
	require.Greater(t, proto.LogicSigVersion, uint64(0))
	debugger := MakeDebugger()

	da := makeTestDbgAdapter(t)
	debugger.AddAdapter(da)

	ep := logic.EvalParams{
		Proto:    &proto,
		Debugger: debugger,
		Txn:      &transactions.SignedTxn{},
	}

	source := `int 0
int 1
+
`
	program, err := logic.AssembleStringV1(source)
	require.NoError(t, err)

	_, err = logic.Eval(program, ep)
	require.NoError(t, err)

	da.WaitForCompletion()

	require.True(t, da.started)
	require.True(t, da.ended)
	require.Equal(t, 3, da.eventCount) // register, update, complete
}

func TestSession(t *testing.T) {
	source := fmt.Sprintf("#pragma version %d\nint 1\ndup\n+\n", logic.LogicVersion)
	program, offsets, err := logic.AssembleStringWithVersionEx(source, logic.LogicVersion)
	require.NoError(t, err)
	disassembly, err := logic.Disassemble(program)
	require.NoError(t, err)

	// create a sample disassembly line to pc mapping
	// this simple source is similar to disassembly except intcblock at the begining
	pcOffset := make(map[int]int, len(offsets))
	for pc, line := range offsets {
		pcOffset[line+1] = pc
	}

	s := makeSession(disassembly, 0)
	s.source = source
	s.programName = "test"
	s.offsetToLine = offsets
	s.pcOffset = pcOffset
	err = s.SetBreakpoint(2)
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

	require.Equal(t, breakpointLine(2), s.debugConfig.BreakAtLine)
	require.Equal(t, breakpoint{true, true}, s.breakpoints[2])
	require.Equal(t, 1, ackCount)

	s.SetBreakpointsActive(false)
	require.Equal(t, breakpoint{true, false}, s.breakpoints[2])

	s.SetBreakpointsActive(true)
	require.Equal(t, breakpoint{true, true}, s.breakpoints[2])

	s.RemoveBreakpoint(2)
	require.Equal(t, breakpoint{false, false}, s.breakpoints[2])

	go ackFunc()

	s.Step()
	<-done

	require.Equal(t, stepBreak, s.debugConfig.BreakAtLine)
	require.Equal(t, 2, ackCount)

	data, err := s.GetSourceMap()
	require.NoError(t, err)
	require.Greater(t, len(data), 0)

	name, data := s.GetSource()
	require.NotEmpty(t, name)
	require.Greater(t, len(data), 0)
}
