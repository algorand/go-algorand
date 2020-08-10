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
	"testing"
	"time"

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
			// simulate user delay to workaround race cond
			time.Sleep(10 * time.Millisecond)
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
