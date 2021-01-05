// Copyright (C) 2019-2021 Algorand, Inc.
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
==
&&
&&
`

func TestWebDebuggerManual(t *testing.T) {
	debugURL := os.Getenv("TEAL_DEBUGGER_URL")
	if len(debugURL) == 0 {
		return
	}

	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	txn.Lsig.Args = [][]byte{
		txn.Txn.Sender[:],
		txn.Txn.Receiver[:],
		txn.Txn.CloseRemainderTo[:],
		txn.Txn.VotePK[:],
		txn.Txn.SelectionPK[:],
		txn.Txn.Note,
	}

	ops, err := AssembleString(testProgram)
	require.NoError(t, err)
	ep := defaultEvalParams(nil, &txn)
	ep.TxnGroup = txgroup
	ep.Debugger = &WebDebuggerHook{URL: debugURL}
	_, err = Eval(ops.Program, ep)
	require.NoError(t, err)
}

type testDbgHook struct {
	register int
	update   int
	complete int
	state    *DebugState
}

func (d *testDbgHook) Register(state *DebugState) error {
	d.register++
	d.state = state
	return nil
}

func (d *testDbgHook) Update(state *DebugState) error {
	d.update++
	d.state = state
	return nil
}

func (d *testDbgHook) Complete(state *DebugState) error {
	d.complete++
	d.state = state
	return nil
}

func TestDebuggerHook(t *testing.T) {
	testDbg := testDbgHook{}
	ops, err := AssembleString(testProgram)
	require.NoError(t, err)
	ep := defaultEvalParams(nil, nil)
	ep.Debugger = &testDbg
	_, err = Eval(ops.Program, ep)
	require.NoError(t, err)

	require.Equal(t, 1, testDbg.register)
	require.Equal(t, 1, testDbg.complete)
	require.Greater(t, testDbg.update, 1)
	require.Equal(t, 1, len(testDbg.state.Stack))
}

func TestLineToPC(t *testing.T) {
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
