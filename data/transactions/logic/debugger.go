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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// DebuggerHook functions are called by eval function during TEAL program execution
// if provided
type DebuggerHook interface {
	// Register is fired on program creation
	Register(state *DebugState) error
	// Update is fired on every step
	Update(state *DebugState) error
	// Complete is called when the program exits
	Complete(state *DebugState) error
}

// WebDebuggerHook represents a connection to tealdbg
type WebDebuggerHook struct {
	URL string
}

// PCOffset stores the mapping from a program counter value to an offset in the
// disassembly of the bytecode
type PCOffset struct {
	PC     int `codec:"pc"`
	Offset int `codec:"offset"`
}

// DebugState is a representation of the evaluation context that we encode
// to json and send to tealdbg
type DebugState struct {
	// fields set once on Register
	ExecID      string                   `codec:"execid"`
	Disassembly string                   `codec:"disasm"`
	PCOffset    []PCOffset               `codec:"pctooffset"`
	TxnGroup    []transactions.SignedTxn `codec:"txngroup"`
	GroupIndex  int                      `codec:"gindex"`
	Proto       *config.ConsensusParams  `codec:"proto"`
	Globals     []basics.TealValue       `codec:"globals"`

	// fields updated every step
	PC      int                `codec:"pc"`
	Line    int                `codec:"line"`
	Stack   []basics.TealValue `codec:"stack"`
	Scratch []basics.TealValue `codec:"scratch"`
	Error   string             `codec:"error"`

	// global/local state changes are updated every step. Stateful TEAL only.
	basics.EvalDelta
}

// GetProgramID returns program or execution ID that is string representation of sha256 checksum.
// It is used later to link program on the user-facing side of the debugger with TEAL evaluator.
func GetProgramID(program []byte) string {
	hash := sha256.Sum256([]byte(program))
	return hex.EncodeToString(hash[:])
}

func makeDebugState(cx *EvalContext) DebugState {
	disasm, dsInfo, err := disassembleInstrumented(cx.program)
	if err != nil {
		// Report disassembly error as program text
		disasm = err.Error()
	}

	// initialize DebuggerState with immutable fields
	ds := DebugState{
		ExecID:      GetProgramID(cx.program),
		Disassembly: disasm,
		PCOffset:    dsInfo.pcOffset,
		GroupIndex:  cx.GroupIndex,
		TxnGroup:    cx.TxnGroup,
		Proto:       cx.Proto,
	}

	globals := make([]basics.TealValue, len(GlobalFieldNames))
	for fieldIdx := range GlobalFieldNames {
		sv, err := cx.globalFieldToStack(GlobalField(fieldIdx))
		if err != nil {
			sv = stackValue{Bytes: []byte(err.Error())}
		}
		globals[fieldIdx] = stackValueToTealValue(&sv)
	}
	ds.Globals = globals

	// pre-allocate state maps
	if (cx.runModeFlags & runModeApplication) != 0 {
		ds.EvalDelta, err = cx.Ledger.GetDelta(&cx.Txn.Txn)
		if err != nil {
			sv := stackValue{Bytes: []byte(err.Error())}
			tv := stackValueToTealValue(&sv)
			vd := tv.ToValueDelta()
			ds.EvalDelta.GlobalDelta = basics.StateDelta{"error": vd}
		}
	}

	return ds
}

// LineToPC converts line to pc
// Return 0 on unsuccess
func (d *DebugState) LineToPC(line int) int {
	if len(d.PCOffset) == 0 || line < 1 {
		return 0
	}

	lines := strings.Split(d.Disassembly, "\n")
	if line > len(lines) {
		return 0
	}
	offset := len(strings.Join(lines[:line], "\n"))

	for i := 0; i < len(d.PCOffset); i++ {
		if d.PCOffset[i].Offset >= offset {
			return d.PCOffset[i].PC
		}
	}
	return 0
}

// PCToLine converts pc to line
// Return 0 on unsuccess
func (d *DebugState) PCToLine(pc int) int {
	if len(d.PCOffset) == 0 {
		return 0
	}

	offset := 0
	for i := 0; i < len(d.PCOffset); i++ {
		if d.PCOffset[i].PC >= pc {
			offset = d.PCOffset[i].Offset
			break
		}
	}

	one := 1
	// handle end of the program
	if offset == 0 {
		offset = d.PCOffset[len(d.PCOffset)-1].Offset
		one = 0
	}
	if offset > len(d.Disassembly) {
		return 0
	}

	return len(strings.Split(d.Disassembly[:offset], "\n")) - one
}

func stackValueToTealValue(sv *stackValue) basics.TealValue {
	tv := sv.toTealValue()
	return basics.TealValue{
		Type:  tv.Type,
		Bytes: base64.StdEncoding.EncodeToString([]byte(tv.Bytes)),
		Uint:  tv.Uint,
	}
}

// valueDeltaToValueDelta converts delta's bytes to base64 in a new struct
func valueDeltaToValueDelta(vd *basics.ValueDelta) basics.ValueDelta {
	return basics.ValueDelta{
		Action: vd.Action,
		Bytes:  base64.StdEncoding.EncodeToString([]byte(vd.Bytes)),
		Uint:   vd.Uint,
	}
}

func (cx *EvalContext) refreshDebugState() *DebugState {
	ds := &cx.debugState

	// Update pc, line, error, stack, and scratch space
	ds.PC = cx.pc
	ds.Line = ds.PCToLine(cx.pc)
	if cx.err != nil {
		ds.Error = cx.err.Error()
	}

	stack := make([]basics.TealValue, len(cx.stack), len(cx.stack))
	for i, sv := range cx.stack {
		stack[i] = stackValueToTealValue(&sv)
	}

	scratch := make([]basics.TealValue, len(cx.scratch), len(cx.scratch))
	for i, sv := range cx.scratch {
		scratch[i] = stackValueToTealValue(&sv)
	}

	ds.Stack = stack
	ds.Scratch = scratch

	if (cx.runModeFlags & runModeApplication) != 0 {
		var err error
		ds.EvalDelta, err = cx.Ledger.GetDelta(&cx.Txn.Txn)
		if err != nil {
			sv := stackValue{Bytes: []byte(err.Error())}
			tv := stackValueToTealValue(&sv)
			vd := tv.ToValueDelta()
			ds.EvalDelta.GlobalDelta = basics.StateDelta{"error": vd}
		}
	}

	return ds
}

func (dbg *WebDebuggerHook) postState(state *DebugState, endpoint string) error {
	var body bytes.Buffer
	enc := protocol.NewJSONEncoder(&body)
	err := enc.Encode(state)
	if err != nil {
		return err
	}

	u, err := url.Parse(dbg.URL)
	if err != nil {
		return err
	}
	u.Path = endpoint

	req, err := http.NewRequest(http.MethodPost, u.String(), &body)
	if err != nil {
		return err
	}

	httpClient := &http.Client{}
	r, err := httpClient.Do(req)
	if err == nil {
		if r.StatusCode != 200 {
			err = fmt.Errorf("bad response: %d", r.StatusCode)
		}
		r.Body.Close()
	}
	return err
}

// Register sends state to remote debugger
func (dbg *WebDebuggerHook) Register(state *DebugState) error {
	u, err := url.Parse(dbg.URL)
	if err != nil {
		logging.Base().Errorf("Failed to parse url: %s", err.Error())
	}
	h := u.Hostname()
	// check for 127.0.0/8 ?
	if h != "localhost" && h != "127.0.0.1" && h != "::1" {
		logging.Base().Warnf("Unsecured communication with non-local debugger: %s", h)
	}
	return dbg.postState(state, "exec/register")
}

// Update sends state to remote debugger
func (dbg *WebDebuggerHook) Update(state *DebugState) error {
	return dbg.postState(state, "exec/update")
}

// Complete sends state to remote debugger
func (dbg *WebDebuggerHook) Complete(state *DebugState) error {
	return dbg.postState(state, "exec/complete")
}
