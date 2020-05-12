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

package logic

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/transactions"
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
	PC     int `json:"pc"`
	Offset int `json:"offset"`
}

// DebugState is a representation of the evaluation context that we encode
// to json and send to tealdbg
type DebugState struct {
	ExecID      string                   `json:"execid"`
	Disassembly string                   `json:"disasm"`
	PCOffset    []PCOffset               `json:"pctooffset"`
	TxnGroup    []transactions.SignedTxn `json:"txngroup"`
	GroupIndex  int                      `json:"gindex"`
	Proto       *config.ConsensusParams  `json:"proto"`
	Globals     []v1.TealValue           `json:"globals"`

	PC      int            `json:"pc"`
	Line    int            `json:"line"`
	Stack   []v1.TealValue `json:"stack"`
	Scratch []v1.TealValue `json:"scratch"`
	Error   string         `json:"error"`
}

// LineToPC converts line to pc
// Return 0 on unsuccess
func (d *DebugState) LineToPC(line int) int {
	if len(d.PCOffset) == 0 || line < 1 {
		return 0
	}

	lines := strings.Split(d.Disassembly, "\n")
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

	return len(strings.Split(d.Disassembly[:offset], "\n")) - one
}

func (cx *evalContext) setDebugStateGlobals() {
	globals := make([]v1.TealValue, len(GlobalFieldNames))
	for fieldIdx := range GlobalFieldNames {
		sv, err := cx.globalFieldToStack(GlobalField(fieldIdx))
		if err != nil {
			sv = stackValue{Bytes: []byte(err.Error())}
		}
		globals[fieldIdx] = stackValueToV1TealValue(&sv)
	}
	cx.debugState.Globals = globals
}

func stackValueToV1TealValue(sv *stackValue) v1.TealValue {
	tv := sv.toTealValue()
	return v1.TealValue{
		Type:  tv.Type.String(),
		Bytes: base64.StdEncoding.EncodeToString([]byte(tv.Bytes)),
		Uint:  tv.Uint,
	}
}

func (cx *evalContext) refreshDebugState() *DebugState {
	ds := &cx.debugState

	// Update pc, line, error, stack, and scratch space
	ds.PC = cx.pc
	ds.Line = ds.PCToLine(cx.pc)
	if cx.err != nil {
		ds.Error = cx.err.Error()
	}

	stack := make([]v1.TealValue, len(cx.stack), len(cx.stack))
	for i, sv := range cx.stack {
		stack[i] = stackValueToV1TealValue(&sv)
	}

	scratch := make([]v1.TealValue, len(cx.scratch), len(cx.scratch))
	for i, sv := range cx.scratch {
		scratch[i] = stackValueToV1TealValue(&sv)
	}

	ds.Stack = stack
	ds.Scratch = scratch

	return ds
}

func (dbg *WebDebuggerHook) postState(state *DebugState, endpoint string) error {
	enc, err := json.Marshal(state)
	if err != nil {
		return err
	}

	body := bytes.NewBuffer(enc)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", dbg.URL, endpoint), body)
	if err != nil {
		return err
	}

	httpClient := &http.Client{}
	_, err = httpClient.Do(req)
	return err
}

// Register sends state to remote debugger
func (dbg *WebDebuggerHook) Register(state *DebugState) error {
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
