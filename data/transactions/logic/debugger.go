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
	PC          int                      `json:"pc"`
	Stack       []v1.TealValue           `json:"stack"`
	Scratch     []v1.TealValue           `json:"scratch"`
	Disassembly string                   `json:"disasm"`
	PCOffset    []PCOffset               `json:"pctooffset"`
	ExecID      string                   `json:"execid"`
	Error       string                   `json:"error"`
	TxnGroup    []transactions.SignedTxn `json:"txngroup"`
	GroupIndex  int                      `json:"gindex"`
	Proto       *config.ConsensusParams  `json:"proto"`
}

func (cx *evalContext) refreshDebugState() *DebugState {
	ds := &cx.debugState

	// Update PC, error, stack, and scratch space
	ds.PC = cx.pc
	if cx.err != nil {
		ds.Error = cx.err.Error()
	}

	stack := make([]v1.TealValue, len(cx.stack), len(cx.stack))
	for i, sv := range cx.stack {
		tv := sv.toTealValue()
		stack[i] = v1.TealValue{
			Type:  tv.Type.String(),
			Bytes: base64.StdEncoding.EncodeToString([]byte(tv.Bytes)),
			Uint:  tv.Uint,
		}
	}

	scratch := make([]v1.TealValue, len(cx.scratch), len(cx.scratch))
	for i, sv := range cx.scratch {
		tv := sv.toTealValue()
		scratch[i] = v1.TealValue{
			Type:  tv.Type.String(),
			Bytes: base64.StdEncoding.EncodeToString([]byte(tv.Bytes)),
			Uint:  tv.Uint,
		}
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
