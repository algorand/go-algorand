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

	"github.com/satori/go.uuid"
)

// Debugger represents a connection to tealdbg
type Debugger struct {
	URL string
}

// PCOffset stores the mapping from a program counter value to an offset in the
// disassembly of the bytecode
type PCOffset struct {
	PC     int `json:"pc"`
	Offset int `json:"offset"`
}

// DebuggerState is a representation of the evaluation context that we encode
// to json and send to tealdbg
type DebuggerState struct {
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

func (cx *evalContext) debugState() *DebuggerState {
	ds := &cx.debuggerState

	// Generate unique execution ID if necessary
	if ds.ExecID == "" {
		ds.ExecID = uuid.NewV4().String()
	}

	if ds.Disassembly == "" {
		// Disassemble if necessary
		disasm, pcOffset, err := DisassembleInstrumented(cx.program)
		if err != nil {
			// Report disassembly error as program text
			disasm = err.Error()
		}

		ds.Disassembly = disasm
		ds.PCOffset = pcOffset
	}

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
	ds.GroupIndex = cx.GroupIndex
	ds.TxnGroup = cx.TxnGroup
	ds.Proto = cx.Proto

	return ds
}

func (dbg *Debugger) postState(cx *evalContext, endpoint string) error {
	state := cx.debugState()
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

func (dbg *Debugger) register(cx *evalContext) error {
	return dbg.postState(cx, "exec/register")
}

func (dbg *Debugger) update(cx *evalContext) error {
	return dbg.postState(cx, "exec/update")
}

func (dbg *Debugger) complete(cx *evalContext) error {
	return dbg.postState(cx, "exec/complete")
}
