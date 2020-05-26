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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/algorand/go-algorand/config"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
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
	// fields set once on Register
	ExecID      string                   `json:"execid"`
	Disassembly string                   `json:"disasm"`
	PCOffset    []PCOffset               `json:"pctooffset"`
	TxnGroup    []transactions.SignedTxn `json:"txngroup"`
	GroupIndex  int                      `json:"gindex"`
	Proto       *config.ConsensusParams  `json:"proto"`
	Globals     []v2.TealValue           `json:"globals"`

	// fields updated every step
	PC      int            `json:"pc"`
	Line    int            `json:"line"`
	Stack   []v2.TealValue `json:"stack"`
	Scratch []v2.TealValue `json:"scratch"`
	Error   string         `json:"error"`

	// global/local state changes are updated every step. Stateful TEAL only.
	AppStateChage
}

// AppStateChage encapsulates global and local app state changes
type AppStateChage struct {
	GlobalStateChanges basics.StateDelta                    `json:"gsch"`
	LocalStateChanges  map[basics.Address]basics.StateDelta `json:"lsch"`
}

func makeDebugState(cx *evalContext) DebugState {
	disasm, dsInfo, err := disassembleInstrumented(cx.program)
	if err != nil {
		// Report disassembly error as program text
		disasm = err.Error()
	}

	hash := sha256.Sum256(cx.program)
	// initialize DebuggerState with immutable fields
	ds := DebugState{
		ExecID:      hex.EncodeToString(hash[:]),
		Disassembly: disasm,
		PCOffset:    dsInfo.pcOffset,
		GroupIndex:  cx.GroupIndex,
		TxnGroup:    cx.TxnGroup,
		Proto:       cx.Proto,
	}

	globals := make([]v2.TealValue, len(GlobalFieldNames))
	for fieldIdx := range GlobalFieldNames {
		sv, err := cx.globalFieldToStack(GlobalField(fieldIdx))
		if err != nil {
			sv = stackValue{Bytes: []byte(err.Error())}
		}
		globals[fieldIdx] = stackValueToV2TealValue(&sv)
	}
	cx.debugState.Globals = globals

	// pre-allocate state maps
	if (cx.runModeFlags & runModeApplication) != 0 {
		ds.GlobalStateChanges = make(basics.StateDelta)

		// allocate maximum possible slots in the hashmap even if Txn.Accounts might have duplicate entries
		locals := 1 + len(cx.Txn.Txn.Accounts) // sender + referenced accounts
		ds.LocalStateChanges = make(map[basics.Address]basics.StateDelta, locals)

		// do not pre-allocate ds.LocalStateChanges[addr] since it initialized during update
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

func stackValueToV2TealValue(sv *stackValue) v2.TealValue {
	tv := sv.toTealValue()
	return v2.TealValue{
		Type:  uint64(tv.Type),
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

	stack := make([]v2.TealValue, len(cx.stack), len(cx.stack))
	for i, sv := range cx.stack {
		stack[i] = stackValueToV2TealValue(&sv)
	}

	scratch := make([]v2.TealValue, len(cx.scratch), len(cx.scratch))
	for i, sv := range cx.scratch {
		scratch[i] = stackValueToV2TealValue(&sv)
	}

	ds.Stack = stack
	ds.Scratch = scratch

	if (cx.runModeFlags & runModeApplication) != 0 {
		if cx.globalStateCow != nil {
			for k, v := range cx.globalStateCow.delta {
				ds.GlobalStateChanges[k] = v
			}
		}
		for addr, cow := range cx.localStateCows {
			delta := make(basics.StateDelta)
			for k, v := range cow.cow.delta {
				delta[k] = v
			}
			ds.LocalStateChanges[addr] = delta
		}
	}

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
