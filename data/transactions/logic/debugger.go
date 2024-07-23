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
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// Debugger is an interface that supports the first version of AVM debuggers.
// It consists of a set of functions called by eval function during AVM program execution.
//
// Deprecated: This interface does not support non-app call or inner transactions. Use EvalTracer
// instead.
type Debugger interface {
	// Register is fired on program creation
	Register(state *DebugState)
	// Update is fired on every step
	Update(state *DebugState)
	// Complete is called when the program exits
	Complete(state *DebugState)
}

type debuggerEvalTracerAdaptor struct {
	NullEvalTracer

	debugger   Debugger
	txnDepth   int
	debugState *DebugState
}

// MakeEvalTracerDebuggerAdaptor creates an adaptor that externally adheres to the EvalTracer
// interface, but drives a Debugger interface
//
// Warning: The output EvalTracer is specifically designed to be invoked under the exact same
// circumstances that the previous Debugger interface was invoked. This means that it will only work
// properly if you attach it directly to a logic.EvalParams and execute a program. If you attempt to
// run this EvalTracer under a different entry point (such as by attaching it to a BlockEvaluator),
// it WILL NOT work properly.
func MakeEvalTracerDebuggerAdaptor(debugger Debugger) EvalTracer {
	return &debuggerEvalTracerAdaptor{debugger: debugger}
}

// BeforeTxnGroup updates inner txn depth
func (a *debuggerEvalTracerAdaptor) BeforeTxnGroup(ep *EvalParams) {
	a.txnDepth++
}

// AfterTxnGroup updates inner txn depth
func (a *debuggerEvalTracerAdaptor) AfterTxnGroup(ep *EvalParams, deltas *ledgercore.StateDelta, evalError error) {
	a.txnDepth--
}

// BeforeProgram invokes the debugger's Register hook
func (a *debuggerEvalTracerAdaptor) BeforeProgram(cx *EvalContext) {
	if a.txnDepth > 0 {
		// only report updates for top-level transactions, for backwards compatibility
		return
	}
	a.debugState = makeDebugState(cx)
	a.debugger.Register(a.refreshDebugState(cx, nil))
}

// BeforeOpcode invokes the debugger's Update hook
func (a *debuggerEvalTracerAdaptor) BeforeOpcode(cx *EvalContext) {
	if a.txnDepth > 0 {
		// only report updates for top-level transactions, for backwards compatibility
		return
	}
	a.debugger.Update(a.refreshDebugState(cx, nil))
}

// AfterProgram invokes the debugger's Complete hook
func (a *debuggerEvalTracerAdaptor) AfterProgram(cx *EvalContext, pass bool, evalError error) {
	if a.txnDepth > 0 {
		// only report updates for top-level transactions, for backwards compatibility
		return
	}
	a.debugger.Complete(a.refreshDebugState(cx, evalError))
}

// WebDebugger represents a connection to tealdbg
type WebDebugger struct {
	URL string
}

// PCOffset stores the mapping from a program counter value to an offset in the
// disassembly of the bytecode
type PCOffset struct {
	PC     int `codec:"pc"`
	Offset int `codec:"offset"`
}

// CallFrame stores the label name and the line of the subroutine.
// An array of CallFrames form the CallStack.
type CallFrame struct {
	FrameLine int    `codec:"frameLine"`
	LabelName string `codec:"labelname"`
}

// DebugState is a representation of the evaluation context that we encode
// to json and send to tealdbg
type DebugState struct {
	// fields set once on Register
	ExecID      string                         `codec:"execid"`
	Disassembly string                         `codec:"disasm"`
	PCOffset    []PCOffset                     `codec:"pctooffset"`
	TxnGroup    []transactions.SignedTxnWithAD `codec:"txngroup"`
	GroupIndex  int                            `codec:"gindex"`
	Proto       *config.ConsensusParams        `codec:"proto"`
	Globals     []basics.TealValue             `codec:"globals"`

	// fields updated every step
	PC           int                `codec:"pc"`
	Line         int                `codec:"line"`
	Stack        []basics.TealValue `codec:"stack"`
	Scratch      []basics.TealValue `codec:"scratch"`
	Error        string             `codec:"error"`
	OpcodeBudget int                `codec:"budget"`
	CallStack    []CallFrame        `codec:"callstack"`

	// global/local state changes are updated every step. Stateful TEAL only.
	transactions.EvalDelta
}

// GetProgramID returns program or execution ID that is string representation of sha256 checksum.
// It is used later to link program on the user-facing side of the debugger with TEAL evaluator.
func GetProgramID(program []byte) string {
	hash := sha256.Sum256([]byte(program))
	return hex.EncodeToString(hash[:])
}

func makeDebugState(cx *EvalContext) *DebugState {
	disasm, dsInfo, err := disassembleInstrumented(cx.program, nil)
	if err != nil {
		// Report disassembly error as program text
		disasm = err.Error()
	}

	// initialize DebuggerState with immutable fields
	ds := &DebugState{
		ExecID:      GetProgramID(cx.program),
		Disassembly: disasm,
		PCOffset:    dsInfo.pcOffset,
		GroupIndex:  int(cx.groupIndex),
		TxnGroup:    cx.TxnGroup,
		Proto:       cx.Proto,
	}

	globals := make([]basics.TealValue, len(globalFieldSpecs))
	for _, fs := range globalFieldSpecs {
		// Don't try to grab app only fields when evaluating a signature
		if cx.runMode == ModeSig && fs.mode == ModeApp {
			continue
		}
		sv, err := cx.globalFieldToValue(fs)
		if err != nil {
			sv = stackValue{Bytes: []byte(err.Error())}
		}
		globals[fs.field] = sv.toEncodedTealValue()
	}
	ds.Globals = globals

	if cx.runMode == ModeApp {
		ds.EvalDelta = cx.txn.EvalDelta
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

// toEncodedTealValue converts stackValue to basics.TealValue, with the Bytes
// field b64 encoded, so it is suitable for conversion to JSON.
func (sv stackValue) toEncodedTealValue() basics.TealValue {
	if sv.avmType() == avmBytes {
		return basics.TealValue{Type: basics.TealBytesType, Bytes: base64.StdEncoding.EncodeToString(sv.Bytes)}
	}
	return basics.TealValue{Type: basics.TealUintType, Uint: sv.Uint}
}

// parseCallStack initializes an array of CallFrame objects from the raw
// callstack.
func (d *DebugState) parseCallstack(callstack []frame) []CallFrame {
	callFrames := make([]CallFrame, 0)
	lines := strings.Split(d.Disassembly, "\n")
	for _, fr := range callstack {
		// The callsub is pc - 3 from the callstack pc
		callsubLineNum := d.PCToLine(fr.retpc - 3)
		callSubLine := strings.Fields(lines[callsubLineNum])
		label := ""
		if callSubLine[0] == "callsub" {
			label = callSubLine[1]
		}
		callFrames = append(callFrames, CallFrame{
			FrameLine: callsubLineNum,
			LabelName: label,
		})
	}
	return callFrames
}

func (a *debuggerEvalTracerAdaptor) refreshDebugState(cx *EvalContext, evalError error) *DebugState {
	ds := a.debugState

	// Update pc, line, error, stack, scratch space, callstack,
	// and opcode budget
	ds.PC = cx.pc
	ds.Line = ds.PCToLine(cx.pc)
	if evalError != nil {
		ds.Error = evalError.Error()
	}

	stack := make([]basics.TealValue, len(cx.Stack))
	for i, sv := range cx.Stack {
		stack[i] = sv.toEncodedTealValue()
	}

	scratch := make([]basics.TealValue, len(cx.Scratch))
	for i, sv := range cx.Scratch {
		scratch[i] = sv.toEncodedTealValue()
	}

	ds.Stack = stack
	ds.Scratch = scratch
	ds.OpcodeBudget = cx.remainingBudget()
	ds.CallStack = ds.parseCallstack(cx.callstack)

	if cx.runMode == ModeApp {
		ds.EvalDelta = cx.txn.EvalDelta
	}

	return ds
}

func (dbg *WebDebugger) postState(state *DebugState, endpoint string) error {
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
func (dbg *WebDebugger) Register(state *DebugState) {
	u, err := url.Parse(dbg.URL)
	if err != nil {
		logging.Base().Errorf("Failed to parse url: %s", err.Error())
	}
	h := u.Hostname()
	// check for 127.0.0/8 ?
	if h != "localhost" && h != "127.0.0.1" && h != "::1" {
		logging.Base().Warnf("Unsecured communication with non-local debugger: %s", h)
	}
	err = dbg.postState(state, "exec/register")
	if err != nil {
		logging.Base().Errorf("Failed to post state to exec/register: %s", err.Error())
	}
}

// Update sends state to remote debugger
func (dbg *WebDebugger) Update(state *DebugState) {
	err := dbg.postState(state, "exec/update")
	if err != nil {
		logging.Base().Errorf("Failed to post state to exec/update: %s", err.Error())
	}
}

// Complete sends state to remote debugger
func (dbg *WebDebugger) Complete(state *DebugState) {
	err := dbg.postState(state, "exec/complete")
	if err != nil {
		logging.Base().Errorf("Failed to post state to exec/complete: %s", err.Error())
	}
}
