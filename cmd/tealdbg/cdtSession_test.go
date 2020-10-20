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

	"github.com/algorand/go-algorand/cmd/tealdbg/cdt"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

func TestCdtSessionProto11Common(t *testing.T) {
	sid := "test"
	dbg := MockDebugControl{}
	ch := make(chan Notification)
	s := makeCdtSession(sid, &dbg, ch)

	var rid int64 = 1
	req := cdt.ChromeRequest{ID: rid}
	state := cdtState{}
	resp, events, err := s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.Empty(t, resp.Result)

	req.Method = "Runtime.getIsolateId"
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.NotEmpty(t, resp.Result)
	result := resp.Result.(map[string]string)
	require.Contains(t, result, "id")

	req.Method = "Debugger.setPauseOnExceptions"
	req.Params = map[string]interface{}{"state": "enable"}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.Empty(t, resp.Result)
	require.True(t, state.pauseOnError.IsSet())

	req.Method = "Debugger.setPauseOnExceptions"
	req.Params = map[string]interface{}{"state": "none"}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.Empty(t, resp.Result)
	require.False(t, state.pauseOnError.IsSet())

	state.disassembly = "int 1\n"
	req.Method = "Debugger.getScriptSource"
	req.Params = map[string]interface{}{"scriptId": "any"}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.NotEmpty(t, resp.Result)
	result = resp.Result.(map[string]string)
	require.Contains(t, result, "scriptSource")
	require.Equal(t, result["scriptSource"], state.disassembly)

	req.Method = "Debugger.getScriptSource"
	req.Params = map[string]interface{}{}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.Error(t, err)
	require.Equal(t, 0, len(events))
	require.Empty(t, resp.Result)
	require.Empty(t, resp.ID)
}

func TestCdtSessionProto11Breakpoints(t *testing.T) {
	sid := "test"
	dbg := MockDebugControl{}
	ch := make(chan Notification)
	s := makeCdtSession(sid, &dbg, ch)

	var rid int64 = 2
	req := cdt.ChromeRequest{ID: rid}
	state := cdtState{}

	req.Method = "Debugger.setBreakpointsActive"
	req.Params = map[string]interface{}{"active": true}
	resp, events, err := s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.Empty(t, resp.Result)
	require.True(t, dbg.bpActive)

	req.Method = "Debugger.setBreakpointsActive"
	req.Params = map[string]interface{}{"active": "none"}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.Empty(t, resp.Result)
	require.False(t, dbg.bpActive)

	req.Method = "Debugger.removeBreakpoint"
	req.Params = map[string]interface{}{"breakpointId": "1"}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.Empty(t, resp.Result)

	req.Method = "Debugger.removeBreakpoint"
	req.Params = map[string]interface{}{"breakpointId": "test"}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.Error(t, err)
	require.Equal(t, 0, len(events))
	require.Empty(t, resp.ID)
	require.Empty(t, resp.Result)

	req.Method = "Debugger.setBreakpointByUrl"
	req.Params = map[string]interface{}{"lineNumber": 1.}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.NotEmpty(t, resp.Result)
	result := resp.Result.(map[string]interface{})
	require.Contains(t, result, "breakpointId")
	require.Contains(t, result, "locations")
	require.Equal(t, "1", result["breakpointId"].(string))

	req.Method = "Debugger.getPossibleBreakpoints"
	req.Params = map[string]interface{}{
		"start": map[string]interface{}{
			"lineNumber": 1.0,
			"scriptId":   "test",
		},
		"end": map[string]interface{}{
			"lineNumber": 2.0,
		},
	}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.NotEmpty(t, resp.Result)
	result = resp.Result.(map[string]interface{})
	require.Contains(t, result, "locations")
	require.Equal(t, 2, len(result["locations"].([]cdt.DebuggerLocation)))

	req.Method = "Debugger.getPossibleBreakpoints"
	req.Params = map[string]interface{}{}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.Empty(t, resp.Result)
}

func TestCdtSessionProto11Events(t *testing.T) {
	sid := "test"
	dbg := MockDebugControl{}
	ch := make(chan Notification)
	s := makeCdtSession(sid, &dbg, ch)

	var rid int64 = 1
	req := cdt.ChromeRequest{ID: rid}
	state := cdtState{}

	req.Method = "Debugger.enable"
	resp, events, err := s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 2, len(events))
	_, ok := (events[0]).(*cdt.RuntimeExecutionContextCreatedEvent)
	require.True(t, ok)
	_, ok = (events[1]).(*cdt.DebuggerScriptParsedEvent)
	require.True(t, ok)
	require.Equal(t, rid, resp.ID)
	require.NotEmpty(t, resp.Result)
	result := resp.Result.(map[string]string)
	require.Contains(t, result, "debuggerId")

	req.Method = "Runtime.runIfWaitingForDebugger"
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 1, len(events))
	_, ok = (events[0]).(*cdt.DebuggerPausedEvent)
	require.True(t, ok)
	require.Equal(t, rid, resp.ID)
	require.Empty(t, resp.Result)
}

func TestCdtSessionProto11Controls(t *testing.T) {
	sid := "test"
	dbg := MockDebugControl{}
	ch := make(chan Notification)
	s := makeCdtSession(sid, &dbg, ch)

	var rid int64 = 4
	req := cdt.ChromeRequest{ID: rid}
	state := cdtState{}

	methods := []string{"resume", "stepOut", "stepOver", "stepInto"}
	actionsMap := map[string]string{
		"resume":   "resume",
		"stepOut":  "step",
		"stepOver": "step",
		"stepInto": "step",
	}
	for _, method := range methods {
		req.Method = fmt.Sprintf("Debugger.%s", method)
		resp, events, err := s.handleCdtRequest(&req, &state)
		require.NoError(t, err)
		require.Equal(t, 0, len(events))
		require.Equal(t, rid, resp.ID)
		require.Empty(t, resp.Result)
		action := actionsMap[method]
		require.Equal(t, action, state.lastAction.Load())
	}

	state.completed.SetTo(true)
	for _, method := range methods {
		req.Method = fmt.Sprintf("Debugger.%s", method)
		resp, events, err := s.handleCdtRequest(&req, &state)
		require.NoError(t, err)
		require.Equal(t, 1, len(events))
		_, ok := (events[0]).(*cdt.RuntimeExecutionContextDestroyedEvent)
		require.True(t, ok)
		require.Equal(t, rid, resp.ID)
		require.Empty(t, resp.Result)
		action := actionsMap[method]
		require.Equal(t, action, state.lastAction.Load())
	}
}

func TestCdtSessionProto11Evaluate(t *testing.T) {
	sid := "test"
	dbg := MockDebugControl{}
	ch := make(chan Notification)
	s := makeCdtSession(sid, &dbg, ch)

	var rid int64 = 5
	req := cdt.ChromeRequest{ID: rid}
	state := cdtState{}

	req.Method = "Runtime.evaluate"
	req.Params = map[string]interface{}{"expression": "navigator.userAgent"}
	resp, events, err := s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.NotEmpty(t, resp.Result)
	result, ok := resp.Result.(cmdResult)
	require.True(t, ok)
	_, ok = result.Result.(cdt.RuntimeRemoteObject)
	require.True(t, ok)

	// any other exprs than "navigator.userAgent" not supported in this proto 1.1 implementation
	req.Params = map[string]interface{}{"expression": "test"}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.Empty(t, resp.Result)

	req.Params = map[string]interface{}{}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.Error(t, err)
	require.Equal(t, 0, len(events))
	require.Empty(t, resp.ID)
	require.Empty(t, resp.Result)
}

func TestCdtSessionProto11CallOnFunc(t *testing.T) {
	sid := "test"
	dbg := MockDebugControl{}
	ch := make(chan Notification)
	s := makeCdtSession(sid, &dbg, ch)

	var rid int64 = 6
	req := cdt.ChromeRequest{ID: rid}
	state := cdtState{}

	req.Method = "Runtime.callFunctionOn"
	req.Params = map[string]interface{}{}
	resp, events, err := s.handleCdtRequest(&req, &state)
	require.Error(t, err)

	req.Params = map[string]interface{}{"objectId": ""}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.Error(t, err)

	req.Params = map[string]interface{}{"objectId": "", "functionDeclaration": ""}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.Error(t, err)

	req.Params = map[string]interface{}{"objectId": "", "functionDeclaration": "", "arguments": []interface{}{}}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.Empty(t, resp.Result)

	req.Params = map[string]interface{}{
		"objectId":            "",
		"functionDeclaration": "function packRanges",
		"arguments": []interface{}{
			map[string]interface{}{"value": 1.},
			map[string]interface{}{"value": 2.},
			map[string]interface{}{"value": 3.},
			map[string]interface{}{"value": 4.},
			map[string]interface{}{"value": 5.},
		}}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.NotEmpty(t, resp.Result)
	result, ok := resp.Result.(cmdResult)
	require.True(t, ok)
	require.NotEmpty(t, result)
	_, ok = result.Result.(cdt.RuntimeCallPackRangesObject)
	require.True(t, ok)

	req.Params = map[string]interface{}{
		"objectId":            stackObjID,
		"functionDeclaration": "function buildObjectFragment",
		"arguments": []interface{}{
			map[string]interface{}{"value": 1.},
		}}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.NotEmpty(t, resp.Result)
	result, ok = resp.Result.(cmdResult)
	require.True(t, ok)
	require.NotEmpty(t, result)
	_, ok = result.Result.(cdt.RuntimeRemoteObject)
	require.True(t, ok)

	req.Params = map[string]interface{}{
		"objectId":            stackObjID,
		"functionDeclaration": "function buildArrayFragment",
		"arguments": []interface{}{
			map[string]interface{}{"value": 1.},
			map[string]interface{}{"value": 2.},
			map[string]interface{}{"value": 3.},
		}}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.NotEmpty(t, resp.Result)
	result, ok = resp.Result.(cmdResult)
	require.True(t, ok)
	require.NotEmpty(t, result)
	_, ok = result.Result.(cdt.RuntimeRemoteObject)
	require.True(t, ok)
}

func TestCdtSessionProto11GetProps(t *testing.T) {
	sid := "test"
	dbg := MockDebugControl{}
	ch := make(chan Notification)
	s := makeCdtSession(sid, &dbg, ch)

	var rid int64 = 7
	req := cdt.ChromeRequest{ID: rid}
	state := cdtState{}

	req.Method = "Runtime.getProperties"
	req.Params = map[string]interface{}{}
	resp, events, err := s.handleCdtRequest(&req, &state)
	require.Error(t, err)

	req.Params = map[string]interface{}{"objectId": "", "generatePreview": true}
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.Error(t, err)

	req.Params = map[string]interface{}{"objectId": globalScopeObjID, "generatePreview": true}
	s.verbose = true
	resp, events, err = s.handleCdtRequest(&req, &state)
	require.NoError(t, err)
	require.Equal(t, 0, len(events))
	require.Equal(t, rid, resp.ID)
	require.NotEmpty(t, resp.Result)
	result, ok := resp.Result.(cmdResult)
	require.True(t, ok)
	require.NotEmpty(t, result)
	_ = result.Result.([]cdt.RuntimePropertyDescriptor)
	require.True(t, ok)
}

func TestCdtSessionStateToEvent(t *testing.T) {
	sid := "test"
	dbg := MockDebugControl{}
	ch := make(chan Notification)
	s := makeCdtSession(sid, &dbg, ch)

	state := cdtState{}

	// if no special conditions set then pause
	e := s.computeEvent(&state)
	_, ok := (e).(cdt.DebuggerPausedEvent)
	require.True(t, ok)

	// if completed and pause on competed then pause
	state.completed.SetTo(true)
	state.pauseOnCompeted.SetTo(true)
	e = s.computeEvent(&state)
	_, ok = (e).(cdt.DebuggerPausedEvent)
	require.True(t, ok)

	// if completed and pause on error and error then pause
	state = cdtState{}
	state.completed.SetTo(true)
	state.pauseOnError.SetTo(true)
	state.err.Store("err")
	e = s.computeEvent(&state)
	_, ok = (e).(cdt.DebuggerPausedEvent)
	require.True(t, ok)

	// if completed and resume then exit debugging
	state = cdtState{}
	state.completed.SetTo(true)
	state.lastAction.Store("resume")
	e = s.computeEvent(&state)
	_, ok = (e).(cdt.RuntimeExecutionContextDestroyedEvent)
	require.True(t, ok)
}

func TestCdtSessionGetObjects(t *testing.T) {
	sid := "test"
	dbg := MockDebugControl{}
	ch := make(chan Notification)
	s := makeCdtSession(sid, &dbg, ch)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var globals []basics.TealValue
	for range logic.GlobalFieldNames {
		globals = append(globals, basics.TealValue{Type: basics.TealUintType, Uint: 1})
	}
	e := atomicString{}
	e.Store("mock err")

	var rid int64 = 1
	req := cdt.ChromeRequest{ID: rid}
	state := cdtState{
		disassembly: "version 2\nint 1",
		proto:       &proto,
		txnGroup: []transactions.SignedTxn{
			{
				Txn: transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender: basics.Address{}, Fee: basics.MicroAlgos{Raw: 1000}, FirstValid: 10,
					},
				},
			},
			{
				Txn: transactions.Transaction{
					Type: protocol.ApplicationCallTx,
					ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
						ApplicationArgs: [][]byte{{0, 1, 2, 3}},
					},
				},
			},
		},
		groupIndex: 0,
		globals:    globals,
		stack:      []basics.TealValue{{Type: basics.TealBytesType, Bytes: "test"}},
		scratch: []basics.TealValue{
			{Type: basics.TealUintType, Uint: 1},
			{Type: basics.TealBytesType, Bytes: "\x01\x02"},
		},
		pc:   atomicInt{1},
		line: atomicInt{1},
		err:  e,
		AppState: AppState{
			appIdx: basics.AppIndex(1),
			schemas: basics.StateSchemas{
				GlobalStateSchema: basics.StateSchema{NumUint: 1, NumByteSlice: 1},
				LocalStateSchema:  basics.StateSchema{NumUint: 1, NumByteSlice: 1},
			},
			global: map[basics.AppIndex]basics.TealKeyValue{
				basics.AppIndex(1): {
					"a": basics.TealValue{Type: basics.TealUintType, Uint: 1},
					"b": basics.TealValue{Type: basics.TealBytesType, Bytes: "\x01\x02"},
				},
			},
			locals: map[basics.Address]map[basics.AppIndex]basics.TealKeyValue{
				{}: {
					basics.AppIndex(1): {
						"c": basics.TealValue{Type: basics.TealUintType, Uint: 1},
						"b": basics.TealValue{Type: basics.TealBytesType, Bytes: "\x01\x02"},
					},
				},
			},
		},
	}

	req.Method = "Runtime.getProperties"
	req.Params = map[string]interface{}{}
	resp, events, err := s.handleCdtRequest(&req, &state)
	require.Error(t, err)

	for k := range objectDescMap {
		req.Params = map[string]interface{}{"objectId": k, "generatePreview": true}
		resp, events, err = s.handleCdtRequest(&req, &state)
		require.NoError(t, err)
		require.Equal(t, 0, len(events))
		require.Equal(t, rid, resp.ID)
		require.NotEmpty(t, resp.Result)
		result, ok := resp.Result.(cmdResult)
		require.True(t, ok)
		require.NotEmpty(t, result)
		_ = result.Result.([]cdt.RuntimePropertyDescriptor)
		require.True(t, ok)
	}

	objIds := []string{
		encodeTxnArrayField(0, 1), encodeGroupTxnID(0), encodeGroupTxnID(1),
		encodeArrayLength(stackObjID), encodeArraySlice(scratchObjID, 0, 1),
		encodeAppLocalsAddr(basics.Address{}.String()),
		encodeAppGlobalAppID("0"), encodeAppGlobalAppID("1"),
		encodeAppLocalsAppID(basics.Address{}.String(), "1"),
	}
	for _, k := range objIds {
		req.Params = map[string]interface{}{"objectId": k, "generatePreview": true}
		resp, events, err = s.handleCdtRequest(&req, &state)
		require.NoError(t, err)
		require.Equal(t, 0, len(events))
		require.Equal(t, rid, resp.ID)
		require.NotEmpty(t, resp.Result)
		result, ok := resp.Result.(cmdResult)
		require.True(t, ok)
		require.NotEmpty(t, result)
		_ = result.Result.([]cdt.RuntimePropertyDescriptor)
		require.True(t, ok)
	}
}
