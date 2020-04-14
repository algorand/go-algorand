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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	// "math/rand"
	// "sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

type atomicString struct {
	value atomic.Value
}

func (s *atomicString) Store(other string) {
	s.value.Store(other)
}

func (s *atomicString) Load() string {
	result := s.value.Load()
	if result != nil {
		if value, ok := result.(string); ok {
			return value
		}
	}
	return ""
}

type atomicBool struct {
	value uint32
}

func (b *atomicBool) SetTo(other bool) {
	var converted uint32 = 0
	if other {
		converted = 1
	}
	atomic.StoreUint32(&b.value, converted)
}

func (b *atomicBool) IsSet() bool {
	return atomic.LoadUint32(&b.value) != 0
}

type cdtDebugger struct {
	uuid         string
	rctx         *requestContext
	contextID    int
	scriptID     string
	breakpoints  []bool
	program      string
	offsets      []logic.PCOffset
	lines        []string
	currentLine  uint32
	lastAction   atomicString
	err          atomicString
	pauseOnError atomicBool

	txnGroup   []transactions.SignedTxn
	groupIndex int
	stack      []v1.TealValue
	scratch    []v1.TealValue
	proto      *config.ConsensusParams
}

func makeObject(name, id string) RuntimePropertyDescriptor {
	return RuntimePropertyDescriptor{
		Name:         name,
		Configurable: false,
		Writable:     false,
		Enumerable:   true,
		IsOwn:        true,
		Value: &RuntimeRemoteObject{
			Type:        "object",
			ClassName:   "Object",
			Description: "Object",
			ObjectID:    id,
		},
	}
}

func makeArray(name string, length int, id string) RuntimePropertyDescriptor {
	return RuntimePropertyDescriptor{
		Name:         name,
		Configurable: false,
		Writable:     false,
		Enumerable:   true,
		IsOwn:        true,
		Value: &RuntimeRemoteObject{
			Type:        "object",
			Subtype:     "array",
			ClassName:   "Array",
			Description: fmt.Sprintf("Array(%d)", length),
			ObjectID:    id,
		},
	}
}

func makePrimitive(field fieldDesc) RuntimePropertyDescriptor {
	return RuntimePropertyDescriptor{
		Name:         field.Name,
		Configurable: false,
		Writable:     false,
		Enumerable:   true,
		IsOwn:        true,
		Value: &RuntimeRemoteObject{
			Type:  field.Type,
			Value: field.Value,
		},
	}
}

// tealTypeMap maps TealType to JS type
var tealTypeMap = map[basics.TealType]string{
	basics.TealBytesType: "string",
	basics.TealUintType:  "number",
}

type fieldDesc struct {
	Name  string
	Value string
	Type  string
}

func prepareGlobals(cdt *cdtDebugger) []fieldDesc {
	result := make([]fieldDesc, 0, len(logic.GlobalFieldNames))
	for _, name := range logic.GlobalFieldNames {
		var value string
		var valType string = "string"
		tv, err := logic.GlobalFieldToTealValue(cdt.proto, cdt.txnGroup, cdt.groupIndex)
		if err != nil {
			value = err.Error()
			valType = "undefined"
		} else {
			value = tv.String()
			valType = tealTypeMap[tv.Type]
		}
		result = append(result, fieldDesc{name, value, valType})
	}
	return result
}

func prepareTxn(txn *transactions.Transaction, groupIndex int) []fieldDesc {
	result := make([]fieldDesc, 0, len(logic.TxnFieldNames))
	for field, name := range logic.TxnFieldNames {
		if field == int(logic.FirstValidTime) ||
			field == int(logic.Accounts) ||
			field == int(logic.ApplicationArgs) {
			continue
		}
		var value string
		var valType string = "string"
		tv, err := logic.TxnFieldToTealValue(txn, groupIndex, logic.TxnField(field))
		if err != nil {
			value = err.Error()
			valType = "undefined"
		} else {
			value = tv.String()
			valType = tealTypeMap[tv.Type]
		}
		result = append(result, fieldDesc{name, value, valType})
	}
	return result
}

func prepareArray(array []v1.TealValue) []fieldDesc {
	result := make([]fieldDesc, 0, len(logic.TxnFieldNames))
	for i := 0; i < len(array); i++ {
		tv := array[i]
		name := strconv.Itoa(i)
		var value string
		var valType string
		if tv.Type == "b" {
			valType = "string"
			data, err := base64.StdEncoding.DecodeString(tv.Bytes)
			if err != nil {
				value = tv.Bytes
			} else {
				printable := true
				for i := 0; i < len(data); i++ {
					if !strconv.IsPrint(rune(data[i])) {
						printable = false
						break
					}
				}
				if printable {
					value = string(data)
				} else if len(data) < 8 {
					value = fmt.Sprintf("%q", data)
					if value[0] == '"' {
						value = value[1 : len(value)-1]
					}
				} else {
					value = hex.EncodeToString(data)
				}
			}
		} else {
			valType = "number"
			value = strconv.Itoa(int(tv.Uint))
		}
		result = append(result, fieldDesc{name, value, valType})
	}
	return result
}

func (cdt *cdtDebugger) makeTxnPreview(groupIndex int) RuntimeObjectPreview {
	var prop []RuntimePropertyPreview
	if len(cdt.txnGroup) > 0 {
		fields := prepareTxn(&cdt.txnGroup[groupIndex].Txn, groupIndex)
		for _, field := range fields {
			v := RuntimePropertyPreview{
				Name:  field.Name,
				Value: field.Value,
				Type:  field.Type,
			}
			prop = append(prop, v)
		}
	}

	p := RuntimeObjectPreview{Type: "object", Overflow: true, Properties: prop}
	return p
}

func (cdt *cdtDebugger) makeGtxnPreview() RuntimeObjectPreview {
	var prop []RuntimePropertyPreview
	if len(cdt.txnGroup) > 0 {
		for i := 0; i < len(cdt.txnGroup); i++ {
			v := RuntimePropertyPreview{
				Name:  strconv.Itoa(i),
				Value: "Object",
				Type:  "object",
			}
			prop = append(prop, v)
		}
	}
	p := RuntimeObjectPreview{
		Type:        "object",
		Subtype:     "array",
		Description: fmt.Sprintf("Array(%d)", len(cdt.txnGroup)),
		Overflow:    false,
		Properties:  prop}
	return p
}

const maxArrayPreviewLength = 20

func (cdt *cdtDebugger) makeArrayPreview(array []v1.TealValue) RuntimeObjectPreview {
	var prop []RuntimePropertyPreview
	fields := prepareArray(array)

	length := len(fields)
	if length > maxArrayPreviewLength {
		length = maxArrayPreviewLength
	}
	for _, field := range fields[:length] {
		v := RuntimePropertyPreview{
			Name:  field.Name,
			Value: field.Value,
			Type:  field.Type,
		}
		prop = append(prop, v)
	}

	p := RuntimeObjectPreview{
		Type:        "object",
		Subtype:     "array",
		Description: fmt.Sprintf("Array(%d)", len(array)),
		Overflow:    true,
		Properties:  prop}
	return p
}

func (cdt *cdtDebugger) makeGlobalsPreview() RuntimeObjectPreview {
	var prop []RuntimePropertyPreview
	fields := prepareGlobals(cdt)

	for _, field := range fields {
		v := RuntimePropertyPreview{
			Name:  field.Name,
			Value: field.Value,
			Type:  field.Type,
		}
		prop = append(prop, v)
	}

	p := RuntimeObjectPreview{
		Type:        "object",
		Description: "Object",
		Overflow:    true,
		Properties:  prop}
	return p
}

const localScopeObjID = "localScopeObjId"
const globalScopeObjID = "globalScopeObjID"
const globalsObjID = "globalsObjID"
const txnObjID = "txnObjID"
const gtxnObjID = "gtxnObjID"
const stackObjID = "stackObjID"
const scratchObjID = "scratchObjID"
const tealErrorID = "tealErrorID"

var gtxnObjIDPrefix = fmt.Sprintf("%s_gid_", gtxnObjID)

func encodeGroupTxnID(groupIndex int) string {
	return gtxnObjIDPrefix + strconv.Itoa(groupIndex)
}

func decodeGroupTxnID(objID string) (int, bool) {
	if strings.HasPrefix(objID, gtxnObjIDPrefix) {
		if val, err := strconv.ParseInt(objID[len(gtxnObjIDPrefix):], 10, 32); err == nil {
			return int(val), true
		}
	}
	return 0, false
}

func makeGlobalScope(cdt *cdtDebugger, preview bool) (descr []RuntimePropertyDescriptor) {
	globals := makeObject("globals", globalsObjID)
	if preview {
		globalsPreview := cdt.makeGlobalsPreview()
		globals.Value.Preview = &globalsPreview
	}

	descr = []RuntimePropertyDescriptor{
		globals,
	}
	return descr
}

func makeLocalScope(cdt *cdtDebugger, preview bool) (descr []RuntimePropertyDescriptor) {
	txn := makeObject("txn", txnObjID)
	gtxn := makeArray("gtxn", len(cdt.txnGroup), gtxnObjID)
	stack := makeArray("stack", len(cdt.stack), stackObjID)
	scratch := makeArray("scratch", len(cdt.scratch), scratchObjID)
	if preview {
		txnPreview := cdt.makeTxnPreview(cdt.groupIndex)
		if len(txnPreview.Properties) > 0 {
			txn.Value.Preview = &txnPreview
		}
		gtxnPreview := cdt.makeGtxnPreview()
		if len(gtxnPreview.Properties) > 0 {
			gtxn.Value.Preview = &gtxnPreview
		}
		stackPreview := cdt.makeArrayPreview(cdt.stack)
		if len(stackPreview.Properties) > 0 {
			stack.Value.Preview = &stackPreview
		}
		scratchPreview := cdt.makeArrayPreview(cdt.scratch)
		if len(scratchPreview.Properties) > 0 {
			scratch.Value.Preview = &scratchPreview
		}
	}

	pc := makePrimitive(fieldDesc{
		Name:  "PC",
		Value: strconv.Itoa(cdt.lineToPC(atomic.LoadUint32(&cdt.currentLine))),
		Type:  "number",
	})
	descr = []RuntimePropertyDescriptor{
		pc,
		txn,
		gtxn,
		stack,
		scratch,
	}

	return descr
}

func makeGlobals(cdt *cdtDebugger, preview bool) (descr []RuntimePropertyDescriptor) {
	fields := prepareGlobals(cdt)
	for _, field := range fields {
		descr = append(descr, makePrimitive(field))
	}
	return
}

func makeTxn(cdt *cdtDebugger, preview bool) (descr []RuntimePropertyDescriptor) {
	if len(cdt.txnGroup) > 0 && cdt.groupIndex < len(cdt.txnGroup) && cdt.groupIndex >= 0 {
		return makeTxnImpl(&cdt.txnGroup[cdt.groupIndex].Txn, cdt.groupIndex, preview)
	}
	return
}

func makeTxnImpl(txn *transactions.Transaction, groupIndex int, preview bool) (descr []RuntimePropertyDescriptor) {
	fields := prepareTxn(txn, groupIndex)
	for _, field := range fields {
		descr = append(descr, makePrimitive(field))
	}
	return
}

func makeTxnGroup(cdt *cdtDebugger, preview bool) (descr []RuntimePropertyDescriptor) {
	if len(cdt.txnGroup) > 0 {
		for i := 0; i < len(cdt.txnGroup); i++ {
			item := makeObject(strconv.Itoa(i), encodeGroupTxnID(i))
			if preview {
				txnPreview := cdt.makeTxnPreview(i)
				item.Value.Preview = &txnPreview
			}
			descr = append(descr, item)
		}
	}
	return
}

func makeStack(cdt *cdtDebugger, preview bool) (descr []RuntimePropertyDescriptor) {
	fmt.Printf("makeStack\n")
	stack := make([]v1.TealValue, len(cdt.stack))
	for i := 0; i < len(stack); i++ {
		stack[i] = cdt.stack[len(cdt.stack)-1-i]
	}

	fields := prepareArray(stack)
	for _, field := range fields {
		descr = append(descr, makePrimitive(field))
	}
	field := fieldDesc{Name: "length", Value: strconv.Itoa(len(cdt.stack)), Type: "number"}
	descr = append(descr, makePrimitive(field))
	return
}

func makeScratch(cdt *cdtDebugger, preview bool) (descr []RuntimePropertyDescriptor) {
	fields := prepareArray(cdt.scratch)
	for _, field := range fields {
		descr = append(descr, makePrimitive(field))
	}
	field := fieldDesc{Name: "length", Value: strconv.Itoa(len(cdt.scratch)), Type: "number"}
	descr = append(descr, makePrimitive(field))
	return
}

func makeTealError(cdt *cdtDebugger, preview bool) (descr []RuntimePropertyDescriptor) {
	if lastError := cdt.err.Load(); len(lastError) != 0 {
		field := fieldDesc{Name: "message", Value: lastError, Type: "string"}
		descr = append(descr, makePrimitive(field))
	}
	return
}

type objectDescFn func(cdt *cdtDebugger, preview bool) []RuntimePropertyDescriptor

var objectDescMap = map[string]objectDescFn{
	globalScopeObjID: makeGlobalScope,
	localScopeObjID:  makeLocalScope,
	globalsObjID:     makeGlobals,
	txnObjID:         makeTxn,
	gtxnObjID:        makeTxnGroup,
	stackObjID:       makeStack,
	scratchObjID:     makeScratch,
	tealErrorID:      makeTealError,
}

func (cdt *cdtDebugger) getObjectDescriptor(objID string, preview bool) (descr []RuntimePropertyDescriptor, err error) {
	maker, ok := objectDescMap[objID]
	if !ok {
		if idx, ok := decodeGroupTxnID(objID); ok {
			if idx >= len(cdt.txnGroup) || idx < 0 {
				err = fmt.Errorf("invalid group idx: %d", idx)
				return
			}
			if len(cdt.txnGroup) > 0 {
				return makeTxnImpl(&cdt.txnGroup[idx].Txn, idx, preview), nil
			}
		}
		// might be nested object in array, parse and call
		err = fmt.Errorf("unk object id: %s", objID)
		return
	}
	return maker(cdt, preview), nil
}

func (cdt *cdtDebugger) handleCDTRequest(req *ChromeRequest, isCompleted bool) (response ChromeResponse, events []interface{}, err error) {
	empty := make(map[string]interface{})
	switch req.Method {
	case "Debugger.enable":
		evCtxCreated := cdt.makeContextCreatedEvent()
		evParsed := cdt.makeScriptParsedEvent()
		events = append(events, &evCtxCreated, &evParsed)

		debuggerID := make(map[string]string)
		debuggerID["debuggerId"] = cdt.uuid
		response = ChromeResponse{ID: req.ID, Result: debuggerID}
	case "Runtime.runIfWaitingForDebugger":
		evPaused := cdt.makeDebuggerPausedEvent()
		events = append(events, &evPaused)
		response = ChromeResponse{ID: req.ID, Result: empty}
	case "Runtime.getIsolateId":
		isolateID := make(map[string]string)
		isolateID["id"] = cdt.uuid
		response = ChromeResponse{ID: req.ID, Result: isolateID}
	case "Debugger.getScriptSource":
		p := req.Params.(map[string]interface{})
		_, ok := p["scriptId"]
		source := make(map[string]string)
		if !ok {
			err = fmt.Errorf("getScriptSource failed: no scriptId")
			return
		}
		source["scriptSource"] = cdt.program
		response = ChromeResponse{ID: req.ID, Result: source}
	case "Debugger.setPauseOnExceptions":
		p := req.Params.(map[string]interface{})
		stateRaw, ok := p["state"]
		enable := false
		if ok {
			if state, ok := stateRaw.(string); ok && state != "none" {
				enable = true
			}
		}
		cdt.pauseOnError.SetTo(enable)
		response = ChromeResponse{ID: req.ID, Result: empty}
	case "Runtime.getProperties":
		p := req.Params.(map[string]interface{})
		objIDRaw, ok := p["objectId"]
		if !ok {
			err = fmt.Errorf("getProperties failed: no objectId")
			return
		}
		objID := objIDRaw.(string)

		preview := false
		previewRaw, ok := p["generatePreview"]
		if ok {
			preview = previewRaw.(bool)
		}

		var descr []RuntimePropertyDescriptor
		descr, err = cdt.getObjectDescriptor(objID, preview)
		if err != nil {
			err = fmt.Errorf("getObjectDescriptor error: " + err.Error())
			return
		}

		var data []byte
		data, err = json.Marshal(descr)
		if err != nil {
			err = fmt.Errorf("getObjectDescriptor json error: " + err.Error())
			return
		}
		fmt.Printf("Descr object: %s\n", string(data))

		result := map[string][]RuntimePropertyDescriptor{
			"result": descr,
		}
		response = ChromeResponse{ID: req.ID, Result: result}
	case "Debugger.getPossibleBreakpoints":
		p := req.Params.(map[string]interface{})
		var start, end map[string]interface{}
		var startLine, endLine int
		var scriptID string
		if _, ok := p["start"]; !ok {
			response = ChromeResponse{ID: req.ID, Result: empty}
			return
		}

		start = p["start"].(map[string]interface{})
		startLine = int(start["lineNumber"].(float64))
		scriptID = start["scriptId"].(string)
		if _, ok := p["end"]; ok {
			end = p["end"].(map[string]interface{})
			endLine = int(end["lineNumber"].(float64))
		} else {
			endLine = startLine
		}

		result := make(map[string]interface{})
		locs := make([]DebuggerLocation, 0, endLine-startLine+1)
		for ln := startLine; ln <= endLine; ln++ {
			locs = append(locs, DebuggerLocation{ScriptID: scriptID, LineNumber: ln})
		}
		result["locations"] = locs
		response = ChromeResponse{ID: req.ID, Result: result}
	case "Debugger.removeBreakpoint":
		p := req.Params.(map[string]interface{})
		var bpLine int
		bpLine, err = strconv.Atoi(p["breakpointId"].(string))
		if err != nil {
			return
		}
		if bpLine < 0 || bpLine >= len(cdt.breakpoints) {
			err = fmt.Errorf("invalid bp line %d", bpLine)
			return
		}
		if cdt.breakpoints[bpLine] {
			cdt.rctx.delBreakpoint(ExecID(cdt.uuid))
			cdt.breakpoints[bpLine] = false
		}
		response = ChromeResponse{ID: req.ID, Result: empty}
	case "Debugger.setBreakpointByUrl":
		p := req.Params.(map[string]interface{})
		bpLine := int(p["lineNumber"].(float64))
		if bpLine >= len(cdt.lines) {
			err = fmt.Errorf("invalid bp line %d", bpLine)
			return
		}
		cdt.breakpoints[bpLine] = true
		targetpc := cdt.lineToPC(uint32(bpLine))
		cdt.rctx.setBreakpoint(ExecID(cdt.uuid), targetpc)

		result := make(map[string]interface{})
		result["breakpointId"] = strconv.Itoa(bpLine)
		result["locations"] = []DebuggerLocation{
			DebuggerLocation{ScriptID: cdt.scriptID, LineNumber: bpLine},
		}
		response = ChromeResponse{ID: req.ID, Result: result}
	case "Debugger.resume":
		currentLine := atomic.LoadUint32(&cdt.currentLine)
		if currentLine < uint32(len(cdt.breakpoints)) {
			for line, active := range cdt.breakpoints[currentLine+1:] {
				if active {
					targetpc := cdt.lineToPC(uint32(line) + currentLine + 1)
					cdt.rctx.setBreakpoint(ExecID(cdt.uuid), targetpc)
					break
				}
			}
		}
		cdt.lastAction.Store("resume")
		cdt.rctx.resume(ExecID(cdt.uuid))
		if isCompleted {
			evDestroyed := cdt.makeContextDestroyedEvent()
			events = append(events, &evDestroyed)
		}
		response = ChromeResponse{ID: req.ID, Result: empty}
	case "Debugger.stepOver", "Debugger.stepInto", "Debugger.stepOut":
		nextpc := cdt.lineToPC(atomic.LoadUint32(&cdt.currentLine) + uint32(1))
		cdt.rctx.setBreakpoint(ExecID(cdt.uuid), nextpc)
		cdt.rctx.resume(ExecID(cdt.uuid))
		atomic.AddUint32(&cdt.currentLine, 1)
		cdt.lastAction.Store("step")
		if isCompleted {
			evDestroyed := cdt.makeContextDestroyedEvent()
			events = append(events, &evDestroyed)
		}
		response = ChromeResponse{ID: req.ID, Result: empty}
	default:
		response = ChromeResponse{ID: req.ID, Result: empty}
	}

	return
}

func (cdt *cdtDebugger) makeContextCreatedEvent() RuntimeExecutionContextCreatedEvent {
	// {"method":"Runtime.executionContextCreated","params":{"context":{"id":1,"origin":"","name":"node[47576]","auxData":{"isDefault":true}}}}

	aux := make(map[string]interface{})
	aux["isDefault"] = true
	evCtxCreated := RuntimeExecutionContextCreatedEvent{
		Method: "Runtime.executionContextCreated",
		Params: RuntimeExecutionContextCreatedParams{
			Context: RuntimeExecutionContextDescription{
				ID:      cdt.contextID,
				Origin:  "",
				Name:    "TEAL program",
				AuxData: map[string]interface{}{"isDefault": true},
			},
		},
	}
	return evCtxCreated
}

func (cdt *cdtDebugger) makeContextDestroyedEvent() RuntimeExecutionContextDestroyedEvent {
	return RuntimeExecutionContextDestroyedEvent{
		Method: "Runtime.executionContextDestroyed",
		Params: RuntimeExecutionContextDestroyedParams{cdt.contextID},
	}
}

func (cdt *cdtDebugger) makeScriptParsedEvent() DebuggerScriptParsedEvent {
	// {"method":"Debugger.scriptParsed","params":{"scriptId":"69","url":"internal/dtrace.js","startLine":0,"startColumn":0,"endLine":21,"endColumn":0,"executionContextId":1,"hash":"2e8fbf2f9f6aaa183be557d25f5fbc5b09fae00a","executionContextAuxData":{"isDefault":true},"isLiveEdit":false,"sourceMapURL":"","hasSourceURL":false,"isModule":false,"length":568,"stackTrace":{"callFrames":[{"functionName":"NativeModule.compile","scriptId":"7","url":"internal/bootstrap/loaders.js","lineNumber":298,"columnNumber":15}]}}}
	hash := sha256.Sum256([]byte(cdt.program)) // some random hash
	progLines := strings.Count(cdt.program, "\n")
	length := len(cdt.program)

	evParsed := DebuggerScriptParsedEvent{
		Method: "Debugger.scriptParsed",
		Params: DebuggerScriptParsedParams{
			ScriptID:           cdt.scriptID,
			URL:                "file://program.teal.js",
			StartLine:          0,
			StartColumn:        0,
			EndLine:            progLines,
			EndColumn:          0,
			ExecutionContextID: cdt.contextID,
			Hash:               hex.EncodeToString(hash[:]),
			IsLiveEdit:         false,
			Length:             length,
		},
	}
	return evParsed
}

func (cdt *cdtDebugger) makeDebuggerPausedEvent() DebuggerPausedEvent {
	progLines := strings.Count(cdt.program, "\n")

	scopeLocal := DebuggerScope{
		Type: "local",
		Object: RuntimeRemoteObject{
			Type:        "object",
			ClassName:   "Object",
			Description: "Object",
			ObjectID:    localScopeObjID,
		},
		StartLocation: &DebuggerLocation{
			ScriptID:     cdt.scriptID,
			LineNumber:   0,
			ColumnNumber: 0,
		},
		EndLocation: &DebuggerLocation{
			ScriptID:     cdt.scriptID,
			LineNumber:   progLines,
			ColumnNumber: 0,
		},
	}
	scopeGlobal := DebuggerScope{
		Type: "global",
		Object: RuntimeRemoteObject{
			Type:        "object",
			ClassName:   "Object",
			Description: "Object",
			ObjectID:    globalScopeObjID,
		},
	}
	sc := []DebuggerScope{scopeLocal, scopeGlobal}
	cf := DebuggerCallFrame{
		CallFrameID:  "mainframe",
		FunctionName: "",
		Location: &DebuggerLocation{
			ScriptID:     cdt.scriptID,
			LineNumber:   int(atomic.LoadUint32(&cdt.currentLine)),
			ColumnNumber: progLines,
		},
		URL:        "file://program.teal.js",
		ScopeChain: sc,
	}

	evPaused := DebuggerPausedEvent{
		Method: "Debugger.paused",
		Params: DebuggerPausedParams{
			CallFrames:     []DebuggerCallFrame{cf},
			Reason:         "other",
			HitBreakpoints: make([]string, 0),
		},
	}

	if lastError := cdt.err.Load(); len(lastError) != 0 {
		evPaused.Params.Reason = "exception"
		evPaused.Params.Data = map[string]interface{}{
			"type":        "object",
			"className":   "Error",
			"description": lastError,
			"objectId":    "tealErrorID",
		}
	}

	return evPaused
}

func (cdt *cdtDebugger) computeEvent(isCompleted bool) (event interface{}) {
	if isCompleted && cdt.pauseOnError.IsSet() && len(cdt.err.Load()) != 0 {
		event = cdt.makeDebuggerPausedEvent()
	} else if isCompleted && cdt.lastAction.Load() == "resume" {
		event = cdt.makeContextDestroyedEvent()
	} else {
		event = cdt.makeDebuggerPausedEvent()
	}
	return
}

func (cdt *cdtDebugger) lineToPC(line uint32) int {
	if len(cdt.offsets) == 0 || line < 1 {
		return 0
	}

	offset := len(strings.Join(cdt.lines[:line], "\n"))

	for i := 0; i < len(cdt.offsets); i++ {
		if cdt.offsets[i].Offset >= offset {
			return cdt.offsets[i].PC
		}
	}
	return 0
}

func (cdt *cdtDebugger) pcToLine(pc int) uint32 {
	if len(cdt.offsets) == 0 {
		return 0
	}

	offset := 0
	for i := 0; i < len(cdt.offsets); i++ {
		if cdt.offsets[i].PC >= pc {
			offset = cdt.offsets[i].Offset
			break
		}
	}
	if offset == 0 {
		offset = cdt.offsets[len(cdt.offsets)-1].Offset
	}

	return uint32(len(strings.Split(cdt.program[:offset], "\n")) - 1)
}
