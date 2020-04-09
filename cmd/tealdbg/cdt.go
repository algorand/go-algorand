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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/algorand/go-algorand/data/basics"
	"math/rand"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

type cdtDebugger struct {
	uuid        string
	rctx        *requestContext
	contextID   int
	scriptID    string
	program     string
	offsets     []logic.PCOffset
	lines       []string
	currentLine int
	txnGroup    []transactions.SignedTxn
	groupIndex  int
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

const localScopeObjID = "localScopeObjId"
const txnObjID = "txnObjID"
const gtxnObjID = "gtxnObjID"
const stackObjID = "stackObjID"
const scratchObjID = "scratchObjID"

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

func makeScope(cdt *cdtDebugger, preview bool) (descr []RuntimePropertyDescriptor) {
	txn := makeObject("txn", txnObjID)
	gtxn := makeArray("gtxn", len(cdt.txnGroup), gtxnObjID)
	if preview {
		txnPreview := cdt.makeTxnPreview(cdt.groupIndex)
		gtxnPreview := cdt.makeGtxnPreview()
		txn.Value.Preview = &txnPreview
		gtxn.Value.Preview = &gtxnPreview
	}

	descr = []RuntimePropertyDescriptor{
		txn,
		gtxn,
	}
	return descr
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
	return
}
func makeScratch(cdt *cdtDebugger, preview bool) (descr []RuntimePropertyDescriptor) {
	return
}

type objectDescFn func(cdt *cdtDebugger, preview bool) []RuntimePropertyDescriptor

var objectDescMap = map[string]objectDescFn{
	localScopeObjID: makeScope,
	txnObjID:        makeTxn,
	gtxnObjID:       makeTxnGroup,
	stackObjID:      makeStack,
	scratchObjID:    makeScratch,
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

func (cdt *cdtDebugger) handleCDTRequest(req *ChromeRequest) (ChromeResponse, error) {
	empty := make(map[string]interface{})

	switch req.Method {
	case "Debugger.enable":
		debuggerID := make(map[string]string)
		debuggerID["debuggerId"] = cdt.uuid
		return ChromeResponse{ID: req.ID, Result: debuggerID}, nil
	case "Runtime.getIsolateId":
		isolateID := make(map[string]string)
		isolateID["id"] = cdt.uuid
		return ChromeResponse{ID: req.ID, Result: isolateID}, nil
	case "Debugger.getScriptSource":
		p := req.Params.(map[string]interface{})
		_, ok := p["scriptId"]
		source := make(map[string]string)
		if !ok {
			return ChromeResponse{}, fmt.Errorf("getScriptSource failed: no scriptId")
		}
		source["scriptSource"] = cdt.program
		return ChromeResponse{ID: req.ID, Result: source}, nil
	case "Runtime.getProperties":
		p := req.Params.(map[string]interface{})
		objIDRaw, ok := p["objectId"]
		if !ok {
			return ChromeResponse{}, fmt.Errorf("getProperties failed: no objectId")
		}
		objID := objIDRaw.(string)

		preview := false
		previewRaw, ok := p["generatePreview"]
		if ok {
			preview = previewRaw.(bool)
		}

		descr, err := cdt.getObjectDescriptor(objID, preview)
		if err != nil {
			fmt.Println("getObjectDescriptor error: " + err.Error())
			return ChromeResponse{}, err
		}
		data, err := json.Marshal(descr)
		if err != nil {
			fmt.Println("getObjectDescriptor json error: " + err.Error())
			return ChromeResponse{}, err
		}
		fmt.Printf("Descr object: %s\n", string(data))
		result := map[string][]RuntimePropertyDescriptor{
			"result": descr,
		}
		return ChromeResponse{ID: req.ID, Result: result}, nil
	case "Debugger.getPossibleBreakpoints":
		p := req.Params.(map[string]interface{})
		var start, end map[string]interface{}
		var startLine, endLine int
		var scriptID string
		if _, ok := p["start"]; !ok {
			return ChromeResponse{ID: req.ID, Result: empty}, nil
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
		return ChromeResponse{ID: req.ID, Result: result}, nil
	case "Debugger.setBreakpointByUrl":
		p := req.Params.(map[string]interface{})
		bpLine := int(p["lineNumber"].(float64))
		pc := cdt.lineToPC(bpLine)
		fmt.Printf("setBp line %d, pc %d\n", bpLine, pc)
		cdt.rctx.setBreakpoint(ExecID(cdt.uuid), pc)
		result := make(map[string]interface{})
		result["breakpointId"] = strconv.Itoa(rand.Int())
		result["locations"] = []DebuggerLocation{DebuggerLocation{ScriptID: cdt.scriptID, LineNumber: bpLine}}
		return ChromeResponse{ID: req.ID, Result: result}, nil
	case "Debugger.resume":
		cdt.rctx.resume(ExecID(cdt.uuid))
		return ChromeResponse{ID: req.ID, Result: empty}, nil
	case "Debugger.stepOver", "Debugger.stepInto", "Debugger.stepOut":
		nextpc := cdt.lineToPC(cdt.currentLine + 1)
		fmt.Printf("step line %d, pc %d\n", cdt.currentLine+1, nextpc)
		cdt.rctx.setBreakpoint(ExecID(cdt.uuid), nextpc)
		cdt.rctx.resume(ExecID(cdt.uuid))
		cdt.currentLine++
		fallthrough
	default:
		return ChromeResponse{ID: req.ID, Result: empty}, nil
	}
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
	sc := []DebuggerScope{scopeLocal}
	cf := DebuggerCallFrame{
		CallFrameID:  "mainframe",
		FunctionName: "",
		Location: &DebuggerLocation{
			ScriptID:     cdt.scriptID,
			LineNumber:   cdt.currentLine,
			ColumnNumber: progLines,
		},
		URL:        "file://program.teal.js",
		ScopeChain: sc,
	}

	evPaused := DebuggerPausedEvent{
		Method: "Debugger.paused",
		Params: DebuggerPausedParams{
			CallFrames:     []DebuggerCallFrame{cf},
			Reason:         "Break on start",
			HitBreakpoints: make([]string, 0),
		},
	}

	return evPaused
}

func (cdt *cdtDebugger) lineToPC(line int) int {
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

func (cdt *cdtDebugger) pcToLine(pc int) int {
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

	return len(strings.Split(cdt.program[:offset], "\n")) - 1
}
