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
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/data/transactions/logic"
)

type cdtDebugger struct {
	uuid        string
	rctx        *requestContext
	contextID   int
	scriptID    string
	program     string
	lines       []string
	currentLine int
}

func (cdt *cdtDebugger) getObjectDescriptor(objID string, preview bool) (descr []RuntimePropertyDescriptor, err error) {
	if objID == "localscope" {
		descr = []RuntimePropertyDescriptor{
			RuntimePropertyDescriptor{
				Name:         "txn",
				Configurable: false,
				Writable:     true,
				Value: &RuntimeRemoteObject{
					Type:        "object",
					ClassName:   "Object",
					Description: "Current transaction",
					ObjectID:    "txnobj",
				},
			},
			RuntimePropertyDescriptor{
				Name:         "gtxn",
				Configurable: false,
				Writable:     true,
				Value: &RuntimeRemoteObject{
					Type:        "object",
					ClassName:   "Object",
					Description: "Transaction group",
					ObjectID:    "gtxnobj",
				},
			},
		}
	} else if objID == "txnobj" {
		descr = []RuntimePropertyDescriptor{
			RuntimePropertyDescriptor{
				Name:         "Sender",
				Configurable: false,
				Writable:     true,
				IsOwn:        true,
				Value: &RuntimeRemoteObject{
					Type:  "string",
					Value: "test sender",
				},
			},
			RuntimePropertyDescriptor{
				Name:         "Receiver",
				Configurable: false,
				Writable:     true,
				IsOwn:        true,
				Value: &RuntimeRemoteObject{
					Type:  "string",
					Value: "test receiver",
				},
			},
		}
	} else {
		err = fmt.Errorf("unk object id: %s", objID)
	}
	return descr, err
}

func (cdt *cdtDebugger) handleCDTRequest(req *ChromeRequest, state *logic.DebuggerState) (ChromeResponse, error) {
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
		source["scriptSource"] = state.Disassembly
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
			return ChromeResponse{}, err
		}
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
		pc := cdt.lineToPC(bpLine, state)
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
		nextpc := cdt.lineToPC(cdt.currentLine+1, state)
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
			ObjectID:    "localscope",
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

func (cdt *cdtDebugger) lineToPC(line int, state *logic.DebuggerState) int {
	if len(state.PCOffset) == 0 || line < 1 {
		return 0
	}

	offset := len(strings.Join(cdt.lines[:line], "\n"))

	for i := 0; i < len(state.PCOffset); i++ {
		if state.PCOffset[i].Offset >= offset {
			return state.PCOffset[i].PC
		}
	}
	return 0
}

func (cdt *cdtDebugger) pcToLine(state *logic.DebuggerState) int {
	if len(state.PCOffset) == 0 {
		return 0
	}

	pc := state.PC
	offset := 0
	for i := 0; i < len(state.PCOffset); i++ {
		if state.PCOffset[i].PC >= pc {
			offset = state.PCOffset[i].Offset
			break
		}
	}
	if offset == 0 {
		offset = state.PCOffset[len(state.PCOffset)-1].Offset
	}

	return len(strings.Split(cdt.program[:offset], "\n")) - 1
}
