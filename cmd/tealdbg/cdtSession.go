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
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/algorand/go-algorand/data/transactions/logic"

	"github.com/algorand/websocket"
)

type cdtSession struct {
	uuid          string
	debugger      Control
	notifications chan Notification
	endpoint      cdtTabDescription

	contextID   int
	scriptID    string
	breakpoints []breakpointState
}

var contextCounter int32 = 0
var scriptCounter int32 = 0

func (s *cdtSession) Setup() {
	s.contextID = int(atomic.AddInt32(&contextCounter, 1))
	s.scriptID = strconv.Itoa(int(atomic.AddInt32(&scriptCounter, 1)))
}

func (s *cdtSession) initBreakpoints(size int) {
	s.breakpoints = make([]breakpointState, size)
}

func (s *cdtSession) websocketHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Path
	if uuid[0] == '/' {
		uuid = uuid[1:]
	}
	if uuid != s.uuid {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error on connection upgrade: %v\n", err)
		return
	}
	defer ws.Close()

	notifications := s.notifications

	cdtRespCh := make(chan ChromeResponse, 128)
	cdtEventCh := make(chan interface{}, 128)
	cdtUpdatedCh := make(chan interface{}, 1)

	closed := make(chan struct{})
	registred := make(chan struct{})

	var dbgStateMu sync.Mutex
	var dbgState logic.DebugState

	var state cdtState

	// Debugger notifications processing loop
	go func() {
		for {
			select {
			case notification := <-notifications:
				log.Printf("received: %s\n", notification.Event)
				switch notification.Event {
				case "registered":
					// no mutex, the access already synchronized by "registred" chan
					dbgState = notification.DebugState
					registred <- struct{}{}
				case "completed":
					// if completed we still want to see updated state
					state.completed.SetTo(true)
					close(notifications)
					fallthrough
				case "updated":
					dbgStateMu.Lock()
					dbgState = notification.DebugState
					dbgStateMu.Unlock()
					cdtUpdatedCh <- struct{}{}
				default:
					log.Println("Unk event: " + notification.Event)
				}
			case <-closed:
				return
			}
			if state.completed.IsSet() {
				return
			}
		}
	}()

	// wait until initial "registred" event
	<-registred

	func() {
		dbgStateMu.Lock()
		defer dbgStateMu.Unlock()

		lines := strings.Split(dbgState.Disassembly, "\n")
		s.initBreakpoints(len(lines))

		// set immutable items
		state.Init(dbgState.Disassembly, dbgState.Proto, dbgState.TxnGroup, dbgState.GroupIndex)
		// mutable
		state.Update(0, 1, dbgState.Stack, dbgState.Scratch, "")
	}()

	// Chrome Devtools reader
	go func() {
		for {
			var cdtReq ChromeRequest
			mtype, reader, err := ws.NextReader()
			if err != nil {
				log.Println(err.Error())
				closed <- struct{}{}
				close(closed)
				return
			}
			if mtype != websocket.TextMessage {
				log.Printf("Unexpected type: %d\n", mtype)
				continue
			}
			msg := make([]byte, 64000)
			n, err := reader.Read(msg)
			if err != nil {
				log.Println(err.Error())
				closed <- struct{}{}
				close(closed)
				return
			}
			json.Unmarshal(msg[:n], &cdtReq)
			log.Printf("%v\n", cdtReq)

			dbgStateMu.Lock()
			cdtResp, events, err := s.handleCDTRequest(&cdtReq, &state)
			dbgStateMu.Unlock()
			if err != nil {
				log.Println(err.Error())
				continue
			}
			cdtRespCh <- cdtResp
			for _, event := range events {
				cdtEventCh <- event
			}
		}
	}()

	// Chrome Devtools writer
	go func() {
		for {
			select {
			case devtoolResp := <-cdtRespCh:
				log.Printf("responsing: %v\n", devtoolResp)
				err := ws.WriteJSON(&devtoolResp)
				if err != nil {
					log.Println(err.Error())
					return
				}
			case devtoolEv := <-cdtEventCh:
				log.Printf("firing: %v\n", devtoolEv)
				err := ws.WriteJSON(&devtoolEv)
				if err != nil {
					log.Println(err.Error())
					return
				}
			case <-cdtUpdatedCh:
				dbgStateMu.Lock()
				state.Update(dbgState.PC, dbgState.Line, dbgState.Stack, dbgState.Scratch, dbgState.Error)
				dbgStateMu.Unlock()

				event := s.computeEvent(&state)
				cdtEventCh <- event
			case <-closed:
				return
			}
		}
	}()

	<-closed

	// handle CDT window closing without resuming execution
	// resume and consume a final "completed" notification
	if !state.completed.IsSet() {
		s.debugger.Resume()
		defer func() {
			for {
				select {
				case <-notifications:
					return
				}
			}
		}()
	}
}

func (s *cdtSession) handleCDTRequest(req *ChromeRequest, state *cdtState) (response ChromeResponse, events []interface{}, err error) {
	empty := make(map[string]interface{})
	switch req.Method {
	case "Debugger.enable":
		evCtxCreated := s.makeContextCreatedEvent()
		evParsed := s.makeScriptParsedEvent(state)
		events = append(events, &evCtxCreated, &evParsed)

		debuggerID := make(map[string]string)
		debuggerID["debuggerId"] = s.uuid
		response = ChromeResponse{ID: req.ID, Result: debuggerID}
	case "Runtime.runIfWaitingForDebugger":
		evPaused := s.makeDebuggerPausedEvent(state)
		events = append(events, &evPaused)
		response = ChromeResponse{ID: req.ID, Result: empty}
	case "Runtime.getIsolateId":
		isolateID := make(map[string]string)
		isolateID["id"] = s.uuid
		response = ChromeResponse{ID: req.ID, Result: isolateID}
	case "Debugger.getScriptSource":
		p := req.Params.(map[string]interface{})
		_, ok := p["scriptId"]
		source := make(map[string]string)
		if !ok {
			err = fmt.Errorf("getScriptSource failed: no scriptId")
			return
		}
		source["scriptSource"] = state.program
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
		state.pauseOnError.SetTo(enable)
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
		descr, err = state.getObjectDescriptor(objID, preview)
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
		log.Printf("Descr object: %s", string(data))

		result := map[string][]RuntimePropertyDescriptor{
			"result": descr,
		}
		response = ChromeResponse{ID: req.ID, Result: result}
	case "Debugger.setBreakpointsActive":
		p := req.Params.(map[string]interface{})
		activeRaw, ok := p["active"]
		active := false
		if ok {
			if value, ok := activeRaw.(bool); ok && value {
				active = true
			}
		}
		log.Printf("Setting all bpx to %v\n", active)
		for i := 0; i < len(s.breakpoints); i++ {
			if s.breakpoints[i].NonEmpty() {
				s.breakpoints[i].active = active
				log.Printf("Set %d to %v\n", i, active)
			}
		}
		if !active {
			s.debugger.RemoveBreakpoint(0)
		}

		response = ChromeResponse{ID: req.ID, Result: empty}
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
		if bpLine < 0 || bpLine >= len(s.breakpoints) {
			err = fmt.Errorf("invalid bp line %d", bpLine)
			return
		}
		if s.breakpoints[bpLine].NonEmpty() {
			s.debugger.RemoveBreakpoint(0)
			s.breakpoints[bpLine] = breakpointState{}
		}
		response = ChromeResponse{ID: req.ID, Result: empty}
	case "Debugger.setBreakpointByUrl":
		p := req.Params.(map[string]interface{})
		bpLine := int(p["lineNumber"].(float64))
		lines := strings.Split(state.program, "\n")
		if bpLine >= len(lines) {
			err = fmt.Errorf("invalid bp line %d", bpLine)
			return
		}
		s.breakpoints[bpLine] = breakpointState{set: true, active: true}
		s.debugger.SetBreakpointAtLine(bpLine)

		result := make(map[string]interface{})
		result["breakpointId"] = strconv.Itoa(bpLine)
		result["locations"] = []DebuggerLocation{
			DebuggerLocation{ScriptID: s.scriptID, LineNumber: bpLine},
		}
		response = ChromeResponse{ID: req.ID, Result: result}
	case "Debugger.resume":
		currentLine := state.line.Load()
		if currentLine < len(s.breakpoints) {
			for line, bpState := range s.breakpoints[currentLine+1:] {
				if bpState.set && bpState.active {
					s.debugger.SetBreakpointAtLine(line + currentLine + 1)
					break
				}
			}
		}
		state.lastAction.Store("resume")
		s.debugger.Resume()
		if state.completed.IsSet() {
			evDestroyed := s.makeContextDestroyedEvent()
			events = append(events, &evDestroyed)
		}
		response = ChromeResponse{ID: req.ID, Result: empty}
	case "Debugger.stepOver", "Debugger.stepInto", "Debugger.stepOut":
		s.debugger.SetBreakpointAtLine(state.line.Load() + 1)
		s.debugger.Resume()
		state.line.Add(1)
		state.lastAction.Store("step")
		if state.completed.IsSet() {
			evDestroyed := s.makeContextDestroyedEvent()
			events = append(events, &evDestroyed)
		}
		response = ChromeResponse{ID: req.ID, Result: empty}
	default:
		response = ChromeResponse{ID: req.ID, Result: empty}
	}

	return
}

func (s *cdtSession) computeEvent(state *cdtState) (event interface{}) {
	if state.completed.IsSet() && state.pauseOnError.IsSet() && state.err.Length() != 0 {
		event = s.makeDebuggerPausedEvent(state)
	} else if state.completed.IsSet() && state.lastAction.Load() == "resume" {
		event = s.makeContextDestroyedEvent()
	} else {
		event = s.makeDebuggerPausedEvent(state)
	}
	return
}

func (s *cdtSession) makeScriptParsedEvent(state *cdtState) DebuggerScriptParsedEvent {
	// {"method":"Debugger.scriptParsed","params":{"scriptId":"69","url":"internal/dtrace.js","startLine":0,"startColumn":0,"endLine":21,"endColumn":0,"executionContextId":1,"hash":"2e8fbf2f9f6aaa183be557d25f5fbc5b09fae00a","executionContextAuxData":{"isDefault":true},"isLiveEdit":false,"sourceMapURL":"","hasSourceURL":false,"isModule":false,"length":568,"stackTrace":{"callFrames":[{"functionName":"NativeModule.compile","scriptId":"7","url":"internal/bootstrap/loaders.js","lineNumber":298,"columnNumber":15}]}}}
	hash := sha256.Sum256([]byte(state.program)) // some random hash
	progLines := strings.Count(state.program, "\n")
	length := len(state.program)

	evParsed := DebuggerScriptParsedEvent{
		Method: "Debugger.scriptParsed",
		Params: DebuggerScriptParsedParams{
			ScriptID:           s.scriptID,
			URL:                "file://program.teal.js",
			StartLine:          0,
			StartColumn:        0,
			EndLine:            progLines,
			EndColumn:          0,
			ExecutionContextID: s.contextID,
			Hash:               hex.EncodeToString(hash[:]),
			IsLiveEdit:         false,
			Length:             length,
		},
	}
	return evParsed
}

func (s *cdtSession) makeDebuggerPausedEvent(state *cdtState) DebuggerPausedEvent {
	progLines := strings.Count(state.program, "\n")

	scopeLocal := DebuggerScope{
		Type: "local",
		Object: RuntimeRemoteObject{
			Type:        "object",
			ClassName:   "Object",
			Description: "Object",
			ObjectID:    localScopeObjID,
		},
		StartLocation: &DebuggerLocation{
			ScriptID:     s.scriptID,
			LineNumber:   0,
			ColumnNumber: 0,
		},
		EndLocation: &DebuggerLocation{
			ScriptID:     s.scriptID,
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
			ScriptID:     s.scriptID,
			LineNumber:   state.line.Load(),
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

	if lastError := state.err.Load(); len(lastError) != 0 {
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

func (s *cdtSession) makeContextCreatedEvent() RuntimeExecutionContextCreatedEvent {
	// {"method":"Runtime.executionContextCreated","params":{"context":{"id":1,"origin":"","name":"node[47576]","auxData":{"isDefault":true}}}}

	aux := make(map[string]interface{})
	aux["isDefault"] = true
	evCtxCreated := RuntimeExecutionContextCreatedEvent{
		Method: "Runtime.executionContextCreated",
		Params: RuntimeExecutionContextCreatedParams{
			Context: RuntimeExecutionContextDescription{
				ID:      s.contextID,
				Origin:  "",
				Name:    "TEAL program",
				AuxData: map[string]interface{}{"isDefault": true},
			},
		},
	}
	return evCtxCreated
}

func (s *cdtSession) makeContextDestroyedEvent() RuntimeExecutionContextDestroyedEvent {
	return RuntimeExecutionContextDestroyedEvent{
		Method: "Runtime.executionContextDestroyed",
		Params: RuntimeExecutionContextDestroyedParams{s.contextID},
	}
}
