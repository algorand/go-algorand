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
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/websocket"
	"github.com/gorilla/mux"

	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-deadlock"
)

// ExecID is a unique execution ID
type ExecID string

type debugConfig struct {
	// If -1, don't break
	BreakOnPC int `json:"breakonpc"`
}

type execContext struct {
	// Reply to registration/update when bool received on acknolwedgement
	// channel, allowing program execution to continue
	acknowledged chan bool

	// debugConfigs holds information about this debugging session,
	// currently just when we want to break
	debugConfig debugConfig

	// devtools context id
	execContextID int32

	// notifications from eval
	notifications chan Notification
}

// ConfigRequest tells us what breakpoints to hit, if any
type ConfigRequest struct {
	debugConfig
	ExecID ExecID `json:"execid"`
}

// ContinueRequest tells a particular execution to continue
type ContinueRequest struct {
	ExecID ExecID `json:"execid"`
}

// Notification is sent to the client over their websocket connection
// on each new TEAL execution/update/complation
type Notification struct {
	Event      string           `json:"event"`
	DebugState logic.DebugState `json:"state"`
}

type requestContext struct {
	// Prevent races when accessing maps
	mux deadlock.Mutex

	// Last subscription ID used for notifications broadcasts to web clients
	maxSubID uint64

	// State stored per execution
	execContexts map[ExecID]execContext

	// Listening address, needed dynamic endpoints for Devtools inspector protocol
	apiAddress string

	// Registered API endpoints for debug sessions
	endpoints map[ExecID]cdtTabDescription

	// Router for API endpoints registration
	router *mux.Router
}

var execContextCounter int32 = 0

func (rctx *requestContext) register(state logic.DebugState) {
	var exec execContext

	// Allocate a default debugConfig (don't break)
	exec.debugConfig = debugConfig{
		BreakOnPC: -1,
	}

	exec.execContextID = atomic.AddInt32(&execContextCounter, 1)

	// Allocate an acknowledgement channel
	exec.acknowledged = make(chan bool)
	exec.notifications = make(chan Notification)

	// Store the state for this execution
	rctx.mux.Lock()
	rctx.execContexts[ExecID(state.ExecID)] = exec
	rctx.addCDTEndpoint(ExecID(state.ExecID))
	rctx.mux.Unlock()

	// Inform the user to configure execution
	exec.notifications <- Notification{"registered", state}

	// Wait for acknowledgement
	<-exec.acknowledged
}

func (rctx *requestContext) registerHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a logic.DebuggerState from the request
	var state logic.DebugState
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&state)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Register, and wait for user to acknowledge registration
	rctx.register(state)

	// Proceed!
	w.WriteHeader(http.StatusBadRequest)
	return
}

func (rctx *requestContext) updateHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a logic.DebuggerState from the request
	var state logic.DebugState
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&state)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Grab execution context
	exec, ok := rctx.fetchExecContext(ExecID(state.ExecID))
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	go func() {
		// Check if we are triggered and acknolwedge asynchronously
		cfg := exec.debugConfig
		if cfg.BreakOnPC != -1 {
			if cfg.BreakOnPC == 0 || state.PC == cfg.BreakOnPC {
				// Breakpoint hit! Inform the user
				exec.notifications <- Notification{"updated", state}
			} else {
				// Continue if we haven't hit the next breakpoint
				exec.acknowledged <- true
			}
		} else {
			// User won't send acknowledement, so we will
			exec.acknowledged <- true
		}
	}()

	// Let TEAL continue when acknowledged
	<-exec.acknowledged
	w.WriteHeader(http.StatusOK)
	return
}

func (rctx *requestContext) fetchExecContext(eid ExecID) (execContext, bool) {
	rctx.mux.Lock()
	defer rctx.mux.Unlock()
	exec, ok := rctx.execContexts[eid]
	return exec, ok
}

func (rctx *requestContext) completeHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a logic.DebuggerState from the request
	var state logic.DebugState
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&state)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	exec, ok := rctx.execContexts[ExecID(state.ExecID)]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Inform the user
	exec.notifications <- Notification{"completed", state}

	// Clean up exec-specific state
	rctx.mux.Lock()
	delete(rctx.execContexts, ExecID(state.ExecID))
	rctx.removeCDTEndpoint(ExecID(state.ExecID))
	rctx.mux.Unlock()

	// Proceed!
	w.WriteHeader(http.StatusOK)
	return
}

func (rctx *requestContext) delBreakpoint(execID ExecID) error {
	exec, ok := rctx.fetchExecContext(execID)
	if !ok {
		return fmt.Errorf("no such exec id: %s", execID)
	}

	// Update the config
	exec.debugConfig = debugConfig{BreakOnPC: -1}

	// Write the config
	rctx.mux.Lock()
	rctx.execContexts[execID] = exec
	rctx.mux.Unlock()

	return nil
}

func (rctx *requestContext) setBreakpoint(execID ExecID, pc int) error {
	exec, ok := rctx.fetchExecContext(execID)
	if !ok {
		return fmt.Errorf("no such exec id: %s", execID)
	}

	// Update the config
	exec.debugConfig = debugConfig{BreakOnPC: pc}

	// Write the config
	rctx.mux.Lock()
	rctx.execContexts[execID] = exec
	rctx.mux.Unlock()

	return nil
}

func (rctx *requestContext) configHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a ConfigRequest
	var req ConfigRequest
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Ensure that we are trying to configure an execution we know about
	exec, ok := rctx.fetchExecContext(req.ExecID)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Update the config
	exec.debugConfig = req.debugConfig

	// Write the config
	rctx.mux.Lock()
	rctx.execContexts[ExecID(req.ExecID)] = exec
	rctx.mux.Unlock()

	w.WriteHeader(http.StatusOK)
	return
}

func (rctx *requestContext) resume(execID ExecID) error {
	exec, ok := rctx.fetchExecContext(execID)
	if !ok {
		return fmt.Errorf("no such exec id: %s", execID)
	}

	// Try to continue
	select {
	case exec.acknowledged <- true:
	default:
	}

	return nil
}

func (rctx *requestContext) continueHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a ContinueRequest
	var req ContinueRequest
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err = rctx.resume(req.ExecID); err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	return
}

func (rctx *requestContext) homeHandler(w http.ResponseWriter, r *http.Request) {
	home, err := template.New("home").Parse(homepage)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	home.Execute(w, nil)
	return
}

type devtoolsVersion struct {
	Browser         string `json:"Browser"`
	ProtocolVersion string `json:"Protocol-Version"`
}

func (rctx *requestContext) cdtVersionHandler(w http.ResponseWriter, r *http.Request) {
	version := devtoolsVersion{Browser: "teal dbg", ProtocolVersion: "1.1"}
	enc, err := json.Marshal(version)
	if err != nil {
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(enc)
	return
}

func (rctx *requestContext) removeCDTEndpoint(execID ExecID) {
	if _, ok := rctx.endpoints[execID]; !ok {
		return
	}
	delete(rctx.endpoints, execID)
}

// must be called with rctx.mux locked
func (rctx *requestContext) addCDTEndpoint(execID ExecID) {
	if _, ok := rctx.endpoints[execID]; ok {
		return
	}
	uuid := string(execID)
	address := rctx.apiAddress + "/" + uuid
	desc := cdtTabDescription{
		Description:               "",
		ID:                        uuid,
		Title:                     "Algorand TEAL program",
		TabType:                   "node",
		URL:                       "https://algorand.com/",
		DevtoolsFrontendURL:       "chrome-devtools://devtools/bundled/js_app.html?experiments=true&v8only=false&ws=" + address,
		DevtoolsFrontendURLCompat: "chrome-devtools://devtools/bundled/inspector.html?experiments=true&v8only=false&ws=" + address,
		WebSocketDebuggerURL:      "ws://" + address,
		FaviconURL:                "https://www.algorand.com/icons/icon-144x144.png",
	}

	rctx.router.HandleFunc("/"+uuid, rctx.cdtWsHandler)
	rctx.endpoints[execID] = desc

	fmt.Printf("Debugger listening on: %s\n", desc.WebSocketDebuggerURL)
	fmt.Printf("Or open in Chrome:\n%s\n", desc.DevtoolsFrontendURL)
}

func (rctx *requestContext) cdtJSONHandler(w http.ResponseWriter, r *http.Request) {
	tabs := make([]cdtTabDescription, 0, len(rctx.execContexts))

	func() {
		rctx.mux.Lock()
		defer rctx.mux.Unlock()
		for _, desc := range rctx.endpoints {
			tabs = append(tabs, desc)
		}
	}()

	enc, err := json.Marshal(tabs)
	if err != nil {
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(enc)
	return
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  10240,
	WriteBufferSize: 10240,
	CheckOrigin: func(r *http.Request) bool {
		if len(r.Header.Get("Origin")) == 0 {
			return true
		}
		if strings.HasPrefix(r.Header.Get("Origin"), "devtools://") {
			return true
		}
		return false
	},
}

func (rctx *requestContext) subscribeHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	// Acknowledge connection
	event := Notification{
		Event: "connected",
	}
	err = ws.WriteJSON(&event)
	if err != nil {
		return
	}

	var notifications chan Notification
	rctx.mux.Lock()
	for _, exec := range rctx.execContexts {
		notifications = exec.notifications
	}
	rctx.mux.Unlock()

	// Wait on notifications and forward to the user
	for {
		select {
		case notification := <-notifications:
			err := ws.WriteJSON(&notification)
			if err != nil {
				return
			}
		}
	}
}

func (rctx *requestContext) cdtWsHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("Error on connection upgrade: %v\n", err)
		return
	}
	defer ws.Close()

	uuid := r.URL.Path
	if uuid[0] == '/' {
		uuid = uuid[1:]
	}
	exec, ok := rctx.execContexts[ExecID(uuid)]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	notifications := exec.notifications

	cdtRespCh := make(chan ChromeResponse, 128)
	cdtEventCh := make(chan interface{}, 128)
	cdtUpdatedCh := make(chan interface{}, 1)

	closed := make(chan struct{})
	registred := make(chan struct{})

	completed := false

	var dbgStateMu sync.Mutex
	var dbgState logic.DebugState

	// Debugger notifications processing loop
	go func() {
		for {
			select {
			case notification := <-notifications:
				fmt.Printf("received: %s\n", notification.Event)
				switch notification.Event {
				case "registered":
					// no mutex, the access already synchronized by "registred" chan
					dbgState = notification.DebugState
					registred <- struct{}{}
				case "completed":
					// if completed we still want to see updated state
					completed = true
					close(notifications)
					fallthrough
				case "updated":
					dbgStateMu.Lock()
					dbgState = notification.DebugState
					dbgStateMu.Unlock()
					cdtUpdatedCh <- struct{}{}
				default:
					fmt.Println("Unk event: " + notification.Event)
				}
			case <-closed:
				return
			}
			if completed {
				return
			}
		}
	}()

	// wait until initial "registred" event
	<-registred

	dbgStateMu.Lock()
	lines := strings.Split(dbgState.Disassembly, "\n")
	cdtd := cdtDebugger{
		uuid:        uuid,
		rctx:        rctx,
		contextID:   int(exec.execContextID),
		scriptID:    "52",
		breakpoints: make([]breakpointState, len(lines)),
		program:     dbgState.Disassembly,
		offsets:     dbgState.PCOffset,
		lines:       lines,
		currentLine: 1,
		// execution environment
		txnGroup:   dbgState.TxnGroup,
		groupIndex: dbgState.GroupIndex,
		stack:      dbgState.Stack,
		scratch:    dbgState.Scratch,
		proto:      dbgState.Proto,
	}
	dbgStateMu.Unlock()
	// Chrome Devtools reader
	go func() {
		for {
			var cdtReq ChromeRequest
			mtype, reader, err := ws.NextReader()
			if err != nil {
				fmt.Println(err.Error())
				closed <- struct{}{}
				close(closed)
				return
			}
			if mtype != websocket.TextMessage {
				fmt.Printf("Unexpected type: %d\n", mtype)
				continue
			}
			msg := make([]byte, 64000)
			n, err := reader.Read(msg)
			if err != nil {
				fmt.Println(err.Error())
				closed <- struct{}{}
				close(closed)
				return
			}
			json.Unmarshal(msg[:n], &cdtReq)
			fmt.Printf("%v\n", cdtReq)

			dbgStateMu.Lock()
			cdtResp, events, err := cdtd.handleCDTRequest(&cdtReq, completed)
			dbgStateMu.Unlock()
			if err != nil {
				fmt.Println(err.Error())
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
				fmt.Printf("responsing: %v\n", devtoolResp)
				err := ws.WriteJSON(&devtoolResp)
				if err != nil {
					fmt.Println(err.Error())
					return
				}
			case devtoolEv := <-cdtEventCh:
				fmt.Printf("firing: %v\n", devtoolEv)
				err := ws.WriteJSON(&devtoolEv)
				if err != nil {
					fmt.Println(err.Error())
					return
				}
			case <-cdtUpdatedCh:
				dbgStateMu.Lock()
				line := cdtd.pcToLine(dbgState.PC)
				if completed {
					line++
				}
				cdtd.err.Store(dbgState.Error)
				atomic.StoreUint32(&cdtd.currentLine, line)
				cdtd.stack = dbgState.Stack
				cdtd.scratch = dbgState.Scratch
				dbgStateMu.Unlock()

				event := cdtd.computeEvent(completed)
				cdtEventCh <- event
			case <-closed:
				return
			}
		}
	}()

	<-closed

	// handle CDT window closing without resuming execution
	// resume and consume a final "completed" notification
	if !completed {
		rctx.resume(ExecID(uuid))
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

func main() {
	router := mux.NewRouter()

	appAddress := "localhost:9392"

	rctx := requestContext{
		mux:          deadlock.Mutex{},
		execContexts: make(map[ExecID]execContext),
		apiAddress:   appAddress,
		endpoints:    make(map[ExecID]cdtTabDescription),
		router:       router,
	}

	// Requests from TEAL evaluator
	router.HandleFunc("/exec/register", rctx.registerHandler).Methods("POST")
	router.HandleFunc("/exec/update", rctx.updateHandler).Methods("POST")
	router.HandleFunc("/exec/complete", rctx.completeHandler).Methods("POST")

	// Requests from client
	router.HandleFunc("/", rctx.homeHandler).Methods("GET")
	router.HandleFunc("/exec/config", rctx.configHandler).Methods("POST")
	router.HandleFunc("/exec/continue", rctx.continueHandler).Methods("POST")

	// Requests from Chrome Devtools
	router.HandleFunc("/json/version", rctx.cdtVersionHandler).Methods("GET")
	router.HandleFunc("/json", rctx.cdtJSONHandler).Methods("GET")
	router.HandleFunc("/json/list", rctx.cdtJSONHandler).Methods("GET")

	// Websocket requests from client
	router.HandleFunc("/ws", rctx.subscribeHandler)

	server := http.Server{
		Handler:      router,
		Addr:         appAddress,
		WriteTimeout: time.Duration(0),
		ReadTimeout:  time.Duration(0),
	}

	log.Printf("starting server on %s", appAddress)
	server.ListenAndServe()
}
