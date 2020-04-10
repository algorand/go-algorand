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
	Event         string              `json:"event"`
	DebuggerState logic.DebuggerState `json:"state"`
}

type requestContext struct {
	// Prevent races when accessing maps
	mux deadlock.Mutex

	// Receive registration, update, and completed notifications from TEAL
	notifications chan Notification

	// Last subscription ID used for notifications broadcasts to web clients
	maxSubID uint64

	// Broadcast notifications to all web clients over their respective channels
	subscriptions map[uint64]chan Notification

	// State stored per execution
	execContexts map[ExecID]execContext

	// Listening address, needed dynamic endpoints for Devtools inspector protocol
	apiAddress string

	// Registered API endpoints for debug sessions
	endpoints map[ExecID]struct{}

	// Router for API endpoints registration
	router *mux.Router
}

var execContextCounter int32 = 0

func (rctx *requestContext) register(state logic.DebuggerState) {
	var exec execContext

	// Allocate a default debugConfig (don't break)
	exec.debugConfig = debugConfig{
		BreakOnPC: -1,
	}

	exec.execContextID = atomic.AddInt32(&execContextCounter, 1)

	// Allocate an acknowledgement channel
	exec.acknowledged = make(chan bool)

	// Store the state for this execution
	rctx.mux.Lock()
	rctx.execContexts[ExecID(state.ExecID)] = exec
	rctx.mux.Unlock()

	// Inform the user to configure execution
	rctx.notifications <- Notification{"registered", state}

	fmt.Printf("register wait for ack\n")

	// Wait for acknowledgement
	<-exec.acknowledged
}

func (rctx *requestContext) registerHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a logic.DebuggerState from the request
	var state logic.DebuggerState
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
	var state logic.DebuggerState
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
				rctx.notifications <- Notification{"updated", state}
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
	var state logic.DebuggerState
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&state)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Inform the user
	rctx.notifications <- Notification{"completed", state}

	// Clean up exec-specific state
	rctx.mux.Lock()
	delete(rctx.execContexts, ExecID(state.ExecID))
	rctx.mux.Unlock()

	// Proceed!
	w.WriteHeader(http.StatusOK)
	return
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

func (rctx *requestContext) devtoolsVersionHandler(w http.ResponseWriter, r *http.Request) {
	version := devtoolsVersion{Browser: "teal dbg", ProtocolVersion: "1.1"}
	enc, err := json.Marshal(version)
	if err != nil {
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(enc)
	return
}

type devtoolsTabDescription struct {
	Description               string `json:"description"`
	DevtoolsFrontendURL       string `json:"devtoolsFrontendUrl"`
	ID                        string `json:"id"`
	Title                     string `json:"title"`
	TabType                   string `json:"type"`
	URL                       string `json:"url"`
	WebSocketDebuggerURL      string `json:"webSocketDebuggerUrl"`
	DevtoolsFrontendURLCompat string `json:"devtoolsFrontendUrlCompat"`
	FaviconURL                string `json:"faviconUrl"`
}

func (rctx *requestContext) devtoolsJSONHandler(w http.ResponseWriter, r *http.Request) {
	tabList := make([]devtoolsTabDescription, 0, len(rctx.execContexts))
	for execID := range rctx.execContexts {
		uuid := string(execID)
		address := rctx.apiAddress + "/" + uuid
		desc := devtoolsTabDescription{
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
		tabList = append(tabList, desc)
		if _, ok := rctx.endpoints[execID]; !ok {
			rctx.router.HandleFunc("/"+uuid, rctx.devtoolsWsHandler)
			rctx.endpoints[execID] = struct{}{}
		}
	}
	enc, err := json.Marshal(tabList)
	if err != nil {
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(enc)
	return
}

func (rctx *requestContext) broadcastNotifications() {
	for {
		if len(rctx.subscriptions) == 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		select {
		case notification := <-rctx.notifications:
			rctx.mux.Lock()
			for _, ch := range rctx.subscriptions {
				select {
				case ch <- notification:
				default:
				}
			}
			rctx.mux.Unlock()
		}
	}
}

func (rctx *requestContext) registerNotifications() (uint64, chan Notification) {
	rctx.mux.Lock()
	defer rctx.mux.Unlock()
	rctx.maxSubID++
	notifications := make(chan Notification)
	rctx.subscriptions[rctx.maxSubID] = notifications
	return rctx.maxSubID, notifications
}

func (rctx *requestContext) unregisterNotifications(id uint64) {
	rctx.mux.Lock()
	defer rctx.mux.Unlock()
	delete(rctx.subscriptions, id)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  10240,
	WriteBufferSize: 10240,
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

	subid, notifications := rctx.registerNotifications()
	defer rctx.unregisterNotifications(subid)

	// Wait on notifications and forward to the user
	for {
		select {
		case notification := <-notifications:
			fmt.Printf("received: %v\n", notification)
			err := ws.WriteJSON(&notification)
			if err != nil {
				return
			}
		}
	}
}

func (rctx *requestContext) devtoolsWsHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	uuid := r.URL.Path
	if uuid[0] == '/' {
		uuid = uuid[1:]
	}
	exec, ok := rctx.execContexts[ExecID(uuid)]
	if !ok {
		return
	}

	subid, notifications := rctx.registerNotifications()
	defer rctx.unregisterNotifications(subid)

	cdtRespCh := make(chan ChromeResponse, 128)
	cdtEventCh := make(chan interface{}, 128)
	cdtUpdatedCh := make(chan interface{}, 1)

	done := make(chan struct{})
	registred := make(chan struct{})

	var dbgStateMu sync.Mutex
	var dbgState logic.DebuggerState

	// Debugger notifications processing loop
	go func() {
		for {
			select {
			case notification := <-notifications:
				switch notification.Event {
				case "completed":
					evCxtDestroyed := RuntimeExecutionContextDestroyedEvent{
						Method: "Runtime.executionContextDestroyed",
						Params: RuntimeExecutionContextDestroyedParams{int(exec.execContextID)},
					}
					cdtEventCh <- &evCxtDestroyed
					done <- struct{}{}
					close(done)
				case "registered":
					// no mutex, the access already synchronized by "registred" chan
					dbgState = notification.DebuggerState
					registred <- struct{}{}
				case "updated":
					dbgStateMu.Lock()
					dbgState = notification.DebuggerState
					dbgStateMu.Unlock()
					cdtUpdatedCh <- struct{}{}
				default:
					fmt.Println("Unk event: " + notification.Event)
				}
			}
		}
	}()

	// wait until initial "registred" event
	<-registred

	dbgStateMu.Lock()
	cdtd := cdtDebugger{
		uuid:        uuid,
		rctx:        rctx,
		contextID:   int(exec.execContextID),
		scriptID:    "52",
		program:     dbgState.Disassembly,
		offsets:     dbgState.PCOffset,
		lines:       strings.Split(dbgState.Disassembly, "\n"),
		currentLine: 1,
		// execution environment
		txnGroup:   dbgState.TxnGroup,
		groupIndex: dbgState.GroupIndex,
		stack:      dbgState.Stack,
		scratch:    dbgState.Scratch,
	}
	dbgStateMu.Unlock()
	// Chrome Devtools reader
	go func() {
		for {
			var cdtReq ChromeRequest
			mtype, reader, err := ws.NextReader()
			if err != nil {
				fmt.Println(err.Error())
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
				return
			}
			json.Unmarshal(msg[:n], &cdtReq)
			fmt.Printf("%v\n", cdtReq)

			dbgStateMu.Lock()
			cdtResp, err := cdtd.handleCDTRequest(&cdtReq)
			dbgStateMu.Unlock()
			if err == nil {
				cdtRespCh <- cdtResp
			} else {
				fmt.Println(err.Error())
			}
			// some messages change processing state
			switch cdtReq.Method {
			case "Debugger.enable":
				evCtxCreated := cdtd.makeContextCreatedEvent()
				evParsed := cdtd.makeScriptParsedEvent()
				cdtEventCh <- &evCtxCreated
				cdtEventCh <- &evParsed
			case "Runtime.runIfWaitingForDebugger":
				evPaused := cdtd.makeDebuggerPausedEvent()
				cdtEventCh <- &evPaused
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
				cdtd.currentLine = cdtd.pcToLine(dbgState.PC)
				cdtd.stack = dbgState.Stack
				cdtd.scratch = dbgState.Scratch
				dbgStateMu.Unlock()
				evPaused := cdtd.makeDebuggerPausedEvent()
				cdtEventCh <- &evPaused
			case <-done:
				return
			}
		}
	}()

	<-done
}

func main() {
	router := mux.NewRouter()

	appAddress := "localhost:9392"

	rctx := requestContext{
		mux:           deadlock.Mutex{},
		notifications: make(chan Notification),
		subscriptions: make(map[uint64]chan Notification),
		execContexts:  make(map[ExecID]execContext),
		apiAddress:    appAddress,
		endpoints:     make(map[ExecID]struct{}),
		router:        router,
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
	router.HandleFunc("/json/version", rctx.devtoolsVersionHandler).Methods("GET")
	router.HandleFunc("/json", rctx.devtoolsJSONHandler).Methods("GET")
	router.HandleFunc("/json/list", rctx.devtoolsJSONHandler).Methods("GET")

	// Websocket requests from client
	router.HandleFunc("/ws", rctx.subscribeHandler)

	server := http.Server{
		Handler:      router,
		Addr:         appAddress,
		WriteTimeout: time.Duration(0),
		ReadTimeout:  time.Duration(0),
	}

	go rctx.broadcastNotifications()

	log.Printf("starting server on %s", appAddress)
	server.ListenAndServe()
}
