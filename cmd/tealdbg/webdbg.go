// Copyright (C) 2019-2021 Algorand, Inc.
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

//go:generate ./bundle_home_html.sh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-deadlock"
	"github.com/algorand/websocket"
	"github.com/gorilla/mux"
)

// WebPageFrontend is web page debugging frontend
type WebPageFrontend struct {
	mu         deadlock.Mutex
	sessions   map[string]wpaSession
	apiAddress string
	done       chan struct{}
}

type wpaSession struct {
	debugger      Control
	notifications chan Notification
}

// ExecID is a unique execution ID
type ExecID string

// ConfigRequest tells us what breakpoints to hit, if any
type ConfigRequest struct {
	debugConfig
	ExecID ExecID `json:"execid"`
}

// ContinueRequest tells a particular execution to continue
type ContinueRequest struct {
	ExecID ExecID `json:"execid"`
}

// WebPageFrontendParams initialization parameters
type WebPageFrontendParams struct {
	router     *mux.Router
	apiAddress string
}

// MakeWebPageFrontend creates new WebPageFrontend
func MakeWebPageFrontend(params *WebPageFrontendParams) (a *WebPageFrontend) {
	a = new(WebPageFrontend)
	a.sessions = make(map[string]wpaSession)
	a.apiAddress = params.apiAddress
	a.done = make(chan struct{})

	params.router.HandleFunc("/", a.homeHandler).Methods("GET")
	params.router.HandleFunc("/exec/step", a.stepHandler).Methods("POST")
	params.router.HandleFunc("/exec/config", a.configHandler).Methods("POST")
	params.router.HandleFunc("/exec/continue", a.continueHandler).Methods("POST")

	params.router.HandleFunc("/ws", a.subscribeHandler)

	return a
}

// SessionStarted registers new session
func (a *WebPageFrontend) SessionStarted(sid string, debugger Control, ch chan Notification) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.sessions[sid] = wpaSession{debugger, ch}

	log.Printf("Open http://%s in a web browser", a.apiAddress)
}

// SessionEnded removes the session
func (a *WebPageFrontend) SessionEnded(sid string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.sessions, sid)
}

// WaitForCompletion waits session to complete
func (a *WebPageFrontend) WaitForCompletion() {
	<-a.done
}

// URL returns an URL to access the latest debugging session
func (a *WebPageFrontend) URL() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.sessions) == 0 {
		return ""
	}

	return fmt.Sprintf("http://%s/", a.apiAddress)
}

func (a *WebPageFrontend) homeHandler(w http.ResponseWriter, r *http.Request) {
	home, err := template.New("home").Parse(homepage)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	home.Execute(w, nil)
	return
}

func (a *WebPageFrontend) stepHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a ConfigRequest
	var req ConfigRequest
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Ensure that we are trying to configure an execution we know about
	a.mu.Lock()
	s, ok := a.sessions[string(req.ExecID)]
	a.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	s.debugger.Step()

	w.WriteHeader(http.StatusOK)
	return
}

func (a *WebPageFrontend) configHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a ConfigRequest
	var req ConfigRequest
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Ensure that we are trying to configure an execution we know about
	a.mu.Lock()
	s, ok := a.sessions[string(req.ExecID)]
	a.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Extract PC from config
	line := req.debugConfig.BreakAtLine
	if line == noBreak {
		s.debugger.RemoveBreakpoint(int(line))
	} else {
		s.debugger.SetBreakpoint(int(line))
	}

	w.WriteHeader(http.StatusOK)
	return
}

func (a *WebPageFrontend) continueHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a ContinueRequest
	var req ContinueRequest
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	s, ok := a.sessions[string(req.ExecID)]
	a.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	s.debugger.Resume()

	w.WriteHeader(http.StatusOK)
	return
}

func (a *WebPageFrontend) subscribeHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		close(a.done)
	}()

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("subscribeHandler error: %s\n", err.Error())
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

	a.mu.Lock()
	// TODO: FIXME: subscribe proto needs be updated and subscribeHandler have to know session ID
	// for now take the first session. In most cases there is only one session.
	var notifications chan Notification
	for _, s := range a.sessions {
		notifications = s.notifications
		break
	}
	a.mu.Unlock()

	// Wait on notifications and forward to the user
	for {
		select {
		case notification := <-notifications:
			var data bytes.Buffer
			enc := protocol.NewJSONEncoder(&data)
			err := enc.Encode(notification)
			if err != nil {
				return
			}
			err = ws.WriteMessage(websocket.TextMessage, data.Bytes())
			if err != nil {
				return
			}
		}
	}
}
