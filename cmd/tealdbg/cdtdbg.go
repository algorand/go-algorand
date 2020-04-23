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
	"log"
	"net/http"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/gorilla/mux"
)

// CDTAdapter is Chrome DevTools frontend
type CDTAdapter struct {
	mu         deadlock.Mutex
	sessions   map[string]cdtSession
	router     *mux.Router
	apiAddress string
}

// CDTSetupParams for Setup
type CDTSetupParams struct {
	router     *mux.Router
	apiAddress string
}

// MakeCDTAdapter creates new CDTAdapter
func MakeCDTAdapter(ctx interface{}) (a *CDTAdapter) {
	params, ok := ctx.(*CDTSetupParams)
	if !ok {
		panic("CDTAdapter.Setup expected CDTSetupParams")
	}

	a = new(CDTAdapter)

	a.sessions = make(map[string]cdtSession)
	a.router = params.router
	a.apiAddress = params.apiAddress

	a.router.HandleFunc("/json/version", a.versionHandler).Methods("GET")
	a.router.HandleFunc("/json", a.jsonHandler).Methods("GET")
	a.router.HandleFunc("/json/list", a.jsonHandler).Methods("GET")

	return a
}

// SessionStarted registers new session
func (a *CDTAdapter) SessionStarted(sid string, debugger Control, ch chan Notification) {
	s := makeCDTSession(sid, debugger, ch)

	a.mu.Lock()
	defer a.mu.Unlock()

	s.endpoint = a.enableWebsocketEndpoint(sid, a.apiAddress, s.websocketHandler)

	a.sessions[sid] = *s
}

// SessionEnded removes the session
func (a *CDTAdapter) SessionEnded(sid string) {
	go func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		s := a.sessions[sid]
		<-s.done
		delete(a.sessions, sid)
		log.Printf("CDT session %s closed\n", sid)
	}()
}

// WaitForCompletion returns when no active connections left
func (a *CDTAdapter) WaitForCompletion() {
	for {
		a.mu.Lock()
		active := len(a.sessions)
		a.mu.Unlock()
		if active == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// must be called with rctx.mux locked
func (a *CDTAdapter) enableWebsocketEndpoint(uuid string, apiAddress string, handler func(http.ResponseWriter,
	*http.Request)) cdtTabDescription {
	address := apiAddress + "/" + uuid
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

	a.router.HandleFunc("/"+uuid, handler)

	log.Println("------------------------------------------------")
	log.Printf("CDT debugger listening on: %s", desc.WebSocketDebuggerURL)
	log.Printf("Or open in Chrome:")
	log.Printf("%s", desc.DevtoolsFrontendURL)
	log.Println("------------------------------------------------")

	return desc
}

func (a *CDTAdapter) versionHandler(w http.ResponseWriter, r *http.Request) {
	type devtoolsVersion struct {
		Browser         string `json:"Browser"`
		ProtocolVersion string `json:"Protocol-Version"`
	}

	version := devtoolsVersion{Browser: "teal dbg", ProtocolVersion: "1.1"}
	enc, err := json.Marshal(version)
	if err != nil {
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(enc)
	return
}

func (a *CDTAdapter) jsonHandler(w http.ResponseWriter, r *http.Request) {
	tabs := make([]cdtTabDescription, 0, len(a.sessions))

	func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, s := range a.sessions {
			tabs = append(tabs, s.endpoint)
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
