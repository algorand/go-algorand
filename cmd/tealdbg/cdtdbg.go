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
	"net/http"
	"sync"

	"github.com/gorilla/mux"
)

// CDTAdapter is Chrome DevTools frontend
type CDTAdapter struct {
	mu         sync.Mutex
	sessions   map[string]cdtSession
	router     *mux.Router
	apiAddress string
}

// CDTSetupParams for Setup
type CDTSetupParams struct {
	router     *mux.Router
	apiAddress string
}

// Setup initialized the adapter
func (a *CDTAdapter) Setup(ctx interface{}) error {
	params, ok := ctx.(*CDTSetupParams)
	if !ok {
		return fmt.Errorf("CDTAdapter.Setup expected CDTSetupParams")
	}

	a.sessions = make(map[string]cdtSession)
	a.router = params.router
	a.apiAddress = params.apiAddress

	a.router.HandleFunc("/json/version", a.versionHandler).Methods("GET")
	a.router.HandleFunc("/json", a.jsonHandler).Methods("GET")
	a.router.HandleFunc("/json/list", a.jsonHandler).Methods("GET")

	return nil
}

// SessionStarted registers new session
func (a *CDTAdapter) SessionStarted(sid string, debugger Control, ch chan Notification) {
	s := cdtSession{
		uuid:          sid,
		debugger:      debugger,
		notifications: ch,
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	s.endpoint = a.enableWebsocketEndpoint(sid, a.apiAddress, s.websocketHandler)
	s.Setup()

	a.sessions[sid] = s
}

// SessionEnded removes the session
func (a *CDTAdapter) SessionEnded(sid string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, sid)
	fmt.Printf("CDT session %s closed\n", sid)
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

	fmt.Printf("CDT debugger listening on: %s\n", desc.WebSocketDebuggerURL)
	fmt.Printf("Or open in Chrome:\n%s\n", desc.DevtoolsFrontendURL)

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
