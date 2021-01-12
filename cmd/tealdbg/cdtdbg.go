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

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/gorilla/mux"

	"github.com/algorand/go-algorand/cmd/tealdbg/cdt"
)

// CdtFrontend is Chrome DevTools frontend
type CdtFrontend struct {
	mu         deadlock.Mutex
	sessions   map[string]cdtSession
	latestSids []string
	router     *mux.Router
	apiAddress string
	verbose    bool
}

// CdtFrontendParams for Setup
type CdtFrontendParams struct {
	router     *mux.Router
	apiAddress string
	verbose    bool
}

// MakeCdtFrontend creates new CdtFrontend
func MakeCdtFrontend(params *CdtFrontendParams) (a *CdtFrontend) {
	a = new(CdtFrontend)

	a.sessions = make(map[string]cdtSession)
	a.router = params.router
	a.apiAddress = params.apiAddress
	a.verbose = params.verbose

	a.router.HandleFunc("/json/version", a.versionHandler).Methods("GET")
	a.router.HandleFunc("/json", a.jsonHandler).Methods("GET")
	a.router.HandleFunc("/json/list", a.jsonHandler).Methods("GET")

	return a
}

// SessionStarted registers new session
func (a *CdtFrontend) SessionStarted(sid string, debugger Control, ch chan Notification) {
	s := makeCdtSession(sid, debugger, ch)

	a.mu.Lock()
	defer a.mu.Unlock()

	// first add new routes
	if name, source := debugger.GetSource(); len(source) != 0 {
		s.scriptURL = name
		s.sourceMapURL = fmt.Sprintf("http://%s/%s/sourcemap", a.apiAddress, sid)
		a.router.HandleFunc(fmt.Sprintf("/%s/sourcemap", sid), s.sourceMapHandler).Methods("GET")
		a.router.HandleFunc(fmt.Sprintf("/%s/source", sid), s.sourceHandler).Methods("GET")
	}

	// then add a websocket route and publish (output to console) it
	// after that mux.Router.routes may not be modifed due to possible data race
	s.endpoint = a.enableWebsocketEndpoint(sid, a.apiAddress, s.websocketHandler)

	s.verbose = a.verbose
	s.states = debugger.GetStates(nil)

	a.sessions[sid] = *s
	a.latestSids = append(a.latestSids, sid)
}

// SessionEnded removes the session
func (a *CdtFrontend) SessionEnded(sid string) {
	go func() {
		a.mu.Lock()
		s := a.sessions[sid]
		// remove this session id from ordred a.latestSids array
		var i int
		for i = 0; i < len(a.latestSids); i++ {
			if a.latestSids[i] == sid {
				a.latestSids = append(a.latestSids[:i], a.latestSids[i+1:]...)
				break
			}
		}
		a.mu.Unlock()

		<-s.done

		a.mu.Lock()
		delete(a.sessions, sid)
		a.mu.Unlock()
		log.Printf("CDT session %s closed\n", sid)
	}()
}

// URL returns an URL to access the latest debugging session
func (a *CdtFrontend) URL() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.latestSids) == 0 {
		return ""
	}

	return a.sessions[a.latestSids[len(a.latestSids)-1]].endpoint.WebSocketDebuggerURL
}

// WaitForCompletion returns when no active connections left
func (a *CdtFrontend) WaitForCompletion() {
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

// must be called with ctx.mux locked
func (a *CdtFrontend) enableWebsocketEndpoint(
	uuid string, apiAddress string,
	handler func(http.ResponseWriter, *http.Request),
) cdt.TabDescription {
	address := apiAddress + "/" + uuid
	desc := cdt.TabDescription{
		Description:               "",
		ID:                        uuid,
		Title:                     "Algorand TEAL program",
		TabType:                   "node",
		URL:                       "https://algorand.com/",
		DevtoolsFrontendURL:       "devtools://devtools/bundled/js_app.html?experiments=true&v8only=false&ws=" + address,
		DevtoolsFrontendURLCompat: "devtools://devtools/bundled/inspector.html?experiments=true&v8only=false&ws=" + address,
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

func (a *CdtFrontend) versionHandler(w http.ResponseWriter, r *http.Request) {
	type devtoolsVersion struct {
		Browser         string `json:"Browser"`
		ProtocolVersion string `json:"Protocol-Version"`
	}

	version := devtoolsVersion{Browser: "Algorand TEAL Debugger", ProtocolVersion: "1.1"}
	enc, err := json.Marshal(version)
	if err != nil {
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(enc)
	return
}

func (a *CdtFrontend) jsonHandler(w http.ResponseWriter, r *http.Request) {
	tabs := make([]cdt.TabDescription, 0, len(a.sessions))

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
