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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/cmd/tealdbg/cdt"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

func TestCdtHandlers(t *testing.T) {
	params := CdtFrontendParams{
		router:     mux.NewRouter(),
		apiAddress: "127.0.0.1:12345",
	}

	a := MakeCdtFrontend(&params)

	req, _ := http.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	a.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusNotFound, rr.Code)

	req, _ = http.NewRequest("GET", "/json/version", nil)
	rr = httptest.NewRecorder()
	a.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	require.Contains(t, rr.Body.String(), "Browser")
	require.Contains(t, rr.Body.String(), "Protocol-Version")

	req, _ = http.NewRequest("GET", "/json/list", nil)
	rr = httptest.NewRecorder()
	a.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	req, _ = http.NewRequest("GET", "/json", nil)
	rr = httptest.NewRecorder()
	a.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var tabs []cdt.TabDescription
	json.Unmarshal(rr.Body.Bytes(), &tabs)
	require.Equal(t, 0, len(tabs))

	// simulate new session
	urlPath := "test"
	called := false
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		called = true
		return
	}
	desc := a.enableWebsocketEndpoint(urlPath, params.apiAddress, handler)
	a.sessions[urlPath] = cdtSession{endpoint: desc}

	// and ensure description is returned
	req, _ = http.NewRequest("GET", "/json", nil)
	rr = httptest.NewRecorder()
	a.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	json.Unmarshal(rr.Body.Bytes(), &tabs)
	require.Equal(t, 1, len(tabs))
	require.NotEmpty(t, tabs[0].ID)
	require.NotEmpty(t, tabs[0].DevtoolsFrontendURL)

	// and ensure description is returned
	req, _ = http.NewRequest("GET", "/"+urlPath, nil)
	rr = httptest.NewRecorder()
	a.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	require.True(t, called)
}

type MockDebugControl struct {
	errOnCall bool
	bpActive  bool
}

func (c *MockDebugControl) Step() {
}

func (c *MockDebugControl) Resume() {
}

func (c *MockDebugControl) SetBreakpoint(line int) error {
	if c.errOnCall {
		return errors.New("mock err")
	}
	return nil
}

func (c *MockDebugControl) RemoveBreakpoint(line int) error {
	if c.errOnCall {
		return errors.New("mock err")
	}
	return nil
}

func (c *MockDebugControl) SetBreakpointsActive(active bool) {
	c.bpActive = active
}

func (c *MockDebugControl) GetSourceMap() ([]byte, error) {
	if c.errOnCall {
		return nil, errors.New("mock err")
	}

	return []byte("mock"), nil
}

func (c *MockDebugControl) GetSource() (string, []byte) {
	return "name", []byte("int 1")
}

func (c *MockDebugControl) GetStates(changes *logic.AppStateChange) AppState {
	return AppState{}
}

func TestCdtFrontendSessionStarted(t *testing.T) {
	params := CdtFrontendParams{
		router:     mux.NewRouter(),
		apiAddress: "127.0.0.1:12345",
	}

	a := MakeCdtFrontend(&params)
	sid := "test"
	dbg := MockDebugControl{}
	ch := make(chan Notification)
	a.SessionStarted(sid, &dbg, ch)

	req, _ := http.NewRequest("GET", "/"+sid+"/source", nil)
	rr := httptest.NewRecorder()
	a.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "int 1", rr.Body.String())

	req, _ = http.NewRequest("GET", "/"+sid+"/sourcemap", nil)
	rr = httptest.NewRecorder()
	a.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "mock", rr.Body.String())

	sid = "test2"
	dbg = MockDebugControl{errOnCall: true}
	ch = make(chan Notification)
	a.SessionStarted(sid, &dbg, ch)

	req, _ = http.NewRequest("GET", "/"+sid+"/sourcemap", nil)
	rr = httptest.NewRecorder()
	a.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusInternalServerError, rr.Code)
	require.Contains(t, rr.Body.String(), "mock err")
}

func TestCdtAdapterSessionEnded(t *testing.T) {
	params := CdtFrontendParams{
		router:     mux.NewRouter(),
		apiAddress: "127.0.0.1:12345",
	}

	a := MakeCdtFrontend(&params)
	sid := "test"
	dbg := MockDebugControl{}
	ch := make(chan Notification)
	a.SessionStarted(sid, &dbg, ch)
	s := a.sessions[sid]

	a.SessionEnded(sid)
	close(s.done)

	ended := false
	i := 0
	for i < 5 && !ended {
		a.mu.Lock()
		ended = len(a.sessions) == 0
		a.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	require.True(t, ended)
}
