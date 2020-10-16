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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func TestWebPageFrontendHandlers(t *testing.T) {
	params := WebPageFrontendParams{
		router:     mux.NewRouter(),
		apiAddress: "127.0.0.1:12345",
	}

	a := MakeWebPageFrontend(&params)

	req, _ := http.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	params.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), "<html>")

	// check handlers on non-existing session
	sid := "test"

	cr := ConfigRequest{ExecID: ExecID(sid)}
	data, err := json.Marshal(&cr)
	require.NoError(t, err)
	body := bytes.NewReader(data)
	req, err = http.NewRequest("POST", "/exec/config", body)
	require.NoError(t, err)
	rr = httptest.NewRecorder()
	params.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusNotFound, rr.Code)

	body = bytes.NewReader(data)
	req, err = http.NewRequest("POST", "/exec/step", body)
	require.NoError(t, err)
	rr = httptest.NewRecorder()
	params.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusNotFound, rr.Code)

	body = bytes.NewReader(data)
	req, err = http.NewRequest("POST", "/exec/continue", body)
	require.NoError(t, err)
	rr = httptest.NewRecorder()
	params.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusNotFound, rr.Code)

	// check handlers on existing session
	dbg := MockDebugControl{}
	ch := make(chan Notification)
	a.SessionStarted(sid, &dbg, ch)

	body = bytes.NewReader(data)
	req, err = http.NewRequest("POST", "/exec/config", body)
	require.NoError(t, err)
	rr = httptest.NewRecorder()
	params.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	body = bytes.NewReader(data)
	req, err = http.NewRequest("POST", "/exec/step", body)
	require.NoError(t, err)
	rr = httptest.NewRecorder()
	params.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	body = bytes.NewReader(data)
	req, err = http.NewRequest("POST", "/exec/continue", body)
	require.NoError(t, err)
	rr = httptest.NewRecorder()
	params.router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	a.SessionEnded(sid)

	req, _ = http.NewRequest("GET", "/ws", nil)
	req.Header.Add("Upgrade", "websocket")
	req.Header.Add("Connection", "Upgrade")
	req.Header.Add("Sec-Websocket-Version", "13")
	req.Header.Add("Sec-Websocket-Key", "A")
	rr = httptest.NewRecorder()
	params.router.ServeHTTP(rr, req)
	// httptest.RequestRecorder does not implement http.Hijacker
	require.Equal(t, http.StatusInternalServerError, rr.Code)
}
