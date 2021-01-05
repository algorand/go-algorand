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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

func TestRemoteAdapterHandlers(t *testing.T) {
	d := MakeDebugger()
	a := MakeRemoteHook(d)
	router := mux.NewRouter()
	a.Setup(router)

	ad := testServerDebugFrontend{}
	d.AddAdapter(ad)

	sid := "test"
	state := logic.DebugState{ExecID: sid}
	data := protocol.EncodeJSON(&state)
	body := bytes.NewReader(data)
	req, _ := http.NewRequest("POST", "/exec/register", body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	// ensure non-canonical json encoding does not work
	// only canonical one by protocol package is supported
	data2, err := json.Marshal(&state)
	require.NoError(t, err)
	body2 := bytes.NewReader(data2)
	req, _ = http.NewRequest("POST", "/exec/register", body2)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)

	body = bytes.NewReader(data)
	req, _ = http.NewRequest("POST", "/exec/update", body)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	body2 = bytes.NewReader(data2)
	req, _ = http.NewRequest("POST", "/exec/update", body2)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)

	body = bytes.NewReader(data)
	req, _ = http.NewRequest("POST", "/exec/complete", body)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	body2 = bytes.NewReader(data2)
	req, _ = http.NewRequest("POST", "/exec/complete", body2)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
}
