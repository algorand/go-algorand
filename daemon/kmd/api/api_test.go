// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/kmd/config"
	"github.com/algorand/go-algorand/daemon/kmd/session"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const testToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func makeTestHandler(t *testing.T, origins []string, pna bool, reqCB func()) http.Handler {
	t.Helper()
	cfg := config.KMDConfig{SessionLifetimeSecs: 60}
	sm := session.MakeManager(cfg)
	t.Cleanup(func() { sm.Kill() })
	log := logging.TestingLog(t)
	if reqCB == nil {
		reqCB = func() {}
	}
	return Handler(sm, log, origins, testToken, pna, reqCB)
}

// malformedAuthedRequest builds a v1 request with a valid token and a body
// that fails to decode, so the handler returns 400 without touching wallet
// drivers.
func malformedAuthedRequest() *http.Request {
	req := httptest.NewRequest("POST", "/v1/wallet/info", strings.NewReader("{bad json"))
	req.Header.Set("X-KMD-API-Token", testToken)
	return req
}

func TestVersionsEndpoint(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	h := makeTestHandler(t, nil, false, nil)
	// No X-KMD-API-Token header: /versions needs no auth
	req := httptest.NewRequest("GET", "/versions", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	a.Equal("application/json", rr.Header().Get("Content-Type"))

	var resp struct {
		Versions []string `json:"versions"`
	}
	a.NoError(json.Unmarshal(rr.Body.Bytes(), &resp))
	a.Equal([]string{"v1"}, resp.Versions)
}

func TestSwaggerEndpoint(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	h := makeTestHandler(t, nil, false, nil)
	req := httptest.NewRequest("GET", "/swagger.json", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	a.Equal(http.StatusOK, rr.Code)
	a.Equal("application/json", rr.Header().Get("Content-Type"))
}

func TestOptionsAnyPath(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	h := makeTestHandler(t, nil, false, nil)

	for _, path := range []string{"/", "/versions", "/v1/wallets", "/v1/key", "/nonexistent", "/v1/nonexistent"} {
		req := httptest.NewRequest("OPTIONS", path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		a.Equal(http.StatusOK, rr.Code, "OPTIONS %s should return 200", path)
	}
}

func TestCORS(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	localhost := []string{"http://localhost:3000"}
	tests := []struct {
		name    string
		allowed []string
		origin  string
		path    string
		code    int
		want    string // expected Access-Control-Allow-Origin
	}{
		{"allowed origin", localhost, "http://localhost:3000", "/versions", http.StatusOK, "http://localhost:3000"},
		{"disallowed origin", localhost, "http://evil.com", "/versions", http.StatusOK, ""},
		{"wildcard", []string{"*"}, "http://anything.example.com", "/versions", http.StatusOK, "http://anything.example.com"},
		{"no origin header", localhost, "", "/versions", http.StatusOK, ""},
		// CORS wraps the whole mux, so a 404 carries the headers too
		{"unknown path", localhost, "http://localhost:3000", "/nonexistent", http.StatusNotFound, "http://localhost:3000"},
	}

	for _, tt := range tests {
		h := makeTestHandler(t, tt.allowed, false, nil)
		req := httptest.NewRequest("GET", tt.path, nil)
		if tt.origin != "" {
			req.Header.Set("Origin", tt.origin)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		a.Equal(tt.code, rr.Code, tt.name)
		a.Equal(tt.want, rr.Header().Get("Access-Control-Allow-Origin"), tt.name)
		if tt.want != "" {
			a.Equal(allowedMethods, rr.Header().Get("Access-Control-Allow-Methods"), tt.name)
			a.Equal(allowedHeaders, rr.Header().Get("Access-Control-Allow-Headers"), tt.name)
		}
	}
}

func TestPNA(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	tests := []struct {
		name   string
		pna    bool
		method string
		path   string
		want   string // expected Access-Control-Allow-Private-Network
	}{
		{"enabled preflight", true, "OPTIONS", "/v1/wallets", "true"},
		{"disabled preflight", false, "OPTIONS", "/v1/wallets", ""},
		{"enabled non-preflight", true, "GET", "/versions", ""},
	}

	for _, tt := range tests {
		h := makeTestHandler(t, nil, tt.pna, nil)
		req := httptest.NewRequest(tt.method, tt.path, nil)
		req.Header.Set("Access-Control-Request-Private-Network", "true")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		a.Equal(http.StatusOK, rr.Code, tt.name)
		a.Equal(tt.want, rr.Header().Get("Access-Control-Allow-Private-Network"), tt.name)
	}
}

func TestRequestCallback(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	var callCount atomic.Int32
	h := makeTestHandler(t, nil, false, func() {
		callCount.Add(1)
	})

	// Authenticated v1 request should trigger the callback
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, malformedAuthedRequest())

	a.Equal(http.StatusBadRequest, rr.Code)
	a.Equal(int32(1), callCount.Load())
}

func TestRequestCallbackNotCalledWithoutAuth(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	var callCount atomic.Int32
	h := makeTestHandler(t, nil, false, func() {
		callCount.Add(1)
	})

	// Unauthenticated request: auth middleware rejects before reqCB runs
	req := httptest.NewRequest("GET", "/v1/wallets", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	a.Equal(http.StatusUnauthorized, rr.Code)
	a.Equal(int32(0), callCount.Load())
}

// TestRouteStatusCodes pins how the API answers requests that use the wrong
// method, match no route, or have an unclean path.
func TestRouteStatusCodes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	h := makeTestHandler(t, nil, false, nil)

	tests := []struct {
		method string
		path   string
		want   int
	}{
		// Correct methods reach auth
		{"GET", "/v1/wallets", http.StatusUnauthorized},
		// ServeMux routes HEAD to GET patterns
		{"HEAD", "/v1/wallets", http.StatusUnauthorized},
		// Wrong methods on known paths fall through to the catch-all 404
		{"POST", "/v1/wallets", http.StatusNotFound},
		{"DELETE", "/v1/wallets", http.StatusNotFound},
		{"GET", "/v1/wallet", http.StatusNotFound},
		{"GET", "/v1/key", http.StatusNotFound},
		// Unknown paths get 404
		{"GET", "/nonexistent", http.StatusNotFound},
		{"GET", "/v1/nonexistent", http.StatusNotFound},
		{"POST", "/v1/nonexistent", http.StatusNotFound},
		// The unversioned endpoints accept any method
		{"POST", "/versions", http.StatusOK},
		{"POST", "/swagger.json", http.StatusOK},
		// ServeMux redirects unclean paths
		{"GET", "/v1//wallets", http.StatusTemporaryRedirect},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		a.Equal(tt.want, rr.Code, "%s %s", tt.method, tt.path)
	}
}
