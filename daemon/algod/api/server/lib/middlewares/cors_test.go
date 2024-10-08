// Copyright (C) 2019-2024 Algorand, Inc.
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

package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestMakeCORS(t *testing.T) {
	partitiontest.PartitionTest(t)
	e := echo.New()
	tokenHeader := "X-Algo-API-Token"
	corsMiddleware := MakeCORS(tokenHeader)

	testCases := []struct {
		name            string
		method          string
		headers         map[string]string
		expectedStatus  int
		expectedHeaders map[string]string
	}{
		{
			name:   "OPTIONS request",
			method: http.MethodOptions,
			headers: map[string]string{
				"Origin":                         "http://algorand.com",
				"Access-Control-Request-Headers": "Content-Type," + tokenHeader,
			},
			expectedStatus: http.StatusNoContent,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":  "*",
				"Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
				"Access-Control-Allow-Headers": tokenHeader + ",Content-Type",
			},
		},
		{
			name:   "GET request",
			method: http.MethodGet,
			headers: map[string]string{
				"Origin": "http://algorand.com",
			},
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin": "*",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/health", nil)
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			handler := corsMiddleware(func(c echo.Context) error {
				return c.NoContent(http.StatusOK)
			})

			err := handler(c)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
			for key, value := range tc.expectedHeaders {
				assert.Equal(t, value, rec.Header().Get(key))
			}
		})
	}
}

func TestMakePNA(t *testing.T) {
	partitiontest.PartitionTest(t)
	e := echo.New()
	pnaMiddleware := MakePNA()

	testCases := []struct {
		name               string
		method             string
		headers            map[string]string
		expectedStatusCode int
		expectedHeader     string
	}{
		{
			name:               "OPTIONS request with PNA header",
			method:             http.MethodOptions,
			headers:            map[string]string{"Access-Control-Request-Private-Network": "true"},
			expectedStatusCode: http.StatusOK,
			expectedHeader:     "true",
		},
		{
			name:               "OPTIONS request without PNA header",
			method:             http.MethodOptions,
			headers:            map[string]string{},
			expectedStatusCode: http.StatusOK,
			expectedHeader:     "",
		},
		{
			name:               "GET request",
			method:             http.MethodGet,
			headers:            map[string]string{},
			expectedStatusCode: http.StatusOK,
			expectedHeader:     "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/", nil)
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			handler := pnaMiddleware(func(c echo.Context) error {
				return c.NoContent(http.StatusOK)
			})

			err := handler(c)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedStatusCode, rec.Code)
			assert.Equal(t, tc.expectedHeader, rec.Header().Get("Access-Control-Allow-Private-Network"))
		})
	}
}
