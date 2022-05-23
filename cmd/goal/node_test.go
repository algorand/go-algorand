// Copyright (C) 2019-2022 Algorand, Inc.
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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetMissingCatchpointLabel(t *testing.T) {
	tests := []struct {
		name        string
		URL         string
		catchpoint  string
		expectedErr string
		statusCode  int
	}{
		{
			"bad request",
			"",
			"",
			"400 Bad Request",
			http.StatusBadRequest,
		},
		{
			"forbidden request",
			"",
			"",
			"403 Forbidden",
			http.StatusForbidden,
		},
		{
			"page not found",
			"",
			"",
			"404 Not Found",
			http.StatusNotFound,
		},
		{
			"bad gateway",
			"",
			"",
			"502 Bad Gateway",
			http.StatusBadGateway,
		},
		{
			"mainnet catchpoint",
			"https://algorand-catchpoints.s3.us-east-2.amazonaws.com/channel/mainnet/latest.catchpoint",
			"21170000#2NS7QHOLJDBBR2FBYWZK32M7RYQOMYJ4LMA7ID3CJXWVQVC4JSEA",
			"",
			http.StatusAccepted,
		},
		{
			"betanet catchpoint",
			"https://algorand-catchpoints.s3.us-east-2.amazonaws.com/channel/betanet/latest.catchpoint",
			"18230000#XCZXJSBUKVTVP2Q6V4KTGQKDPEXM3JQ3JCAIY66JCDWAAYHCNPXA",
			"",
			http.StatusAccepted,
		},
		{
			"testnet catchpoint",
			"https://algorand-catchpoints.s3.us-east-2.amazonaws.com/channel/testnet/latest.catchpoint",
			"21760000#3UX4ELEEKZMIXGFUGAGLJOFUDBWIZEJHX37P4YSOD3QE62E63LMQ",
			"",
			http.StatusAccepted,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.expectedErr != "" {
					http.Error(w, test.expectedErr, test.statusCode)
				} else {
					fmt.Fprintln(w, test.catchpoint)
				}
			}))
			defer ts.Close()

			label, err := getMissingCatchpointLabel(ts.URL)

			if test.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedErr)
			} else {
				require.Equal(t, test.catchpoint, label)
			}
		})
	}
}
