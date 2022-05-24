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
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var isNum = regexp.MustCompile(`^[0-9]+$`)
var isAlnum = regexp.MustCompile(`^[a-zA-Z0-9_]*$`)

func TestGetMissingCatchpointLabel(t *testing.T) {
	partitiontest.PartitionTest(t)
	tests := []struct {
		name        string
		URL         string
		expectedErr string
		statusCode  int
	}{
		{
			"bad request",
			"",
			"400 Bad Request",
			http.StatusBadRequest,
		},
		{
			"forbidden request",
			"",
			"403 Forbidden",
			http.StatusForbidden,
		},
		{
			"page not found",
			"",
			"404 Not Found",
			http.StatusNotFound,
		},
		{
			"bad gateway",
			"",
			"502 Bad Gateway",
			http.StatusBadGateway,
		},
		{
			"mainnet catchpoint",
			"https://algorand-catchpoints.s3.us-east-2.amazonaws.com/channel/mainnet/latest.catchpoint",
			"",
			http.StatusAccepted,
		},
		{
			"betanet catchpoint",
			"https://algorand-catchpoints.s3.us-east-2.amazonaws.com/channel/betanet/latest.catchpoint",
			"",
			http.StatusAccepted,
		},
		{
			"testnet catchpoint",
			"https://algorand-catchpoints.s3.us-east-2.amazonaws.com/channel/testnet/latest.catchpoint",
			"",
			http.StatusAccepted,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, test.expectedErr, test.statusCode)
			}))
			defer ts.Close()

			if test.expectedErr != "" {
				test.URL = ts.URL
			}

			label, err := getMissingCatchpointLabel(test.URL)

			if test.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedErr)
			} else {
				_, _, err = ledgercore.ParseCatchpointLabel(label)
				assert.Equal(t, err, nil)
				splittedLabel := strings.Split(label, "#")
				assert.Equal(t, len(splittedLabel), 2)
				assert.True(t, isNum.MatchString(splittedLabel[0]))
				assert.True(t, isAlnum.MatchString(splittedLabel[1]))
			}
		})
	}
}
