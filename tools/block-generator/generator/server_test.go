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

package generator

import (
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseURL(t *testing.T) {
	partitiontest.PartitionTest(t)
	const blockQueryPrefix = "http://v2/blocks/"
	const accountQueryPrefix = "http://v2/accounts/"
	const deltaQueryPrefix = "http://v2/deltas/"
	var testcases = []struct {
		name          string
		url           string
		expectedParam string
		err           string
	}{
		{
			name:          "no block",
			url:           "/v2/blocks/",
			expectedParam: "",
			err:           "invalid request path, /v2/blocks/",
		},
		{
			name:          "normal one digit",
			url:           fmt.Sprintf("%s1", blockQueryPrefix),
			expectedParam: "1",
			err:           "",
		},
		{
			name:          "normal long number",
			url:           fmt.Sprintf("%s12345678", blockQueryPrefix),
			expectedParam: "12345678",
			err:           "",
		},
		{
			name:          "with query parameters",
			url:           fmt.Sprintf("%s1234?pretty", blockQueryPrefix),
			expectedParam: "1234",
			err:           "",
		},
		{
			name:          "with query parameters",
			url:           fmt.Sprintf("%s1234?pretty", blockQueryPrefix),
			expectedParam: "1234",
			err:           "",
		},
		{
			name:          "no deltas",
			url:           "/v2/deltas/",
			expectedParam: "",
			err:           "invalid request path, /v2/deltas/",
		},
		{
			name:          "deltas",
			url:           fmt.Sprintf("%s123?Format=msgp", deltaQueryPrefix),
			expectedParam: "123",
			err:           "",
		},
		{
			name:          "no account",
			url:           "/v2/accounts/",
			expectedParam: "",
			err:           "invalid request path, /v2/accounts/",
		},
		{
			name:          "accounts",
			url:           fmt.Sprintf("%sAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGFFWAF4", accountQueryPrefix),
			expectedParam: "AIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGFFWAF4",
			err:           "",
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			round, err := parseURL(tc.url)
			if len(tc.err) == 0 {
				msg := fmt.Sprintf("Unexpected error parsing '%s', expected round '%s' received error: %v",
					tc.url, tc.expectedParam, err)
				require.NoError(t, err, msg)
				assert.Equal(t, tc.expectedParam, round)
			} else {
				require.Error(t, err, fmt.Sprintf("Expected an error containing: %s", tc.err))
				require.True(t, strings.Contains(err.Error(), tc.err))
			}
		})
	}
}
