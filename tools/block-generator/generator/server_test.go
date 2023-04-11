// Copyright (C) 2019-2023 Algorand, Inc.
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
	"os"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitConfigFile(t *testing.T) {
	partitiontest.PartitionTest(t)
	config, err := initializeConfigFile("../test_config.yml")
	require.NoError(t, err)
	require.Equal(t, uint64(10), config.NumGenesisAccounts)
	require.Equal(t, float32(0.25), config.AssetCloseFraction)
	require.Equal(t, float32(0.0), config.AssetDestroyFraction)
}

func TestInitConfigFileNotExist(t *testing.T) {
	partitiontest.PartitionTest(t)
	_, err := initializeConfigFile("this_is_not_a_config_file")

	if _, ok := err.(*os.PathError); !ok {
		require.Fail(t, "This should generate a path error")
	}
}

func TestParseURL(t *testing.T) {
	partitiontest.PartitionTest(t)
	const blockQueryPrefix = "http://v2/blocks/"
	const accountQueryPrefix = "http://v2/accounts/"
	const deltaQueryPrefix = "http://v2/deltas/"
	var testcases = []struct {
		name          string
		url           string
		expectedRound string
		err           string
	}{
		{
			name:          "no block",
			url:           "/v2/blocks/",
			expectedRound: "",
			err:           "invalid request path, /v2/blocks/",
		},
		{
			name:          "normal one digit",
			url:           fmt.Sprintf("%s1", blockQueryPrefix),
			expectedRound: "1",
			err:           "",
		},
		{
			name:          "normal long number",
			url:           fmt.Sprintf("%s12345678", blockQueryPrefix),
			expectedRound: "12345678",
			err:           "",
		},
		{
			name:          "with query parameters",
			url:           fmt.Sprintf("%s1234?pretty", blockQueryPrefix),
			expectedRound: "1234",
			err:           "",
		},
		{
			name:          "with query parameters",
			url:           fmt.Sprintf("%s1234?pretty", blockQueryPrefix),
			expectedRound: "1234",
			err:           "",
		},
		{
			name:          "no deltas",
			url:           "/v2/deltas/",
			expectedRound: "",
			err:           "invalid request path, /v2/deltas/",
		},
		{
			name:          "deltas",
			url:           fmt.Sprintf("%s123?Format=msgp", deltaQueryPrefix),
			expectedRound: "123",
			err:           "",
		},
		{
			name:          "no account",
			url:           "/v2/accounts/",
			expectedRound: "",
			err:           "invalid request path, /v2/accounts/",
		},
		{
			name:          "accounts",
			url:           fmt.Sprintf("%sAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGFFWAF4", accountQueryPrefix),
			expectedRound: "AIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGFFWAF4",
			err:           "",
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			round, err := parseURL(testcase.url)
			if len(testcase.err) == 0 {
				msg := fmt.Sprintf("Unexpected error parsing '%s', expected round '%s' received error: %v",
					testcase.url, testcase.expectedRound, err)
				require.NoError(t, err, msg)
				assert.Equal(t, testcase.expectedRound, round)
			} else {
				require.Error(t, err, fmt.Sprintf("Expected an error containing: %s", testcase.err))
				require.True(t, strings.Contains(err.Error(), testcase.err))
			}
		})
	}
}
