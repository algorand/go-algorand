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
	"os"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
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
	_, err := parseURL("http://v2/blocks/")
	require.NotNil(t, err)
	_, err = parseURL("http://v2/accounts/")
	require.NotNil(t, err)
	_, err = parseURL("http://v2/deltas/")
	require.NotNil(t, err)

	round, err := parseURL("http://v2/blocks/123")
	require.Nil(t, err)
	require.Equal(t, round, "123")

	addr, err := parseURL("http://v2/accounts/AIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGFFWAF4")
	require.Nil(t, err)
	require.Equal(t, addr, "AIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGFFWAF4")

	_, err = parseURL("http://v2/deltas/123?Format=msgp")
	require.Nil(t, err)
	require.Equal(t, round, "123")
}
