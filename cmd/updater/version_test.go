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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/util/s3"
)

func TestGetVersion(t *testing.T) {
	testValidVersion(t, "algonode_update_0.1.0.log", uint64(0x00010000))
	testValidVersion(t, "algo_update_0.1.0", uint64(0x00010000))
	testValidVersion(t, "algo_update_65535.1.0", uint64(0xFFFF00010000))
	testValidVersion(t, "algo_update_65535.65535.65535", uint64(0xFFFFFFFFFFFF))

	testInvalidVersion(t, "algo_update_0.-1.0")
	testInvalidVersion(t, "algo_update_1e5.0.0")
	testInvalidVersion(t, "algo_update_0.0")
	testInvalidVersion(t, "algo_update_0.0,1.1")
	testInvalidVersion(t, "algo_update_0.0+1.1")
	testInvalidVersion(t, "algo_update_0.0-1.1")
}

func testValidVersion(t *testing.T, name string, expected uint64) {
	ver, err := s3.GetVersionFromName(name)

	require.NoError(t, err, "%q should parse to a valid version", name)
	require.Equal(t, expected, ver, "%q should evaluate to %v", name, expected)
}

func testInvalidVersion(t *testing.T, name string) {
	_, err := s3.GetVersionFromName(name)

	require.NotNil(t, err, "%q should fail to parse", name)
}
