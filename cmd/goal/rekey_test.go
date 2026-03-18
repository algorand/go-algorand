// Copyright (C) 2019-2026 Algorand, Inc.
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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestParseRekey(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Test empty address
	require.Equal(t, basics.Address{}, parseRekey(""))

	// Test valid address
	validAddrStr := "5ZHAMU2BLPLFEE2VFFBVWMKRIZKUBSPUUWT3YIOWSP7VWFRJIT4XF3VYNI"
	validAddr, err := basics.UnmarshalChecksumAddress(validAddrStr)
	require.NoError(t, err)
	require.Equal(t, validAddr, parseRekey(validAddrStr))

	// Test invalid address (should panic because reportErrorf calls exit(1) which panics in tests)
	require.Panics(t, func() {
		parseRekey("INVALID_ADDRESS")
	})
}
