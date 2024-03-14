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

package network

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestReadFromSRVPriority(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	service := "telemetry"
	protocol := "tls"
	name := "devnet.algodev.network"
	fallback := ""
	secure := true

	prioAddrs, err := ReadFromSRVPriority("", protocol, name, fallback, secure)
	require.Error(t, err)

	prioAddrs, err = ReadFromSRVPriority(service, protocol, name, fallback, secure)
	require.NoError(t, err)
	addrs, ok := prioAddrs[1]
	require.True(t, ok)
	require.GreaterOrEqual(t, len(addrs), 1)
	addr := addrs[0]
	require.Greater(t, len(addr), 1)
}

func TestReadFromSRV(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	service := "telemetry"
	protocol := "tls"
	name := "devnet.algodev.network"
	fallback := ""
	secure := true

	addrs, err := ReadFromSRV(context.Background(), "", protocol, name, fallback, secure)
	require.Error(t, err)

	addrs, err = ReadFromSRV(context.Background(), service, protocol, name, fallback, secure)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(addrs), 1)
	addr := addrs[0]
	require.Greater(t, len(addr), 1)
}
