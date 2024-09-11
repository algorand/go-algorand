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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestResolverWithDefaultDNSResolution(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// configure a resolver that has no specific DNS address defined.
	// we want to make sure that it will go to the default DNS server ( 8.8.8.8 )
	resolver := Resolver{}
	cname, addrs, err := resolver.LookupSRV(context.Background(), "telemetry", "tls", "devnet.algodev.network")
	require.NoError(t, err)
	require.Equal(t, "_telemetry._tls.devnet.algodev.network.", cname)
	require.True(t, len(addrs) == 1)
	require.Equal(t, defaultDNSAddress, resolver.EffectiveResolverDNS())
}

func TestResolverWithCloudflareDNSResolution(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	resolver := Resolver{}

	// The test previously specified Cloudflare's primary DNS server (1.1.1.1).
	// However, CircleCI began blocking requests to 1.1.1.1.  In order to
	// preserve the test's spirit, it now uses Cloudflare's secondary DNS
	// server (1.0.0.1).
	cloudflareIPAddr, _ := net.ResolveIPAddr("ip", "1.0.0.1")
	resolver = Resolver{
		dnsAddress: *cloudflareIPAddr,
	}
	cname, addrs, err := resolver.LookupSRV(context.Background(), "telemetry", "tls", "devnet.algodev.network")
	require.NoError(t, err)
	require.Equal(t, "_telemetry._tls.devnet.algodev.network.", cname)
	require.True(t, len(addrs) == 1)
	require.Equal(t, "1.0.0.1", resolver.EffectiveResolverDNS())
}

func TestResolverWithInvalidDNSResolution(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	resolver := Resolver{}
	// specify an invalid dns resolver ip address and examine the fail case.
	dummyIPAddr, _ := net.ResolveIPAddr("ip", "255.255.128.1")
	resolver = Resolver{
		dnsAddress: *dummyIPAddr,
	}
	timingOutContext, timingOutContextFunc := context.WithTimeout(context.Background(), time.Duration(100)*time.Millisecond)
	defer timingOutContextFunc()
	cname, addrs, err := resolver.LookupSRV(timingOutContext, "telemetry", "tls", "devnet.algodev.network")
	require.Error(t, err)
	require.Equal(t, "", cname)
	require.True(t, len(addrs) == 0)
	require.Equal(t, "255.255.128.1", resolver.EffectiveResolverDNS())
}
