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

package network

import (
	"context"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"net"
	"os"
	"strings"
	"testing"
	"time"
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

	if strings.ToUpper(os.Getenv("CIRCLECI")) == "TRUE" {
		t.Skip("Disabled on CircleCI while investigating Cloudflare DNS resolution issue")
	}

	resolver := Resolver{}

	// specify a specific resolver to work with ( cloudflare DNS server is 1.1.1.1 )
	cloudFlareIPAddr, _ := net.ResolveIPAddr("ip", "1.1.1.1")
	resolver = Resolver{
		dnsAddress: *cloudFlareIPAddr,
	}
	cname, addrs, err := resolver.LookupSRV(context.Background(), "telemetry", "tls", "devnet.algodev.network")
	require.NoError(t, err)
	require.Equal(t, "_telemetry._tls.devnet.algodev.network.", cname)
	require.True(t, len(addrs) == 1)
	require.Equal(t, "1.1.1.1", resolver.EffectiveResolverDNS())
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
