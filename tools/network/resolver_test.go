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

package network

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResolver(t *testing.T) {
	// start with a resolver that has no specific DNS address defined.
	// we want to make sure that it will go to the default DNS server ( 8.8.8.8 )
	resolver := Resolver{}
	cname, addrs, err := resolver.LookupSRV(context.Background(), "jabber", "tcp", "gmail.com")
	require.NoError(t, err)
	require.Equal(t, "_jabber._tcp.gmail.com.", cname)
	require.True(t, len(addrs) > 3)
	require.Equal(t, defaultDNSAddress, resolver.EffectiveResolverDNS())

	// specify a specific resolver to work with ( cloudflare DNS server is 1.1.1.1 )
	cloudFlareIPAddr, _ := net.ResolveIPAddr("ip", "1.1.1.1")
	resolver = Resolver{
		dnsAddress: *cloudFlareIPAddr,
	}
	cname, addrs, err = resolver.LookupSRV(context.Background(), "jabber", "tcp", "gmail.com")
	require.NoError(t, err)
	require.Equal(t, "_jabber._tcp.gmail.com.", cname)
	require.True(t, len(addrs) > 3)
	require.Equal(t, "1.1.1.1", resolver.EffectiveResolverDNS())

	// specify an invalid dns resolver ip address and examine the fail case.
	dummyIPAddr, _ := net.ResolveIPAddr("ip", "255.255.128.1")
	resolver = Resolver{
		dnsAddress: *dummyIPAddr,
	}
	timingOutContext, timingOutContextFunc := context.WithTimeout(context.Background(), time.Duration(100)*time.Millisecond)
	defer timingOutContextFunc()
	cname, addrs, err = resolver.LookupSRV(timingOutContext, "jabber", "tcp", "gmail.com")
	require.Error(t, err)
	require.Equal(t, "", cname)
	require.True(t, len(addrs) == 0)
	require.Equal(t, "255.255.128.1", resolver.EffectiveResolverDNS())
}
