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

package dnsaddr

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/tools/network"
)

func TestIsDnsaddr(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testcases := []struct {
		name     string
		addr     string
		expected bool
	}{
		{name: "DnsAddr", addr: "/dnsaddr/foobar.com", expected: true},
		{name: "DnsAddrWithPeerId", addr: "/dnsaddr/foobar.com/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN", expected: true},
		{name: "DnsAddrWithIPPeerId", addr: "/dnsaddr/foobar.com/ip4/127.0.0.1/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN", expected: true},
		{name: "Dns4Addr", addr: "/dns4/foobar.com/", expected: false},
		{name: "Dns6Addr", addr: "/dns6/foobar.com/", expected: false},
		{name: "Dns4AddrWithPeerId", addr: "/dns4/foobar.com/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN", expected: false},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			maddr, err := multiaddr.NewMultiaddr(testcase.addr)
			require.NoError(t, err)
			require.Equal(t, testcase.expected, isDnsaddr(maddr))
		})
	}
}

func TestMultiaddrsFromResolver(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	dnsaddrCont := NewMultiaddrDNSResolveController(false, "")

	// Fail on bad dnsaddr domain
	maddrs, err := MultiaddrsFromResolver("/bogus/foobar", dnsaddrCont)
	assert.Empty(t, maddrs)
	assert.ErrorContains(t, err, fmt.Sprintf("unable to construct multiaddr for %s", "/bogus/foobar"))

	// Success on a dnsaddr that needs to resolve recursively
	maddrs, err = MultiaddrsFromResolver("bootstrap.libp2p.io", dnsaddrCont)
	assert.NoError(t, err)
	assert.NotEmpty(t, maddrs)
	// bootstrap.libp2p.io's dnsaddr record contains 4 more dnsaddrs to resolve
	assert.Greater(t, len(maddrs), 4)
}

type failureResolver struct{}

func (f *failureResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, fmt.Errorf("always errors")
}
func (f *failureResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, fmt.Errorf("always errors")
}

func TestMultiaddrsFromResolverDnsFailure(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	dnsaddrCont := &MultiaddrDNSResolveController{
		resolver:      nil,
		nextResolvers: nil,
	}

	// Fail on no resolver
	maddrs, err := MultiaddrsFromResolver("0.0.0.1", dnsaddrCont)
	assert.Empty(t, maddrs)
	assert.ErrorContains(t, err, fmt.Sprintf("passed controller has no resolvers Iterate"))

	resolver, _ := madns.NewResolver(madns.WithDefaultResolver(&failureResolver{}))
	dnsaddrCont = &MultiaddrDNSResolveController{
		resolver:      resolver,
		nextResolvers: nil,
		controller:    network.ResolveController{},
	}
	// Fail on resolver error
	maddrs, err = MultiaddrsFromResolver("bootstrap.libp2p.io", dnsaddrCont)
	assert.Empty(t, maddrs)
	assert.ErrorContains(t, err, "always errors")
}
