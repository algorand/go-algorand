// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	madns "github.com/multiformats/go-multiaddr-dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestDnsAddrResolveController(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	dnsaddrCont := NewMultiaddrDNSResolveController(true, "127.0.0.1")

	// Assert that the dnsaddr resolver cycles through the dns resolvers properly
	assert.Equal(t, dnsaddrCont.controller.SystemDnsaddrResolver(), dnsaddrCont.Resolver())
	assert.Equal(t, dnsaddrCont.controller.FallbackDnsaddrResolver(), dnsaddrCont.NextResolver())
	assert.Equal(t, dnsaddrCont.controller.DefaultDnsaddrResolver(), dnsaddrCont.NextResolver())
	// It should return nil once all the resolvers have been tried
	assert.Nil(t, dnsaddrCont.NextResolver())
	assert.Nil(t, dnsaddrCont.NextResolver())

	// It should not include fallback if none was specified
	dnsaddrCont = NewMultiaddrDNSResolveController(true, "")
	assert.Equal(t, 2, len(dnsaddrCont.newResolvers))

}

const testDnsaddr = "dnsaddr=/ip4/1.2.3.4/tcp/4190/p2p/12D3KooWSH9L2dT6GYUg2HKXDzNiY3tjH75ibU4yJsWVWGaQRZ2x"

// fakeDNS answers dnsaddr TXT lookups and counts them. It fails while down is set,
// and always fails for domains starting with "down.".
type fakeDNS struct {
	down    atomic.Bool
	lookups atomic.Int32
}

func (f *fakeDNS) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, errors.New("no A records")
}

func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.lookups.Add(1)
	if f.down.Load() || strings.HasPrefix(name, "_dnsaddr.down.") {
		return nil, errors.New("i/o timeout")
	}
	return []string{testDnsaddr}, nil
}

// makeTestController returns a controller with a resolver for each backend, in
// order of preference, and a count of the resolvers it has created.
func makeTestController(backends ...*fakeDNS) (*MultiaddrDNSResolveController, *atomic.Int32) {
	created := &atomic.Int32{}
	c := &MultiaddrDNSResolveController{}
	for _, backend := range backends {
		c.newResolvers = append(c.newResolvers, func() *madns.Resolver {
			created.Add(1)
			r, err := madns.NewResolver(madns.WithDefaultResolver(backend))
			if err != nil {
				panic(err)
			}
			return r
		})
	}
	return c, created
}

// TestControllerRecoversAfterOutage checks that a lookup after a DNS outage tries the
// resolvers again, rather than failing because the outage used them all up, and that
// each resolver is created on first use and then reused.
func TestControllerRecoversAfterOutage(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a, b := &fakeDNS{}, &fakeDNS{}
	c, created := makeTestController(a, b)
	lookup := func(aDown, bDown bool) error {
		a.down.Store(aDown)
		b.down.Store(bDown)
		_, err := MultiaddrsFromResolver("example.com", c)
		return err
	}

	require.NoError(t, lookup(false, false))
	require.EqualValues(t, 1, created.Load())
	require.Error(t, lookup(true, true))
	require.EqualValues(t, 2, created.Load())
	require.NoError(t, lookup(true, false))
	require.NoError(t, lookup(false, false))
	require.EqualValues(t, 2, created.Load())
}

// TestControllerTriesEachResolverPerLookup checks that every lookup starts with the
// preferred resolver, and tries each resolver once before failing.
func TestControllerTriesEachResolverPerLookup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a, b := &fakeDNS{}, &fakeDNS{}
	c, _ := makeTestController(a, b)
	lookup := func() error {
		_, err := MultiaddrsFromResolver("example.com", c)
		return err
	}

	a.down.Store(true)
	require.NoError(t, lookup())
	require.EqualValues(t, 1, a.lookups.Load())
	require.EqualValues(t, 1, b.lookups.Load())

	// The next lookup starts again with a, which has recovered.
	a.down.Store(false)
	b.down.Store(true)
	require.NoError(t, lookup())
	require.EqualValues(t, 2, a.lookups.Load())
	require.EqualValues(t, 1, b.lookups.Load())

	a.down.Store(true)
	require.Error(t, lookup())
	require.EqualValues(t, 3, a.lookups.Load())
	require.EqualValues(t, 2, b.lookups.Load())
}

// TestControllerBackupAfterPrimaryFailure checks that a failed lookup of the primary
// bootstrap domain does not prevent the backup domain lookup on the same controller.
func TestControllerBackupAfterPrimaryFailure(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	dns := &fakeDNS{}
	c, _ := makeTestController(dns, dns)
	_, err := MultiaddrsFromResolver("down.example.com", c)
	require.Error(t, err)
	addrs, err := MultiaddrsFromResolver("example.com", c)
	require.NoError(t, err)
	require.Len(t, addrs, 1)
}
