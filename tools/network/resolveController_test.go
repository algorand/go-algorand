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

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/tools/network/dnssec"
)

func TestSystemResolver(t *testing.T) {
	a := require.New(t)
	log := logging.Base()

	c := NewResolveController(false, "127.0.0.1", log)
	r := c.SystemResolver()
	a.IsType(&net.Resolver{}, r)

	c = NewResolveController(true, "127.0.0.1", log)
	r = c.SystemResolver()
	a.IsType(&dnssec.Resolver{}, r)
	a.GreaterOrEqual(len(r.(*dnssec.Resolver).EffectiveResolverDNS()), 0)
}

func TestFallbackResolver(t *testing.T) {
	a := require.New(t)
	log := logging.Base()

	c := NewResolveController(false, "127.0.0.1", log)
	r := c.FallbackResolver()
	a.IsType(&Resolver{}, r)
	a.Equal("127.0.0.1", r.(*Resolver).EffectiveResolverDNS())

	c = NewResolveController(true, "127.0.0.1", log)
	r = c.FallbackResolver()
	a.IsType(&dnssec.Resolver{}, r)
	a.Equal(r.(*dnssec.Resolver).EffectiveResolverDNS(), []dnssec.ResolverAddress{dnssec.MakeResolverAddress("127.0.0.1", "53")})
}

func TestDefaultResolver(t *testing.T) {
	a := require.New(t)
	log := logging.Base()

	c := NewResolveController(false, "127.0.0.1", log)
	r := c.DefaultResolver()
	a.IsType(&Resolver{}, r)
	a.Equal(defaultDNSAddress, r.(*Resolver).EffectiveResolverDNS())

	c = NewResolveController(true, "127.0.0.1", log)
	r = c.DefaultResolver()
	a.IsType(&dnssec.Resolver{}, r)
	a.Equal(r.(*dnssec.Resolver).EffectiveResolverDNS(), dnssec.DefaultDnssecAwareNSServers)
}

func TestRealNamesWithResolver(t *testing.T) {
	t.Skip() // skip real network tests in autotest
	a := require.New(t)
	log := logging.Base()

	example := "example.com"
	nsec := NewResolveController(false, "1.1.1.1", log)
	sec := NewResolveController(true, "1.1.1.1", log)
	r := nsec.SystemResolver()
	addrs, err := r.LookupIPAddr(context.Background(), example)
	a.NoError(err)
	a.GreaterOrEqual(len(addrs), 1) // ipv4 + ipv6

	r = sec.SystemResolver()
	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	addrs, err = r.LookupIPAddr(timeoutCtx, example)
	cancel()
	a.NoError(err)
	a.Equal(len(addrs), 1) // ipv4 only

	for _, secure := range []bool{false, true} {
		c := NewResolveController(secure, "1.1.1.1", log)
		r = c.FallbackResolver()
		addrs, err = r.LookupIPAddr(context.Background(), example)
		a.NoError(err)
		a.GreaterOrEqual(len(addrs), 1)

		r = c.DefaultResolver()
		addrs, err = r.LookupIPAddr(context.Background(), example)
		a.NoError(err)
		a.GreaterOrEqual(len(addrs), 1)

		c = NewResolveController(secure, "192.168.12.34", log)
		r = c.FallbackResolver()
		timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err = r.LookupIPAddr(timeoutCtx, example)
		cancel()
		a.Error(err)
	}
}
