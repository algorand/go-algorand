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

	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"

	log "github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/tools/network"
)

// Resolver is an interface for resolving dnsaddrs
type Resolver interface {
	Resolve(ctx context.Context, maddr multiaddr.Multiaddr) ([]multiaddr.Multiaddr, error)
}

// ResolveController is an interface for cycling through resolvers.
// Resolver starts a pass through the resolvers and returns the first one.
// NextResolver returns the next one in the pass, or nil once all have been tried.
type ResolveController interface {
	Resolver() Resolver
	NextResolver() Resolver
}

// MultiaddrDNSResolveController returns a madns.Resolver, cycling through underlying net.Resolvers.
// Each lookup starts a new pass, so a resolver that failed in an earlier lookup is tried again.
// Resolvers are created on first use and then kept, so a DNSSEC resolver keeps its trust chain
// cache across lookups. It is not safe for concurrent use.
type MultiaddrDNSResolveController struct {
	newResolvers []func() *madns.Resolver // in order of preference
	resolvers    []*madns.Resolver        // the resolvers created so far
	next         int                      // index of the resolver NextResolver returns
	controller   network.ResolveController
}

// NewMultiaddrDNSResolveController constructs a MultiaddrDNSResolveController
func NewMultiaddrDNSResolveController(secure bool, fallbackDNSResolverAddress string) *MultiaddrDNSResolveController {
	controller := network.NewResolveController(secure, fallbackDNSResolverAddress, log.Base())
	newResolvers := []func() *madns.Resolver{controller.SystemDnsaddrResolver}
	if fallbackDNSResolverAddress != "" {
		newResolvers = append(newResolvers, controller.FallbackDnsaddrResolver)
	}
	return &MultiaddrDNSResolveController{
		newResolvers: append(newResolvers, controller.DefaultDnsaddrResolver),
		controller:   controller,
	}
}

// NextResolver returns the next resolver in this pass, or nil once all have been tried.
func (c *MultiaddrDNSResolveController) NextResolver() Resolver {
	if c.next >= len(c.newResolvers) {
		return nil
	}
	if c.next == len(c.resolvers) {
		c.resolvers = append(c.resolvers, c.newResolvers[c.next]())
	}
	resolver := c.resolvers[c.next]
	c.next++
	return resolver
}

// Resolver starts a new pass through the resolvers and returns the first one.
func (c *MultiaddrDNSResolveController) Resolver() Resolver {
	c.next = 0
	return c.NextResolver()
}
