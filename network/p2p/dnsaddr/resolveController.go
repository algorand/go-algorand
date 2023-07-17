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
	madns "github.com/multiformats/go-multiaddr-dns"

	"github.com/algorand/go-algorand/tools/network"
)

type DnsaddrResolveController struct {
	resolver      *madns.Resolver
	nextResolvers []func() *madns.Resolver
	controller    network.ResolveController
}

func NewDnsaddrResolveController(controller network.ResolveController) *DnsaddrResolveController {
	return &DnsaddrResolveController{
		resolver:      nil,
		nextResolvers: []func() *madns.Resolver{controller.SystemDnsaddrResolver, controller.FallbackDnsaddrResolver, controller.DefaultDnsaddrResolver},
		controller:    controller,
	}
}

// NextResolver applies the nextResolvers functions in order and returns the most recent result
func (c *DnsaddrResolveController) NextResolver() *madns.Resolver {
	if len(c.nextResolvers) == 0 {
		c.resolver = nil
	} else {
		c.resolver = c.nextResolvers[0]()
		c.nextResolvers = c.nextResolvers[1:]
	}
	return c.resolver
}

// Resolver returns the current resolver, invokes NextResolver if the resolver is nil
func (c *DnsaddrResolveController) Resolver() *madns.Resolver {
	if c.resolver == nil {
		c.resolver = c.NextResolver()
	}
	return c.resolver
}
