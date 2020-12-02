// Copyright (C) 2019-2020 Algorand, Inc.
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
	"net"
	"time"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/tools/network/dnssec"
)

// ResolverIf is re-import from dnssec.ResolverIf
type ResolverIf interface {
	dnssec.ResolverIf
}

// compile-time check
var _ dnssec.ResolverIf = &Resolver{}
var _ dnssec.ResolverIf = &dnssec.Resolver{}

// ResolveController provides a layer of abstaction for a regular, or DNSSEC-aware resolvers
type ResolveController struct {
	secure   bool
	fallback string
}

// NewResolveController creates a new ResolveController
func NewResolveController(secure bool, fallbackDNSResolverAddress string) ResolveController {
	return ResolveController{secure, fallbackDNSResolverAddress}
}

// SystemResolver returns a resolver that uses OS-defined DNS servers
func (c *ResolveController) SystemResolver() ResolverIf {
	log := logging.Base()
	if c.secure {
		servers, timeout, err := dnssec.SystemConfig()
		if err != nil {
			log.Debugf("retrieving system config failed with %s", err.Error())
			servers = []string{}
			timeout = time.Millisecond
		}
		return dnssec.MakeDnssecResolver(servers, timeout)
	}
	return net.DefaultResolver
}

// FallbackResolver returns a resolver that uses fallback DNS address
func (c *ResolveController) FallbackResolver() ResolverIf {
	log := logging.Base()
	var dnsIPAddr *net.IPAddr
	var err error
	if dnsIPAddr, err = net.ResolveIPAddr("ip", c.fallback); err != nil {
		log.Debugf("resolving fallback %s failed with %s", c.fallback, err.Error())
	}

	if c.secure {
		return dnssec.MakeDnssecResolver([]string{dnsIPAddr.String() + dnsPortSuffix}, dnssec.DefaultTimeout)
	}

	r := Resolver{}
	r.SetFallbackResolverAddress(*dnsIPAddr)
	return &r
}

// DefaultResolver returns a resolver that uses fallback DNS address
func (c *ResolveController) DefaultResolver() ResolverIf {
	if c.secure {
		return dnssec.MakeDnssecResolver(dnssec.DefaultDnssecAwareNSServers, dnssec.DefaultTimeout)
	}
	return &Resolver{}
}
