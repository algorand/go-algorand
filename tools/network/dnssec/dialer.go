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

package dnssec

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Dialer wraps net.Dialer and provides a custom DNSSEC-aware resolver
type Dialer struct {
	InnerDialer *net.Dialer
	Resolver    ResolverIf
}

// DialContext connects to the address on the named network using the provided context.
// It waits if needed not to exceed connectionsRateLimitingCount.
// Idea:
//   net.Dialer.DialContext calls net.Dialer.resolver().resolveAddrList
//   that calls net.Resolver.internetAddrList
//   that ends up in LookupIPAddr -> lookupIPAddr -> parseIPZone -> return
//   So this DialContext:
//   1. Parses address to host and port
//   2. If the host is not IPv4/IPv6 address then resolves it with DNSSEC
//   3. Calls original net.DialContext knowing that the name already resolved
//   and the control flow would be as described above
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {

	// snipped below is from net.Resolver.internetAddrList
	var (
		err        error
		host, port string
		portnum    int
	)

	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		if address != "" {
			if host, port, err = net.SplitHostPort(address); err != nil {
				return nil, err
			}
			if portnum, err = d.Resolver.LookupPort(ctx, network, port); err != nil {
				return nil, err
			}
		}
	default:
		return nil, net.UnknownNetworkError(network)
	}
	// end snippet

	if host == "" {
		return nil, fmt.Errorf("Empty host")
	}

	var resolvedAddr string

	// check if address is IPv4 or IPv6 address
	var zone string
	if i := strings.LastIndex(host, "%"); i > 0 {
		host, zone = host[:i], host[i+1:]
	}

	if netIP := net.ParseIP(host); netIP != nil {
		resolvedAddr = netIP.String()
		if zone != "" {
			resolvedAddr = fmt.Sprintf("%s%%%s", resolvedAddr, zone)
		}
	} else {
		// not an address, lookup with DNS
		var ipAddrs []net.IPAddr
		if ipAddrs, err = d.Resolver.LookupIPAddr(ctx, host); err != nil {
			return nil, err
		}
		resolvedAddr = ipAddrs[0].String() // LookupIPAddr returns non-empty list
	}

	resolvedAddr = net.JoinHostPort(resolvedAddr, strconv.Itoa(portnum))
	return d.InnerDialer.DialContext(ctx, network, resolvedAddr)
}
