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
	"context"
	"fmt"
	"net"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/tools/network/dnssec"
)

// ReadFromSRV is a helper to collect SRV addresses for a given name.
func ReadFromSRV(service string, protocol string, name string, fallbackDNSResolverAddress string, secure bool) (addrs []string, err error) {
	log := logging.Base()
	if name == "" {
		log.Debug("no dns lookup due to empty name")
		return
	}
	if protocol != "tcp" && protocol != "udp" && protocol != "tls" {
		err = fmt.Errorf("unsupported protocol '%s' specified", protocol)
		return
	}

	var records []*net.SRV
	if secure {
		var dnssecError error
		_, records, dnssecError = dnssec.LookupSRV(service, protocol, name)
		if dnssecError != nil {
			err = fmt.Errorf("ReadFromBootstrap: Failed to obtain SRV with DNSSEC: %s", dnssecError.Error())
			return
		}
	} else {
		var sysLookupErr error
		_, records, sysLookupErr = net.LookupSRV(service, protocol, name)
		if sysLookupErr != nil {
			var resolver Resolver
			// try to resolve the address. If it's an dotted-numbers format, it would return that right away.
			// if it's a named address, we would attempt to parse it and might fail.
			// ( failing isn't that bad; the resolver would internally try to use 8.8.8.8 instead )
			if DNSIPAddr, err2 := net.ResolveIPAddr("ip", fallbackDNSResolverAddress); err2 == nil {
				resolver.DNSAddress = *DNSIPAddr
			} else {
				log.Infof("ReadFromBootstrap: Failed to resolve fallback DNS resolver address '%s': %v; falling back to default fallback resolver address", fallbackDNSResolverAddress, err2)
			}

			_, records, err = resolver.LookupSRV(context.Background(), service, protocol, name)
			if err != nil {
				err = fmt.Errorf("ReadFromBootstrap: DNS LookupSRV failed when using system resolver(%v) as well as via %s due to %v", sysLookupErr, resolver.EffectiveResolverDNS(), err)
				return
			}
			// we succeeded when using the public dns. log this.
			log.Infof("ReadFromBootstrap: DNS LookupSRV failed when using the system resolver(%v); using public DNS(%s) server directly instead.", sysLookupErr, resolver.EffectiveResolverDNS())
		}
	}
	for _, srv := range records {
		// empty target won't take us far; skip these
		if srv.Target == "" {
			continue
		}
		// according to the SRV spec, each target need to end with a dot. While this would make a valid host name, including the
		// last dot could lead to a non-canonical domain name representation, which would better get avoided.
		if srv.Target[len(srv.Target)-1:] == "." {
			srv.Target = srv.Target[:len(srv.Target)-1]
		}
		addrs = append(addrs, fmt.Sprintf("%s:%d", srv.Target, srv.Port))
	}
	return
}
