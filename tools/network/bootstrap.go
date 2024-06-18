// Copyright (C) 2019-2024 Algorand, Inc.
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
)

func readFromSRV(ctx context.Context, service string, protocol string, name string, fallbackDNSResolverAddress string, secure bool) (records []*net.SRV, err error) {
	log := logging.Base()
	if name == "" {
		log.Debug("no dns lookup due to empty name")
		return
	}
	if protocol != "tcp" && protocol != "udp" && protocol != "tls" {
		err = fmt.Errorf("unsupported protocol '%s' specified", protocol)
		return
	}

	controller := NewResolveController(secure, fallbackDNSResolverAddress, log)

	systemResolver := controller.SystemResolver()
	_, records, sysLookupErr := systemResolver.LookupSRV(ctx, service, protocol, name)
	if sysLookupErr != nil {
		log.Infof("ReadFromBootstrap: DNS LookupSRV failed when using system resolver: %v", sysLookupErr)

		var fallbackLookupErr error
		if fallbackDNSResolverAddress != "" {
			fallbackResolver := controller.FallbackResolver()
			_, records, fallbackLookupErr = fallbackResolver.LookupSRV(ctx, service, protocol, name)
		}
		if fallbackLookupErr != nil {
			log.Infof("ReadFromBootstrap: DNS LookupSRV failed when using fallback '%s' resolver: %v", fallbackDNSResolverAddress, fallbackLookupErr)
		}

		if fallbackLookupErr != nil || fallbackDNSResolverAddress == "" {
			fallbackResolver := controller.DefaultResolver()
			var defaultLookupErr error
			_, records, defaultLookupErr = fallbackResolver.LookupSRV(ctx, service, protocol, name)
			if defaultLookupErr != nil {
				err = fmt.Errorf("ReadFromBootstrap: DNS LookupSRV failed when using system resolver(%v), fallback resolver(%v), as well as using default resolver due to %v", sysLookupErr, fallbackLookupErr, defaultLookupErr)
				return
			}
		}
	}
	return records, err
}

// ReadFromSRV is a helper to collect SRV addresses for a given name
func ReadFromSRV(ctx context.Context, service string, protocol string, name string, fallbackDNSResolverAddress string, secure bool) (addrs []string, err error) {
	records, err := readFromSRV(ctx, service, protocol, name, fallbackDNSResolverAddress, secure)
	if err != nil {
		return addrs, err
	}

	for _, srv := range records {
		// empty target won't take us far; skip these
		if srv.Target == "" {
			continue
		}
		// according to the SRV spec, each target need to end with a dot. While this would make a valid host name, including the
		// last dot could lead to a non-canonical domain name representation, which is better avoided.
		if srv.Target[len(srv.Target)-1:] == "." {
			srv.Target = srv.Target[:len(srv.Target)-1]
		}
		addrs = append(addrs, fmt.Sprintf("%s:%d", srv.Target, srv.Port))
	}
	return
}

// ReadFromSRVPriority is a helper to collect SRV addresses with priorities for a given name
func ReadFromSRVPriority(service string, protocol string, name string, fallbackDNSResolverAddress string, secure bool) (prioAddrs map[uint16][]string, err error) {
	records, err := readFromSRV(context.Background(), service, protocol, name, fallbackDNSResolverAddress, secure)
	if err != nil {
		return prioAddrs, err
	}
	prioAddrs = make(map[uint16][]string, 4)
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
		addrs := prioAddrs[srv.Priority]
		addrs = append(addrs, fmt.Sprintf("%s:%d", srv.Target, srv.Port))
		prioAddrs[srv.Priority] = addrs
	}
	return
}
