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
	"time"
)

// DefaultMaxHops sets max hops for DNS request
const DefaultMaxHops = 10

// DefaultTimeout is seconds before giving up request
const DefaultTimeout = 1 * time.Second
const maxTimeout = 5 * time.Second

// List of DNSSEC-aware public servers
// CloudFlare: 1.1.1.1:53 1.0.0.1:53
// Google: 8.8.8.8:53 8.8.4.4:53
// Yandex 77.88.8.8:53 77.88.8.1:53
// Comodo 8.26.56.26:53 8.20.247.20:53
// OpenDNS 208.67.222.222:53, 208.67.220.220:53
// Baidu 180.76.76.76:53

// Other - no DNSSEC - last check 2020-12-01
// Alibaba 223.6.6.6:53

// DefaultDnssecAwareNSServers is a list of known public DNSSEC-aware servers
var DefaultDnssecAwareNSServers = []ResolverAddress{"1.1.1.1:53", "208.67.222.222:53", "8.8.8.8:53", "77.88.8.8:53", "8.26.56.26:53", "180.76.76.76:53"}

// ResolverAddress is ip addr + port as string
type ResolverAddress string

// MakeResolverAddress creates a new ResolverAddress instance from address and port
func MakeResolverAddress(addr, port string) ResolverAddress {
	return ResolverAddress(addr + ":" + port)
}
