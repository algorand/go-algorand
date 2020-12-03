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
	"net"
)

const (
	dnsPortSuffix     = ":53"
	defaultDNSAddress = "8.8.8.8"
)

// Resolver provides equivalent functionality to the net.Resolver with one exception - it allows to use a provided DNS server instead of relying on the existing default resolver.
type Resolver struct {
	// DNSAddress is the the DNS server that we'll be trying to connect to.
	dnsAddress net.IPAddr
	resolver   ResolverIf
}

// LookupSRV tries to resolve an SRV query of the given service, protocol, and domain name. The proto is "tcp" or "udp". The returned records are sorted by priority and randomized by weight within a priority.
// LookupSRV constructs the DNS name to look up following RFC 2782. That is, it looks up _service._proto.name. To accommodate services publishing SRV records under non-standard names, if both service and proto are empty strings, LookupSRV looks up name directly.
func (p *Resolver) LookupSRV(ctx context.Context, service, proto, name string) (cname string, addrs []*net.SRV, err error) {
	p.resolver = p.effectiveResolver()
	return p.resolver.LookupSRV(ctx, service, proto, name)
}

// LookupAddr performs a reverse lookup for the given address, returning a list of names mapping to that address.
func (p *Resolver) LookupAddr(ctx context.Context, addr string) (names []string, err error) {
	p.resolver = p.effectiveResolver()
	return p.resolver.LookupAddr(ctx, addr)
}

// LookupCNAME returns the canonical name for the given host. Callers that do not care about the canonical name can call LookupHost or LookupIP directly; both take care of resolving the canonical name as part of the lookup.
// A canonical name is the final name after following zero or more CNAME records. LookupCNAME does not return an error if host does not contain DNS "CNAME" records, as long as host resolves to address records.
func (p *Resolver) LookupCNAME(ctx context.Context, host string) (cname string, err error) {
	p.resolver = p.effectiveResolver()
	return p.resolver.LookupCNAME(ctx, host)

}

// LookupHost looks up the given host using the local resolver. It returns a slice of that host's addresses.
func (p *Resolver) LookupHost(ctx context.Context, host string) (addrs []string, err error) {
	p.resolver = p.effectiveResolver()
	return p.resolver.LookupHost(ctx, host)

}

// LookupIPAddr looks up host using the local resolver. It returns a slice of that host's IPv4 and IPv6 addresses.
func (p *Resolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	p.resolver = p.effectiveResolver()
	return p.resolver.LookupIPAddr(ctx, host)

}

// LookupMX returns the DNS MX records for the given domain name sorted by preference.
func (p *Resolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	p.resolver = p.effectiveResolver()
	return p.resolver.LookupMX(ctx, name)

}

// LookupNS returns the DNS NS records for the given domain name.
func (p *Resolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	p.resolver = p.effectiveResolver()
	return p.resolver.LookupNS(ctx, name)
}

// LookupPort looks up the port for the given network and service.
func (p *Resolver) LookupPort(ctx context.Context, network, service string) (port int, err error) {
	p.resolver = p.effectiveResolver()
	return p.resolver.LookupPort(ctx, network, service)
}

// LookupTXT returns the DNS TXT records for the given domain name.
func (p *Resolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	p.resolver = p.effectiveResolver()
	return p.resolver.LookupTXT(ctx, name)
}

// EffectiveResolverDNS returns effective DNS server address that would be used for the resolve operation.
func (p *Resolver) EffectiveResolverDNS() string {
	address := p.dnsAddress.String()
	if address == "" {
		return defaultDNSAddress
	}
	return address
}

func (p *Resolver) effectiveResolver() ResolverIf {
	return &net.Resolver{PreferGo: true, Dial: p.resolverDial}
}

// SetFallbackResolverAddress sets preferred DNS server address
func (p *Resolver) SetFallbackResolverAddress(fallbackDNSResolverAddress net.IPAddr) {
	p.dnsAddress = fallbackDNSResolverAddress
	return
}

func (p *Resolver) resolverDial(ctx context.Context, network, address string) (net.Conn, error) {
	// override the default address with our own.
	address = p.EffectiveResolverDNS() + dnsPortSuffix
	return (&net.Dialer{}).DialContext(ctx, network, address)
}
