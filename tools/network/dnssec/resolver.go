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

/*
Package dnssec provides net.Resolver-compatible methods for DNSSEC.

Fully DNSSEC-compliant:
LookupIPAddr, LookupCNAME, LookupSRV, LookupTXT, LookupMX, LookupNS, LookupTLSA

Fallbacks to net.DefaultResolver:
LookupAddr, LookupPort, LookupHost

The package uses miekg/dns for low-level DNS intractions and DNS messages parsing.

References
1. DNS https://tools.ietf.org/html/rfc1035
2. DNS clarifications https://tools.ietf.org/html/rfc2181
3. DNSSEC proto change https://tools.ietf.org/html/rfc4035
4. DNSSEC RR change https://tools.ietf.org/html/rfc4034
5. DNSSEC clarifications https://tools.ietf.org/html/rfc6840
6. DNSSEC keys management https://tools.ietf.org/html/rfc6781
7. DNS SRV https://tools.ietf.org/html/rfc2782

*/
package dnssec

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/algorand/go-algorand/logging"
)

// ResolverIf represents net.Resolver-compatible interface
type ResolverIf interface {
	LookupAddr(ctx context.Context, addr string) (names []string, err error)
	LookupCNAME(ctx context.Context, host string) (cname string, err error)
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupPort(ctx context.Context, network, service string) (port int, err error)
	LookupSRV(ctx context.Context, service, proto, name string) (cname string, addrs []*net.SRV, err error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Resolver provides DNSSEC resolution
type Resolver struct {
	client     Querier
	trustChain *trustChain
	maxHops    int
}

// MakeDnssecResolver return resolver from given NS servers and timeout duration
func MakeDnssecResolver(servers []ResolverAddress, timeout time.Duration) ResolverIf {
	dc := MakeDNSClient(servers, timeout)
	tc := &QueryWrapper{dc}
	return &Resolver{client: dc, trustChain: makeTrustChain(tc), maxHops: DefaultMaxHops}
}

// MakeDefaultDnssecResolver returns a resolver with all possible DNS servers:
// system, fallback, default
func MakeDefaultDnssecResolver(fallbackAddress string) ResolverIf {
	log := logging.Base()
	servers, timeout, err := SystemConfig()
	if err != nil {
		log.Debugf("retrieving system config failed with %s", err.Error())
		timeout = DefaultTimeout
	}

	var fallback string
	var dnsIPAddr *net.IPAddr
	if dnsIPAddr, err = net.ResolveIPAddr("ip", fallbackAddress); err != nil {
		log.Debugf("resolving fallback %s failed with %s", fallbackAddress, err.Error())
	} else {
		fallback = dnsIPAddr.String()
	}

	servers = append(servers, MakeResolverAddress(fallback, "53"))
	servers = append(servers, DefaultDnssecAwareNSServers...)
	return MakeDnssecResolver(servers, timeout)
}

// EffectiveResolverDNS return list of active DNS servers
func (r *Resolver) EffectiveResolverDNS() (servers []ResolverAddress) {
	return r.client.(*dnsClient).servers
}

// TLSARec represents TLSA record content
type TLSARec struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  string `dns:"hex"`
}

// lookupImpl makes DNS request for a zone and verifies response signature
func (r *Resolver) lookup(ctx context.Context, name string, qt uint16) (rrSet []dns.RR, err error) {
	rrSet, rrSig, err := r.client.QueryRRSet(ctx, name, qt)
	if err != nil {
		return
	}
	err = r.trustChain.Authenticate(ctx, rrSet, rrSig)
	return
}

// lookupImplCnameAware like lookupImpl requests a zone and verifies response signature
// but also it is aware about possible A/CNAME entries for A-requests and supposed to be used for CNAME alias resolution.
// if CNAME signature presents for requested domain name, then consider the response as CNAME
// and extract CNAME record(s) and its RRSIG
func (r *Resolver) lookupCnameAware(ctx context.Context, name string, qt uint16) (rrSet []dns.RR, err error) {
	rrSet, rrSig, err := r.client.QueryRRSet(ctx, name, qt)
	if err != nil {
		return
	}

	// As https://tools.ietf.org/html/rfc1034 section 3.6.2 says
	// NS can return CNAME for A request if there are no A but CNAME
	// in real world such A-response can also have second-level CNAME alias and A records with signatures
	//
	// so that we leave only CNAME RR matching to requested name to verify signature and return the filtered set
	if qt == dns.TypeA || qt == dns.TypeAAAA {
		newRRSig := make([]dns.RRSIG, 0, len(rrSig))
		for _, sig := range rrSig {
			if sig.Hdr.Name == name {
				if sig.TypeCovered == dns.TypeCNAME || sig.TypeCovered == dns.TypeA || sig.TypeCovered == dns.TypeAAAA {
					if len(newRRSig) == 0 {
						newRRSig = append(newRRSig, sig)
					} else if sig.TypeCovered == newRRSig[len(newRRSig)-1].TypeCovered {
						newRRSig = append(newRRSig, sig)
					}
				}
			}
		}
		if len(newRRSig) > 0 {
			newRRSet := make([]dns.RR, 0, len(rrSet))
			for _, rr := range rrSet {
				if rr.Header().Name == name && rr.Header().Rrtype == newRRSig[0].TypeCovered {
					newRRSet = append(newRRSet, rr)
				}
			}
			if len(newRRSet) == 0 {
				return nil, fmt.Errorf("no RR in A response mathing signature with type %d", newRRSig[0].TypeCovered)
			}
			if newRRSig[0].TypeCovered == dns.TypeCNAME && len(newRRSet) > 1 {
				// RFC 1034 section 3.6.2 requires a single CNAME RR per name
				return nil, fmt.Errorf("multiple CNAME RR detected")
			}
			rrSet = newRRSet
			rrSig = newRRSig
		}
	}
	err = r.trustChain.Authenticate(ctx, rrSet, rrSig)
	return
}

// LookupIPAddr resolves a given hostname to ipv4 or ipv6 address following CNAME aliaces
func (r *Resolver) lookupIPAddr(ctx context.Context, hostname string) (cname string, addrs []net.IPAddr, err error) {
	var rrSet []dns.RR
	nextName := hostname
	seen := make(map[string]bool)
	for hop := 0; hop < r.maxHops; hop++ {
		if _, ok := seen[nextName]; ok {
			err = fmt.Errorf("loop detected: %s already seen", nextName)
			return
		}

		if rrSet, err = r.lookupCnameAware(ctx, nextName, dns.TypeA); err != nil {
			var err2 error
			if rrSet, err2 = r.lookupCnameAware(ctx, nextName, dns.TypeAAAA); err2 != nil {
				return // return original error
			}
		}
		seen[nextName] = true
		addrs = make([]net.IPAddr, 0, len(rrSet))
		for _, rr := range rrSet {
			switch obj := rr.(type) {
			case *dns.A:
				addrs = append(addrs, net.IPAddr{IP: obj.A, Zone: ""})
			case *dns.AAAA:
				addrs = append(addrs, net.IPAddr{IP: obj.AAAA, Zone: ""})
			case *dns.CNAME:
				nextName = obj.Target
			}
		}
		if len(addrs) > 0 {
			cname = nextName
			return
		}
	}
	err = fmt.Errorf("exceed max attempts %d", r.maxHops)
	return
}

// LookupIPAddr resolves a given hostname to ipv4 or ipv6 address
func (r *Resolver) LookupIPAddr(ctx context.Context, host string) (addrs []net.IPAddr, err error) {
	_, addrs, err = r.lookupIPAddr(ctx, host)
	return
}

// LookupCNAME returns CNAME record content for a given name
func (r *Resolver) LookupCNAME(ctx context.Context, host string) (cname string, err error) {
	cname, _, err = r.lookupIPAddr(ctx, host)
	return
}

// LookupSRV returns SRV records content for a service, proto and given name
// Like net.Resolver, it orders results according to Priority and Weight
func (r *Resolver) LookupSRV(ctx context.Context, service, proto, name string) (cname string, addrs []*net.SRV, err error) {
	var fullName string
	if service == "" && proto == "" {
		fullName = name
	} else {
		fullName = "_" + service + "._" + proto + "." + name
	}

	var rrSet []dns.RR
	if rrSet, err = r.lookup(ctx, fullName, dns.TypeSRV); err != nil {
		return
	}

	for _, rr := range rrSet {
		switch obj := rr.(type) {
		case *dns.SRV:
			if cname == "" && obj.Hdr.Name != "" {
				cname = obj.Hdr.Name
			}
			addrs = append(
				addrs,
				&net.SRV{
					Target:   obj.Target,
					Port:     obj.Port,
					Priority: obj.Priority,
					Weight:   obj.Weight,
				},
			)
		}
	}

	srvRecArray(addrs).sortAndRand()

	return
}

// LookupMX returns MX records content for a given name
func (r *Resolver) LookupMX(ctx context.Context, name string) (addrs []*net.MX, err error) {
	var rrSet []dns.RR
	if rrSet, err = r.lookup(ctx, name, dns.TypeMX); err != nil {
		return
	}

	for _, rr := range rrSet {
		switch obj := rr.(type) {
		case *dns.MX:
			addrs = append(
				addrs,
				&net.MX{
					Host: obj.Mx,
					Pref: obj.Preference,
				},
			)
		}
	}
	return
}

// LookupNS returns NS records content for a given name
func (r *Resolver) LookupNS(ctx context.Context, name string) (addrs []*net.NS, err error) {
	var rrSet []dns.RR
	if rrSet, err = r.lookup(ctx, name, dns.TypeNS); err != nil {
		return
	}

	for _, rr := range rrSet {
		switch obj := rr.(type) {
		case *dns.NS:
			addrs = append(
				addrs,
				&net.NS{
					Host: obj.Ns,
				},
			)
		}
	}
	return
}

// LookupTXT returns TXT records content for a given name
func (r *Resolver) LookupTXT(ctx context.Context, name string) (addrs []string, err error) {
	var rrSet []dns.RR
	if rrSet, err = r.lookup(ctx, name, dns.TypeTXT); err != nil {
		return
	}

	for _, rr := range rrSet {
		switch obj := rr.(type) {
		case *dns.TXT:
			addrs = append(
				addrs,
				obj.Txt...,
			)
		}
	}
	return
}

// LookupTLSA returns TLSA records content for a service, proto and name
func (r *Resolver) LookupTLSA(ctx context.Context, service, proto, name string) (addrs []TLSARec, err error) {
	var fullName string
	if service == "" && proto == "" {
		fullName = name
	} else {
		fullName = "_" + service + "._" + proto + "." + name
	}

	var rrSet []dns.RR
	if rrSet, err = r.lookup(ctx, fullName, dns.TypeTLSA); err != nil {
		return
	}

	for _, rr := range rrSet {
		switch obj := rr.(type) {
		case *dns.TLSA:
			addrs = append(
				addrs,
				TLSARec{
					Usage:        obj.Usage,
					Selector:     obj.Selector,
					MatchingType: obj.MatchingType,
					Certificate:  obj.Certificate,
				},
			)
		}
	}
	return
}

// LookupPort looks up the port for the given network and service.
func (r *Resolver) LookupPort(ctx context.Context, network, service string) (port int, err error) {
	return net.DefaultResolver.LookupPort(ctx, network, service)
}

// LookupAddr performs a reverse lookup for the given address, returning a list of names mapping to that address.
func (r *Resolver) LookupAddr(ctx context.Context, addr string) (names []string, err error) {
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

// LookupHost looks up the given host using the local resolver. It returns a slice of that host's addresses.
func (r *Resolver) LookupHost(ctx context.Context, host string) (addrs []string, err error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}
