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

package dnssec

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Resolver provides DNSSEC resolution
type Resolver struct {
	resolver   resolverIf
	trustChain *trustChain
}

type resolverIf interface {
	query(domain string, qtype uint16) (resp *dns.Msg, err error)
	queryRRSet(domain string, qtype uint16) (*[]dns.RR, *[]dns.RRSIG, error)
	rootTrustAnchor() ([]dns.DS, error)

	// test functions
	serverList() []string
}

// SRVRec represent an entry in SRV response
type SRVRec struct {
	Prio   uint16
	Weight uint16
	Port   uint16
	Target string
}

const defaultDnssecAwareServer = "1.1.1.1:53"

// MakeDnssecResolver return resolver from given NS servers and timeout duration
func MakeDnssecResolver(servers []string, timeout time.Duration) (r Resolver) {
	client := makeDNSClient("udp", timeout)
	rs := &resolverImpl{client: client, servers: servers, rootAnchor: rootAnchorXML}

	if len(rs.servers) == 0 {
		rs.servers = append(rs.servers, defaultDnssecAwareServer)
	}
	r.resolver = rs
	r.trustChain = makeTrustChain(r.resolver)
	return
}

// lookupImpl makes DNS request for a zone and verifies response signature
func (r *Resolver) lookupImpl(name string, qt uint16) (rrSet *[]dns.RR, err error) {
	rrSet, rrSig, err := r.resolver.queryRRSet(name, qt)
	if err != nil {
		return
	}
	err = r.trustChain.authenticate(rrSet, rrSig)
	return
}

// lookupImplCnameAware like lookupImpl makes DNS request for a zone and verifies response signature
// but also it is aware about possible A/CNAME entries for A-requests and supposed to be used for CNAME alias resolution.
// if CNAME signature presents for requested domain name, then consider the response as CNAME
// and extract CNAME record(s) and its RRSIG
func (r *Resolver) lookupImplCnameAware(name string, qt uint16) (rrSet *[]dns.RR, err error) {
	rrSet, rrSig, err := r.resolver.queryRRSet(name, qt)
	if err != nil {
		return
	}

	// as https://tools.ietf.org/html/rfc1034 section 3.6.2 says
	// NS can return CNAME for A request if there no A but CNAME
	// in real world such A-response can also have second-level CNAME alias
	//
	// so that leave only CNAME RR matching to requested name to verify signature and return the filtered set
	if qt == dns.TypeA || qt == dns.TypeAAAA {
		newRRSig := make([]dns.RRSIG, 0, len(*rrSig))
		for _, sig := range *rrSig {
			if sig.Hdr.Name == name && sig.TypeCovered == dns.TypeCNAME {
				newRRSig = append(newRRSig, sig)
				break
			}
		}
		if len(newRRSig) > 0 {
			newRRSet := make([]dns.RR, 0, len(*rrSet))
			for _, rr := range *rrSet {
				switch obj := rr.(type) {
				case *dns.CNAME:
					if obj.Hdr.Name == name {
						newRRSet = append(newRRSet, obj)
					}
				}
			}
			if len(newRRSet) == 0 {
				return nil, fmt.Errorf("no CNAME RR in A request and CNAME signed response")
			}
			if len(newRRSet) > 1 {
				// RFC 1034 section 3.6.2 requires a single CNAME RR per name
				return nil, fmt.Errorf("multiple CNAME RR detected")
			}
			rrSet = &newRRSet
			rrSig = &newRRSig
		}
	}
	err = r.trustChain.authenticate(rrSet, rrSig)
	return
}

// LookupIPRecursive resolves a given hostname to ipv4 or ipv6 address following CNAME aliaces
func (r *Resolver) LookupIPRecursive(hostname string, maxHops int) (addrs []net.IP, err error) {
	var rrSet *[]dns.RR
	alias := hostname
	for hop := 0; hop < maxHops; hop++ {
		if rrSet, err = r.lookupImplCnameAware(alias, dns.TypeA); err != nil {
			return
		}
		addrs = make([]net.IP, 0, len(*rrSet))
		for _, rr := range *rrSet {
			switch obj := rr.(type) {
			case *dns.A:
				addrs = append(addrs, obj.A)
			case *dns.AAAA:
				addrs = append(addrs, obj.AAAA)
			case *dns.CNAME:
				alias = obj.Target
			}
		}
		if len(addrs) > 0 {
			return
		}
	}
	err = fmt.Errorf("exceed max attempts %d", maxHops)
	return
}

// LookupIP resolves a given hostname to ipv4 or ipv6 address
func (r *Resolver) LookupIP(hostname string) (addrs []net.IP, err error) {
	var rrSet *[]dns.RR
	if rrSet, err = r.lookupImpl(hostname, dns.TypeA); err != nil {
		return
	}
	addrs = make([]net.IP, 0, len(*rrSet))
	for _, rr := range *rrSet {
		switch obj := rr.(type) {
		case *dns.A:
			addrs = append(addrs, obj.A)
		case *dns.AAAA:
			addrs = append(addrs, obj.AAAA)
		}
	}
	return
}

// LookupSRV returns SRV records content for a given name
func (r *Resolver) LookupSRV(name string) (entries []SRVRec, err error) {
	var rrSet *[]dns.RR
	if rrSet, err = r.lookupImpl(name, dns.TypeSRV); err != nil {
		return
	}

	result := make([]SRVRec, 0, len(*rrSet))
	for _, rr := range *rrSet {
		switch obj := rr.(type) {
		case *dns.SRV:
			r := SRVRec{
				Prio: obj.Priority, Weight: obj.Weight,
				Port: obj.Port, Target: obj.Target,
			}
			result = append(result, r)
		}
	}
	return result, err
}

// LookupCNAME returns CNAME record content for a given name
func (r *Resolver) LookupCNAME(name string) (entry string, err error) {
	var rrSet *[]dns.RR
	if rrSet, err = r.lookupImpl(name, dns.TypeCNAME); err != nil {
		return
	}

	for _, rr := range *rrSet {
		switch obj := rr.(type) {
		case *dns.CNAME:
			entry = obj.Target
		}
	}
	return
}
