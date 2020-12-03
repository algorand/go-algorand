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
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// Querier provides a method for getting RRSet and RRSig from DNSSEC-aware server
type Querier interface {
	QueryRRSet(ctx context.Context, domain string, qtype uint16) ([]dns.RR, []dns.RRSIG, error)
}

// dnsClient implements Querier interface and it is a DNS client that tries all entries servers until success
type dnsClient struct {
	servers     []ResolverAddress
	readTimeout time.Duration
	transport   queryServerIf
}

// MakeDNSClient creates a new instance of dnsClient
func MakeDNSClient(servers []ResolverAddress, timeout time.Duration) Querier {
	return &dnsClient{servers: servers, readTimeout: timeout, transport: qsi{}}
}

// queryServerIf abstracts network communication layer in DNSClient
type queryServerIf interface {
	queryServer(ctx context.Context, server ResolverAddress, msg *dns.Msg, timeout time.Duration) (resp *dns.Msg, err error)
}

// qsi type implements queryServerIf
type qsi struct {
}

// queryServer performs DNS query against provided server with respect of both context and timeout restrictions.
// If UDP fails then retries with TCP client
func (t qsi) queryServer(ctx context.Context, server ResolverAddress, msg *dns.Msg, timeout time.Duration) (resp *dns.Msg, err error) {
	for _, netType := range []string{"udp", "tcp"} {
		if resp, _, err = (&dns.Client{Net: netType, ReadTimeout: timeout}).ExchangeContext(ctx, msg, string(server)); err != nil {
			return nil, err
		}
		if !resp.Truncated {
			return
		}
	}
	var name string
	if len(msg.Question) > 0 {
		name = msg.Question[0].Name
	}
	return nil, fmt.Errorf("DNS response for %s is still truncated even after retrying TCP", name)
}

// query builds a DNS request and tries it against all servers
func (r *dnsClient) query(ctx context.Context, name string, qtype uint16) (resp *dns.Msg, err error) {
	name = dns.Fqdn(name)

	msg := new(dns.Msg)
	msg.RecursionDesired = true
	msg.SetQuestion(name, qtype)
	msg.SetEdns0(4096, true) // high enough value prevents truncation and retries with TCP

	for _, server := range r.servers {
		resp, err := r.transport.queryServer(ctx, server, msg, r.readTimeout)
		if err != nil {
			continue
		}
		return resp, err
	}
	return nil, fmt.Errorf("no answer for (%s, %d) from DNS servers %v", name, qtype, r.servers)
}

// QueryRRSet returns resource records of qtype for name and and its signatures
func (r *dnsClient) QueryRRSet(ctx context.Context, name string, qtype uint16) ([]dns.RR, []dns.RRSIG, error) {
	msg, err := r.query(ctx, name, qtype)
	if err != nil {
		return nil, nil, err
	}
	if msg.Rcode != dns.RcodeSuccess {
		return nil, nil, fmt.Errorf("DNS error: %s", dns.RcodeToString[msg.Rcode])
	}

	rrSet := make([]dns.RR, 0, len(msg.Answer)) // answer usually contains 1-2 RRSIG so we use quite a bit more memory than needed
	rrSig := make([]dns.RRSIG, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		switch obj := rr.(type) {
		case *dns.RRSIG:
			rrSig = append(rrSig, *obj)
		default:
			rrSet = append(rrSet, rr)
		}
	}
	if len(rrSig) == 0 {
		return nil, nil, fmt.Errorf("no signature in DNS response for %s", name)
	}
	return rrSet, rrSig, nil
}
