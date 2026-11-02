// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ednsUDPBufferSize is the EDNS0 UDP payload size advertised to DNS servers. Per DNS Flag
// Day 2020, 1232 bytes keeps responses below the common path MTU to avoid IP fragmentation;
// larger responses come back truncated (or are dropped) and are retried over TCP by queryServer.
const ednsUDPBufferSize = 1232

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

// makeClient creates a new instance of dnsClient.
func makeClient(servers []ResolverAddress, timeout time.Duration) *dnsClient {
	return &dnsClient{servers: servers, readTimeout: timeout, transport: qsi{}}
}

// filteredClient binds answers from a TrustQuerier to the requested name,
// type, and class before either the resolver or trust chain can use them.
type filteredClient struct {
	client TrustQuerier
}

func makeFilteredClient(client TrustQuerier) *filteredClient {
	return &filteredClient{client: client}
}

func (c *filteredClient) QueryRRSet(ctx context.Context, name string, qtype uint16) ([]dns.RR, []dns.RRSIG, error) {
	rrSet, rrSig, err := c.client.QueryRRSet(ctx, name, qtype)
	if err != nil {
		return nil, nil, err
	}
	return selectRRSet(name, qtype, rrSet, rrSig)
}

func (c *filteredClient) GetRootAnchorDS() ([]dns.DS, error) {
	return c.client.GetRootAnchorDS()
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
func (t qsi) queryServer(ctx context.Context, server ResolverAddress, msg *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	var lastErr error
	for _, netType := range []string{"udp", "tcp"} {
		// Timeout bounds dial+write+read; without it dial/write use miekg's 2s default.
		resp, _, err := (&dns.Client{Net: netType, Timeout: timeout}).ExchangeContext(ctx, msg, string(server))
		if err != nil {
			// Fall through to TCP on a UDP error too (dropped response, or UDP/53
			// filtered); only a finished context is fatal.
			if ctx.Err() != nil {
				return nil, err
			}
			lastErr = err
			continue
		}
		if !resp.Truncated {
			return resp, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
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
	msg.SetEdns0(ednsUDPBufferSize, true)

	var errs []error
	for _, server := range r.servers {
		resp, err = r.transport.queryServer(ctx, server, msg, r.readTimeout)
		if err != nil {
			// Keep each server's error so the eventual failure explains itself.
			errs = append(errs, fmt.Errorf("%s: %w", server, err))
			continue
		}
		return resp, nil
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("no answer for (%s, %d) from DNS servers %v: %w", name, qtype, r.servers, errors.Join(errs...))
	}
	return nil, fmt.Errorf("no answer for (%s, %d) from DNS servers %v", name, qtype, r.servers)
}

// QueryRRSet returns the records and signatures in the answer section of a qtype query for name.
// The answer is not filtered: it may hold records for other names, such as a CNAME target.
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

// selectRRSet returns the signed RRset belonging to the queried name and type.
// A and AAAA queries may instead return a CNAME at the queried name; its target
// is resolved and authenticated by a separate query.
func selectRRSet(name string, qtype uint16, rrSet []dns.RR, rrSig []dns.RRSIG) ([]dns.RR, []dns.RRSIG, error) {
	expectedName := dns.CanonicalName(name)
	// RFC 4034 section 3.1.3: the Labels field does not count a leading wildcard label.
	expectedLabels := dns.CountLabel(expectedName)
	if strings.HasPrefix(expectedName, "*.") {
		expectedLabels--
	}
	allowCNAME := qtype == dns.TypeA || qtype == dns.TypeAAAA
	var selectedType uint16
	selectedSigs := make([]dns.RRSIG, 0, len(rrSig))
	var rejectErr error
	for _, sig := range rrSig {
		// RFC 4035 section 5.3.1 requires an RRSIG and its RRset to have the same class.
		if sig.Hdr.Class != dns.ClassINET {
			continue
		}
		if dns.CanonicalName(sig.Hdr.Name) != expectedName {
			continue
		}
		if sig.TypeCovered != qtype && !(allowCNAME && sig.TypeCovered == dns.TypeCNAME) {
			continue
		}
		signer := dns.CanonicalName(sig.SignerName)
		if !dns.IsSubDomain(signer, expectedName) {
			rejectErr = fmt.Errorf("RRSIG for %s type %s has non-ancestor signer %s", expectedName, dns.Type(sig.TypeCovered), signer)
			continue
		}
		// A smaller label count denotes a wildcard-expanded signature. The RRSIG
		// authenticates the wildcard RRset, but proving that the wildcard applies
		// to this name also requires authenticated NSEC/NSEC3 denial proofs. The
		// go-algorand DNSSEC validation path does not retain those proofs, so reject
		// wildcard-expanded answers.
		if int(sig.Labels) < expectedLabels {
			rejectErr = fmt.Errorf("wildcard-expanded answer for %s type %s is not supported", expectedName, dns.Type(sig.TypeCovered))
			continue
		}
		if selectedType != 0 && selectedType != sig.TypeCovered {
			return nil, nil, fmt.Errorf("multiple signed RRsets for %s in DNS response", expectedName)
		}
		selectedType = sig.TypeCovered
		selectedSigs = append(selectedSigs, sig)
	}
	if len(selectedSigs) == 0 {
		if rejectErr != nil {
			return nil, nil, rejectErr
		}
		return nil, nil, fmt.Errorf("no signature for %s type %s in DNS response", expectedName, dns.Type(qtype))
	}

	selectedRRs := make([]dns.RR, 0, len(rrSet))
	for _, rr := range rrSet {
		header := rr.Header()
		// RFC 2181 section 5 defines an RRset by owner, class, and type.
		// DNS queries made by dnsClient use the IN class.
		if header.Class == dns.ClassINET && dns.CanonicalName(header.Name) == expectedName && header.Rrtype == selectedType {
			selectedRRs = append(selectedRRs, rr)
		}
	}
	if len(selectedRRs) == 0 {
		return nil, nil, fmt.Errorf("no records for %s type %s in DNS response", expectedName, dns.Type(selectedType))
	}
	if selectedType == dns.TypeCNAME && len(selectedRRs) > 1 {
		// RFC 1034 section 3.6.2 requires a single CNAME RR per name.
		return nil, nil, fmt.Errorf("multiple CNAME RR detected")
	}
	return selectedRRs, selectedSigs, nil
}
