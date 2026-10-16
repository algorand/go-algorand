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
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestEmptyClient(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	c := MakeDNSClient(nil, time.Second)
	rr, rsig, err := c.QueryRRSet(context.Background(), "test", 0)
	a.Error(err)
	a.Empty(rr)
	a.Empty(rsig)

	c = MakeDNSClient([]ResolverAddress{}, time.Second)
	rr, rsig, err = c.QueryRRSet(context.Background(), "test", 0)
	a.Error(err)
	a.Empty(rr)
	a.Empty(rsig)

	c = MakeDNSClient([]ResolverAddress{"example.com"}, time.Millisecond)
	rr, rsig, err = c.QueryRRSet(context.Background(), "test", 0)
	a.Error(err)
	a.Empty(rr)
	a.Empty(rsig)
}

type ttr struct {
	msg dns.Msg
}

func (t ttr) queryServer(ctx context.Context, server ResolverAddress, msg *dns.Msg, timeout time.Duration) (resp *dns.Msg, err error) {
	return &t.msg, nil
}

func TestMockedClient(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	qs := ttr{}
	c := dnsClient{[]ResolverAddress{"test"}, time.Second, qs}
	rr, rsig, err := c.QueryRRSet(context.Background(), "test", 0)
	a.Error(err)
	a.Empty(rr)
	a.Empty(rsig)

	var answer = []dns.RR{&dns.DNSKEY{}, &dns.RRSIG{}}
	qs = ttr{msg: dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}, Answer: answer}}
	c = dnsClient{[]ResolverAddress{"test"}, time.Second, qs}
	rr, rsig, err = c.QueryRRSet(context.Background(), "test", 0)
	a.Error(err)
	a.Contains(err.Error(), "SERVFAIL")
	a.Empty(rr)
	a.Empty(rsig)

	qs = ttr{msg: dns.Msg{Answer: answer}}
	c = dnsClient{[]ResolverAddress{"test"}, time.Second, qs}
	rr, rsig, err = c.QueryRRSet(context.Background(), "test", 0)
	a.NoError(err)
	a.Equal(1, len(rr))
	a.Equal(1, len(rsig))
}

func TestSelectRRSet(t *testing.T) {
	partitiontest.PartitionTest(t)

	txt := func(owner string) dns.RR {
		return &dns.TXT{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{owner}}
	}
	aRecord := func(owner string) dns.RR {
		return &dns.A{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(1, 2, 3, 4)}
	}
	cname := func(owner, target string) dns.RR {
		return &dns.CNAME{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: target}
	}
	sig := func(owner string, covered uint16, labels uint8, signer string) dns.RRSIG {
		return dns.RRSIG{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET}, TypeCovered: covered, Labels: labels, SignerName: signer}
	}

	wanted, wantedSig := txt("wanted.test."), sig("wanted.test.", dns.TypeTXT, 2, "test.")
	foreign, foreignSig := txt("foreign.test."), sig("foreign.test.", dns.TypeTXT, 2, "test.")
	chaos, chaosSig := txt("wanted.test."), sig("wanted.test.", dns.TypeTXT, 2, "test.")
	chaos.Header().Class = dns.ClassCHAOS
	chaosSig.Hdr.Class = dns.ClassCHAOS
	mixedCase, mixedCaseSig := txt("Wanted.TEST."), sig("WANTED.test.", dns.TypeTXT, 2, "Test.")
	alias, aliasSig := cname("alias.test.", "target.test."), sig("alias.test.", dns.TypeCNAME, 2, "test.")
	target, targetSig := aRecord("target.test."), sig("target.test.", dns.TypeA, 2, "test.")
	literalWildcard, literalWildcardSig := txt("*.test."), sig("*.test.", dns.TypeTXT, 1, "test.")

	tests := []struct {
		name    string
		qname   string
		qtype   uint16
		rrSet   []dns.RR
		rrSig   []dns.RRSIG
		wantSet []dns.RR
		wantSig []dns.RRSIG
		wantErr string
	}{
		{name: "selects the queried name", qname: "wanted.test", qtype: dns.TypeTXT,
			rrSet: []dns.RR{foreign, wanted}, rrSig: []dns.RRSIG{foreignSig, wantedSig},
			wantSet: []dns.RR{wanted}, wantSig: []dns.RRSIG{wantedSig}},
		{name: "rejects another name", qname: "wanted.test", qtype: dns.TypeTXT,
			rrSet: []dns.RR{foreign}, rrSig: []dns.RRSIG{foreignSig},
			wantErr: "no signature for wanted.test. type TXT in DNS response"},
		{name: "ignores query name case", qname: "WANTED.Test", qtype: dns.TypeTXT,
			rrSet: []dns.RR{wanted}, rrSig: []dns.RRSIG{wantedSig},
			wantSet: []dns.RR{wanted}, wantSig: []dns.RRSIG{wantedSig}},
		{name: "ignores response name case", qname: "wanted.test.", qtype: dns.TypeTXT,
			rrSet: []dns.RR{mixedCase}, rrSig: []dns.RRSIG{mixedCaseSig},
			wantSet: []dns.RR{mixedCase}, wantSig: []dns.RRSIG{mixedCaseSig}},
		{name: "ignores other classes", qname: "wanted.test.", qtype: dns.TypeTXT,
			rrSet: []dns.RR{chaos, wanted}, rrSig: []dns.RRSIG{chaosSig, wantedSig},
			wantSet: []dns.RR{wanted}, wantSig: []dns.RRSIG{wantedSig}},
		{name: "rejects a signature for another type", qname: "wanted.test.", qtype: dns.TypeTXT,
			rrSet: []dns.RR{aRecord("wanted.test.")}, rrSig: []dns.RRSIG{sig("wanted.test.", dns.TypeA, 2, "test.")},
			wantErr: "no signature for wanted.test. type TXT in DNS response"},
		{name: "selects a CNAME for an A query", qname: "alias.test.", qtype: dns.TypeA,
			rrSet: []dns.RR{alias, target}, rrSig: []dns.RRSIG{aliasSig, targetSig},
			wantSet: []dns.RR{alias}, wantSig: []dns.RRSIG{aliasSig}},
		{name: "rejects a CNAME for a TXT query", qname: "alias.test.", qtype: dns.TypeTXT,
			rrSet: []dns.RR{alias}, rrSig: []dns.RRSIG{aliasSig},
			wantErr: "no signature for alias.test. type TXT in DNS response"},
		{name: "rejects a CNAME signed next to A records", qname: "alias.test.", qtype: dns.TypeA,
			rrSet: []dns.RR{alias, aRecord("alias.test.")}, rrSig: []dns.RRSIG{aliasSig, sig("alias.test.", dns.TypeA, 2, "test.")},
			wantErr: "multiple signed RRsets for alias.test. in DNS response"},
		{name: "rejects multiple CNAMEs", qname: "alias.test.", qtype: dns.TypeA,
			rrSet: []dns.RR{alias, cname("alias.test.", "other.test.")}, rrSig: []dns.RRSIG{aliasSig},
			wantErr: "multiple CNAME RR detected"},
		{name: "rejects a signature without records", qname: "wanted.test.", qtype: dns.TypeTXT,
			rrSig:   []dns.RRSIG{wantedSig},
			wantErr: "no records for wanted.test. type TXT in DNS response"},
		{name: "rejects a signer that is only a string suffix", qname: "algorand.test.", qtype: dns.TypeTXT,
			rrSet: []dns.RR{txt("algorand.test.")}, rrSig: []dns.RRSIG{sig("algorand.test.", dns.TypeTXT, 2, "rand.test.")},
			wantErr: "RRSIG for algorand.test. type TXT has non-ancestor signer rand.test."},
		{name: "rejects a wildcard expansion", qname: "wanted.test.", qtype: dns.TypeTXT,
			rrSet: []dns.RR{wanted}, rrSig: []dns.RRSIG{sig("wanted.test.", dns.TypeTXT, 1, "test.")},
			wantErr: "wildcard-expanded answer for wanted.test. type TXT is not supported"},
		{name: "accepts a literal wildcard owner", qname: "*.test.", qtype: dns.TypeTXT,
			rrSet: []dns.RR{literalWildcard}, rrSig: []dns.RRSIG{literalWildcardSig},
			wantSet: []dns.RR{literalWildcard}, wantSig: []dns.RRSIG{literalWildcardSig}},
		{name: "names unknown types", qname: "wanted.test.", qtype: 65280,
			rrSet: []dns.RR{wanted}, rrSig: []dns.RRSIG{wantedSig},
			wantErr: "no signature for wanted.test. type TYPE65280 in DNS response"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rrSet, rrSig, err := selectRRSet(tc.qname, tc.qtype, tc.rrSet, tc.rrSig)
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				require.Empty(t, rrSet)
				require.Empty(t, rrSig)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantSet, rrSet)
			require.Equal(t, tc.wantSig, rrSig)
		})
	}
}

// startTestDNSServer starts a miekg/dns server with handler on network ("udp"
// or "tcp"), bound to addr ("127.0.0.1:0" for an ephemeral port). It blocks
// until the server is ready and returns the bound address and a shutdown func.
func startTestDNSServer(t *testing.T, network, addr string, handler dns.HandlerFunc) (string, func()) {
	t.Helper()
	srv := &dns.Server{Net: network, Handler: handler}
	var bound string
	switch network {
	case "udp":
		pc, err := net.ListenPacket("udp", addr)
		require.NoError(t, err)
		srv.PacketConn = pc
		bound = pc.LocalAddr().String()
	case "tcp":
		l, err := net.Listen("tcp", addr)
		require.NoError(t, err)
		srv.Listener = l
		bound = l.Addr().String()
	default:
		t.Fatalf("unsupported network %q", network)
	}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	return bound, func() { _ = srv.Shutdown() }
}

func replyWithA(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
		A:   net.IPv4(1, 2, 3, 4),
	})
	_ = w.WriteMsg(m)
}

// A UDP error (nothing answering on UDP) must still retry over TCP.
func TestQueryServerFallsBackToTCPOnUDPError(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	addr, shutdown := startTestDNSServer(t, "tcp", "127.0.0.1:0", replyWithA)
	defer shutdown()

	c := &dnsClient{servers: []ResolverAddress{ResolverAddress(addr)}, readTimeout: 2 * time.Second, transport: qsi{}}
	resp, err := c.query(context.Background(), "example.com", dns.TypeA)
	a.NoError(err)
	a.NotNil(resp)
	a.Len(resp.Answer, 1)
}

// A truncated UDP response must trigger a TCP retry that returns the full answer.
func TestQueryServerFallsBackToTCPOnTruncation(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	addr, shutdownTCP := startTestDNSServer(t, "tcp", "127.0.0.1:0", replyWithA)
	defer shutdownTCP()
	_, shutdownUDP := startTestDNSServer(t, "udp", addr, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})
	defer shutdownUDP()

	c := &dnsClient{servers: []ResolverAddress{ResolverAddress(addr)}, readTimeout: 2 * time.Second, transport: qsi{}}
	resp, err := c.query(context.Background(), "example.com", dns.TypeA)
	a.NoError(err)
	a.False(resp.Truncated)
	a.Len(resp.Answer, 1)
}

// Queries must advertise the reduced EDNS0 UDP buffer size (DNS Flag Day 2020).
func TestQueryAdvertisesReducedEDNSBuffer(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var got atomic.Uint32
	addr, shutdown := startTestDNSServer(t, "udp", "127.0.0.1:0", func(w dns.ResponseWriter, r *dns.Msg) {
		if o := r.IsEdns0(); o != nil {
			got.Store(uint32(o.UDPSize()))
		}
		replyWithA(w, r)
	})
	defer shutdown()

	c := &dnsClient{servers: []ResolverAddress{ResolverAddress(addr)}, readTimeout: 2 * time.Second, transport: qsi{}}
	_, err := c.query(context.Background(), "example.com", dns.TypeA)
	a.NoError(err)
	a.Equal(uint32(ednsUDPBufferSize), got.Load())
}

// When every server attempt errors, the failure surfaces the underlying cause.
func TestQueryReportsUnderlyingErrors(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	// Nothing listens on 127.0.0.1:1, so both the UDP and TCP attempts fail.
	c := &dnsClient{servers: []ResolverAddress{"127.0.0.1:1"}, readTimeout: 500 * time.Millisecond, transport: qsi{}}
	resp, err := c.query(context.Background(), "example.com", dns.TypeA)
	a.Error(err)
	a.Nil(resp)
	a.Contains(err.Error(), "127.0.0.1:1")
}
