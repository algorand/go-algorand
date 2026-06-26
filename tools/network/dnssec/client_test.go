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
	a.Equal(uint32(1232), got.Load())
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
