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
	"context"
	"testing"
	"time"

	"github.com/algorand/go-algorand/testPartitioning"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestEmptyClient(t *testing.T) {
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

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
