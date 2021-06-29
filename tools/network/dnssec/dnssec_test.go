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
	"net"
	"testing"
	"time"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/testPartitioning"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestLookup(t *testing.T) {
	testPartitioning.PartitionTest(t)

	a := require.New(t)

	r := makeEmptyTestResolver()
	dnssec := Resolver{
		client:     r,
		trustChain: makeTrustChain(r),
		maxHops:    DefaultMaxHops,
	}

	var err error
	rootKSK, rootKSKsk := getKey(".", dns.ZONE|dns.SEP)
	rootZSK, rootZSKsk := getKey(".", dns.ZONE)
	rootAnchor := rootKSK.ToDS(dns.SHA256)

	// make . zone
	err = r.updateDSRecord(".", &[]dns.DS{*rootAnchor}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord(".", rootKSK, rootKSKsk, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord(".", rootZSK, rootZSKsk, time.Time{})
	a.NoError(err)

	testKSK, testKSKsk := getKey("test.", dns.ZONE|dns.SEP)
	testZSK, testZSKsk := getKey("test.", dns.ZONE)
	testZSK2, testZSK2sk := getKey("test.", dns.ZONE)

	// make test. zone
	err = r.updateDSRecord("test.", &[]dns.DS{*testKSK.ToDS(dns.SHA256)}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("test.", testKSK, testKSKsk, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("test.", testZSK, testZSKsk, time.Time{})
	a.NoError(err)
	err = r.updateARecord("www.test.", net.IPv4(1, 2, 3, 4), time.Time{})
	a.NoError(err)

	// create one more signature for www.test. but do not store the key
	// ensure that one signature and the matched key found and validated
	rrset := r.entries["www.test."][dns.TypeA]
	sig, err := r.sign(rrset.rr, "test.", testZSK2.KeyTag(), time.Time{}, testZSK2sk)
	old := rrset.sig
	rrset.sig = []dns.RRSIG{sig}
	rrset.sig = append(rrset.sig, old...)
	r.entries["www.test."][dns.TypeA] = rrset

	addrs, err := dnssec.LookupIPAddr(context.Background(), "www.test.")
	a.NoError(err)
	a.Equal(2, len(addrs))
	a.Equal(net.IPv4(1, 2, 3, 4), addrs[0].IP)

	// check SRV
	srv0 := dns.SRV{
		Hdr:      dns.RR_Header{Name: "my-srv.test.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 3600},
		Priority: 2,
		Weight:   1,
		Port:     80,
		Target:   "target0.test.",
	}
	srv1 := srv0
	srv1.Target = "target1.test."
	srv1.Priority = 3
	srv1.Weight = 2
	srv2 := srv0
	srv2.Target = "target2.test."
	srv2.Priority = 1
	srv2.Weight = 1
	srvs := []dns.RR{&srv0, &srv1, &srv2}
	err = r.updateRegRecord("my-srv.test.", "test.", dns.TypeSRV, srvs, time.Time{})
	a.NoError(err)

	name, res, err := dnssec.LookupSRV(context.Background(), "", "", "my-srv.test.")
	a.NoError(err)
	a.Equal("my-srv.test.", name)
	a.Equal(3, len(res))
	// check sorting
	a.Equal("target2.test.", res[0].Target)
	a.Equal("target0.test.", res[1].Target)
	a.Equal("target1.test.", res[2].Target)

	name, res, err = dnssec.LookupSRV(context.Background(), "", "", "my-srv-1.test.")
	a.Error(err)

	// check CNAME
	cname := dns.CNAME{
		Hdr:    dns.RR_Header{Name: "algo.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
		Target: "my-algo.test.",
	}
	err = r.updateRegRecord("algo.test.", "test.", dns.TypeCNAME, []dns.RR{&cname}, time.Time{})
	a.NoError(err)

	_, err = dnssec.LookupCNAME(context.Background(), "algo.test.")
	a.Error(err)
	a.Contains(err.Error(), "my-algo.test. not found")

	_, err = dnssec.LookupCNAME(context.Background(), "algo-1.test.")
	a.Error(err)

	err = r.updateARecord("my-algo.test.", net.IPv4(11, 12, 13, 14), time.Time{})
	a.NoError(err)
	addrs, err = dnssec.LookupIPAddr(context.Background(), "algo.test.")
	a.NoError(err)
	a.Equal(net.IPv4(11, 12, 13, 14), addrs[0].IP)

	addrs, err = dnssec.LookupIPAddr(context.Background(), "algo-1.test.")
	a.Error(err)
	a.Empty(addrs)

	// test double redirection
	cname1 := dns.CNAME{
		Hdr:    dns.RR_Header{Name: "main.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
		Target: "follower1.test.",
	}
	err = r.updateRegRecord("main.test.", "test.", dns.TypeCNAME, []dns.RR{&cname1}, time.Time{})
	a.NoError(err)

	cname2 := dns.CNAME{
		Hdr:    dns.RR_Header{Name: "follower1.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
		Target: "follower2.test.",
	}
	err = r.updateRegRecord("follower1.test.", "test.", dns.TypeCNAME, []dns.RR{&cname2}, time.Time{})
	a.NoError(err)

	err = r.updateARecord("follower2.test.", net.IPv4(21, 22, 23, 24), time.Time{})
	a.NoError(err)

	dnssec.maxHops = 3
	addrs, err = dnssec.LookupIPAddr(context.Background(), "main.test.")
	a.NoError(err)
	a.Equal(net.IPv4(21, 22, 23, 24), addrs[0].IP)

	dnssec.maxHops = 2
	addrs, err = dnssec.LookupIPAddr(context.Background(), "main.test.")
	a.Error(err)
	a.Empty(addrs)

	// check non-existing
	addrs, err = dnssec.LookupIPAddr(context.Background(), "main-12.test.")
	a.Error(err)
	a.Empty(addrs)

	// create a loop and expect failure
	delete(r.entries["follower2.test."], dns.TypeA)
	cname3 := dns.CNAME{
		Hdr:    dns.RR_Header{Name: "follower2.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
		Target: "main.test.",
	}
	err = r.updateRegRecord("follower2.test.", "test.", dns.TypeCNAME, []dns.RR{&cname3}, time.Time{})
	a.NoError(err)

	dnssec.maxHops = DefaultMaxHops
	addrs, err = dnssec.LookupIPAddr(context.Background(), "main.test.")
	a.Error(err)
	a.Contains(err.Error(), "loop detected: main.test. already seen")
	a.Empty(addrs)

	// create double CNAME entry and expect failure due to DNS RFC violation
	delete(r.entries["follower2.test."], dns.TypeCNAME)
	cname4 := dns.CNAME{
		Hdr:    dns.RR_Header{Name: "follower2.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
		Target: "algo.test.",
	}
	err = r.updateRegRecord("follower2.test.", "test.", dns.TypeCNAME, []dns.RR{&cname3, &cname4}, time.Time{})
	a.NoError(err)
	// err = r.updateARecord("follower2.test.", net.IPv4(21, 22, 23, 24), time.Time{})
	a.NoError(err)

	addrs, err = dnssec.LookupIPAddr(context.Background(), "follower2.test.")
	a.Error(err)
	a.Contains(err.Error(), "multiple CNAME RR detected")
	a.Empty(addrs)

	// delete root and expect error on broken chain
	delete(r.entries, ".")

	dnssec = Resolver{
		client:     r,
		trustChain: makeTrustChain(r),
		maxHops:    DefaultMaxHops,
	}
	addrs, err = dnssec.LookupIPAddr(context.Background(), "www.test.")
	a.Error(err)
	a.Contains(err.Error(), ". not found")
}

func TestLookupAux(t *testing.T) {
	testPartitioning.PartitionTest(t)

	a := require.New(t)

	r := makeEmptyTestResolver()
	dnssec := Resolver{
		client:     r,
		trustChain: makeTrustChain(r),
		maxHops:    DefaultMaxHops,
	}

	var err error
	rootKSK, rootKSKsk := getKey(".", dns.ZONE|dns.SEP)
	rootZSK, rootZSKsk := getKey(".", dns.ZONE)
	rootAnchor := rootKSK.ToDS(dns.SHA256)

	// make . zone
	err = r.updateDSRecord(".", &[]dns.DS{*rootAnchor}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord(".", rootKSK, rootKSKsk, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord(".", rootZSK, rootZSKsk, time.Time{})
	a.NoError(err)

	testKSK, testKSKsk := getKey("test.", dns.ZONE|dns.SEP)
	testZSK, testZSKsk := getKey("test.", dns.ZONE)

	// make test. zone
	err = r.updateDSRecord("test.", &[]dns.DS{*testKSK.ToDS(dns.SHA256)}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("test.", testKSK, testKSKsk, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("test.", testZSK, testZSKsk, time.Time{})
	a.NoError(err)

	// check MX
	mxIn := []dns.RR{
		&dns.MX{
			Hdr:        dns.RR_Header{Name: "test.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600},
			Preference: 1,
			Mx:         "mail.test.",
		},
	}
	err = r.updateRegRecord("test.", "test.", dns.TypeMX, mxIn, time.Time{})
	a.NoError(err)
	mxOut, err := dnssec.LookupMX(context.Background(), "test.")
	a.NoError(err)
	a.Equal(1, len(mxOut))
	a.Equal("mail.test.", mxOut[0].Host)

	// check TXT
	txtIn := []dns.RR{
		&dns.TXT{
			Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
			Txt: []string{"some text", "some other text"},
		},
		&dns.TXT{
			Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
			Txt: []string{"aaa"},
		},
	}
	err = r.updateRegRecord("test.", "test.", dns.TypeTXT, txtIn, time.Time{})
	a.NoError(err)
	txtOut, err := dnssec.LookupTXT(context.Background(), "test.")
	a.NoError(err)
	a.Equal(3, len(txtOut))
	a.Equal("some text", txtOut[0])

	// check NS
	nsIn := []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns.test.",
		},
	}
	err = r.updateRegRecord("test.", "test.", dns.TypeNS, nsIn, time.Time{})
	a.NoError(err)
	nsOut, err := dnssec.LookupNS(context.Background(), "test.")
	a.NoError(err)
	a.Equal(1, len(nsOut))
	a.Equal("ns.test.", nsOut[0].Host)

	// check TLSA
	tlsaIn := []dns.RR{
		&dns.TLSA{
			Hdr:          dns.RR_Header{Name: "test.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 3600},
			Usage:        1,
			Selector:     2,
			MatchingType: 3,
			Certificate:  "AABBCCDD",
		},
	}
	err = r.updateRegRecord("_443._tcp.test.", "test.", dns.TypeTLSA, tlsaIn, time.Time{})
	a.NoError(err)
	tlsaOut, err := dnssec.LookupTLSA(context.Background(), "443", "tcp", "test.")
	a.NoError(err)
	a.Equal(1, len(tlsaOut))
	a.Equal(TLSARec{1, 2, 3, "AABBCCDD"}, tlsaOut[0])
}

func TestDeadNS(t *testing.T) {
	testPartitioning.PartitionTest(t)

	t.Skip() // skip real network tests in autotest
	a := require.New(t)

	r := MakeDnssecResolver([]ResolverAddress{"192.168.12.34:5678", "10.12.34.56:890"}, time.Microsecond)
	addrs, err := r.LookupIPAddr(context.Background(), "example.com")
	a.Error(err)
	a.Contains(err.Error(), "no answer for")
	a.Empty(addrs)

	// possible race :( with 100ms timeout
	r = MakeDnssecResolver([]ResolverAddress{"192.168.12.34:5678", "1.1.1.1:53"}, 100*time.Millisecond)
	addrs, err = r.LookupIPAddr(context.Background(), "example.com")
	a.NoError(err)
	a.Equal(1, len(addrs))
}

func TestRealRequests(t *testing.T) {
	testPartitioning.PartitionTest(t)

	t.Skip() // skip real network tests in autotest
	a := require.New(t)

	// A
	r := MakeDnssecResolver(DefaultDnssecAwareNSServers, time.Second)
	addrs, err := r.LookupIPAddr(context.Background(), "example.com")
	a.NoError(err)
	a.Equal(1, len(addrs))
	addrs, err = r.LookupIPAddr(context.Background(), "www.example.com")
	a.NoError(err)
	a.Equal(1, len(addrs))
	addrs, err = r.LookupIPAddr(context.Background(), "www.algorand.com")
	a.NoError(err)
	a.Equal(2, len(addrs))
	_, err = r.LookupIPAddr(context.Background(), "dnssec-failed.org")
	a.Error(err)

	// SRV
	srvFullName := "_algobootstrap._tcp.mainnet.algorand.network."
	name, entries, err := r.LookupSRV(context.Background(), "algobootstrap", "tcp", "mainnet.algorand.network")
	a.NoError(err)
	a.Equal(srvFullName, name)
	a.Greater(len(entries), 1)

	// CNAME
	cname := "r-sn.algorand-mainnet.network."
	cnameResult, err := r.LookupCNAME(context.Background(), cname)
	a.NoError(err)
	a.NotEmpty(cnameResult)

	addrs, err = r.LookupIPAddr(context.Background(), cname)
	a.NoError(err)
	a.NotEmpty(addrs)

	// CNAME -> A -> IP
	// fails, no DNSSEC on the second hop
	// addrs, err = r.LookupIPRecursive("r-br.algorand-mainnet.network", 2)
	// a.NoError(err)
	// a.Equal(1, len(addrs))

	// fails, as well, no DNSSEC on the second hop
	// but it is two-level aliasing
	r.(*Resolver).maxHops = 1
	addrs, err = r.LookupIPAddr(context.Background(), "relay-montreal-mainnet-algorand.algorand-mainnet.network.")
	a.Error(err)
	a.Contains(err.Error(), "exceed max attempts")
}

func TestDefaultResolver(t *testing.T) {
	testPartitioning.PartitionTest(t)

	a := require.New(t)
	r := MakeDefaultDnssecResolver("127.0.0.1", logging.Base())
	provided := len(DefaultDnssecAwareNSServers) + 1
	actual := len(r.(*Resolver).EffectiveResolverDNS())
	a.GreaterOrEqual(actual, provided)
}
