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
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type substitutingQuerier struct {
	TrustQuerier
	queryName  string
	queryType  uint16
	answerName string
}

func (s substitutingQuerier) QueryRRSet(ctx context.Context, name string, qtype uint16) ([]dns.RR, []dns.RRSIG, error) {
	if dns.CanonicalName(name) == dns.CanonicalName(s.queryName) && qtype == s.queryType {
		name = s.answerName
	}
	return s.TrustQuerier.QueryRRSet(ctx, name, qtype)
}

type wildcardExpandingQuerier struct {
	TrustQuerier
	queryName    string
	queryType    uint16
	wildcardName string
}

func (w wildcardExpandingQuerier) QueryRRSet(ctx context.Context, name string, qtype uint16) ([]dns.RR, []dns.RRSIG, error) {
	if dns.CanonicalName(name) != dns.CanonicalName(w.queryName) || qtype != w.queryType {
		return w.TrustQuerier.QueryRRSet(ctx, name, qtype)
	}
	rrSet, rrSig, err := w.TrustQuerier.QueryRRSet(ctx, w.wildcardName, qtype)
	if err != nil {
		return nil, nil, err
	}
	for i, rr := range rrSet {
		rrSet[i] = dns.Copy(rr)
		rrSet[i].Header().Name = name
	}
	expandedSig := append([]dns.RRSIG(nil), rrSig...)
	for i := range expandedSig {
		expandedSig[i].Hdr.Name = name
	}
	return rrSet, expandedSig, nil
}

func makeSignedTestZone(t *testing.T) *testResolver {
	t.Helper()
	r := makeEmptyTestResolver()

	rootKSK, rootKSKsk := getKey(".", dns.ZONE|dns.SEP)
	rootZSK, rootZSKsk := getKey(".", dns.ZONE)
	require.NoError(t, r.updateDSRecord(".", &[]dns.DS{*rootKSK.ToDS(dns.SHA256)}, time.Time{}))
	require.NoError(t, r.updateDNSKeyRecord(".", rootKSK, rootKSKsk, time.Time{}))
	require.NoError(t, r.updateDNSKeyRecord(".", rootZSK, rootZSKsk, time.Time{}))

	testKSK, testKSKsk := getKey("test.", dns.ZONE|dns.SEP)
	testZSK, testZSKsk := getKey("test.", dns.ZONE)
	require.NoError(t, r.updateDSRecord("test.", &[]dns.DS{*testKSK.ToDS(dns.SHA256)}, time.Time{}))
	require.NoError(t, r.updateDNSKeyRecord("test.", testKSK, testKSKsk, time.Time{}))
	require.NoError(t, r.updateDNSKeyRecord("test.", testZSK, testZSKsk, time.Time{}))
	return r
}

func TestLookupRejectsSignedRRSetFromAnotherName(t *testing.T) {
	partitiontest.PartitionTest(t)

	r := makeSignedTestZone(t)
	foreign := &dns.TXT{
		Hdr: dns.RR_Header{Name: "foreign.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"foreign"},
	}
	require.NoError(t, r.updateRegRecord("foreign.test.", "test.", dns.TypeTXT, []dns.RR{foreign}, time.Time{}))

	client := substitutingQuerier{
		TrustQuerier: r,
		queryName:    "wanted.test.",
		queryType:    dns.TypeTXT,
		answerName:   "foreign.test.",
	}
	resolver := Resolver{client: client, trustChain: makeTrustChain(client), maxHops: DefaultMaxHops}
	_, err := resolver.LookupTXT(context.Background(), "wanted.test.")
	require.ErrorContains(t, err, "no signature for wanted.test.")
}

func TestLookupRejectsSignerOutsideOwnerZone(t *testing.T) {
	partitiontest.PartitionTest(t)

	r := makeSignedTestZone(t)
	attackerKSK, attackerKSKsk := getKey("rand.test.", dns.ZONE|dns.SEP)
	attackerZSK, attackerZSKsk := getKey("rand.test.", dns.ZONE)
	require.NoError(t, r.updateDSRecord("rand.test.", &[]dns.DS{*attackerKSK.ToDS(dns.SHA256)}, time.Time{}))
	require.NoError(t, r.updateDNSKeyRecord("rand.test.", attackerKSK, attackerKSKsk, time.Time{}))
	require.NoError(t, r.updateDNSKeyRecord("rand.test.", attackerZSK, attackerZSKsk, time.Time{}))

	forged := &dns.TXT{
		Hdr: dns.RR_Header{Name: "algorand.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"attacker controlled"},
	}
	require.NoError(t, r.updateRegRecord("algorand.test.", "rand.test.", dns.TypeTXT, []dns.RR{forged}, time.Time{}))

	resolver := Resolver{client: r, trustChain: makeTrustChain(r), maxHops: DefaultMaxHops}
	_, err := resolver.LookupTXT(context.Background(), "algorand.test.")
	require.ErrorContains(t, err, "no signature for algorand.test.")
}

func TestLookupRejectsDSFromAnotherName(t *testing.T) {
	partitiontest.PartitionTest(t)

	r := makeSignedTestZone(t)
	victimKSK, victimKSKsk := getKey("victim.test.", dns.ZONE|dns.SEP)
	victimZSK, victimZSKsk := getKey("victim.test.", dns.ZONE)

	// The attacker's genuine parent-signed DS contains the digest of keys that
	// claim to belong to victim.test. A resolver must still reject it because
	// the DS owner is not the name that was queried.
	attackerDS := victimKSK.ToDS(dns.SHA256)
	attackerDS.Hdr.Name = "attacker.test."
	require.NoError(t, r.updateDSRecord("attacker.test.", &[]dns.DS{*attackerDS}, time.Time{}))
	require.NoError(t, r.updateKSKNoCheck("victim.test.", victimKSK, victimKSKsk, time.Time{}))
	require.NoError(t, r.updateZSK("victim.test.", victimZSK, victimZSKsk, time.Time{}))

	victimTXT := &dns.TXT{
		Hdr: dns.RR_Header{Name: "victim.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"victim"},
	}
	require.NoError(t, r.updateRegRecord("victim.test.", "victim.test.", dns.TypeTXT, []dns.RR{victimTXT}, time.Time{}))

	client := substitutingQuerier{
		TrustQuerier: r,
		queryName:    "victim.test.",
		queryType:    dns.TypeDS,
		answerName:   "attacker.test.",
	}
	resolver := Resolver{client: client, trustChain: makeTrustChain(client), maxHops: DefaultMaxHops}
	_, err := resolver.LookupTXT(context.Background(), "victim.test.")
	require.ErrorContains(t, err, "no signature for victim.test. type DS")
}

func TestLookupRejectsUnprovedWildcardExpansion(t *testing.T) {
	partitiontest.PartitionTest(t)

	r := makeSignedTestZone(t)
	wildcard := &dns.TXT{
		Hdr: dns.RR_Header{Name: "*.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"wildcard"},
	}
	require.NoError(t, r.updateRegRecord("*.test.", "test.", dns.TypeTXT, []dns.RR{wildcard}, time.Time{}))

	client := wildcardExpandingQuerier{
		TrustQuerier: r,
		queryName:    "wanted.test.",
		queryType:    dns.TypeTXT,
		wildcardName: "*.test.",
	}
	resolver := Resolver{client: client, trustChain: makeTrustChain(client), maxHops: DefaultMaxHops}
	_, err := resolver.LookupTXT(context.Background(), "wanted.test.")
	require.ErrorContains(t, err, "no signature for wanted.test.")
}

func TestLookup(t *testing.T) {
	partitiontest.PartitionTest(t)

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

func TestLookupCombinedSigningKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	r := makeEmptyTestResolver()
	dnssecResolver := Resolver{
		client:     r,
		trustChain: makeTrustChain(r),
		maxHops:    DefaultMaxHops,
	}

	rootKey, rootKeySK := getKey(".", dns.ZONE|dns.SEP)
	rootAnchor := rootKey.ToDS(dns.SHA256)
	a.NoError(r.updateDSRecord(".", &[]dns.DS{*rootAnchor}, time.Time{}))
	a.NoError(r.updateDNSKeyRecord(".", rootKey, rootKeySK, time.Time{}))

	combinedKey, combinedKeySK := getKey("test.", dns.ZONE|dns.SEP)
	testDS := combinedKey.ToDS(dns.SHA256)
	dsRRSet := []dns.RR{testDS}
	dsSig, err := r.sign(dsRRSet, ".", rootKey.KeyTag(), time.Time{}, rootKeySK)
	a.NoError(err)
	r.entries["test."] = map[uint16]rrRec{
		dns.TypeDS: {rr: dsRRSet, sig: []dns.RRSIG{dsSig}},
	}
	a.NoError(r.updateKSKNoCheck("test.", combinedKey, combinedKeySK, time.Time{}))

	aRecord := dns.A{
		Hdr: dns.RR_Header{Name: "www.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.IPv4(1, 2, 3, 4),
	}
	rrSet := []dns.RR{&aRecord}
	sig, err := r.sign(rrSet, "test.", combinedKey.KeyTag(), time.Time{}, combinedKeySK)
	a.NoError(err)
	r.entries["www.test."] = map[uint16]rrRec{
		dns.TypeA: {rr: rrSet, sig: []dns.RRSIG{sig}},
	}

	addrs, err := dnssecResolver.LookupIPAddr(context.Background(), "www.test.")
	a.NoError(err)
	a.Equal([]net.IPAddr{{IP: net.IPv4(1, 2, 3, 4)}}, addrs)

	// A revoked key may remain published during rollover, but must not be used
	// to authenticate DNS data.
	revokedKey, revokedKeySK := getKey("test.", dns.ZONE|dns.SEP|dns.REVOKE)
	dnskeyRRSet := []dns.RR{combinedKey, revokedKey}
	dnskeySig, err := r.sign(dnskeyRRSet, "test.", combinedKey.KeyTag(), time.Time{}, combinedKeySK)
	a.NoError(err)
	r.entries["test."][dns.TypeDNSKEY] = rrRec{rr: dnskeyRRSet, sig: []dns.RRSIG{dnskeySig}}
	dnssecResolver.trustChain = makeTrustChain(r)
	addrs, err = dnssecResolver.LookupIPAddr(context.Background(), "www.test.")
	a.NoError(err)
	a.Equal([]net.IPAddr{{IP: net.IPv4(1, 2, 3, 4)}}, addrs)

	revokedSig, err := r.sign(rrSet, "test.", revokedKey.KeyTag(), time.Time{}, revokedKeySK)
	a.NoError(err)
	r.entries["www.test."][dns.TypeA] = rrRec{rr: rrSet, sig: []dns.RRSIG{revokedSig}}

	_, err = dnssecResolver.LookupIPAddr(context.Background(), "www.test.")
	a.Error(err)
	a.Contains(err.Error(), "not found in zone test.")
}

func TestLookupCollidingDNSKEYTags(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	r := makeEmptyTestResolver()

	rootKSK, rootKSKsk := getKey(".", dns.ZONE|dns.SEP)
	rootZSK, rootZSKsk := getKey(".", dns.ZONE)
	a.NoError(r.updateDSRecord(".", &[]dns.DS{*rootKSK.ToDS(dns.SHA256)}, time.Time{}))
	a.NoError(r.updateDNSKeyRecord(".", rootKSK, rootKSKsk, time.Time{}))
	a.NoError(r.updateDNSKeyRecord(".", rootZSK, rootZSKsk, time.Time{}))

	ksk, kskSK := getKey("test.", dns.ZONE|dns.SEP)
	zsk, zskSK := getKey("test.", dns.ZONE)
	a.NoError(r.updateDSRecord("test.", &[]dns.DS{*ksk.ToDS(dns.SHA256)}, time.Time{}))

	decoyZSK := sameTagKey(t, *zsk)
	decoyKSK := sameTagKey(t, *ksk)
	dnskeyRRSet := []dns.RR{&decoyZSK, zsk, ksk, &decoyKSK}
	dnskeySig, err := r.sign(dnskeyRRSet, "test.", ksk.KeyTag(), time.Time{}, kskSK)
	a.NoError(err)
	r.entries["test."][dns.TypeDNSKEY] = rrRec{rr: dnskeyRRSet, sig: []dns.RRSIG{dnskeySig}}

	record := &dns.A{
		Hdr: dns.RR_Header{Name: "www.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(1, 2, 3, 4),
	}
	recordSig, err := r.sign([]dns.RR{record}, "test.", zsk.KeyTag(), time.Time{}, zskSK)
	a.NoError(err)
	r.entries["www.test."] = map[uint16]rrRec{
		dns.TypeA: {rr: []dns.RR{record}, sig: []dns.RRSIG{recordSig}},
	}

	resolver := Resolver{client: r, trustChain: makeTrustChain(r), maxHops: DefaultMaxHops}
	addrs, err := resolver.LookupIPAddr(context.Background(), "www.test.")
	a.NoError(err)
	a.Equal([]net.IPAddr{{IP: net.IPv4(1, 2, 3, 4)}}, addrs)
}

func TestLookupAux(t *testing.T) {
	partitiontest.PartitionTest(t)

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
			Hdr:          dns.RR_Header{Name: "_443._tcp.test.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 3600},
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
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

	a := require.New(t)
	r := MakeDefaultDnssecResolver("127.0.0.1", logging.Base())
	provided := len(DefaultDnssecAwareNSServers) + 1
	actual := len(r.(*Resolver).EffectiveResolverDNS())
	a.GreaterOrEqual(actual, provided)
}
