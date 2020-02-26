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
	"crypto"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestResolverCreation(t *testing.T) {
	a := require.New(t)
	r := MakeDnssecResolver(nil, time.Second)
	a.NotEmpty(r.resolver.serverList())
	a.Equal("1.1.1.1:53", r.resolver.serverList()[0])
	a.Equal("8.8.8.8:53", r.resolver.serverList()[1])
	a.Equal(2, len(r.resolver.serverList()))

	r = MakeDnssecResolver([]string{}, time.Second)
	a.NotEmpty(r.resolver.serverList())
	a.Equal("1.1.1.1:53", r.resolver.serverList()[0])
	a.Equal("8.8.8.8:53", r.resolver.serverList()[1])
	a.Equal(2, len(r.resolver.serverList()))

	r = MakeDnssecResolver([]string{"8.8.8.8"}, time.Second)
	a.NotEmpty(r.resolver.serverList())
	a.Equal("8.8.8.8", r.resolver.serverList()[0])
	a.Equal(1, len(r.resolver.serverList()))

	r = MakeDnssecResolver([]string{"8.8.8.8", "1.1.1.1"}, time.Second)
	a.NotEmpty(r.resolver.serverList())
	a.Equal(2, len(r.resolver.serverList()))
	a.Equal("8.8.8.8", r.resolver.serverList()[0])
	a.Equal("1.1.1.1", r.resolver.serverList()[1])
}

func TestQuery(t *testing.T) {
	a := require.New(t)
	r := MakeDnssecResolver(nil, time.Second)
	_, err := r.resolver.query(context.Background(), "algorand.com", dns.TypeA)
	a.NoError(err)
}

func TestSplitZone(t *testing.T) {
	a := require.New(t)
	var res []string
	var err error

	res, err = splitToZones("")
	a.Error(err)

	res, err = splitToZones("com")
	a.Error(err)

	res, err = splitToZones("example.com")
	a.Error(err)

	res, err = splitToZones(".")
	a.NoError(err)
	a.Equal([]string{"."}, res)

	res, err = splitToZones("com.")
	a.NoError(err)
	a.Equal([]string{".", "com."}, res)

	res, err = splitToZones("example.com.")
	a.NoError(err)
	a.Equal([]string{".", "com.", "example.com."}, res)

	res, err = splitToZones("dev.example.com.")
	a.NoError(err)
	a.Equal([]string{".", "com.", "example.com.", "dev.example.com."}, res)
}

func TestParentZone(t *testing.T) {
	a := require.New(t)
	var res string
	var err error

	res, err = getParentZone("")
	a.Error(err)

	res, err = getParentZone("com")
	a.Error(err)

	res, err = getParentZone(".")
	a.Error(err)

	res, err = getParentZone("com.")
	a.NoError(err)
	a.Equal(".", res)

	res, err = getParentZone("example.com.")
	a.NoError(err)
	a.Equal("com.", res)

	res, err = getParentZone("dev.example.com.")
	a.NoError(err)
	a.Equal("example.com.", res)
}

func TestParseRootTrustAnchor(t *testing.T) {
	a := require.New(t)
	dss, err := parseRootTrustAnchor(rootAnchorXML)
	a.NoError(err)
	a.Equal(2, len(dss))
	currentDS := dss[1]
	a.Equal("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", currentDS.Digest)
	a.Equal(uint16(20326), currentDS.KeyTag)
	a.Equal(uint8(8), currentDS.Algorithm)
	a.Equal(uint8(2), currentDS.DigestType)

	_, err = parseRootTrustAnchor("not xml")
	a.Error(err)
}

func TestTrustedZone(t *testing.T) {
	a := require.New(t)

	zsk := make(map[uint16]dns.DNSKEY)
	ksk := make(map[uint16]dns.DNSKEY)
	rrSig := make(map[uint16]dns.RRSIG)

	r := makeTestResolver()
	zsks, ksks, rrsigs := r.queryDNSKeyRRSet("com.")
	zk := zsks[0]
	kk := ksks[0]
	sig := rrsigs[0]

	a.Equal(uint16(56311), zk.KeyTag())
	a.Equal(uint16(30909), kk.KeyTag())
	a.Equal(uint16(30909), sig.KeyTag)

	zsk[zk.KeyTag()] = zk
	ksk[kk.KeyTag()] = kk
	rrSig[sig.KeyTag] = sig

	tz := trustedZone{
		name:  "com.",
		zsk:   zsk,
		ksk:   ksk,
		rrSig: rrSig,
	}
	tt, _ := time.Parse(time.RFC3339, "2020-02-12T00:00:00Z")
	a.False(tz.isExpired(tt))
	tt, _ = time.Parse(time.RFC3339, "2020-02-22T00:00:00Z")
	a.True(tz.isExpired(tt))

	a.True(tz.checkKeys([]uint16{zk.KeyTag()}))
	a.False(tz.checkKeys([]uint16{kk.KeyTag()}))

	zsks, ksks, rrsigs = r.queryDNSKeyRRSet(".")
	zskRoot := make(map[uint16]dns.DNSKEY)
	kskRoot := make(map[uint16]dns.DNSKEY)
	rrSigRoot := make(map[uint16]dns.RRSIG)
	zskRoot[zsks[0].KeyTag()] = zsks[0]
	kskRoot[ksks[0].KeyTag()] = ksks[0]
	rrSigRoot[rrsigs[0].KeyTag] = rrsigs[0]

	tzRoot := trustedZone{
		name:  ".",
		zsk:   zskRoot,
		ksk:   kskRoot,
		rrSig: rrSigRoot,
	}

	tt, _ = time.Parse(time.RFC3339, "2020-02-12T00:00:00Z")

	rrsDS, rrsigsDS, _ := r.queryRRSet(context.Background(), "com.", dns.TypeDS)
	cacheOutdated, err := tzRoot.verifyDS(rrsDS, rrsigsDS, tt)
	a.NoError(err)
	a.False(cacheOutdated)

	tzRoot.zsk = make(map[uint16]dns.DNSKEY)
	cacheOutdated, err = tzRoot.verifyDS(rrsDS, rrsigsDS, tt)
	a.NoError(err)
	a.True(cacheOutdated)

	// modify copy ZSK and expect failure
	tzRoot.zsk = zskRoot
	zk = zsks[0]
	zk.PublicKey = ksks[0].PublicKey
	tzRoot.zsk[zsks[0].KeyTag()] = zk
	cacheOutdated, err = tzRoot.verifyDS(rrsDS, rrsigsDS, tt)
	a.Error(err)
	a.False(cacheOutdated)
}

func TestMakeTrustedZone(t *testing.T) {
	a := require.New(t)

	tt, _ := time.Parse(time.RFC3339, "2020-02-12T00:00:00Z")
	r := makeTestResolver()
	tzRoot, cacheOutdated, err := makeTrustedZone(context.Background(), ".", nil, r, tt)
	a.NoError(err)
	a.False(cacheOutdated)
	a.NotEmpty(tzRoot)

	tzCom, cacheOutdated, err := makeTrustedZone(context.Background(), "com.", tzRoot, r, tt)
	a.NoError(err)
	a.False(cacheOutdated)
	a.NotEmpty(tzCom)

	// remove ZSK from root and expect cache outdated error (newer key in com. than in cached root)
	backup := tzRoot.zsk
	tzRoot.zsk = make(map[uint16]dns.DNSKEY)
	tzCom, cacheOutdated, err = makeTrustedZone(context.Background(), "com.", tzRoot, r, tt)
	a.NoError(err)
	a.True(cacheOutdated)
	a.Empty(tzCom)

	// remove KSK from root and expect no errors
	tzRoot.zsk = backup
	backup = tzRoot.ksk
	tzRoot.ksk = make(map[uint16]dns.DNSKEY)
	tzCom, cacheOutdated, err = makeTrustedZone(context.Background(), "com.", tzRoot, r, tt)
	a.NoError(err)
	a.False(cacheOutdated)
	a.NotEmpty(tzCom)

	tzRoot.ksk = backup
	backup = tzRoot.zsk

	var zk, ks dns.DNSKEY
	for _, zk = range tzRoot.zsk {
		break
	}
	for _, ks = range tzRoot.ksk {
		break
	}
	tzRoot.zsk[zk.KeyTag()] = ks
	tzCom, cacheOutdated, err = makeTrustedZone(context.Background(), "com.", tzRoot, r, tt)
	a.Error(err)
	a.Contains(err.Error(), "DS signature verification failed")
	a.False(cacheOutdated)
	a.Empty(tzCom)

	tzRoot.zsk = backup

	// test non-existing zone
	tzOrg, cacheOutdated, err := makeTrustedZone(context.Background(), "ttt.", tzRoot, r, tt)
	a.Error(err)
	a.False(cacheOutdated)
	a.Empty(tzOrg)

	// Test missed root anchor
	re := makeEmptyTestResolver()
	rootKSK, rootKSKsk := getKey(".", dns.ZONE|dns.SEP)
	rootZSK, rootZSKsk := getKey(".", dns.ZONE)

	re.rootAnchorXML = "invalid"
	err = re.updateKSKNoCheck(".", rootKSK, rootKSKsk, time.Time{})
	a.NoError(err)
	err = re.updateDNSKeyRecord(".", rootZSK, rootZSKsk, time.Time{})
	a.NoError(err)

	tzRoot, cacheOutdated, err = makeTrustedZone(context.Background(), ".", nil, re, tt)
	a.Error(err)
	a.Contains(err.Error(), "EOF")
	a.False(cacheOutdated)
	a.Empty(tzRoot)

	// test missed DS record
	testKSK, testKSKsk := getKey("test.", dns.ZONE|dns.SEP)
	testZSK, testZSKsk := getKey("test.", dns.ZONE)

	re.rootAnchorXML = "invalid"
	err = re.updateKSKNoCheck("test.", testKSK, testKSKsk, time.Time{})
	a.NoError(err)
	err = re.updateDNSKeyRecord("test.", testZSK, testZSKsk, time.Time{})
	a.NoError(err)

	tzTest, cacheOutdated, err := makeTrustedZone(context.Background(), "test.", nil, re, tt)
	a.Error(err)
	a.Contains(err.Error(), "test. not found")
	a.False(cacheOutdated)
	a.Empty(tzTest)
}

func TestVerifyRRSig(t *testing.T) {
	a := require.New(t)
	tt, _ := time.Parse(time.RFC3339, "2020-02-12T00:00:00Z")

	r := makeTestResolver()

	// check . DNSKEY RRSIG
	zsks, ksks, _ := r.queryDNSKeyRRSet(".")
	rrs, rrsigs, _ := r.queryRRSet(context.Background(), ".", dns.TypeDNSKEY)

	zskRoot := make(map[uint16]dns.DNSKEY)
	zskRoot[zsks[0].KeyTag()] = zsks[0]
	kskRoot := make(map[uint16]dns.DNSKEY)
	kskRoot[ksks[0].KeyTag()] = ksks[0]

	verified := verifyRRSig(rrs, rrsigs, tt, kskRoot)
	a.Greater(len(verified), 0)

	// check com. DNSKEY RRSIG
	zsks, ksks, _ = r.queryDNSKeyRRSet("com.")
	rrs, rrsigs, _ = r.queryRRSet(context.Background(), "com.", dns.TypeDNSKEY)
	zskCom := make(map[uint16]dns.DNSKEY)
	zskCom[zsks[0].KeyTag()] = zsks[0]
	kskCom := make(map[uint16]dns.DNSKEY)
	kskCom[ksks[0].KeyTag()] = ksks[0]

	verified = verifyRRSig(rrs, rrsigs, tt, kskCom)
	a.Greater(len(verified), 0)

	// check com. DS RRSIG using . ZSK
	rrsDS, rrsigsDS, _ := r.queryRRSet(context.Background(), "com.", dns.TypeDS)
	verified = verifyRRSig(rrsDS, rrsigsDS, tt, zskRoot)
	a.Greater(len(verified), 0)

	// check failure
	verified = verifyRRSig(rrs, rrsigsDS, tt, zskRoot)
	a.Equal(0, len(verified))

}

func TestVerifyKSKDigest(t *testing.T) {
	a := require.New(t)

	r := makeTestResolver()

	zsks, ksks, _ := r.queryDNSKeyRRSet("com.")
	dss, _, _ := r.queryDSRRSet("com.")

	ksk := make(map[uint16]dns.DNSKEY)
	ksk[ksks[0].KeyTag()] = ksks[0]

	matchedDS, verifiedKSK := verifyKSKDigest(dss, ksk)
	a.Equal(1, len(verifiedKSK))
	a.Equal(1, len(matchedDS))

	// add a random key and ensure matches
	ksk[zsks[0].KeyTag()] = zsks[0]
	matchedDS, verifiedKSK = verifyKSKDigest(dss, ksk)
	a.Equal(1, len(verifiedKSK))
	a.Equal(1, len(matchedDS))

	// add more DS records and ensure it still works
	dss2, err := parseRootTrustAnchor(rootAnchorXML)
	a.NoError(err)
	dss = append(dss, dss2...)

	matchedDS, verifiedKSK = verifyKSKDigest(dss, ksk)
	a.Equal(1, len(verifiedKSK))
	a.Equal(1, len(matchedDS))

	// check failure
	dss = dss2
	matchedDS, verifiedKSK = verifyKSKDigest(dss, ksk)
	a.Equal(0, len(verifiedKSK))
	a.Equal(0, len(matchedDS))
}

func TestTrustChainBasic(t *testing.T) {
	a := require.New(t)

	r := makeTestResolver()
	tch := makeTrustChain(r)
	tch.trustedZones["."] = &trustedZone{}
	tch.trustedZones["org."] = &trustedZone{}
	tch.trustedZones["example.org."] = &trustedZone{}
	tch.trustedZones["com."] = &trustedZone{}
	tch.trustedZones["example.com."] = &trustedZone{}
	tch.removeSelfAndChildren("example.com.")
	a.Equal(4, len(tch.trustedZones))
	tch.removeSelfAndChildren("org.")
	a.Equal(2, len(tch.trustedZones))
	tch.removeSelfAndChildren(".")
	a.Equal(0, len(tch.trustedZones))

	tch.trustedZones["com."] = &trustedZone{
		zsk: make(map[uint16]dns.DNSKEY),
	}
	tch.trustedZones["com."].zsk[123] = dns.DNSKEY{Algorithm: 1}
	key, found := tch.getDNSKey("com.", 123)
	a.True(found)
	a.NotEmpty(key)

	key, found = tch.getDNSKey(".", 123)
	a.False(found)
	a.Empty(key)
}

func getKey(zone string, flags uint16) (*dns.DNSKEY, crypto.PrivateKey) {
	rootKSK := new(dns.DNSKEY)
	rootKSK.Hdr.Name = zone
	rootKSK.Hdr.Rrtype = dns.TypeDNSKEY
	rootKSK.Hdr.Class = dns.ClassINET
	rootKSK.Hdr.Ttl = 86400
	rootKSK.Flags = flags
	rootKSK.Protocol = 3
	rootKSK.Algorithm = dns.RSASHA256
	rootKSKsk, _ := rootKSK.Generate(1024)
	return rootKSK, rootKSKsk
}

func TestEnsureTrustChain(t *testing.T) {
	a := require.New(t)

	var err error
	r := makeEmptyTestResolver()

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

	tch := makeTrustChain(r)
	err = tch.ensure(context.Background(), "test.", []uint16{testZSK.KeyTag()})
	a.NoError(err)

	// ensure test harness works
	// update test. KSK and . ZSK
	testKSK, testKSKsk = getKey("test.", dns.ZONE|dns.SEP)
	err = r.updateDSRecord("test.", &[]dns.DS{*testKSK.ToDS(dns.SHA256)}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("test.", testKSK, testKSKsk, time.Time{})
	a.NoError(err)

	rootZSK, rootZSKsk = getKey(".", dns.ZONE)
	err = r.updateDNSKeyRecord(".", rootZSK, rootZSKsk, time.Time{})
	a.NoError(err)

	// check a brand new trust chain (no caches)
	newCh := makeTrustChain(r)
	err = newCh.ensure(context.Background(), "test.", []uint16{testZSK.KeyTag()})
	a.NoError(err)

	// check an old trust chain (with cached entires)
	err = tch.ensure(context.Background(), "test.", []uint16{testZSK.KeyTag()})
	a.NoError(err)

	algoTestKSK, algoTestKSKsk := getKey("algo.test.", dns.ZONE|dns.SEP)
	algoTestZSK, algoTestZSKsk := getKey("algo.test.", dns.ZONE)

	// make algo.test. zone
	err = r.updateDSRecord("algo.test.", &[]dns.DS{*algoTestKSK.ToDS(dns.SHA256)}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("algo.test.", algoTestKSK, algoTestKSKsk, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("algo.test.", algoTestZSK, algoTestZSKsk, time.Time{})
	a.NoError(err)

	// check an old trust chain (with cached entires)
	err = tch.ensure(context.Background(), "algo.test.", []uint16{algoTestZSK.KeyTag()})
	a.NoError(err)

	// ZSK rotation test
	// 1. update test. ZSK
	// 2. add new rand.test. zone => DS for rand.test. will be signed with new ZSK
	// 3. build a trust chain for rand.test. => trigger cache outdated error and the chain update

	// rotate test. ZSK
	testZSK, testZSKsk = getKey("test.", dns.ZONE)
	err = r.updateDNSKeyRecord("test.", testZSK, testZSKsk, time.Time{})
	a.NoError(err)

	randTestKSK, randTestKSKsk := getKey("rand.test.", dns.ZONE|dns.SEP)
	randTestZSK, randTestZSKsk := getKey("rand.test.", dns.ZONE)

	// make rand.test. zone
	err = r.updateDSRecord("rand.test.", &[]dns.DS{*randTestKSK.ToDS(dns.SHA256)}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("rand.test.", randTestKSK, randTestKSKsk, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("rand.test.", randTestZSK, randTestZSKsk, time.Time{})
	a.NoError(err)

	err = tch.ensure(context.Background(), "algo.test.", []uint16{algoTestZSK.KeyTag()})
	a.NoError(err)
	err = tch.ensure(context.Background(), "rand.test.", []uint16{randTestZSK.KeyTag()})
	a.NoError(err)

	// invalid signature test
	// 1. update test. ZSK and set expired signature
	// 2. add new cow.test. zone => DS for cow.test. will be signed with new ZSK
	// 3. build a trust chain for cow.test. => trigger cache outdated error and the chain update
	// 4. chain update fails because of invalid signature

	// rotate test. ZSK
	testZSK, testZSKsk = getKey("test.", dns.ZONE)
	tt, _ := time.Parse(time.RFC3339, "2020-01-02T00:00:00Z")
	err = r.updateDNSKeyRecord("test.", testZSK, testZSKsk, tt)
	a.NoError(err)

	cowTestKSK, cowTestKSKsk := getKey("cow.test.", dns.ZONE|dns.SEP)
	cowTestZSK, cowTestZSKsk := getKey("cow.test.", dns.ZONE)

	// make cow.test. zone
	err = r.updateDSRecord("cow.test.", &[]dns.DS{*cowTestKSK.ToDS(dns.SHA256)}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("cow.test.", cowTestKSK, cowTestKSKsk, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("cow.test.", cowTestZSK, cowTestZSKsk, time.Time{})
	a.NoError(err)

	// this is cached and still valid
	err = tch.ensure(context.Background(), "rand.test.", []uint16{randTestZSK.KeyTag()})
	a.NoError(err)
	// this was removed during last cache re-validation
	// triggers the cache update and the chain is broken
	err = tch.ensure(context.Background(), "algo.test.", []uint16{algoTestZSK.KeyTag()})
	a.Error(err)
	// this is a new, triggers the cache update and the chain is broken
	err = tch.ensure(context.Background(), "cow.test.", []uint16{cowTestZSK.KeyTag()})
	a.Error(err)

	// DNSKEY expiration test
	// DNSKEY is expired when its RRSIG expired
	// 1. restore test. ZSK
	// 2. manually expire test. RRSIG in the cache

	// rotate test. ZSK
	testZSK, testZSKsk = getKey("test.", dns.ZONE)
	err = r.updateDNSKeyRecord("test.", testZSK, testZSKsk, time.Time{})
	a.NoError(err)
	err = tch.ensure(context.Background(), "cow.test.", []uint16{cowTestZSK.KeyTag()})
	a.NoError(err)

	// get a new signature
	rrset, _, err := r.queryRRSet(context.Background(), "test.", dns.TypeDNSKEY)
	a.NoError(err)
	// calc and update sig in the cache with expired one
	tt, _ = time.Parse(time.RFC3339, "2020-01-02T00:00:00Z")
	sig, err := r.sign(rrset, "test.", testKSK.KeyTag(), tt, testKSKsk)
	tch.trustedZones["test."].rrSig[testKSK.KeyTag()] = sig
	a.Equal(1, len(tch.trustedZones["test."].rrSig))
	err = tch.ensure(context.Background(), "algo.test.", []uint16{algoTestZSK.KeyTag()})
	a.NoError(err)

	// ZSK on the last zone rotation for all zones in cache
	// this simulates the scenario with example.com cached
	// and www.example.com requested that is signed with newer ZSK
	// 1. rotate algo.test. ZSK
	// 2. ensure trust and ask for newer ZSK

	// rotate algo.test. ZSK
	algoTestZSK, algoTestZSKsk = getKey("algo.test.", dns.ZONE)
	err = r.updateDNSKeyRecord("algo.test.", algoTestZSK, algoTestZSKsk, time.Time{})
	a.NoError(err)
	// request cached algo.test. with a new ZSK
	err = tch.ensure(context.Background(), "algo.test.", []uint16{algoTestZSK.KeyTag()})
	a.NoError(err)

	// KSK rotation tests
	// 1. rotate all KSK and one of ZSK
	// 2. update cow.test. ZSK
	// 3. request new cow.test. ZSK from the chain
	rootKSK, rootKSKsk = getKey(".", dns.ZONE|dns.SEP)
	rootAnchor = rootKSK.ToDS(dns.SHA256)
	err = r.updateDSRecord(".", &[]dns.DS{*rootAnchor}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord(".", rootKSK, rootKSKsk, time.Time{})
	a.NoError(err)
	testKSK, testKSKsk = getKey("test.", dns.ZONE|dns.SEP)
	err = r.updateDSRecord("test.", &[]dns.DS{*testKSK.ToDS(dns.SHA256)}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("test.", testKSK, testKSKsk, time.Time{})
	a.NoError(err)
	cowTestKSK, cowTestKSKsk = getKey("cow.test.", dns.ZONE|dns.SEP)
	err = r.updateDSRecord("cow.test.", &[]dns.DS{*cowTestKSK.ToDS(dns.SHA256)}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("cow.test.", cowTestKSK, cowTestKSKsk, time.Time{})
	a.NoError(err)

	// rotate test. ZSK
	testZSK, testZSKsk = getKey("test.", dns.ZONE)
	err = r.updateDNSKeyRecord("test.", testZSK, testZSKsk, time.Time{})
	a.NoError(err)
	// rotate cow.test. ZSK
	cowTestZSK, cowTestZSKsk = getKey("cow.test.", dns.ZONE)
	err = r.updateDNSKeyRecord("cow.test.", cowTestZSK, cowTestZSKsk, time.Time{})
	a.NoError(err)

	err = tch.ensure(context.Background(), "cow.test.", []uint16{cowTestZSK.KeyTag()})
	a.NoError(err)

	// Trust chain failure test
	// update KSK but do not update DS
	// using a new trust chain (no cache) ensure it fails
	// note: using an existing cached chain would not work because once an entry is cached
	// it is considered valid if it has ZSK for signature verification
	testKSK, testKSKsk = getKey("test.", dns.ZONE|dns.SEP)
	err = r.updateKSKNoCheck("test.", testKSK, testKSKsk, time.Time{})
	a.NoError(err)
	newCh = makeTrustChain(r)
	err = newCh.ensure(context.Background(), "algo.test.", []uint16{algoTestZSK.KeyTag()})
	a.Error(err)
	a.Contains(err.Error(), "failed to verify test. KSK against digest in parent DS")
}

func TestEnsureTrustChainFailures(t *testing.T) {
	a := require.New(t)

	var err error
	r := makeEmptyTestResolver()

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

	// test error on empty zone
	newCh := makeTrustChain(r)
	err = newCh.ensure(context.Background(), "", []uint16{})
	a.Error(err)
	// test non-existing ZSK
	err = newCh.ensure(context.Background(), ".", []uint16{})
	a.Error(err)
	a.Contains(err.Error(), "ZSK [] not found in zone .")

	testKSK, testKSKsk := getKey("test.", dns.ZONE|dns.SEP)
	testZSK, testZSKsk := getKey("test.", dns.ZONE)

	// make test. zone
	err = r.updateDSRecord("test.", &[]dns.DS{*testKSK.ToDS(dns.SHA256)}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("test.", testKSK, testKSKsk, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("test.", testZSK, testZSKsk, time.Time{})
	a.NoError(err)

	// update . ZSK so that test. DS will mismatch
	rootZSK, rootZSKsk = getKey(".", dns.ZONE)
	err = r.updateZSK(".", rootZSK, rootZSKsk, time.Time{})
	a.NoError(err)

	tch := makeTrustChain(r)
	err = tch.ensure(context.Background(), "test.", []uint16{testZSK.KeyTag()})
	a.Error(err)
	a.Contains(err.Error(), "cache outdated for already updated zone .")
}

func TestAuthenticate(t *testing.T) {
	a := require.New(t)

	var err error
	r := makeEmptyTestResolver()

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

	// check signerName validation
	rrset, rrsig, err := r.queryRRSet(context.Background(), ".", dns.TypeDNSKEY)
	a.NoError(err)
	sig := rrsig[0]
	sig.SignerName = "test"
	rrsig = append(rrsig, sig)
	tch := makeTrustChain(r)
	err = tch.authenticate(context.Background(), rrset, rrsig)
	a.Error(err)
	a.Contains(err.Error(), "signer name mismatch")

	testKSK, testKSKsk := getKey("test.", dns.ZONE|dns.SEP)
	testZSK, testZSKsk := getKey("test.", dns.ZONE)

	// make test. zone
	err = r.updateDSRecord("test.", &[]dns.DS{*testKSK.ToDS(dns.SHA256)}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("test.", testKSK, testKSKsk, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord("test.", testZSK, testZSKsk, time.Time{})
	a.NoError(err)
	err = r.updateARecord("www.test.", net.IPv4(1, 2, 3, 4), time.Time{})
	a.NoError(err)

	rrset, rrsig, err = r.queryRRSet(context.Background(), "www.test.", dns.TypeA)
	err = tch.authenticate(context.Background(), rrset, rrsig)
	a.NoError(err)

	// DNSKEY is signed with KSK so authenticate will fail looking up KSK in ZSK
	rrset, rrsig, err = r.queryRRSet(context.Background(), "test.", dns.TypeDNSKEY)
	err = tch.authenticate(context.Background(), rrset, rrsig)
	a.Error(err)

	err = tch.authenticate(context.Background(), rrset, nil)
	a.Error(err)
	err = tch.authenticate(context.Background(), rrset, []dns.RRSIG{})
	a.Error(err)
}

func TestSrvSort(t *testing.T) {
	a := require.New(t)

	arr := make([]*net.SRV, 0, 7)
	arr = append(arr, &net.SRV{Priority: 4, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 3, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 2})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 1})

	srvRecArray(arr).sortAndRand()
	a.Equal(net.SRV{Priority: 1, Weight: 2}, *arr[0])
	a.Equal(net.SRV{Priority: 1, Weight: 1}, *arr[1])
	a.Equal(net.SRV{Priority: 1, Weight: 1}, *arr[2])
	a.Equal(net.SRV{Priority: 1, Weight: 1}, *arr[3])
	a.Equal(net.SRV{Priority: 1, Weight: 1}, *arr[4])
	a.Equal(net.SRV{Priority: 3, Weight: 1}, *arr[5])
	a.Equal(net.SRV{Priority: 4, Weight: 1}, *arr[6])
}
func TestLookup(t *testing.T) {
	a := require.New(t)

	r := makeEmptyTestResolver()
	dnssec := Resolver{
		resolver:   r,
		trustChain: makeTrustChain(r),
		maxHops:    defaultMaxHops,
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

	dnssec.maxHops = defaultMaxHops
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
		resolver:   r,
		trustChain: makeTrustChain(r),
		maxHops:    defaultMaxHops,
	}
	addrs, err = dnssec.LookupIPAddr(context.Background(), "www.test.")
	a.Error(err)
	a.Contains(err.Error(), ". not found")
}

func TestLookupAux(t *testing.T) {
	a := require.New(t)

	r := makeEmptyTestResolver()
	dnssec := Resolver{
		resolver:   r,
		trustChain: makeTrustChain(r),
		maxHops:    defaultMaxHops,
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
	t.Skip() // skip real network tests in autotest
	a := require.New(t)

	r := MakeDnssecResolver([]string{"192.168.12.34:5678", "10.12.34.56:890"}, time.Microsecond)
	addrs, err := r.LookupIPAddr(context.Background(), "example.com")
	a.Error(err)
	a.Contains(err.Error(), "no answer for")
	a.Empty(addrs)

	// possible race :( with 100ms timeout
	r = MakeDnssecResolver([]string{"192.168.12.34:5678", "1.1.1.1:53"}, 100*time.Millisecond)
	addrs, err = r.LookupIPAddr(context.Background(), "example.com")
	a.NoError(err)
	a.Equal(1, len(addrs))
}

func TestRealRequests(t *testing.T) {
	t.Skip() // skip real network tests in autotest
	a := require.New(t)

	// A
	r := MakeDnssecResolver(nil, time.Second)
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
	r.maxHops = 1
	addrs, err = r.LookupIPAddr(context.Background(), "relay-montreal-mainnet-algorand.algorand-mainnet.network.")
	a.Error(err)
	a.Contains(err.Error(), "exceed max attempts")
}
