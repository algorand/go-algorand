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
	"encoding/base64"
	"maps"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestTrustedZone(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	zsk := make(dnskeysByTag)
	ksk := make(dnskeysByTag)
	rrSig := make(map[uint16]dns.RRSIG)

	r := makeTestResolver()
	zsks, ksks, rrsigs := r.queryDNSKeyRRSet("com.")
	zk := zsks[0]
	kk := ksks[0]
	sig := rrsigs[0]

	a.Equal(uint16(56311), zk.KeyTag())
	a.Equal(uint16(30909), kk.KeyTag())
	a.Equal(uint16(30909), sig.KeyTag)

	zsk.add(zk)
	ksk.add(kk)
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
	zskRoot := make(dnskeysByTag)
	kskRoot := make(dnskeysByTag)
	rrSigRoot := make(map[uint16]dns.RRSIG)
	zskRoot.add(zsks[0])
	kskRoot.add(ksks[0])
	rrSigRoot[rrsigs[0].KeyTag] = rrsigs[0]

	tzRoot := trustedZone{
		name:  ".",
		zsk:   zskRoot,
		ksk:   kskRoot,
		rrSig: rrSigRoot,
	}

	tt, _ = time.Parse(time.RFC3339, "2020-02-12T00:00:00Z")

	rrsDS, rrsigsDS, _ := r.QueryRRSet(context.Background(), "com.", dns.TypeDS)
	cacheOutdated, err := tzRoot.verifyDS(rrsDS, rrsigsDS, tt)
	a.NoError(err)
	a.False(cacheOutdated)

	tzRoot.zsk = make(dnskeysByTag)
	cacheOutdated, err = tzRoot.verifyDS(rrsDS, rrsigsDS, tt)
	a.NoError(err)
	a.True(cacheOutdated)

	// modify copy ZSK and expect failure
	tzRoot.zsk = zskRoot
	zk = zsks[0]
	zk.PublicKey = ksks[0].PublicKey
	tzRoot.zsk[zsks[0].KeyTag()] = []dns.DNSKEY{zk}
	cacheOutdated, err = tzRoot.verifyDS(rrsDS, rrsigsDS, tt)
	a.Error(err)
	a.False(cacheOutdated)
}

func TestMakeTrustedZone(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	tt, _ := time.Parse(time.RFC3339, "2020-02-12T00:00:00Z")
	r := makeTestResolver()
	tzRoot, cacheOutdated, err := makeTrustedZone(context.Background(), ".", trustedZone{}, r, tt)
	a.NoError(err)
	a.False(cacheOutdated)
	a.NotEmpty(tzRoot)

	tzCom, cacheOutdated, err := makeTrustedZone(context.Background(), "com.", tzRoot, r, tt)
	a.NoError(err)
	a.False(cacheOutdated)
	a.NotEmpty(tzCom)

	// remove ZSK from root and expect cache outdated error (newer key in com. than in cached root)
	backup := tzRoot.zsk
	tzRoot.zsk = make(dnskeysByTag)
	tzCom, cacheOutdated, err = makeTrustedZone(context.Background(), "com.", tzRoot, r, tt)
	a.NoError(err)
	a.True(cacheOutdated)
	a.Empty(tzCom)

	// remove KSK from root and expect no errors
	tzRoot.zsk = backup
	backup = tzRoot.ksk
	tzRoot.ksk = make(dnskeysByTag)
	tzCom, cacheOutdated, err = makeTrustedZone(context.Background(), "com.", tzRoot, r, tt)
	a.NoError(err)
	a.False(cacheOutdated)
	a.NotEmpty(tzCom)

	tzRoot.ksk = backup
	backup = make(dnskeysByTag, len(tzRoot.zsk))
	maps.Copy(backup, tzRoot.zsk)

	_, dsSigs, queryErr := r.QueryRRSet(context.Background(), "com.", dns.TypeDS)
	a.NoError(queryErr)
	a.NotEmpty(dsSigs)
	dsSignerTag := dsSigs[0].KeyTag
	for keyTag, keys := range tzRoot.zsk {
		if keyTag != dsSignerTag {
			tzRoot.zsk[dsSignerTag] = keys
			break
		}
	}
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

	tzRoot, cacheOutdated, err = makeTrustedZone(context.Background(), ".", trustedZone{}, re, tt)
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

	tzTest, cacheOutdated, err := makeTrustedZone(context.Background(), "test.", trustedZone{}, re, tt)
	a.Error(err)
	a.Contains(err.Error(), "test. not found")
	a.False(cacheOutdated)
	a.Empty(tzTest)
}

func TestMakeTrustedZoneIgnoresRSAMD5Key(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	r := makeEmptyTestResolver()

	rootKSK, rootKSKsk := getKey(".", dns.ZONE|dns.SEP)
	rootZSK, rootZSKsk := getKey(".", dns.ZONE)
	a.NoError(r.updateDSRecord(".", &[]dns.DS{*rootKSK.ToDS(dns.SHA256)}, time.Time{}))
	a.NoError(r.updateDNSKeyRecord(".", rootKSK, rootKSKsk, time.Time{}))
	a.NoError(r.updateDNSKeyRecord(".", rootZSK, rootZSKsk, time.Time{}))

	malformedKey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     dns.ZONE,
		Protocol:  3,
		Algorithm: dns.RSAMD5,
		PublicKey: "AQI=",
	}
	dnskeyRRSet := append(r.entries["."][dns.TypeDNSKEY].rr, malformedKey)
	dnskeySig, err := r.sign(dnskeyRRSet, ".", rootKSK.KeyTag(), time.Time{}, rootKSKsk)
	a.NoError(err)
	r.entries["."][dns.TypeDNSKEY] = rrRec{rr: dnskeyRRSet, sig: []dns.RRSIG{dnskeySig}}

	tz, cacheOutdated, err := makeTrustedZone(context.Background(), ".", trustedZone{}, r, time.Now())
	a.NoError(err)
	a.False(cacheOutdated)
	keyCount := 0
	for _, keys := range tz.zsk {
		keyCount += len(keys)
		for _, key := range keys {
			a.NotEqual(uint8(dns.RSAMD5), key.Algorithm)
		}
	}
	a.Equal(2, keyCount)
	a.Len(tz.ksk, 1)
}

func TestVerifyRRSig(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	tt, _ := time.Parse(time.RFC3339, "2020-02-12T00:00:00Z")

	r := makeTestResolver()

	// check . DNSKEY RRSIG
	zsks, ksks, _ := r.queryDNSKeyRRSet(".")
	rrs, rrsigs, _ := r.QueryRRSet(context.Background(), ".", dns.TypeDNSKEY)

	zskRoot := make(dnskeysByTag)
	zskRoot.add(sameTagKey(t, zsks[0]))
	zskRoot.add(zsks[0])
	kskRoot := make(dnskeysByTag)
	decoyRootKSK := sameTagKey(t, ksks[0])
	kskRoot.add(decoyRootKSK)
	kskRoot.add(ksks[0])
	a.Len(kskRoot[ksks[0].KeyTag()], 2)

	verified := verifyRRSig(rrs, rrsigs, tt, kskRoot)
	a.Greater(len(verified), 0)

	// check com. DNSKEY RRSIG
	zsks, ksks, _ = r.queryDNSKeyRRSet("com.")
	rrs, rrsigs, _ = r.QueryRRSet(context.Background(), "com.", dns.TypeDNSKEY)
	zskCom := make(dnskeysByTag)
	zskCom.add(zsks[0])
	kskCom := make(dnskeysByTag)
	kskCom.add(ksks[0])

	verified = verifyRRSig(rrs, rrsigs, tt, kskCom)
	a.Greater(len(verified), 0)

	// check com. DS RRSIG using . ZSK
	rrsDS, rrsigsDS, _ := r.QueryRRSet(context.Background(), "com.", dns.TypeDS)
	verified = verifyRRSig(rrsDS, rrsigsDS, tt, zskRoot)
	a.Greater(len(verified), 0)

	// check failure
	verified = verifyRRSig(rrs, rrsigsDS, tt, zskRoot)
	a.Equal(0, len(verified))

}

func TestMatchKSKDigest(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	r := makeTestResolver()

	zsks, ksks, _ := r.queryDNSKeyRRSet("com.")
	dss, _, _ := r.queryDSRRSet("com.")
	matchingDS := dss[0]

	ksk := make(dnskeysByTag)
	decoyKSK := sameTagKey(t, ksks[0])
	ksk.add(decoyKSK)
	ksk.add(ksks[0])

	matchedDS, verifiedKSK := matchKSKDigest(dss, ksk)
	a.Equal(1, len(verifiedKSK))
	a.Equal([]dns.DNSKEY{ksks[0]}, verifiedKSK[ksks[0].KeyTag()])
	a.Equal(1, len(matchedDS))

	// add a random key and ensure matches
	ksk.add(zsks[0])
	matchedDS, verifiedKSK = matchKSKDigest(dss, ksk)
	a.Equal(1, len(verifiedKSK))
	a.Equal(1, len(matchedDS))

	// add more DS records and ensure it still works
	an, err := MakeRootTrustAnchor()
	a.NoError(err)
	dss2 := an.ToDS()
	dss = append(dss, dss2...)

	matchedDS, verifiedKSK = matchKSKDigest(dss, ksk)
	a.Equal(1, len(verifiedKSK))
	a.Equal(1, len(matchedDS))

	// check failure
	dss = dss2
	matchedDS, verifiedKSK = matchKSKDigest(dss, ksk)
	a.Equal(0, len(verifiedKSK))
	a.Equal(0, len(matchedDS))

	// Unsupported DS digest algorithms are ignored.
	unsupportedDS := matchingDS
	unsupportedDS.DigestType = 255
	matchedDS, verifiedKSK = matchKSKDigest([]dns.DS{unsupportedDS}, ksk)
	a.Empty(verifiedKSK)
	a.Empty(matchedDS)
}

func sameTagKey(t *testing.T, key dns.DNSKEY) dns.DNSKEY {
	t.Helper()

	publicKey, err := base64.StdEncoding.DecodeString(key.PublicKey)
	require.NoError(t, err)
	for i := len(publicKey) - 1; i >= 2; i-- {
		for j := i - 2; j >= 0; j -= 2 {
			if publicKey[i] == publicKey[j] {
				continue
			}
			publicKey[i], publicKey[j] = publicKey[j], publicKey[i]
			decoy := key
			decoy.PublicKey = base64.StdEncoding.EncodeToString(publicKey)
			require.Equal(t, key.KeyTag(), decoy.KeyTag())
			return decoy
		}
	}
	require.FailNow(t, "could not construct a different key with the same key tag")
	return dns.DNSKEY{}
}
