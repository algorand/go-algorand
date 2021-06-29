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

	"github.com/algorand/go-algorand/testPartitioning"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestTrustChainBasic(t *testing.T) {
	testPartitioning.PartitionTest(t)

	a := require.New(t)

	r := makeTestResolver()
	tch := makeTrustChain(r)
	tch.trustedZones["."] = trustedZone{}
	tch.trustedZones["org."] = trustedZone{}
	tch.trustedZones["example.org."] = trustedZone{}
	tch.trustedZones["com."] = trustedZone{}
	tch.trustedZones["example.com."] = trustedZone{}
	tch.removeSelfAndChildren("example.com.")
	a.Equal(4, len(tch.trustedZones))
	tch.removeSelfAndChildren("org.")
	a.Equal(2, len(tch.trustedZones))
	tch.removeSelfAndChildren(".")
	a.Equal(0, len(tch.trustedZones))

	tch.trustedZones["com."] = trustedZone{
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

func TestEnsureTrustChain(t *testing.T) {
	testPartitioning.PartitionTest(t)

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
	rrset, _, err := r.QueryRRSet(context.Background(), "test.", dns.TypeDNSKEY)
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
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

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
	rrset, rrsig, err := r.QueryRRSet(context.Background(), ".", dns.TypeDNSKEY)
	a.NoError(err)
	sig := rrsig[0]
	sig.SignerName = "test"
	rrsig = append(rrsig, sig)
	tch := makeTrustChain(r)
	err = tch.Authenticate(context.Background(), rrset, rrsig)
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

	rrset, rrsig, err = r.QueryRRSet(context.Background(), "www.test.", dns.TypeA)
	err = tch.Authenticate(context.Background(), rrset, rrsig)
	a.NoError(err)

	// DNSKEY is signed with KSK so authenticate will fail looking up KSK in ZSK
	rrset, rrsig, err = r.QueryRRSet(context.Background(), "test.", dns.TypeDNSKEY)
	err = tch.Authenticate(context.Background(), rrset, rrsig)
	a.Error(err)

	err = tch.Authenticate(context.Background(), rrset, nil)
	a.Error(err)
	err = tch.Authenticate(context.Background(), rrset, []dns.RRSIG{})
	a.Error(err)
}

func TestQueryWrapper(t *testing.T) {
	testPartitioning.PartitionTest(t)

	a := require.New(t)

	r := makeEmptyTestResolver()
	qr := QueryWrapper{r}

	dss, err := qr.GetRootAnchorDS()
	a.NoError(err)
	a.Equal(2, len(dss))
	currentDS := dss[1]
	a.Equal("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", currentDS.Digest)
	a.Equal(uint16(20326), currentDS.KeyTag)
	a.Equal(uint8(8), currentDS.Algorithm)
	a.Equal(uint8(2), currentDS.DigestType)

	// make . zone
	rootKSK, rootKSKsk := getKey(".", dns.ZONE|dns.SEP)
	rootZSK, rootZSKsk := getKey(".", dns.ZONE)
	rootAnchor := rootKSK.ToDS(dns.SHA256)
	err = r.updateDSRecord(".", &[]dns.DS{*rootAnchor}, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord(".", rootKSK, rootKSKsk, time.Time{})
	a.NoError(err)
	err = r.updateDNSKeyRecord(".", rootZSK, rootZSKsk, time.Time{})
	a.NoError(err)

	// check signerName validation
	rrset, rrsig, err := qr.QueryRRSet(context.Background(), ".", dns.TypeDNSKEY)
	a.NoError(err)
	a.Equal(2, len(rrset))
	a.Equal(1, len(rrsig))
}
