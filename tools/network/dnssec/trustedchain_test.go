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
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestTrustChainBasic(t *testing.T) {
	partitiontest.PartitionTest(t)

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
}

func TestEnsureTrustChain(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	_, _, err = tch.ensure(context.Background(), "test.", []uint16{testZSK.KeyTag()})
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
	_, _, err = newCh.ensure(context.Background(), "test.", []uint16{testZSK.KeyTag()})
	a.NoError(err)

	// check an old trust chain (with cached entires)
	_, _, err = tch.ensure(context.Background(), "test.", []uint16{testZSK.KeyTag()})
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
	_, _, err = tch.ensure(context.Background(), "algo.test.", []uint16{algoTestZSK.KeyTag()})
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

	_, _, err = tch.ensure(context.Background(), "algo.test.", []uint16{algoTestZSK.KeyTag()})
	a.NoError(err)
	_, _, err = tch.ensure(context.Background(), "rand.test.", []uint16{randTestZSK.KeyTag()})
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
	_, _, err = tch.ensure(context.Background(), "rand.test.", []uint16{randTestZSK.KeyTag()})
	a.NoError(err)
	// this was removed during last cache re-validation
	// triggers the cache update and the chain is broken
	_, _, err = tch.ensure(context.Background(), "algo.test.", []uint16{algoTestZSK.KeyTag()})
	a.Error(err)
	// this is a new, triggers the cache update and the chain is broken
	_, _, err = tch.ensure(context.Background(), "cow.test.", []uint16{cowTestZSK.KeyTag()})
	a.Error(err)

	// DNSKEY expiration test
	// DNSKEY is expired when its RRSIG expired
	// 1. restore test. ZSK
	// 2. manually expire test. RRSIG in the cache

	// rotate test. ZSK
	testZSK, testZSKsk = getKey("test.", dns.ZONE)
	err = r.updateDNSKeyRecord("test.", testZSK, testZSKsk, time.Time{})
	a.NoError(err)
	_, _, err = tch.ensure(context.Background(), "cow.test.", []uint16{cowTestZSK.KeyTag()})
	a.NoError(err)

	// get a new signature
	rrset, _, err := r.QueryRRSet(context.Background(), "test.", dns.TypeDNSKEY)
	a.NoError(err)
	// calc and update sig in the cache with expired one
	tt, _ = time.Parse(time.RFC3339, "2020-01-02T00:00:00Z")
	sig, err := r.sign(rrset, "test.", testKSK.KeyTag(), tt, testKSKsk)
	tch.trustedZones["test."].rrSig[testKSK.KeyTag()] = sig
	a.Equal(1, len(tch.trustedZones["test."].rrSig))
	_, _, err = tch.ensure(context.Background(), "algo.test.", []uint16{algoTestZSK.KeyTag()})
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
	_, _, err = tch.ensure(context.Background(), "algo.test.", []uint16{algoTestZSK.KeyTag()})
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

	_, _, err = tch.ensure(context.Background(), "cow.test.", []uint16{cowTestZSK.KeyTag()})
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
	_, _, err = newCh.ensure(context.Background(), "algo.test.", []uint16{algoTestZSK.KeyTag()})
	a.Error(err)
	a.Contains(err.Error(), "no DNSKEY for test. matches a parent DS record or trust anchor")
}

func TestEnsureTrustChainError(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	_, _, err = newCh.ensure(context.Background(), "", []uint16{})
	a.Error(err)
	// test non-existing ZSK
	_, _, err = newCh.ensure(context.Background(), ".", []uint16{})
	a.Error(err)
	a.Contains(err.Error(), "DNSKEY [] not found in zone .")

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
	_, _, err = tch.ensure(context.Background(), "test.", []uint16{testZSK.KeyTag()})
	a.Error(err)
	a.Contains(err.Error(), "DS signature verification failed for test.")
}

func TestAuthenticate(t *testing.T) {
	partitiontest.PartitionTest(t)

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

	// Authenticate checks the signer/owner relationship of every RRSIG, so a
	// valid first relationship must not hide a later non-ancestor owner.
	// Binding the answer to the query itself is left to selectRRSet.
	sig = rrsig[0]
	sig.SignerName = "rand.test."
	sig.Hdr.Name = "rand.test."
	nonAncestorSig := sig
	nonAncestorSig.Hdr.Name = "algorand.test."
	err = tch.Authenticate(context.Background(), rrset, []dns.RRSIG{sig, nonAncestorSig})
	a.EqualError(err, "RRSIG signer rand.test. is not an ancestor of owner algorand.test.")

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
	validSig := rrsig[0]

	// Signer names are case-insensitive: they are compared, and their trusted
	// zones cached, in canonical form.
	upperSig := validSig
	upperSig.SignerName = "TEST."
	err = tch.Authenticate(context.Background(), rrset, []dns.RRSIG{upperSig})
	a.NoError(err)
	err = tch.Authenticate(context.Background(), rrset, []dns.RRSIG{upperSig, validSig})
	a.NoError(err)

	// The final record signature must be valid at the time it is authenticated.
	err = r.updateARecord("www.test.", net.IPv4(1, 2, 3, 4), time.Now().Add(-time.Hour))
	a.NoError(err)
	rrset, rrsig, err = r.QueryRRSet(context.Background(), "www.test.", dns.TypeA)
	a.NoError(err)
	err = tch.Authenticate(context.Background(), rrset, rrsig)
	a.EqualError(err, "no currently valid RRSIG for www.test.")
	expiredSig := rrsig[0]

	// An expired signature must not prevent a second, valid signature from authenticating the record.
	err = tch.Authenticate(context.Background(), rrset, []dns.RRSIG{expiredSig, validSig})
	a.NoError(err)

	// An expired signature from a known key must not authenticate a record whose only valid
	// signature uses an unknown key.
	unknownZSK, unknownZSKsk := getKey("test.", dns.ZONE)
	unknownSig, err := r.sign(rrset, "test.", unknownZSK.KeyTag(), time.Time{}, unknownZSKsk)
	a.NoError(err)
	err = tch.Authenticate(context.Background(), rrset, []dns.RRSIG{expiredSig, unknownSig})
	a.Error(err)

	// A currently valid signature that falsely claims a trusted key tag must not make an
	// expired signature eligible for cryptographic verification.
	forgedSig, err := r.sign(rrset, "test.", testZSK.KeyTag(), time.Time{}, unknownZSKsk)
	a.NoError(err)
	err = tch.Authenticate(context.Background(), rrset, []dns.RRSIG{expiredSig, forgedSig})
	a.Error(err)

	futureStart := time.Now().Add(time.Hour)
	futureSig, err := r.signWithValidity(rrset, "test.", testZSK.KeyTag(), futureStart, futureStart.Add(time.Hour), testZSKsk)
	a.NoError(err)
	err = tch.Authenticate(context.Background(), rrset, []dns.RRSIG{futureSig})
	a.EqualError(err, "no currently valid RRSIG for www.test.")

	// SEP-marked keys remain valid candidates when authenticating an RRset.
	rrset, rrsig, err = r.QueryRRSet(context.Background(), "test.", dns.TypeDNSKEY)
	err = tch.Authenticate(context.Background(), rrset, rrsig)
	a.NoError(err)

	err = tch.Authenticate(context.Background(), rrset, nil)
	a.Error(err)
	err = tch.Authenticate(context.Background(), rrset, []dns.RRSIG{})
	a.Error(err)
}

// countingResolver counts DNSKEY queries per zone.
type countingResolver struct {
	*testResolver
	dnskeyQueries map[string]int
	dnskeyDelays  map[string]time.Duration
}

func (r *countingResolver) QueryRRSet(ctx context.Context, domain string, qtype uint16) ([]dns.RR, []dns.RRSIG, error) {
	if qtype == dns.TypeDNSKEY {
		r.dnskeyQueries[domain]++
		time.Sleep(r.dnskeyDelays[domain])
	}
	return r.testResolver.QueryRRSet(ctx, domain, qtype)
}

// TestSameTagKeyRotation checks that a cached zone is refreshed when its signing key
// is replaced by a key with the same key tag.
func TestSameTagKeyRotation(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	r := &countingResolver{testResolver: makeEmptyTestResolver(), dnskeyQueries: make(map[string]int)}

	rootKSK, rootKSKsk := getKey(".", dns.ZONE|dns.SEP)
	rootZSK, rootZSKsk := getKey(".", dns.ZONE)
	a.NoError(r.updateDSRecord(".", &[]dns.DS{*rootKSK.ToDS(dns.SHA256)}, time.Time{}))
	a.NoError(r.updateDNSKeyRecord(".", rootKSK, rootKSKsk, time.Time{}))
	a.NoError(r.updateDNSKeyRecord(".", rootZSK, rootZSKsk, time.Time{}))

	sameTagZSKs, sameTagZSKsks := getSameTagKeys("test.", dns.ZONE)
	oldZSK, newZSK := sameTagZSKs[0], sameTagZSKs[1]
	keyTag := oldZSK.KeyTag()
	a.Equal(keyTag, newZSK.KeyTag())
	a.NotEqual(oldZSK.PublicKey, newZSK.PublicKey)

	testKSK, testKSKsk := getKey("test.", dns.ZONE|dns.SEP)
	a.NoError(r.updateDSRecord("test.", &[]dns.DS{*testKSK.ToDS(dns.SHA256)}, time.Time{}))
	a.NoError(r.updateDNSKeyRecord("test.", testKSK, testKSKsk, time.Time{}))
	a.NoError(r.updateDNSKeyRecord("test.", oldZSK, sameTagZSKsks[0], time.Time{}))
	a.NoError(r.updateARecord("www.test.", net.IPv4(1, 2, 3, 4), time.Time{}))

	tch := makeTrustChain(r)
	rrset, rrsig, err := r.QueryRRSet(context.Background(), "www.test.", dns.TypeA)
	a.NoError(err)
	a.NoError(tch.Authenticate(context.Background(), rrset, rrsig))
	a.Equal([]dns.DNSKEY{*oldZSK}, tch.trustedZones["test."].zsk[keyTag])

	// Replace the test. ZSK with a key that has the same tag. The cached test. zone
	// still has a candidate for the tag, so only a failed verification reveals the rotation.
	a.NoError(r.updateDNSKeyRecord("test.", newZSK, sameTagZSKsks[1], time.Time{}))
	a.NoError(r.updateARecord("www.test.", net.IPv4(1, 2, 3, 4), time.Time{}))
	rrset, rrsig, err = r.QueryRRSet(context.Background(), "www.test.", dns.TypeA)
	a.NoError(err)
	a.Equal(keyTag, rrsig[0].KeyTag)

	queries := r.dnskeyQueries["test."]
	a.NoError(tch.Authenticate(context.Background(), rrset, rrsig))
	a.Equal(queries+1, r.dnskeyQueries["test."])
	a.Equal([]dns.DNSKEY{*newZSK}, tch.trustedZones["test."].zsk[keyTag])

	// A signature that no key verifies refreshes the signer zone only once.
	_, forgedSK, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	forgedSig, err := r.sign(rrset, "test.", keyTag, time.Time{}, forgedSK)
	a.NoError(err)
	queries = r.dnskeyQueries["test."]
	err = tch.Authenticate(context.Background(), rrset, []dns.RRSIG{forgedSig})
	a.ErrorIs(err, dns.ErrSig)
	a.Equal(queries+1, r.dnskeyQueries["test."])

	// With a cold cache the signer zone was just fetched, so it is not fetched again.
	queries = r.dnskeyQueries["test."]
	err = makeTrustChain(r).Authenticate(context.Background(), rrset, []dns.RRSIG{forgedSig})
	a.ErrorIs(err, dns.ErrSig)
	a.Equal(queries+1, r.dnskeyQueries["test."])

	// The same rotation in a parent zone: the DS of a new child zone is signed by a key
	// with the same tag as the cached test. ZSK, so the cached test. zone must be refreshed.
	a.NoError(r.updateDNSKeyRecord("test.", oldZSK, sameTagZSKsks[0], time.Time{}))
	cowKSK, cowKSKsk := getKey("cow.test.", dns.ZONE|dns.SEP)
	cowZSK, cowZSKsk := getKey("cow.test.", dns.ZONE)
	a.NoError(r.updateDSRecord("cow.test.", &[]dns.DS{*cowKSK.ToDS(dns.SHA256)}, time.Time{}))
	a.NoError(r.updateDNSKeyRecord("cow.test.", cowKSK, cowKSKsk, time.Time{}))
	a.NoError(r.updateDNSKeyRecord("cow.test.", cowZSK, cowZSKsk, time.Time{}))
	_, dsSig, err := r.queryDSRRSet("cow.test.")
	a.NoError(err)
	a.Equal(keyTag, dsSig[0].KeyTag)

	queries = r.dnskeyQueries["test."]
	keys, refreshed, err := tch.ensure(context.Background(), "cow.test.", []uint16{cowZSK.KeyTag()})
	a.NoError(err)
	a.True(refreshed)
	a.Equal([]dns.DNSKEY{*cowZSK}, keys[cowZSK.KeyTag()])
	a.Equal(queries+1, r.dnskeyQueries["test."])
	a.Equal([]dns.DNSKEY{*oldZSK}, tch.trustedZones["test."].zsk[keyTag])

	// A forged DS signature refreshes the parent once and then fails. The child DNSKEY
	// RRset is fetched before and after the parent refresh.
	badKSK, badKSKsk := getKey("bad.test.", dns.ZONE|dns.SEP)
	badZSK, badZSKsk := getKey("bad.test.", dns.ZONE)
	a.NoError(r.updateDSRecord("bad.test.", &[]dns.DS{*badKSK.ToDS(dns.SHA256)}, time.Time{}))
	a.NoError(r.updateDNSKeyRecord("bad.test.", badKSK, badKSKsk, time.Time{}))
	a.NoError(r.updateDNSKeyRecord("bad.test.", badZSK, badZSKsk, time.Time{}))
	dsEntry := r.entries["bad.test."][dns.TypeDS]
	forgedDSSig, err := r.sign(dsEntry.rr, "test.", keyTag, time.Time{}, forgedSK)
	a.NoError(err)
	dsEntry.sig = []dns.RRSIG{forgedDSSig}
	r.entries["bad.test."][dns.TypeDS] = dsEntry

	parentQueries, childQueries := r.dnskeyQueries["test."], r.dnskeyQueries["bad.test."]
	_, _, err = tch.ensure(context.Background(), "bad.test.", []uint16{badZSK.KeyTag()})
	a.ErrorContains(err, "DS signature verification failed for bad.test.")
	a.Equal(parentQueries+1, r.dnskeyQueries["test."])
	a.Equal(childQueries+2, r.dnskeyQueries["bad.test."])
}

// TestTrustChainTTL checks that cached zones are refreshed once their DNSKEY RRset TTL runs out.
func TestTrustChainTTL(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	r := &countingResolver{testResolver: makeEmptyTestResolver(), dnskeyQueries: make(map[string]int)}

	rootKSK, rootKSKsk := getKey(".", dns.ZONE|dns.SEP)
	rootZSK, rootZSKsk := getKey(".", dns.ZONE)
	a.NoError(r.updateDSRecord(".", &[]dns.DS{*rootKSK.ToDS(dns.SHA256)}, time.Time{}))
	a.NoError(r.updateDNSKeyRecord(".", rootKSK, rootKSKsk, time.Time{}))
	a.NoError(r.updateDNSKeyRecord(".", rootZSK, rootZSKsk, time.Time{}))

	testKSK, testKSKsk := getKey("test.", dns.ZONE|dns.SEP)
	testZSK, testZSKsk := getKey("test.", dns.ZONE)
	a.NoError(r.updateDSRecord("test.", &[]dns.DS{*testKSK.ToDS(dns.SHA256)}, time.Time{}))
	a.NoError(r.updateDNSKeyRecord("test.", testKSK, testKSKsk, time.Time{}))
	a.NoError(r.updateDNSKeyRecord("test.", testZSK, testZSKsk, time.Time{}))

	tch := makeTrustChain(r)
	_, refreshed, err := tch.ensure(context.Background(), "test.", []uint16{testZSK.KeyTag()})
	a.NoError(err)
	a.True(refreshed)
	a.Equal(1, r.dnskeyQueries["test."])
	a.WithinDuration(time.Now().Add(time.Duration(testZSK.Hdr.Ttl)*time.Second), tch.trustedZones["test."].cacheUntil, time.Minute)

	// The cached zone is used while its TTL lasts.
	_, refreshed, err = tch.ensure(context.Background(), "test.", []uint16{testZSK.KeyTag()})
	a.NoError(err)
	a.False(refreshed)
	a.Equal(1, r.dnskeyQueries["test."])

	// Once the TTL runs out, the zone is fetched again even though its DNSKEY signature is valid.
	tz := tch.trustedZones["test."]
	tz.cacheUntil = time.Now().Add(-time.Second)
	tch.trustedZones["test."] = tz
	_, refreshed, err = tch.ensure(context.Background(), "test.", []uint16{testZSK.KeyTag()})
	a.NoError(err)
	a.True(refreshed)
	a.Equal(2, r.dnskeyQueries["test."])

	// A zero TTL zone can be used by the call that fetched it, and is fetched again by the next one.
	zeroKSK, zeroKSKsk := getKey("zero.test.", dns.ZONE|dns.SEP)
	zeroZSK, zeroZSKsk := getKey("zero.test.", dns.ZONE)
	zeroKSK.Hdr.Ttl = 0
	zeroZSK.Hdr.Ttl = 0
	a.NoError(r.updateDSRecord("zero.test.", &[]dns.DS{*zeroKSK.ToDS(dns.SHA256)}, time.Time{}))
	a.NoError(r.updateDNSKeyRecord("zero.test.", zeroKSK, zeroKSKsk, time.Time{}))
	a.NoError(r.updateDNSKeyRecord("zero.test.", zeroZSK, zeroZSKsk, time.Time{}))
	for i := 1; i <= 2; i++ {
		_, refreshed, err = tch.ensure(context.Background(), "zero.test.", []uint16{zeroZSK.KeyTag()})
		a.NoError(err)
		a.True(refreshed)
		a.Equal(i, r.dnskeyQueries["zero.test."])
	}

	// The DNSKEY signatures of a zone fetched by this call are checked again after the
	// fetch, so a signature that expires while the response is in flight is rejected.
	slowKSK, slowKSKsk := getKey("slow.test.", dns.ZONE|dns.SEP)
	slowZSK, slowZSKsk := getKey("slow.test.", dns.ZONE)
	a.NoError(r.updateDSRecord("slow.test.", &[]dns.DS{*slowKSK.ToDS(dns.SHA256)}, time.Time{}))
	a.NoError(r.updateDNSKeyRecord("slow.test.", slowKSK, slowKSKsk, time.Time{}))
	a.NoError(r.updateDNSKeyRecord("slow.test.", slowZSK, slowZSKsk, time.Now().Add(time.Second)))
	r.dnskeyDelays = map[string]time.Duration{"slow.test.": 2 * time.Second}
	_, _, err = tch.ensure(context.Background(), "slow.test.", []uint16{slowZSK.KeyTag()})
	a.ErrorContains(err, "cache outdated for already updated zone slow.test.")
}

func TestQueryWrapper(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	r := makeEmptyTestResolver()
	qr := QueryWrapper{r}

	dss, err := qr.GetRootAnchorDS()
	a.NoError(err)
	a.Equal(3, len(dss))
	currentDS := dss[1]
	a.Equal("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", currentDS.Digest)
	a.Equal(uint16(20326), currentDS.KeyTag)
	a.Equal(uint8(8), currentDS.Algorithm)
	a.Equal(uint8(2), currentDS.DigestType)
	nextDS := dss[2]
	a.Equal("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16", nextDS.Digest)
	a.Equal(uint16(38696), nextDS.KeyTag)
	a.Equal(uint8(8), nextDS.Algorithm)
	a.Equal(uint8(2), nextDS.DigestType)

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
