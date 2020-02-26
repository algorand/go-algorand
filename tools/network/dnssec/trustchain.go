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
	"fmt"
	"strings"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/miekg/dns"
)

type trustChain struct {
	resolver     netResolverIf
	trustedZones map[string]*trustedZone
	mu           deadlock.RWMutex
}

type trustedZone struct {
	name  string
	zsk   map[uint16]dns.DNSKEY // zone signing keys
	ksk   map[uint16]dns.DNSKEY // key signing keys
	rrSig map[uint16]dns.RRSIG  // DNSKEY RR signature(s), used for validity
	dss   []dns.DS              // DS or root anchor authenticating this zone in DS format
}

func makeTrustChain(r netResolverIf) *trustChain {
	return &trustChain{
		resolver:     r,
		trustedZones: make(map[string]*trustedZone),
	}
}

// verifyRRSig takes RRSET, array of RRSIG, time and ZSKs in form of map
// and returns a map of matched signatures by keytag
func verifyRRSig(rrSet []dns.RR, rrSig []dns.RRSIG, t time.Time, keys map[uint16]dns.DNSKEY) map[uint16]dns.RRSIG {
	verifiedSig := make(map[uint16]dns.RRSIG)
	for _, sig := range rrSig {
		if !sig.ValidityPeriod(t) {
			continue
		}
		ksk := keys[sig.KeyTag]
		if err := sig.Verify(&ksk, rrSet); err == nil {
			verifiedSig[sig.KeyTag] = sig
		}
	}
	return verifiedSig
}

// verifyKSKDigest takes array of DS and KSKs in form of map
// and returns an array of matched DS records and verified keys
func verifyKSKDigest(dss []dns.DS, ksk map[uint16]dns.DNSKEY) ([]dns.DS, map[uint16]dns.DNSKEY) {
	verifiedKSK := make(map[uint16]dns.DNSKEY)
	matchedDS := make([]dns.DS, 0, len(dss))

	for _, ds := range dss {
		if key, ok := ksk[ds.KeyTag]; ok {
			keyDigest := strings.ToLower(key.ToDS(ds.DigestType).Digest)
			if keyDigest == strings.ToLower(ds.Digest) {
				verifiedKSK[ds.KeyTag] = key
				matchedDS = append(matchedDS, ds)
			}
		}
	}
	return matchedDS, verifiedKSK
}

func (tz *trustedZone) isExpired(t time.Time) bool {
	for _, sig := range tz.rrSig {
		if !sig.ValidityPeriod(t) {
			return true
		}
	}
	return false
}

// ensure at least one of the keytags in ZSK of this zone
func (tz *trustedZone) checkKeys(keytags []uint16) bool {
	for _, kt := range keytags {
		if _, ok := tz.zsk[kt]; ok {
			return true
		}
	}
	return false
}

// verifyDS checks DS RRSIG using this zone ZSK
// cacheOutdated indicates no ZSK in this zone to verify RRSIG provided
func (tz *trustedZone) verifyDS(rrSet []dns.RR, rrSig []dns.RRSIG, t time.Time) (cacheOutdated bool, err error) {
	// parent zone's DNSKEY RRSET is cached but DS is just came from the network
	// and might be signed by newer key
	kt := make([]uint16, 0, len(rrSig))
	for _, sig := range rrSig {
		kt = append(kt, sig.KeyTag)
	}
	// so if no such keys in a cache return cache outdated that must force this zone update
	if !tz.checkKeys(kt) {
		cacheOutdated = true
		return
	}

	// at least one signature must be valid
	verifiedSig := verifyRRSig(rrSet, rrSig, t, tz.zsk)
	if len(verifiedSig) == 0 {
		requestedZone := (rrSig)[0].Hdr.Name
		err = fmt.Errorf("DS signature verification failed for %s", requestedZone)
	}

	return
}

// makeTrustedZone creates a new trustedZone for **fqZoneName**.
// it uses **resolver** is for emitting DNSKEY and DS queries and
// **pz** for DS verification using cached keys.
// returns:
// 1. newly created trustedZone in case of success
// 2. cacheOutdated if cached parent **pz** does not have ZSK for DS validation
// 3. error in all other cases
//
// Note 1: the function should never return cacheOutdated for the root zone
// otherwise it might cause infinity loop in the caller.
//
// Note2: the function requests both DNSKEY (from child) and DS (from parent)
// and this allows to tolerate KSK rotation: if child zone refreshed KSK
// then its digest is propagated to parent DS and used to sign child's DNSKEY
func makeTrustedZone(ctx context.Context, fqZoneName string, pz *trustedZone, r netResolverIf, t time.Time) (tz *trustedZone, cacheOutdated bool, err error) {
	rrSet, rrSig, err := r.queryRRSet(ctx, fqZoneName, dns.TypeDNSKEY)
	if err != nil {
		return nil, false, err
	}

	zsk := make(map[uint16]dns.DNSKEY)
	ksk := make(map[uint16]dns.DNSKEY)
	for _, rr := range rrSet {
		switch obj := rr.(type) {
		case *dns.DNSKEY:
			if obj.Flags&dns.ZONE != 0 { // 256
				if obj.Flags&dns.SEP != 0 { // 257
					ksk[obj.KeyTag()] = *obj
				} else {
					zsk[obj.KeyTag()] = *obj
				}
			}
		default:
		}
	}

	// get DS record from parent
	var dss []dns.DS
	if fqZoneName == "." {
		// for the root zone there no DS record and trust comes from trust anchors
		if dss, err = r.rootTrustAnchor(); err != nil {
			return
		}
	} else {
		var rrSet []dns.RR
		var rrSig []dns.RRSIG
		rrSet, rrSig, err = r.queryRRSet(ctx, fqZoneName, dns.TypeDS) // stored at parent of fqZoneName
		if err != nil {
			return
		}
		// since a new zone is created that DS is always fetched from the network
		// but parent zone is cached and cache outdated error possbile
		cacheOutdated, err = pz.verifyDS(rrSet, rrSig, t)
		if err != nil || cacheOutdated {
			return
		}
		for _, rr := range rrSet {
			switch obj := rr.(type) {
			case *dns.DS:
				dss = append(dss, *obj)
			}
		}
	}

	// find DNSKEY matched to RS retrieved from parent zone or from a trust anchor
	matchedDS, verifiedKSK := verifyKSKDigest(dss, ksk)
	if len(verifiedKSK) == 0 {
		err = fmt.Errorf("failed to verify %s KSK against digest in parent DS", fqZoneName)
		return
	}

	// validate DNSKEY RRSIG using matched (verified) keys
	// DNSKEY RRSET is self-signed so makes sense to check this signature at the very end with authenticated via parent DS
	verifiedSig := verifyRRSig(rrSet, rrSig, t, verifiedKSK)
	if len(verifiedSig) == 0 {
		err = fmt.Errorf("no KSK to verify DNSKEY RRSet of %s", fqZoneName)
		return
	}

	// zone and keys are authenticated, create a new zone
	tz = &trustedZone{
		name:  fqZoneName,
		zsk:   zsk,
		ksk:   verifiedKSK,
		rrSig: verifiedSig,
		dss:   matchedDS,
	}
	return
}

// must be called with the lock taken
func (t *trustChain) removeSelfAndChildren(zone string) {
	for k := range t.trustedZones {
		if strings.HasSuffix(k, zone) {
			delete(t.trustedZones, k)
		}
	}
}

// ensure checks that all zones from root till fqZoneName are valid and places them into a cache.
// It also performs cache invalidation: if child-parent authentication fails because of keys mismatch
// then parent zone is updated from the network and the process repeats.
// For example, example.com. is represented by 3 trusted zones: [".", "com.", "example.com."]
func (t *trustChain) ensure(ctx context.Context, fqZoneName string, keytags []uint16) error {
	// get zones from . to fqZoneName
	zones, err := splitToZones(fqZoneName)
	if err != nil {
		return err
	}

	zoneIdx := 0
	refreshedZones := make([]bool, len(zones)) // indexes of refreshed zones during the loop iterations
	// the loop goes over zones and cached trust chain and creates new entries if needed.
	// cache invalidation happens in these three cases:
	// 1. no ZSK in parent zone to check newly obtained DS
	// Explanation: DS is stored in parent and signed with its ZSK. If no such keys in the cache then ZSK rotation happened.
	// 2. DNSKEY signature (RRSIG) expired
	// 3. no ZSK in the last zone in cache
	// Explanation: server rotated ZSK and the cache does not have key to authenticate response.
	//
	// worst case: the last zone fails to find ZSK, it triggers refreshing back to root
	// causing 2 * len(zones) iterations
	// makeTrustedZone does not return cacheOutdated and refreshedZones has indication that the root was already updated
	// and the second fallback to the root zone will fail

	// this would not survive after granular locks and concurrent underlying zones removal
	t.mu.Lock()
	defer t.mu.Unlock()
	for {
		zone := zones[zoneIdx]
		tz, ok := t.trustedZones[zone]
		if !ok {
			if refreshedZones[zoneIdx] {
				return fmt.Errorf("cache outdated for already updated zone %s", zone)
			}
			var cacheOutdated bool
			parentZone := &trustedZone{}
			if zoneIdx > 0 {
				parentZone = t.trustedZones[zones[zoneIdx-1]]
			}
			if tz, cacheOutdated, err = makeTrustedZone(ctx, zone, parentZone, t.resolver, time.Now()); err != nil {
				return err
			}
			if cacheOutdated {
				// Failed to validate DS using cached parent's keys
				// restart loop from parent
				zoneIdx--
				if zoneIdx < 0 {
					return fmt.Errorf("logic error: cache outdated for root zone")
				}
				parentZoneName := zones[zoneIdx]
				t.removeSelfAndChildren(parentZoneName)
				continue
			}
			// successfully created a new zone, record it
			t.trustedZones[zone] = tz
			refreshedZones[zoneIdx] = true
		}
		if tz.isExpired(time.Now()) {
			// remove current and all child zones and restart with the same zone
			t.removeSelfAndChildren(zone)
			continue
		}
		if zoneIdx == len(zones)-1 {
			// for the last zone also ensure that ZSK used to sign user-requested RR are also in place
			if !tz.checkKeys(keytags) {
				if refreshedZones[zoneIdx] {
					return fmt.Errorf("ZSK %v not found in zone %s", keytags, fqZoneName)
				}
				// seems like the latest zone
				t.removeSelfAndChildren(zone)
				continue
			}
		}

		zoneIdx++
		if zoneIdx >= len(zones) {
			break
		}
	}
	return nil
}

func (t *trustChain) getDNSKey(fqZoneName string, keyTag uint16) (key *dns.DNSKEY, found bool) {
	t.mu.RLock()
	trustedZone, ok := t.trustedZones[fqZoneName]
	t.mu.RUnlock()
	if !ok {
		return
	}
	k, found := trustedZone.zsk[keyTag]
	return &k, found
}

func (t *trustChain) authenticate(ctx context.Context, rrSet []dns.RR, rrSig []dns.RRSIG) (err error) {
	// response authentication includes the following steps
	// 1. Ensure the trust chain is valid. This requires keys' signature check back to the root if not cached
	// 2. Check the signature using authenticated DNSKEY
	if len(rrSig) == 0 {
		return fmt.Errorf("empty RRSIG")
	}

	signer := rrSig[0].SignerName
	// sanity check: ensure all RRSIG contain the same signer, it must be the parent zone
	for i := 1; i < len(rrSig); i++ {
		if signer != rrSig[i].SignerName {
			return fmt.Errorf("signer name mismatch: %s vs %s", signer, rrSig[i].SignerName)
		}
	}

	fqdn := dns.Fqdn(signer)

	keytags := make([]uint16, 0, len(rrSig))
	for _, sig := range rrSig {
		keytags = append(keytags, sig.KeyTag)
	}

	// 1. ensure trust from the root to the signer
	// 2. check the keys are in place
	err = t.ensure(ctx, fqdn, keytags)
	if err != nil {
		return err
	}

	for _, sig := range rrSig {
		// get already authenticated ZSK
		key, ok := t.getDNSKey(fqdn, sig.KeyTag)
		if !ok {
			// skip, trustChain.ensure checks that at least one keytag is available
			continue
		}
		if err = sig.Verify(key, rrSet); err == nil {
			return nil
		}
	}
	return err
}
