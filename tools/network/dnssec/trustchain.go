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
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/algorand/go-deadlock"
)

// TrustQuerier wraps Querier and trusted root anchor retrieval for better testability
type TrustQuerier interface {
	Querier
	GetRootAnchorDS() ([]dns.DS, error)
}

type trustChain struct {
	client       TrustQuerier
	trustedZones map[string]trustedZone
	mu           deadlock.RWMutex
	now          func() time.Time
	nextGen      uint64
}

func makeTrustChain(c TrustQuerier) *trustChain {
	return &trustChain{
		client:       c,
		trustedZones: make(map[string]trustedZone),
		now:          time.Now,
	}
}

// QueryWrapper implements TrustQuerier
// GetRootAnchor is forwared to MakeRootTrustAnchor
type QueryWrapper struct {
	Querier
}

// GetRootAnchorDS returns DS from a real trust anchor
func (qw QueryWrapper) GetRootAnchorDS() (dss []dns.DS, err error) {
	a, err := MakeRootTrustAnchor()
	if err != nil {
		return
	}
	return a.ToDS(), nil
}

// invalidate removes zone from the cache unless another lookup has already replaced it.
func (t *trustChain) invalidate(zone string, gen uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tz, ok := t.trustedZones[zone]; ok && tz.gen == gen {
		delete(t.trustedZones, zone)
	}
}

// ensure checks that all zones from root till fqZoneName are valid and places them into a cache.
// It also performs cache invalidation: if child-parent authentication fails because of keys mismatch
// then parent zone is updated from the network and the process repeats.
// For example, example.com. is represented by 3 trusted zones: [".", "com.", "example.com."]
// It returns the authenticated keys of fqZoneName, which must not be modified, and reports
// whether the zone was fetched from the network rather than taken from the cache,
// along with the generation of that snapshot.
func (t *trustChain) ensure(ctx context.Context, fqZoneName string, keytags []uint16) (keys dnskeysByTag, refreshed bool, gen uint64, err error) {
	// get zones from . to fqZoneName
	zones, err := splitToZones(fqZoneName)
	if err != nil {
		return nil, false, 0, err
	}

	zoneIdx := 0
	refreshedZones := make([]bool, len(zones)) // indexes of refreshed zones during the loop iterations
	// the loop goes over zones and cached trust chain and creates new entries if needed.
	// cache invalidation happens in these three cases:
	// 1. no cached key in parent zone verifies newly obtained DS
	// Explanation: DS is stored in parent and signed with one of its DNSKEYs. If no cached key verifies it then key rotation happened.
	// Key tags are not unique, so the signing key may share a tag with a cached key.
	// 2. DNSKEY signature (RRSIG) or TTL expired
	// 3. no matching key in the last zone in cache
	// Explanation: the server rotated keys and the cache does not have the key needed to authenticate the response.
	//
	// worst case: the last zone fails to find the key, which triggers refreshing back to root
	// causing 2 * len(zones) iterations
	// makeTrustedZone cannot return cacheOutdated for root, and refreshedZones prevents a second refresh

	// this would not survive after granular locks and concurrent underlying zones removal
	t.mu.Lock()
	defer t.mu.Unlock()
	// Evicting a zone keeps its children cached, so drop every expired zone here to
	// keep zones that are no longer looked up from piling up.
	now := t.now()
	for zone, tz := range t.trustedZones {
		if tz.isExpired(now) || tz.ttlExpired(now) {
			delete(t.trustedZones, zone)
		}
	}
	for {
		zone := zones[zoneIdx]
		tz, ok := t.trustedZones[zone]
		if !ok {
			if refreshedZones[zoneIdx] {
				return nil, false, 0, fmt.Errorf("cache outdated for already updated zone %s", zone)
			}
			var cacheOutdated bool
			parentZone := trustedZone{}
			if zoneIdx > 0 {
				parentZone = t.trustedZones[zones[zoneIdx-1]]
			}
			if tz, cacheOutdated, err = makeTrustedZone(ctx, zone, parentZone, t.client, t.now); err != nil {
				return nil, false, 0, err
			}
			if cacheOutdated {
				// Failed to validate DS using cached parent's keys
				// restart loop from parent
				zoneIdx--
				if zoneIdx < 0 {
					return nil, false, 0, fmt.Errorf("logic error: cache outdated for root zone")
				}
				parentZoneName := zones[zoneIdx]
				if refreshedZones[zoneIdx] {
					if parentZone.isExpired(t.now()) {
						return nil, false, 0, fmt.Errorf("DNSKEY RRSIG expired during validation for %s", parentZoneName)
					}
					// the parent keys are already fresh, so refreshing them again would not help
					return nil, false, 0, fmt.Errorf("DS signature verification failed for %s", zone)
				}
				delete(t.trustedZones, parentZoneName)
				continue
			}
			// successfully created a new zone, record it
			t.nextGen++
			tz.gen = t.nextGen
			t.trustedZones[zone] = tz
			refreshedZones[zoneIdx] = true
		}
		// A zone fetched by this call stays usable for it even if its TTL is zero or has
		// just run out, but its DNSKEY signatures must still be valid.
		now = t.now()
		if tz.isExpired(now) || (!refreshedZones[zoneIdx] && tz.ttlExpired(now)) {
			delete(t.trustedZones, zone)
			if refreshedZones[zoneIdx] {
				return nil, false, 0, fmt.Errorf("DNSKEY RRSIG expired during validation for %s", zone)
			}
			continue
		}
		if zoneIdx == len(zones)-1 {
			// For the last zone, ensure that a key used to sign the requested RRset is present.
			if !tz.checkKeys(keytags) {
				if refreshedZones[zoneIdx] {
					return nil, false, 0, fmt.Errorf("DNSKEY %v not found in zone %s", keytags, fqZoneName)
				}
				// seems like the latest zone
				delete(t.trustedZones, zone)
				continue
			}
			keys = tz.zsk
			gen = tz.gen
		}

		zoneIdx++
		if zoneIdx >= len(zones) {
			break
		}
	}
	return keys, refreshedZones[len(zones)-1], gen, nil
}

// verifyRRSet verifies rrSet with an authenticated DNSKEY of the signer zone.
func verifyRRSet(fqZoneName string, rrSet []dns.RR, rrSig []dns.RRSIG, keys dnskeysByTag) (err error) {
	var errs []error
	for _, sig := range rrSig {
		candidates := keys[sig.KeyTag]
		if len(candidates) == 0 {
			errs = append(errs, fmt.Errorf("no authenticated DNSKEY with tag %d", sig.KeyTag))
			continue
		}
		var sigErrs []error
		for i := range candidates {
			if err = sig.Verify(&candidates[i], rrSet); err == nil {
				return nil
			}
			sigErrs = append(sigErrs, err)
		}
		errs = append(errs, fmt.Errorf("RRSIG with key tag %d: %w", sig.KeyTag, errors.Join(sigErrs...)))
	}
	if len(errs) == 0 {
		return fmt.Errorf("no authenticated DNSKEY verifies the RRSet for %s", fqZoneName)
	}
	return fmt.Errorf("no authenticated DNSKEY verifies the RRSet for %s: %w", fqZoneName, errors.Join(errs...))
}

// Authenticate verifies a given rrset and its signatures validity down to the trusted root.
// Following steps are done:
// 1. Ensure the trust chain is valid. This requires keys' signature check back to the root if not cached
// 2. Check the signature validity period and verify it using an authenticated DNSKEY
// 3. If verification fails with cached keys, refresh the signer zone and verify once more
func (t *trustChain) Authenticate(ctx context.Context, rrSet []dns.RR, rrSig []dns.RRSIG) (err error) {
	if !dns.IsRRset(rrSet) {
		return dns.ErrRRset
	}
	if len(rrSig) == 0 {
		return fmt.Errorf("empty RRSIG")
	}

	signer := dns.CanonicalName(rrSig[0].SignerName)
	owner := dns.CanonicalName(rrSig[0].Hdr.Name)
	// sanity check: ensure all RRSIG contain the same signer, it must be the parent zone
	for i := range rrSig {
		sigSigner := dns.CanonicalName(rrSig[i].SignerName)
		if signer != sigSigner {
			return fmt.Errorf("signer name mismatch: %s vs %s", signer, sigSigner)
		}
		sigOwner := dns.CanonicalName(rrSig[i].Hdr.Name)
		if !dns.IsSubDomain(signer, sigOwner) {
			return fmt.Errorf("RRSIG signer %s is not an ancestor of owner %s", signer, sigOwner)
		}
	}

	fqdn := signer

	now := t.now()
	validSignatures := make([]dns.RRSIG, 0, len(rrSig))
	for _, sig := range rrSig {
		if signatureMatchesRRSet(sig, rrSet[0].Header()) && sig.ValidityPeriod(now) {
			validSignatures = append(validSignatures, sig)
		}
	}
	if len(validSignatures) == 0 {
		return fmt.Errorf("no currently valid RRSIG for %s", owner)
	}

	keytags := make([]uint16, 0, len(validSignatures))
	for _, sig := range validSignatures {
		keytags = append(keytags, sig.KeyTag)
	}

	// 1. ensure trust from the root to the signer
	// 2. check the keys are in place
	// Verification uses the keys returned by ensure, so a concurrent cache update
	// cannot remove them in between.
	keys, refreshed, gen, err := t.ensure(ctx, fqdn, keytags)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		validSignatures = signaturesAt(validSignatures, t.now())
		if len(validSignatures) == 0 {
			return fmt.Errorf("RRSIG expired during validation for %s", owner)
		}
		err = verifyRRSet(fqdn, rrSet, validSignatures, keys)
		if err == nil || refreshed || attempt == 1 {
			return err
		}

		// A same-tag rotation only becomes visible when verification fails. Keep a
		// snapshot another goroutine has already refreshed.
		t.invalidate(fqdn, gen)
		if keys, _, _, err = t.ensure(ctx, fqdn, keytags); err != nil {
			return err
		}
	}
}
