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
	"fmt"
	"strings"
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
}

func makeTrustChain(c TrustQuerier) *trustChain {
	return &trustChain{
		client:       c,
		trustedZones: make(map[string]trustedZone),
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
// It reports whether fqZoneName was fetched from the network rather than taken from the cache.
func (t *trustChain) ensure(ctx context.Context, fqZoneName string, keytags []uint16) (refreshed bool, err error) {
	// get zones from . to fqZoneName
	zones, err := splitToZones(fqZoneName)
	if err != nil {
		return false, err
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
				return false, fmt.Errorf("cache outdated for already updated zone %s", zone)
			}
			var cacheOutdated bool
			parentZone := trustedZone{}
			if zoneIdx > 0 {
				parentZone = t.trustedZones[zones[zoneIdx-1]]
			}
			if tz, cacheOutdated, err = makeTrustedZone(ctx, zone, parentZone, t.client, time.Now()); err != nil {
				return false, err
			}
			if cacheOutdated {
				// Failed to validate DS using cached parent's keys
				// restart loop from parent
				zoneIdx--
				if zoneIdx < 0 {
					return false, fmt.Errorf("logic error: cache outdated for root zone")
				}
				if refreshedZones[zoneIdx] {
					// the parent keys are already fresh, so refreshing them again would not help
					return false, fmt.Errorf("DS signature verification failed for %s", zone)
				}
				parentZoneName := zones[zoneIdx]
				t.removeSelfAndChildren(parentZoneName)
				continue
			}
			// successfully created a new zone, record it
			t.trustedZones[zone] = tz
			refreshedZones[zoneIdx] = true
		}
		// A zone fetched by this call is current even if its TTL is zero or has just run out.
		if !refreshedZones[zoneIdx] && tz.isExpired(time.Now()) {
			// remove current and all child zones and restart with the same zone
			t.removeSelfAndChildren(zone)
			continue
		}
		if zoneIdx == len(zones)-1 {
			// For the last zone, ensure that a key used to sign the requested RRset is present.
			if !tz.checkKeys(keytags) {
				if refreshedZones[zoneIdx] {
					return false, fmt.Errorf("DNSKEY %v not found in zone %s", keytags, fqZoneName)
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
	return refreshedZones[len(zones)-1], nil
}

func (t *trustChain) getDNSKeys(fqZoneName string, keyTag uint16) []dns.DNSKEY {
	t.mu.RLock()
	defer t.mu.RUnlock()

	trustedZone, ok := t.trustedZones[fqZoneName]
	if !ok {
		return nil
	}
	return append([]dns.DNSKEY(nil), trustedZone.zsk[keyTag]...)
}

// verifyRRSet verifies rrSet with an authenticated DNSKEY of the signer zone.
func (t *trustChain) verifyRRSet(fqZoneName string, rrSet []dns.RR, rrSig []dns.RRSIG) (err error) {
	err = fmt.Errorf("no authenticated DNSKEY verifies the RRSet for %s", fqZoneName)
	for _, sig := range rrSig {
		// Get an already authenticated key for this zone.
		keys := t.getDNSKeys(fqZoneName, sig.KeyTag)
		for i := range keys {
			if err = sig.Verify(&keys[i], rrSet); err == nil {
				return nil
			}
		}
	}
	return err
}

// Authenticate verifies a given rrset and its signatures validity down to the trusted root.
// Following steps are done:
// 1. Ensure the trust chain is valid. This requires keys' signature check back to the root if not cached
// 2. Check the signature validity period and verify it using an authenticated DNSKEY
// 3. If verification fails with cached keys, refresh the signer zone and verify once more
func (t *trustChain) Authenticate(ctx context.Context, rrSet []dns.RR, rrSig []dns.RRSIG) (err error) {
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

	now := time.Now()
	validSignatures := make([]dns.RRSIG, 0, len(rrSig))
	for _, sig := range rrSig {
		if sig.ValidityPeriod(now) {
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
	refreshed, err := t.ensure(ctx, fqdn, keytags)
	if err != nil {
		return err
	}
	err = t.verifyRRSet(fqdn, rrSet, validSignatures)
	if err == nil || refreshed {
		return err
	}

	// Key tags are not unique, so the cached DNSKEY RRset may hold an older key with
	// the same tag as the signing key. Refresh the signer zone and verify once more.
	t.mu.Lock()
	t.removeSelfAndChildren(fqdn)
	t.mu.Unlock()
	if _, err = t.ensure(ctx, fqdn, keytags); err != nil {
		return err
	}
	return t.verifyRRSet(fqdn, rrSet, validSignatures)
}
