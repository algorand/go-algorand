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

// TrustQuerier wraps Querier and trusted root anchor retrieval for better testability
type TrustQuerier interface {
	Querier
	GetRootAnchorDS() ([]dns.DS, error)
}

type trustChain struct {
	client       TrustQuerier
	trustedZones map[string]*trustedZone
	mu           deadlock.RWMutex
}

func makeTrustChain(c TrustQuerier) *trustChain {
	return &trustChain{
		client:       c,
		trustedZones: make(map[string]*trustedZone),
	}
}

// QueryWrapper implements TrustQuerier
// QueryRRSet is forwarded to Querier.QueryRRSet
// GetRootAnchor is forwared to MakeRootTrustAnchor
type QueryWrapper struct {
	c Querier
}

// QueryRRSet is transparent wrapper for Querier.QueryRRSet
func (qw QueryWrapper) QueryRRSet(ctx context.Context, domain string, qtype uint16) ([]dns.RR, []dns.RRSIG, error) {
	return qw.c.QueryRRSet(ctx, domain, qtype)
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
			if tz, cacheOutdated, err = makeTrustedZone(ctx, zone, parentZone, t.client, time.Now()); err != nil {
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

// Authenticate verifies a given rrset and its signatures validity down to the trusted root.
// Following steps are done:
// 1. Ensure the trust chain is valid. This requires keys' signature check back to the root if not cached
// 2. Check the signature using authenticated DNSKEY
func (t *trustChain) Authenticate(ctx context.Context, rrSet []dns.RR, rrSig []dns.RRSIG) (err error) {
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
