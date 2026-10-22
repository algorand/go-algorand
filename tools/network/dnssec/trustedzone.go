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
	"math"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type trustedZone struct {
	name       string
	zsk        dnskeysByTag         // authenticated keys eligible to sign zone records
	ksk        dnskeysByTag         // keys authenticated by a DS record or trust anchor
	rrSig      map[uint16]dns.RRSIG // DNSKEY RR signature(s), used for validity
	dss        []dns.DS             // DS or root anchor authenticating this zone in DS format
	cacheUntil time.Time            // TTL limit for caching the DNSKEY RRset
	gen        uint64               // cache generation, so a stale lookup does not evict a newer copy
}

// DNSSEC key tags are checksums and are not unique, so every key with a given
// tag must remain available as a verification candidate.
type dnskeysByTag map[uint16][]dns.DNSKEY

func (keys dnskeysByTag) add(key dns.DNSKEY) {
	keyTag := key.KeyTag()
	if slices.Contains(keys[keyTag], key) {
		return
	}
	keys[keyTag] = append(keys[keyTag], key)
}

// ttlExpired reports whether the zone has been cached longer than its TTL allows.
func (tz *trustedZone) ttlExpired(t time.Time) bool {
	return !t.Before(tz.cacheUntil)
}

// isExpired reports whether a DNSKEY RRSIG of the zone is no longer valid.
func (tz *trustedZone) isExpired(t time.Time) bool {
	for _, sig := range tz.rrSig {
		if !sig.ValidityPeriod(t) {
			return true
		}
	}
	return false
}

// checkKeys reports whether this zone has at least one of the requested keys.
func (tz *trustedZone) checkKeys(keytags []uint16) bool {
	for _, kt := range keytags {
		if len(tz.zsk[kt]) > 0 {
			return true
		}
	}
	return false
}

// verifyDS only requests a refresh when a usable signature fails with cached keys.
func (tz *trustedZone) verifyDS(rrSet []dns.RR, rrSig []dns.RRSIG, t time.Time) (verified []dns.RRSIG, cacheOutdated bool, err error) {
	if !dns.IsRRset(rrSet) {
		return nil, false, dns.ErrRRset
	}
	eligible := make([]dns.RRSIG, 0, len(rrSig))
	for _, sig := range rrSig {
		if signatureMatchesRRSet(sig, rrSet[0].Header()) &&
			dns.CanonicalName(sig.SignerName) == dns.CanonicalName(tz.name) && sig.ValidityPeriod(t) {
			eligible = append(eligible, sig)
		}
	}
	if len(eligible) == 0 {
		return nil, false, fmt.Errorf("no eligible DS RRSIG for %s", rrSet[0].Header().Name)
	}
	if tz.isExpired(t) {
		return nil, true, nil
	}
	for _, sig := range eligible {
		if verifyRRSet(tz.name, rrSet, []dns.RRSIG{sig}, tz.zsk) == nil {
			verified = append(verified, sig)
		}
	}
	return verified, len(verified) == 0, nil
}

func getParentDS(ctx context.Context, fqZoneName string, c Querier, parent trustedZone, now func() time.Time) (dss []dns.DS, verified []dns.RRSIG, cacheOutdated bool, err error) {
	var rrSet []dns.RR
	var rrSig []dns.RRSIG
	rrSet, rrSig, err = c.QueryRRSet(ctx, fqZoneName, dns.TypeDS) // physically stored in parent zone of fqZoneName zone
	if err != nil {
		return
	}
	verified, cacheOutdated, err = parent.verifyDS(rrSet, rrSig, now())
	if err != nil || cacheOutdated {
		return
	}
	for _, rr := range rrSet {
		switch obj := rr.(type) {
		case *dns.DS:
			dss = append(dss, *obj)
		}
	}
	return
}

// makeTrustedZone creates a new trustedZone for **fqZoneName**.
// it uses **client** for emitting DNSKEY and DS queries and
// **parent** for DS verification using cached keys.
// returns:
// 1. newly created trustedZone in case of success
// 2. cacheOutdated if no cached parent key verifies the DS
// 3. error in all other cases
//
// Note 1: the function should never return cacheOutdated for the root zone
// otherwise it might cause infinity loop in the caller.
//
// Note2: the function requests both DNSKEY (from child) and DS (from parent)
// and this allows to tolerate KSK rotation: if child zone refreshed KSK
// then its digest is propagated to parent DS and used to sign child's DNSKEY
func makeTrustedZone(ctx context.Context, fqZoneName string, parent trustedZone, c TrustQuerier, now func() time.Time) (tz trustedZone, cacheOutdated bool, err error) {
	var dss []dns.DS
	var dsSignatures []dns.RRSIG
	if fqZoneName == "." {
		if dss, err = c.GetRootAnchorDS(); err != nil {
			return
		}
	} else {
		dss, dsSignatures, cacheOutdated, err = getParentDS(ctx, fqZoneName, c, parent, now)
		if err != nil || cacheOutdated {
			return
		}
	}

	queryTime := now()
	rrSet, rrSig, err := c.QueryRRSet(ctx, fqZoneName, dns.TypeDNSKEY)
	if err != nil {
		return
	}
	verificationTime := now()
	if fqZoneName != "." && len(signaturesAt(dsSignatures, verificationTime)) == 0 {
		err = fmt.Errorf("DS RRSIG expired during validation for %s", fqZoneName)
		return
	}

	zoneKeys := make(dnskeysByTag)
	for _, rr := range rrSet {
		switch obj := rr.(type) {
		case *dns.DNSKEY:
			// RSAMD5 is not allowed for DNSSEC validation. Reject it before KeyTag,
			// which can panic on malformed RSAMD5 public keys in miekg/dns v1.
			if obj.Algorithm == dns.RSAMD5 {
				continue
			}
			if obj.Flags&dns.ZONE != 0 && obj.Flags&dns.REVOKE == 0 {
				// Only zone keys may verify RRSIGs (RFC 4034, Section 2.1.1), and revoked
				// keys must not be used for validation (RFC 5011, Section 2.1).
				zoneKeys.add(*obj)
			}
		default:
		}
	}

	// Find DNSKEYs matching DS records from the parent zone or a trust anchor.
	matchedDS, verifiedKSK := matchKSKDigest(dss, zoneKeys)
	if len(verifiedKSK) == 0 {
		err = fmt.Errorf("no DNSKEY for %s matches a parent DS record or trust anchor", fqZoneName)
		return
	}

	// validate DNSKEY RRSIG using matched (verified) keys
	// DNSKEY RRSET is self-signed so makes sense to check this signature at the very end with authenticated via parent DS
	verifiedSig := verifyRRSig(rrSet, rrSig, verificationTime, verifiedKSK)
	if len(verifiedSig) == 0 {
		err = fmt.Errorf("no DS-matched DNSKEY verifies the DNSKEY RRSet for %s", fqZoneName)
		if len(signaturesAt(rrSig, queryTime)) > 0 && len(signaturesAt(rrSig, verificationTime)) == 0 {
			err = fmt.Errorf("DNSKEY RRSIG expired during validation for %s", fqZoneName)
		}
		return
	}

	// zone and keys are authenticated, create a new zone
	tz = trustedZone{
		name:       fqZoneName,
		zsk:        zoneKeys,
		ksk:        verifiedKSK,
		rrSig:      verifiedSig,
		dss:        matchedDS,
		cacheUntil: queryTime.Add(time.Duration(minTTL(rrSet, verifiedSig)) * time.Second),
	}
	return
}

// minTTL returns the TTL limit for caching an authenticated RRset: the minimum of the
// RRset TTL, the RRSIG TTL and the RRSIG Original TTL (RFC 4035, Section 5.3.3).
// TTLs with the high bit set count as zero (RFC 2181, Section 8).
// Signature expiration is checked separately by isExpired.
func minTTL(rrSet []dns.RR, rrSig map[uint16]dns.RRSIG) uint32 {
	ttl := uint32(math.MaxUint32)
	for _, rr := range rrSet {
		if rr.Header().Ttl&(1<<31) != 0 {
			return 0
		}
		ttl = min(ttl, rr.Header().Ttl)
	}
	for _, sig := range rrSig {
		if (sig.Hdr.Ttl|sig.OrigTtl)&(1<<31) != 0 {
			return 0
		}
		ttl = min(ttl, sig.Hdr.Ttl, sig.OrigTtl)
	}
	return ttl
}

// signatureMatchesRRSet checks the parts of verification that do not depend on a key.
// The caller must first check dns.IsRRset.
func signatureMatchesRRSet(sig dns.RRSIG, hdr *dns.RR_Header) bool {
	if sig.Hdr.Class != hdr.Class || sig.TypeCovered != hdr.Rrtype ||
		dns.CanonicalName(sig.Hdr.Name) != dns.CanonicalName(hdr.Name) || int(sig.Labels) > dns.CountLabel(hdr.Name) {
		return false
	}
	switch sig.Algorithm {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512,
		dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519:
		return true
	default:
		return false
	}
}

// signaturesAt returns the signatures that are within their validity period at t.
func signaturesAt(signatures []dns.RRSIG, t time.Time) []dns.RRSIG {
	valid := make([]dns.RRSIG, 0, len(signatures))
	for _, sig := range signatures {
		if sig.ValidityPeriod(t) {
			valid = append(valid, sig)
		}
	}
	return valid
}

// verifyRRSig takes an RRset, signatures, time, and candidate DNSKEYs.
// and returns a map of matched signatures by keytag
func verifyRRSig(rrSet []dns.RR, rrSig []dns.RRSIG, t time.Time, keys dnskeysByTag) map[uint16]dns.RRSIG {
	verifiedSig := make(map[uint16]dns.RRSIG)
	for _, sig := range rrSig {
		if !sig.ValidityPeriod(t) {
			continue
		}
		for i := range keys[sig.KeyTag] {
			if err := sig.Verify(&keys[sig.KeyTag][i], rrSet); err == nil {
				verifiedSig[sig.KeyTag] = sig
				break
			}
		}
	}
	return verifiedSig
}

// matchKSKDigest returns the DS records and DNSKEYs whose digests match.
func matchKSKDigest(dss []dns.DS, keys dnskeysByTag) ([]dns.DS, dnskeysByTag) {
	verifiedKSK := make(dnskeysByTag)
	matchedDS := make([]dns.DS, 0, len(dss))

	for _, ds := range dss {
		for _, key := range keys[ds.KeyTag] {
			// The DS algorithm must match the DNSKEY algorithm (RFC 4035, Section 5.2).
			if ds.Algorithm != key.Algorithm {
				continue
			}
			keyDS := key.ToDS(ds.DigestType)
			if keyDS == nil {
				continue
			}
			keyDigest := strings.ToLower(keyDS.Digest)
			if keyDigest == strings.ToLower(ds.Digest) {
				verifiedKSK.add(key)
				matchedDS = append(matchedDS, ds)
				break
			}
		}
	}
	return matchedDS, verifiedKSK
}
