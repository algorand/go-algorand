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
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type trustedZone struct {
	name  string
	zsk   map[uint16]dns.DNSKEY // zone signing keys
	ksk   map[uint16]dns.DNSKEY // key signing keys
	rrSig map[uint16]dns.RRSIG  // DNSKEY RR signature(s), used for validity
	dss   []dns.DS              // DS or root anchor authenticating this zone in DS format
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
// cacheOutdated indicates no ZSK in this zone to verify the provided RRSIG
func (tz *trustedZone) verifyDS(rrSet []dns.RR, rrSig []dns.RRSIG, t time.Time) (cacheOutdated bool, err error) {
	// parent zone's DNSKEY RRSET is cached but DS is just came from the network
	// and might be signed by newer key
	kt := make([]uint16, len(rrSig))
	for i, sig := range rrSig {
		kt[i] = sig.KeyTag
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
		err = fmt.Errorf("DS signature verification failed for '%s'", requestedZone)
	}

	return
}

func getParentDS(ctx context.Context, fqZoneName string, c Querier, parent trustedZone, t time.Time) (dss []dns.DS, cacheOutdated bool, err error) {
	var rrSet []dns.RR
	var rrSig []dns.RRSIG
	rrSet, rrSig, err = c.QueryRRSet(ctx, fqZoneName, dns.TypeDS) // physically stored in parent zone of fqZoneName zone
	if err != nil {
		return
	}
	// since a new zone is being created its DS is always fetched from the network
	// but parent zone is cached and cache outdated error possbile
	cacheOutdated, err = parent.verifyDS(rrSet, rrSig, t)
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
// 2. cacheOutdated if cached parent does not have ZSK for DS validation
// 3. error in all other cases
//
// Note 1: the function should never return cacheOutdated for the root zone
// otherwise it might cause infinity loop in the caller.
//
// Note2: the function requests both DNSKEY (from child) and DS (from parent)
// and this allows to tolerate KSK rotation: if child zone refreshed KSK
// then its digest is propagated to parent DS and used to sign child's DNSKEY
func makeTrustedZone(ctx context.Context, fqZoneName string, parent trustedZone, c TrustQuerier, t time.Time) (tz trustedZone, cacheOutdated bool, err error) {
	rrSet, rrSig, err := c.QueryRRSet(ctx, fqZoneName, dns.TypeDNSKEY)
	if err != nil {
		return
	}

	var dss []dns.DS
	if fqZoneName == "." {
		if dss, err = c.GetRootAnchorDS(); err != nil {
			return
		}
	} else {
		dss, cacheOutdated, err = getParentDS(ctx, fqZoneName, c, parent, t)
		if err != nil || cacheOutdated {
			return
		}
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

	// find DNSKEY matched to RS retrieved from parent zone or from a trust anchor
	matchedDS, verifiedKSK := matchKSKDigest(dss, ksk)
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
	tz = trustedZone{
		name:  fqZoneName,
		zsk:   zsk,
		ksk:   verifiedKSK,
		rrSig: verifiedSig,
		dss:   matchedDS,
	}
	return
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

// matchKSKDigest takes array of DS and KSKs in form of map
// and returns an array of matched DS records and verified keys
func matchKSKDigest(dss []dns.DS, ksk map[uint16]dns.DNSKEY) ([]dns.DS, map[uint16]dns.DNSKEY) {
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
