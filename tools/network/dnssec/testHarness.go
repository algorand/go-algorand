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
	"crypto/rsa"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type rrRec struct {
	rr  []dns.RR
	sig []dns.RRSIG
	sk  map[uint16]crypto.PrivateKey // DNSKEY's secret keys, for signing, rotating and etc
}

type testResolver struct {
	entries       map[string]map[uint16]rrRec
	anchor        []dns.DS
	rootAnchorXML string
}

func makeEmptyTestResolver() *testResolver {
	r := new(testResolver)
	r.entries = make(map[string]map[uint16]rrRec)
	return r
}

func makeTestResolver() *testResolver {
	r := new(testResolver)
	r.rootAnchorXML = rootAnchorXML
	r.entries = make(map[string]map[uint16]rrRec)

	// real entries for . and com.
	// DNSKEY com.
	zk := dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     dns.ZONE,
		Algorithm: dns.RSASHA256,
		Protocol:  3,
		PublicKey: "AwEAAcpiOic4s641IPlBcMlBWA0FFomUWuKDWN5CzId/la4aA69RFpakRxPSZM8fegOQ+nYDrUY6UZkQRsowPr18b+MqyvHBUaT6CJUBkdRwlVcD/ikpcjvfGEiH5ttpDdZdS/YKZLBedh/uMCDLNS0baJ+nfkmMZGkYGgnK9K8peU9unWbwAOrJlrK60flM84EUolIIYD6s9g/FfyVB0tE86fE=",
	}

	kk := dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     dns.ZONE | dns.SEP,
		Algorithm: dns.RSASHA256,
		Protocol:  3,
		PublicKey: "AQPDzldNmMvZFX4NcNJ0uEnKDg7tmv/F3MyQR0lpBmVcNcsIszxNFxsBfKNW9JYCYqpik8366LE7VbIcNRzfp2h9OO8HRl+H+E08zauK8k7evWEmu/6od+2boggPoiEfGNyvNPaSI7FOIroDsnw/taggzHRX1Z7SOiOiPWPNIwSUyWOZ79VmcQ1GLkC6NlYvG3HwYmynQv6oFwGv/KELSw7ZSdrbTQ0HXvZbqMUI7BaMskmvgm1G7oKZ1YiF7O9ioVNc0+7ASbqmZN7Z98EGU/Qh2K/BgUe8Hs0XVcdPKrtyYnoQHd2ynKPcMMlTEih2/2HDHjRPJ2aywIpKNnv4oPo/",
	}
	sigdnskey := dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   dns.RSASHA256,
		Labels:      1,
		OrigTtl:     86400,
		Expiration:  0x5e4edce5, // timestamp, 2020-02-20
		Inception:   0x5e3b1539, // timestamp, 2020-02-05
		KeyTag:      30909,
		SignerName:  "com.",
		Signature:   "gTAaqVD+GE8zcjmWd5LfbA3QM1cVPYRULlzLPhJaDL2WIiYM6E1VCqd8+kM2iLW/HwlVjktyBHP2joau+9tnZZnWNqifBGEbridQeqBdqqM+i0Q6ixGVcrCxyIJ+YcieR742YNIEIhR7um9Dj7cCdT2nVW3dp1ZeUWrm9K+YH2qlSvblp2BD//Fmaxk6tCCO3nR7T1/9tixMUvv2hAc+W4dxoQUeyAm9O6yJYn6kUmztwhWZJDiLn/aj/yQLubrr35K7kunuUxiMqs5eq6RCITVKH8vVWbCXR5RhvlFJ2CSlAx2rGPAObPzoW391DHXanUWwwezD19JDqmNYD3lcag==",
	}

	rrset := rrRec{}
	rrset.rr = append(rrset.rr, &zk)
	rrset.rr = append(rrset.rr, &kk)
	rrset.sig = append(rrset.sig, sigdnskey)
	rrset.sk = make(map[uint16]crypto.PrivateKey)

	r.entries["com."] = make(map[uint16]rrRec)
	r.entries["com."][dns.TypeDNSKEY] = rrset

	// DS com.
	ds := dns.DS{
		Hdr:        dns.RR_Header{Name: "com.", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     30909,
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		Digest:     "E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766",
	}
	sigds := dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
		TypeCovered: dns.TypeDS,
		Algorithm:   dns.RSASHA256,
		Labels:      1,
		OrigTtl:     86400,
		Expiration:  0x5e543950, // timestamp, 2020-02-24
		Inception:   0x5e4307c0, // timestamp, 2020-02-11
		KeyTag:      33853,
		SignerName:  ".",
		Signature:   "WV8iCWKrwonYTy6bS2fiE9dFj/pkZeC6mctKZ8ICAP+Kz8RodZOjasoO/Fi+swyKCg/j4d/jjb8MV2GcXWmMl6XwHFdbaKz9KgZND/c5OfpO4kD88fbfa5cPfDOlBoYtfBiJNopiU+dys6VzD0rqUGWB7XPLlsV4Bbtw7Hf56igE/VEwRQkwJRaXXs9OvKPpaGtV9qDoFEnbVsDBetoG7xfy68iqKLwVUld3u4f6hkXcwcOfR21mtXjJnDq/JTxURT3y8jFOuLz12KtjEWNz9juOA35upj8HzzLC35AF5tMkqIRw6EkquhiI3MP0xY05JKjpEXJMT56OzFZ65B/SPA==",
	}
	rrset = rrRec{}
	rrset.rr = append(rrset.rr, &ds)
	rrset.sig = append(rrset.sig, sigds)

	r.entries["com."][dns.TypeDS] = rrset

	// DNSKEY .
	zkRoot := dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     dns.ZONE,
		Algorithm: dns.RSASHA256,
		Protocol:  3,
		PublicKey: "AwEAAeN+h0loXPKt7lFdW2zKIDkVHyJ1aYGUVE1dMNBlRH3kTn40JKcHiPOs+fy0OFVCBwoKa1s9qZtdyP1UC0hgKoldj3oELK1yLI5MUbTMcNkWbBMRuxRz/CgZJu3IxcmuZWZMbn4LQDMj5YeiUiuWns5vipFGWWpyPyozQXmenSWOK2GJOwcm7I/DyHVtVdztTvqiHqzy2aRoxwPhmEuAoYzzuNJJw6JNEnXaN/7l2TIciskFyPVPBFZYHnk+1ma906dfehIR190z3lh1ZESL2Yy3VIE2QGpRU6Px4ydH5sXxZ2wSMgqNNga4kjnfM1msBqk3EI48RvTTkuV0yb1eFuU=",
	}

	kkRoot := dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     dns.ZONE | dns.SEP,
		Algorithm: dns.RSASHA256,
		Protocol:  3,
		PublicKey: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}
	sigdnskey2 := dns.RRSIG{
		Hdr:         dns.RR_Header{Name: ".", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   dns.RSASHA256,
		Labels:      0,
		OrigTtl:     172800,
		Expiration:  0x5e5c4c80, // timestamp, 2020-03-01
		Inception:   0x5e409d00, // timestamp, 2020-02-09
		KeyTag:      20326,
		SignerName:  ".",
		Signature:   "J1YYPv1UjlB7Gk155V4A0q2m1D/LLqAUEHsCg4nVz94lqNza8iRsKN2vR868G3kwdxwPASMDceqGRGHsFOXR1pfasInddcy7IvrVgXnNKu7GrVGh2VlzbG8uyArUREysbtB+07u7/EaNVCkwXI3EiPL4OzhEbFgpUeKs0oGtbT/IBB8uBSHPsy6ntZpyW6YK95FwCeX3comcWyIJgBtKhNHXmLrmahbRieW5xdqE+n5St5x1pRPYTDLKwCE8r2g3SbgAExb9LXCSsr2nO/QWciaATJsMlbmUq3eDmERw/dCkLSWhH+j0c/oWnuW4wIXHRJVb4hwldRSQJfqpK0ijUg==",
	}

	rrset = rrRec{}
	rrset.rr = append(rrset.rr, &zkRoot)
	rrset.rr = append(rrset.rr, &kkRoot)
	rrset.sig = append(rrset.sig, sigdnskey2)
	rrset.sk = make(map[uint16]crypto.PrivateKey)

	r.entries["."] = make(map[uint16]rrRec)
	r.entries["."][dns.TypeDNSKEY] = rrset

	return r
}

func (r *testResolver) GetRootAnchorDS() (dss []dns.DS, err error) {
	if r.anchor != nil {
		dss = r.anchor
	} else {
		var a TrustAnchor
		a, err = makeRootTrustAnchor(r.rootAnchorXML)
		if err != nil {
			return
		}
		dss = a.ToDS()
	}
	return
}

func (r *testResolver) QueryRRSet(ctx context.Context, domain string, qtype uint16) ([]dns.RR, []dns.RRSIG, error) {
	if zone, ok := r.entries[domain]; ok {
		if entry, ok := zone[qtype]; ok {
			return entry.rr, entry.sig, nil
		}
		if qtype == dns.TypeA {
			if entry, ok := zone[dns.TypeCNAME]; ok {
				rr := entry.rr
				sig := entry.sig
				target := rr[0].(*dns.CNAME).Target
				if alias, ok := r.entries[target]; ok {
					// one level deeper, no recursion
					if e2, ok := alias[dns.TypeA]; ok {
						rr = append(rr, e2.rr...)
					} else if e2, ok := alias[dns.TypeCNAME]; ok {
						rr = append(rr, e2.rr...)
					}
				}
				return rr, sig, nil
			}
		}

	}
	return nil, nil, fmt.Errorf("%s not found", domain)
}

func (r *testResolver) serverList() []string {
	return nil
}

func (r *testResolver) queryDNSKeyRRSet(domain string) (zsk []dns.DNSKEY, ksk []dns.DNSKEY, rrSig []dns.RRSIG) {
	rrs, rrsigs, _ := r.QueryRRSet(context.Background(), domain, dns.TypeDNSKEY)
	for _, r := range rrs {
		switch t := r.(type) {
		case *dns.DNSKEY:
			if t.Flags&dns.SEP != 0 {
				ksk = append(ksk, *t)
			} else if t.Flags&dns.ZONE != 0 {
				zsk = append(zsk, *t)
			}
		}
	}
	rrSig = append(rrSig, rrsigs[0])
	return
}

func (r *testResolver) setRootAnchor(dss *[]dns.DS) {
	r.anchor = *dss
}

func (r *testResolver) sign(rrset []dns.RR, signer string, keytag uint16, expTime time.Time, sk crypto.PrivateKey) (sig dns.RRSIG, err error) {
	incTime, _ := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
	if expTime.IsZero() {
		expTime, _ = time.Parse(time.RFC3339, "2030-01-01T00:00:00Z")
	}
	sig.Inception = uint32(incTime.Unix())
	sig.Expiration = uint32(expTime.Unix())
	sig.KeyTag = keytag
	sig.SignerName = signer
	sig.Algorithm = dns.RSASHA256
	err = sig.Sign(sk.(*rsa.PrivateKey), rrset)
	return
}

func (r *testResolver) updateDNSKEYRRSet(zone string, key *dns.DNSKEY, sk crypto.PrivateKey) ([]dns.RR, map[uint16]crypto.PrivateKey) {
	var rrset []dns.RR
	var err error
	if rrset, _, err = r.QueryRRSet(context.Background(), zone, dns.TypeDNSKEY); err != nil {
		// no entry, create a new one
		rr := []dns.RR{key}
		secretKeys := make(map[uint16]crypto.PrivateKey)
		secretKeys[key.KeyTag()] = sk
		return rr, secretKeys
	}
	// filter out keys of the same time as the key provided
	secretKeys := r.entries[zone][dns.TypeDNSKEY].sk
	rrsetNew := []dns.RR{}
	for _, rr := range rrset {
		k := rr.(*dns.DNSKEY)
		if k.Flags != key.Flags {
			rrsetNew = append(rrsetNew, rr)
		} else {
			delete(secretKeys, k.KeyTag())
		}
	}
	rrsetNew = append(rrsetNew, key)
	secretKeys[key.KeyTag()] = sk
	return rrsetNew, secretKeys
}

func (r *testResolver) getKey(zone string, flags uint16) (key *dns.DNSKEY, err error) {
	if _, ok := r.entries[zone]; !ok {
		err = fmt.Errorf("No zone entry for %s", zone)
		return
	}
	entry, ok := r.entries[zone][dns.TypeDNSKEY]
	if !ok {
		err = fmt.Errorf("No DNSKEY entry for %s", zone)
		return
	}
	for idx, rr := range entry.rr {
		k := rr.(*dns.DNSKEY)
		if k.Flags == flags {
			key = entry.rr[idx].(*dns.DNSKEY)
			break
		}
	}
	if key == nil {
		err = fmt.Errorf("No KSK entry for %s", zone)
	}
	return
}

func (r *testResolver) updateKSKNoCheck(zone string, key *dns.DNSKEY, sk crypto.PrivateKey, expTime time.Time) (err error) {
	if key.Flags&dns.SEP == 0 {
		err = fmt.Errorf("not a KSK")
		return
	}

	rrset, secretKeys := r.updateDNSKEYRRSet(zone, key, sk)
	var sig dns.RRSIG
	if sig, err = r.sign(rrset, zone, key.KeyTag(), expTime, sk); err != nil {
		return err
	}
	if _, ok := r.entries[zone]; !ok {
		r.entries[zone] = make(map[uint16]rrRec)
	}
	r.entries[zone][dns.TypeDNSKEY] = rrRec{
		rr:  rrset,
		sig: []dns.RRSIG{sig},
		sk:  secretKeys,
	}
	return
}

func (r *testResolver) updateZSK(zone string, key *dns.DNSKEY, sk crypto.PrivateKey, expTime time.Time) (err error) {
	if key.Flags&dns.SEP != 0 {
		err = fmt.Errorf("not a ZSK")
		return
	}
	// ensure KSK exist
	var ksk *dns.DNSKEY
	if ksk, err = r.getKey(zone, dns.ZONE|dns.SEP); err != nil {
		return
	}

	// update ZSK and sign DNSKEY RR with KSK
	rrset, secretKeys := r.updateDNSKEYRRSet(zone, key, sk)
	skKSK := secretKeys[ksk.KeyTag()]
	var sig dns.RRSIG
	if sig, err = r.sign(rrset, zone, ksk.KeyTag(), expTime, skKSK); err != nil {
		return err
	}
	r.entries[zone][dns.TypeDNSKEY] = rrRec{
		rr:  rrset,
		sig: []dns.RRSIG{sig},
		sk:  secretKeys,
	}
	return
}

func (r *testResolver) updateDNSKeyRecord(zone string, key *dns.DNSKEY, sk crypto.PrivateKey, expTime time.Time) (err error) {
	if key.Flags&dns.SEP != 0 {
		// KSK case
		// ensure parent's DS updated
		var dss []dns.DS
		if zone == "." {
			if dss, err = r.GetRootAnchorDS(); err != nil {
				return err
			}
		} else {
			if dss, _, err = r.queryDSRRSet(zone); err != nil {
				return err
			}
		}
		ok := false
		for _, ds := range dss {
			newDS := key.ToDS(ds.DigestType)
			if strings.ToLower(newDS.Digest) == strings.ToLower(ds.Digest) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("parent DS does not match to this KSK")
		}

		return r.updateKSKNoCheck(zone, key, sk, expTime)
	}

	// ZSK case
	if err = r.updateZSK(zone, key, sk, expTime); err != nil {
		return
	}

	var sig dns.RRSIG
	// re-sign all records except DNSKEY and DS with new ZSK
	for k, rec := range r.entries[zone] {
		if k != dns.TypeDNSKEY && k != dns.TypeDS {
			if sig, err = r.sign(rec.rr, zone, key.KeyTag(), expTime, sk); err != nil {
				return err
			}
			r.entries[zone][k] = rrRec{
				rr:  rec.rr,
				sig: []dns.RRSIG{sig},
			}
		}
	}
	// re-sign all DS records of direct children
	// i.e. if com. ZSK is updated, need to update example.com. DS
	for k, v := range r.entries {
		if k != "." {
			if z, err := getParentZone(k); err == nil && z == zone {
				dsEntry := v[dns.TypeDS]
				if sig, err = r.sign(dsEntry.rr, zone, key.KeyTag(), expTime, sk); err != nil {
					return err
				}
				r.entries[k][dns.TypeDS] = rrRec{
					rr:  dsEntry.rr,
					sig: []dns.RRSIG{sig},
				}
			}
		}
	}
	return
}

func (r *testResolver) updateDSRecord(zone string, dss *[]dns.DS, expTime time.Time) (err error) {
	if zone == "." {
		r.anchor = *dss
		return nil
	}

	parent, err := getParentZone(zone)
	if err != nil {
		return
	}

	var zsk *dns.DNSKEY
	if zsk, err = r.getKey(parent, dns.ZONE); err != nil {
		return
	}
	sk := r.entries[parent][dns.TypeDNSKEY].sk[zsk.KeyTag()]

	rrset := make([]dns.RR, len(*dss))
	for i := range *dss {
		rrset[i] = &(*dss)[i]
	}
	var sig dns.RRSIG
	if sig, err = r.sign(rrset, parent, zsk.KeyTag(), expTime, sk); err != nil {
		return err
	}
	if _, ok := r.entries[zone]; !ok {
		r.entries[zone] = make(map[uint16]rrRec)
	}
	r.entries[zone][dns.TypeDS] = rrRec{
		rr:  rrset,
		sig: []dns.RRSIG{sig},
	}
	return
}

func (r *testResolver) updateARecord(domain string, value net.IP, expTime time.Time) (err error) {
	parent, err := getParentZone(domain)
	if err != nil {
		return
	}

	a := dns.A{
		Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   value,
	}
	aaaa := dns.AAAA{
		Hdr:  a.Hdr,
		AAAA: value,
	}

	rrset := []dns.RR{&a, &aaaa}
	return r.updateRegRecord(domain, parent, dns.TypeA, rrset, expTime)
}

func (r *testResolver) updateRegRecord(domain string, signer string, tp uint16, rrset []dns.RR, expTime time.Time) (err error) {
	var zsk *dns.DNSKEY
	if zsk, err = r.getKey(signer, dns.ZONE); err != nil {
		return
	}
	sk := r.entries[signer][dns.TypeDNSKEY].sk[zsk.KeyTag()]

	var sig dns.RRSIG
	if sig, err = r.sign(rrset, signer, zsk.KeyTag(), expTime, sk); err != nil {
		return err
	}

	if _, ok := r.entries[domain]; !ok {
		r.entries[domain] = make(map[uint16]rrRec)
	}

	r.entries[domain][tp] = rrRec{
		rr:  rrset,
		sig: []dns.RRSIG{sig},
	}
	return
}

func (r *testResolver) queryDSRRSet(domain string) (dss []dns.DS, rrSig []dns.RRSIG, err error) {
	rrs, rrsigs, err := r.QueryRRSet(context.Background(), domain, dns.TypeDS)
	if err != nil {
		return
	}
	for _, r := range rrs {
		switch t := r.(type) {
		case *dns.DS:
			dss = append(dss, *t)
		}
	}
	rrSig = append(rrSig, rrsigs[0])
	return
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
