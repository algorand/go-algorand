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
	"encoding/xml"

	"github.com/miekg/dns"
)

// IANA-provided anchor from https://data.iana.org/root-anchors/root-anchors.xml
const rootAnchorXML = `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="380DC50D-484E-40D0-A3AE-68F2B18F61C7" source="http://data.iana.org/root-anchors/root-anchors.xml">
<Zone>.</Zone>
<KeyDigest id="Kjqmt7v" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
<KeyTag>19036</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
</KeyDigest>
<KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00">
<KeyTag>20326</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
</KeyDigest>
</TrustAnchor>`

// KeyDigest represents a digest entry in the root anchor XML
type KeyDigest struct {
	XMLName    xml.Name `xml:"KeyDigest"`
	ID         string   `xml:"id,attr"`
	ValidFrom  string   `xml:"validFrom,attr"`
	ValidUntil string   `xml:"validUntil,attr"`
	KeyTag     uint16   `xml:"KeyTag"`
	Algorithm  uint8    `xml:"Algorithm"`
	DigestType uint8    `xml:"DigestType"`
	Digest     string   `xml:"Digest"`
}

// TrustAnchor is deserialized the root anchor XML
type TrustAnchor struct {
	XMLName xml.Name    `xml:"TrustAnchor"`
	Zone    string      `xml:"Zone"`
	Digests []KeyDigest `xml:"KeyDigest"`
}

// ToDS converts KeyDigest to DS
func (a TrustAnchor) ToDS() []dns.DS {
	dss := make([]dns.DS, 0, len(a.Digests))
	for _, digest := range a.Digests {
		ds := dns.DS{
			Hdr:        dns.RR_Header{Name: a.Zone},
			KeyTag:     digest.KeyTag,
			Algorithm:  digest.Algorithm,
			DigestType: digest.DigestType,
			Digest:     digest.Digest,
		}
		dss = append(dss, ds)
	}
	return dss
}

// MakeRootTrustAnchor uses hard-coded root anchor XML and returns TrustAnchor instance
func MakeRootTrustAnchor() (TrustAnchor, error) {
	return makeRootTrustAnchor(rootAnchorXML)
}

// makeRootTrustAnchor parses XML anchor to TrustAnchor instance
func makeRootTrustAnchor(data string) (a TrustAnchor, err error) {
	err = xml.Unmarshal([]byte(data), &a)
	return
}
