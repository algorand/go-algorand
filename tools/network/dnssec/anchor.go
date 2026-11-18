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
	_ "embed"
	"encoding/xml"

	"github.com/miekg/dns"
)

// rootAnchorXML is a verbatim copy of https://data.iana.org/root-anchors/root-anchors.xml.
// The dnssec-root-anchor CI workflow compares it against the live file to catch root KSK rollovers.
//
//go:embed root-anchors.xml
var rootAnchorXML string

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
