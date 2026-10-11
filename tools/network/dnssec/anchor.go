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
	"encoding/xml"

	"github.com/miekg/dns"
)

// IANA-provided anchor from https://data.iana.org/root-anchors/root-anchors.xml
const rootAnchorXML = `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="0C05FDD6-422C-4910-8ED6-430ED15E11C2" source="http://data.iana.org/root-anchors/root-anchors.xml">
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
        <PublicKey>AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=</PublicKey>
        <Flags>257</Flags>
    </KeyDigest>
    <KeyDigest id="Kmyv6jo" validFrom="2024-07-18T00:00:00+00:00">
        <KeyTag>38696</KeyTag>
        <Algorithm>8</Algorithm>
        <DigestType>2</DigestType>
        <Digest>683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16</Digest>
        <PublicKey>AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=</PublicKey>
        <Flags>257</Flags>
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
