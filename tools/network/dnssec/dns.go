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
	"encoding/xml"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

type resolverImpl struct {
	readTimeout time.Duration
	servers     []string
	rootAnchor  string
}

func makeDNSClient(net string, timeout time.Duration) (client *dns.Client) {
	client = new(dns.Client)
	client.ReadTimeout = timeout
	client.Net = net
	return
}

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

// queryImpl performs DNS query against provided server. It respects both context and timeout restrictions.
// if it fails then retries with TCP client
func queryImpl(ctx context.Context, server string, msg *dns.Msg, timeout time.Duration) (resp *dns.Msg, err error) {
	for _, netType := range []string{"udp", "tcp"} {
		if resp, _, err = (&dns.Client{Net: netType, ReadTimeout: timeout}).ExchangeContext(ctx, msg, server); err != nil {
			return nil, err
		}
		if !resp.Truncated {
			return
		}
	}
	var name string
	if len(msg.Question) > 0 {
		name = msg.Question[0].Name
	}
	return nil, fmt.Errorf("DNS response for %s is still truncated even after retrying TCP", name)
}

func (r *resolverImpl) serverList() []string {
	return r.servers
}

func (r *resolverImpl) query(ctx context.Context, name string, qtype uint16) (resp *dns.Msg, err error) {
	name = dns.Fqdn(name)

	msg := new(dns.Msg)
	msg.RecursionDesired = true
	msg.SetQuestion(name, qtype)
	msg.SetEdns0(4096, true) // high enough value prevents truncation and retries with TCP

	for _, server := range r.servers {
		resp, err := queryImpl(ctx, server, msg, r.readTimeout)
		if err != nil {
			continue
		}
		return resp, err
	}
	return nil, fmt.Errorf("no answer for (%s, %d) from DNS servers %v", name, qtype, r.servers)
}

func (r *resolverImpl) queryRRSet(ctx context.Context, name string, qtype uint16) ([]dns.RR, []dns.RRSIG, error) {
	msg, err := r.query(ctx, name, qtype)
	if err != nil {
		return nil, nil, err
	}
	if msg.Rcode != dns.RcodeSuccess {
		return nil, nil, fmt.Errorf("DNS error: %s", dns.RcodeToString[msg.Rcode])
	}

	rrSet := make([]dns.RR, 0, len(msg.Answer)) // answer usually contains 1-2 RRSIG so we use quite a bit more memory than needed
	rrSig := make([]dns.RRSIG, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		switch obj := rr.(type) {
		case *dns.RRSIG:
			rrSig = append(rrSig, *obj)
		default:
			rrSet = append(rrSet, rr)
		}
	}
	if len(rrSig) == 0 {
		return nil, nil, fmt.Errorf("no signature in DNS response for %s", name)
	}
	return rrSet, rrSig, nil
}

func (r *resolverImpl) rootTrustAnchor() ([]dns.DS, error) {
	return parseRootTrustAnchor(r.rootAnchor)
}

func parseRootTrustAnchor(data string) ([]dns.DS, error) {
	v := TrustAnchor{}
	err := xml.Unmarshal([]byte(data), &v)
	if err != nil {
		return nil, err
	}

	dss := make([]dns.DS, 0, len(v.Digests))
	for _, digest := range v.Digests {
		ds := dns.DS{
			Hdr:        dns.RR_Header{Name: v.Zone},
			KeyTag:     digest.KeyTag,
			Algorithm:  digest.Algorithm,
			DigestType: digest.DigestType,
			Digest:     digest.Digest,
		}
		dss = append(dss, ds)
	}
	return dss, nil
}
