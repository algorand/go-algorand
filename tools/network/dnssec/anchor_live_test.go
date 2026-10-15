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
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// liveAnchorCheckEnv enables TestLiveRootAnchor. Any non-empty value runs the
// check and skips when IANA or the root servers are unreachable; "strict" fails
// on unreachable sources too.
const liveAnchorCheckEnv = "DNSSEC_LIVE_ANCHOR_CHECK"

const ianaRootAnchorsURL = "https://data.iana.org/root-anchors/root-anchors.xml"

// maxRootAnchorsSize bounds the root-anchors.xml download; the real file is about 1 KB.
const maxRootAnchorsSize = 1 << 20

// rootServers are queried directly for the root DNSKEY RRset (a, k, l).
var rootServers = []string{"198.41.0.4:53", "193.0.14.129:53", "199.7.83.42:53"}

// liveSourceUnavailable is a marker the CI workflow greps for to surface skips.
const liveSourceUnavailable = "live source unavailable"

// TestLiveRootAnchor checks that the embedded root trust anchor covers every key
// currently published by IANA and by the root zone itself, so a KSK rollover is
// caught long before resolution starts failing.
func TestLiveRootAnchor(t *testing.T) {
	partitiontest.PartitionTest(t)

	mode := os.Getenv(liveAnchorCheckEnv)
	if mode == "" {
		t.Skipf("set %s=1 to check the embedded root anchor against live sources", liveAnchorCheckEnv)
	}
	unavailable := func(t *testing.T, err error) {
		t.Helper()
		if mode == "strict" {
			t.Fatalf("%s: %v", liveSourceUnavailable, err)
		}
		t.Skipf("%s: %v", liveSourceUnavailable, err)
	}

	embedded, err := MakeRootTrustAnchor()
	require.NoError(t, err)
	embeddedDS := embedded.ToDS()

	t.Run("IANA", func(t *testing.T) {
		data, err := fetchIANARootAnchors()
		if err != nil {
			unavailable(t, err)
		}
		// A 200 with a body we don't understand (CDN error page, format change) is an unavailable source, not a stale anchor.
		published, err := makeRootTrustAnchor(data)
		if err == nil && len(published.Digests) == 0 {
			err = fmt.Errorf("no KeyDigest entries")
		}
		if err == nil && published.Zone != "." {
			err = fmt.Errorf("unexpected zone %q", published.Zone)
		}
		if err != nil {
			unavailable(t, fmt.Errorf("%s: %w", ianaRootAnchorsURL, err))
		}

		now := time.Now()
		checked := 0
		for _, d := range published.Digests {
			if d.ValidUntil != "" {
				until, err := time.Parse(time.RFC3339, d.ValidUntil)
				if err != nil {
					unavailable(t, fmt.Errorf("%s: key tag %d: bad validUntil %q: %w", ianaRootAnchorsURL, d.KeyTag, d.ValidUntil, err))
				}
				if until.Before(now) {
					continue
				}
			}
			checked++
			found := false
			for _, ds := range embeddedDS {
				if ds.KeyTag == d.KeyTag && ds.Algorithm == d.Algorithm && ds.DigestType == d.DigestType &&
					strings.EqualFold(ds.Digest, d.Digest) {
					found = true
					break
				}
			}
			assert.True(t, found, "IANA publishes root KSK %d (valid from %s, digest %s) but the embedded anchor in anchor.go does not include it; update rootAnchorXML from %s",
				d.KeyTag, d.ValidFrom, d.Digest, ianaRootAnchorsURL)
		}
		if checked == 0 {
			unavailable(t, fmt.Errorf("%s: no unexpired root keys", ianaRootAnchorsURL))
		}
	})

	t.Run("RootDNSKEY", func(t *testing.T) {
		keys, err := fetchRootKSKs()
		if err != nil {
			unavailable(t, err)
		}
		for _, key := range keys {
			tag := key.KeyTag()
			found := false
			for _, ds := range embeddedDS {
				if ds.KeyTag != tag || ds.Algorithm != key.Algorithm {
					continue
				}
				if computed := key.ToDS(ds.DigestType); computed != nil && strings.EqualFold(computed.Digest, ds.Digest) {
					found = true
					break
				}
			}
			digest := ""
			if ds := key.ToDS(dns.SHA256); ds != nil {
				digest = ds.Digest
			}
			assert.True(t, found, "root zone publishes KSK %d (algorithm %d, SHA-256 digest %s) but the embedded anchor in anchor.go does not include it; update rootAnchorXML from %s",
				tag, key.Algorithm, digest, ianaRootAnchorsURL)
		}
	})
}

func fetchIANARootAnchors() (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 5 * time.Second)
		}
		resp, err := client.Get(ianaRootAnchorsURL)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxRootAnchorsSize+1))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if len(body) > maxRootAnchorsSize {
			lastErr = fmt.Errorf("GET %s: body larger than %d bytes", ianaRootAnchorsURL, maxRootAnchorsSize)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("GET %s: %s", ianaRootAnchorsURL, resp.Status)
			continue
		}
		return string(body), nil
	}
	return "", lastErr
}

// fetchRootKSKs returns the non-revoked key-signing keys in the root DNSKEY RRset.
func fetchRootKSKs() ([]*dns.DNSKEY, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeDNSKEY)
	msg.SetEdns0(4096, true)
	client := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}

	var lastErr error
	for _, server := range rootServers {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, _, err := client.ExchangeContext(ctx, msg, server)
		cancel()
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", server, err)
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("%s: rcode %s", server, dns.RcodeToString[resp.Rcode])
			continue
		}
		var keys []*dns.DNSKEY
		for _, rr := range resp.Answer {
			key, ok := rr.(*dns.DNSKEY)
			if ok && key.Flags&dns.SEP != 0 && key.Flags&dns.REVOKE == 0 {
				keys = append(keys, key)
			}
		}
		if len(keys) == 0 {
			lastErr = fmt.Errorf("%s: no KSKs in root DNSKEY answer", server)
			continue
		}
		return keys, nil
	}
	return nil, lastErr
}
