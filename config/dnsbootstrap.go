// Copyright (C) 2019-2023 Algorand, Inc.
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

package config

import (
	"fmt"
	"github.com/algorand/go-algorand/protocol"
	"net/url"
	"regexp"
	"strings"
)

type DNSBootstrap struct {
	PrimarySRVBootstrap string

	// Optional Fields
	BackupSRVBootstrap string

	// Per documentation, thread-safe save for configuration method
	DedupExp *regexp.Regexp
}

var networkBootstrapOverrideMap = map[protocol.NetworkID]DNSBootstrap{
	Devnet: {
		PrimarySRVBootstrap: "devnet.algodev.network",
		BackupSRVBootstrap:  "",
		DedupExp:            nil,
	},
	Betanet: {
		PrimarySRVBootstrap: "betanet.algodev.network",
		BackupSRVBootstrap:  "",
		DedupExp:            nil,
	},
	Alphanet: {
		PrimarySRVBootstrap: "alphanet.algodev.network",
		BackupSRVBootstrap:  "",
		DedupExp:            nil,
	},
}

//var dedupExp = regexp.MustCompile(`(\(.*?\))`)
var pipeExp = regexp.MustCompile(`\|`)
var nameExp = regexp.MustCompile(`<name>\.?`)

// Error strings
const (
	bootstrapErrorEmpty              = "DNSBootstrapID must be non-empty and a valid URL"
	bootstrapErrorInvalidFormat      = "invalid formatted DNSBootstrapID"
	bootstrapErrorParsingQueryParams = "error parsing query params from DNSBootstrapID"
)

// For supported networks, supports template formats like
// `<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(net|network)`
func parseDNSBootstrap(dnsBootstrapID string, network protocol.NetworkID, defaultTemplateOverridden bool) (*DNSBootstrap, error) {
	// For several non-mainnet/testnet networks, we essentially ignore the bootstrap and use our own
	// if template was not overridden
	if !defaultTemplateOverridden {
		bootstrap, exists := networkBootstrapOverrideMap[network]
		if exists {
			return &bootstrap, nil
		}
	}

	// Normalize the dnsBootstrapID and insert the network
	dnsBootstrapID = strings.Replace(strings.TrimSpace(strings.ToLower(dnsBootstrapID)), "<network>", string(network), -1)

	if dnsBootstrapID == "" {
		return nil, fmt.Errorf(bootstrapErrorEmpty)
	}

	vu, e := url.Parse(dnsBootstrapID)

	if e != nil || vu.Host == "" {
		// Try parsing with scheme prepended
		var e2 error
		vu, e2 = url.Parse("https://" + dnsBootstrapID)

		if e2 != nil {
			return nil, fmt.Errorf("%s: %s, orig error: %s, with scheme error: %s",
				bootstrapErrorInvalidFormat, dnsBootstrapID, e, e2)
		}
	}

	m, qe := url.ParseQuery(vu.RawQuery)

	if qe != nil {
		return nil, fmt.Errorf("%s: %s, error: %s", bootstrapErrorParsingQueryParams, dnsBootstrapID, qe)
	}

	bq := m["backup"]
	var backupSRVBootstrap string
	if len(bq) != 0 && bq[0] != "" {
		backupSRVBootstrap = bq[0]
	}

	var dedupExp *regexp.Regexp // = regexp.MustCompile(`(\(.*?\))`)
	if backupSRVBootstrap != "" {
		//dedup mask is optional, even with backup present
		dq := m["dedup"]
		if len(dq) != 0 && dq[0] != "" {
			// If the string happens to start with <name>, we drop this part
			dq[0] = nameExp.ReplaceAllString(dq[0], "")

			dedupExp = regexp.MustCompile("(" + dq[0] + ")")
		}
	}

	return &DNSBootstrap{PrimarySRVBootstrap: vu.Host, BackupSRVBootstrap: backupSRVBootstrap, DedupExp: dedupExp}, nil
}
