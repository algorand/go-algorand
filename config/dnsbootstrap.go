// Copyright (C) 2019-2024 Algorand, Inc.
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
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/algorand/go-algorand/protocol"
)

// DNSBootstrap represents parsed / validated components derived from a DNSBootstrapID
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

var nameExp = regexp.MustCompile(`<name>\.?`)

// Error strings
const (
	bootstrapErrorEmpty                 = "DNSBootstrapID must be non-empty and a valid URL"
	bootstrapErrorInvalidFormat         = "invalid formatted DNSBootstrapID"
	bootstrapErrorParsingQueryParams    = "error parsing query params from DNSBootstrapID"
	bootstrapErrorInvalidNameMacroUsage = "invalid usage of <name> macro in dedup param; must be at the beginning of the expression"
	bootstrapDedupRegexDoesNotCompile   = "dedup regex does not compile"
)

// For supported networks, supports template formats like
// `<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(net|network)`

/**
 * Validates and parses a DNSBootstrapID into a DNSBootstrap struct. We use Golang's url.ParseQuery as
 * a convenience to parse out the ID and parameters (as the rules overlap cleanly).
 *
 * Non-exhaustive examples of valid formats:
 *
 * 1. <network>.algorand.network
 * 2. myawesomebootstrap-<network>.specialdomain.com
 * 3. <network>.algorand.network?backup=<network>.algorand.net
 * 4. <network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(net|network)
 * 5. <network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(net|network)
 * 6. mybootstrap-<network>.sd.com?backup=mybackup-<network>.asd.net&dedup=<name>.md-<network>.(com|net)
 *
 * A few notes:
 * 1. The network parameter to this function is substituted into the dnsBootstrapID anywhere that <network> appears.
 * 2. The backup parameter's presence in the dNSBootstrapID is optional
 *
 * On the dedup mask/expression in particular:
 * 1. The dedup mask/expression is intended to be used to deduplicate SRV records returned from the primary and backup DNS servers
 * 2. It is optional, even if backup is present. The dedup mask/expression must be a valid regular expression if set.
 * 3. If the <name> macro is used in the dedup mask/expression (in most circumstances, recommended), it must be at the beginning of the expression. It is intended as a placeholder for unique server names.
 *
 * @param dnsBootstrapID The DNSBootstrapID to parse
 * @param network The network to substitute into the DNSBootstrapID
 * @param defaultTemplateOverridden Whether the default template was overridden at runtime
 * @return A DNSBootstrap struct if successful, error otherwise
 */
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
		return nil, errors.New(bootstrapErrorEmpty)
	}

	parsedTemplate, err := url.Parse(dnsBootstrapID)

	if err != nil || parsedTemplate.Host == "" {
		// Try parsing with scheme prepended
		var err2 error
		parsedTemplate, err2 = url.Parse("https://" + dnsBootstrapID)

		if err2 != nil {
			return nil, fmt.Errorf("%s: %s, orig error: %s, with scheme error: %s",
				bootstrapErrorInvalidFormat, dnsBootstrapID, err, err2)
		}
	}

	m, err3 := url.ParseQuery(parsedTemplate.RawQuery)

	if err3 != nil {
		return nil, fmt.Errorf("%s: %s, error: %s", bootstrapErrorParsingQueryParams, dnsBootstrapID, err3)
	}

	backupBootstrapParam := m["backup"]
	var backupSRVBootstrap string
	if len(backupBootstrapParam) != 0 && backupBootstrapParam[0] != "" {
		backupSRVBootstrap = backupBootstrapParam[0]
	}

	var dedupExp *regexp.Regexp
	if backupSRVBootstrap != "" {
		//dedup mask is optional, even with backup present
		dedupParam := m["dedup"]
		if len(dedupParam) != 0 && dedupParam[0] != "" {
			// If <name> shows up anywhere other than the beginning of the dedup expression, we return an error.
			nameMacroLocations := nameExp.FindAllStringIndex(dedupParam[0], -1)
			for _, loc := range nameMacroLocations {
				if loc[0] != 0 {
					return nil, fmt.Errorf("%s: %s", bootstrapErrorInvalidNameMacroUsage, dnsBootstrapID)
				}
			}
			// If the string happens to start with <name>, we replace it with an empty string.
			dedupParam[0] = nameExp.ReplaceAllString(dedupParam[0], "")

			var err4 error
			dedupExp, err4 = regexp.Compile("(" + dedupParam[0] + ")")

			if err4 != nil {
				return nil, fmt.Errorf("%s: %s, error: %s", bootstrapDedupRegexDoesNotCompile, dnsBootstrapID, err4)
			}
		}
	}

	return &DNSBootstrap{PrimarySRVBootstrap: parsedTemplate.Host, BackupSRVBootstrap: backupSRVBootstrap, DedupExp: dedupExp}, nil
}
