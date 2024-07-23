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
	"github.com/algorand/go-algorand/protocol"
	"pgregory.net/rapid"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/internal/rapidgen"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
)

/**
TODOs:
* Consider a test with random dedup TLDs?
*/

func bootstrapParsingNetworkGen() *rapid.Generator[string] {
	return rapid.OneOf(rapid.StringMatching(string(Testnet)), rapid.StringMatching(string(Mainnet)),
		rapid.StringMatching(string(Devtestnet)), rapid.StringMatching(string(Devnet)),
		rapid.StringMatching(string(Betanet)), rapid.StringMatching(string(Alphanet)))
}

func bootstrapHardCodedNetworkGen() *rapid.Generator[string] {
	return rapid.OneOf(rapid.StringMatching(string(Devnet)), rapid.StringMatching(string(Betanet)),
		rapid.StringMatching(string(Alphanet)))
}

func TestParseDNSBootstrapIDBackupWithExpectedDefaultTemplate(t *testing.T) {
	partitiontest.PartitionTest(t)

	rapid.Check(t, func(t1 *rapid.T) {
		network := protocol.NetworkID(bootstrapParsingNetworkGen().Draw(t1, "network"))

		var expectedDefaultTemplate = "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)"

		dnsBootstrap, err := parseDNSBootstrap(expectedDefaultTemplate, network, true)

		assert.NoError(t, err)

		assert.True(t, strings.EqualFold(strings.Replace("<network>.algorand.network", "<network>",
			string(network), -1), dnsBootstrap.PrimarySRVBootstrap))
		assert.True(t, strings.EqualFold(strings.Replace("<network>.algorand.net", "<network>",
			string(network), -1), dnsBootstrap.BackupSRVBootstrap))
		assert.Equal(t,
			strings.Replace("(algorand-<network>.(network|net))", "<network>", string(network), -1),
			dnsBootstrap.DedupExp.String())
	})
}

func TestParseDNSBootstrapIDBackupWithHardCodedNetworkBootstraps(t *testing.T) {
	partitiontest.PartitionTest(t)

	rapid.Check(t, func(t1 *rapid.T) {
		network := protocol.NetworkID(bootstrapHardCodedNetworkGen().Draw(t1, "network"))

		var expectedDefaultTemplate = "<network>.algorand.network?backup=<network>.algorand.net" +
			"&dedup=<name>.algorand-<network>.(network|net)"

		dnsBootstrap, err := parseDNSBootstrap(expectedDefaultTemplate, network, false)

		assert.NoError(t, err)

		assert.Equal(t, strings.Replace("<network>.algodev.network", "<network>",
			string(network), -1), dnsBootstrap.PrimarySRVBootstrap)
		assert.Equal(t, "", dnsBootstrap.BackupSRVBootstrap)
		assert.Nil(t, dnsBootstrap.DedupExp)
	})
}

func TestParseDNSBootstrapIDWithLegacyTemplate(t *testing.T) {
	partitiontest.PartitionTest(t)

	rapid.Check(t, func(t1 *rapid.T) {
		network := protocol.NetworkID(bootstrapParsingNetworkGen().Draw(t1, "network"))

		var expectedDefaultTemplate = "<network>.algorand.network"

		dnsBootstrap, err := parseDNSBootstrap(expectedDefaultTemplate, network, true)

		assert.NoError(t, err)

		assert.True(t, strings.EqualFold(strings.Replace(expectedDefaultTemplate, "<network>",
			string(network), -1), dnsBootstrap.PrimarySRVBootstrap))
		assert.True(t, strings.EqualFold("", dnsBootstrap.BackupSRVBootstrap))
		assert.Nil(t, dnsBootstrap.DedupExp)
	})
}

func TestParseDNSBootstrapIDNoBackup(t *testing.T) {
	partitiontest.PartitionTest(t)

	rapid.Check(t, func(t1 *rapid.T) {
		network := protocol.NetworkID(bootstrapParsingNetworkGen().Draw(t1, "network"))
		domainGen := rapidgen.Domain()
		primaryDomain := domainGen.Draw(t1, "domain")
		includeDedup := rapid.Bool().Draw(t1, "with Dedup")
		includeHTTPS := rapid.Bool().Draw(t1, "with HTTPS")

		primaryDomainInput := primaryDomain
		// Should be ignored without backup parameter being set
		if includeDedup {
			primaryDomainInput += "?dedup=<name>.algorand-<network>.(net|network)"
		}

		if includeHTTPS {
			primaryDomainInput = "https://" + primaryDomainInput
		}

		dnsBootstrap, err := parseDNSBootstrap(primaryDomainInput, network, true)

		assert.NoError(t, err)

		assert.True(t, strings.EqualFold(primaryDomain, dnsBootstrap.PrimarySRVBootstrap))
		assert.Equal(t, "", dnsBootstrap.BackupSRVBootstrap)
		assert.Nil(t, dnsBootstrap.DedupExp)
	})
}

func TestParseDNSBootstrapIDBackupNoDedup(t *testing.T) {
	partitiontest.PartitionTest(t)

	rapid.Check(t, func(t1 *rapid.T) {
		network := protocol.NetworkID(bootstrapParsingNetworkGen().Draw(t1, "network"))
		domainGen := rapidgen.Domain()
		primaryDomain := domainGen.Draw(t1, "domain")
		backupDomain := domainGen.Draw(t1, "backupDomain")

		dnsBootstrap, err := parseDNSBootstrap(primaryDomain+"?backup="+backupDomain, network, true)

		assert.NoError(t, err)

		assert.True(t, strings.EqualFold(primaryDomain, dnsBootstrap.PrimarySRVBootstrap))
		assert.True(t, strings.EqualFold(backupDomain, dnsBootstrap.BackupSRVBootstrap))
		assert.Nil(t, dnsBootstrap.DedupExp)
	})
}

func TestParseDNSBootstrapIDBackupWithSingleDomainDedup(t *testing.T) {
	partitiontest.PartitionTest(t)

	rapid.Check(t, func(t1 *rapid.T) {
		network := protocol.NetworkID(bootstrapParsingNetworkGen().Draw(t1, "network"))
		domainGen := rapidgen.Domain()
		primaryDomain := domainGen.Draw(t1, "domain")
		backupDomain := domainGen.Draw(t1, "backupDomain")

		var defaultExpectedDedup = "<name>.algorand-<network>.network"
		dnsBootstrap, err := parseDNSBootstrap(primaryDomain+"?backup="+backupDomain+"&dedup="+defaultExpectedDedup,
			network, true)

		assert.NoError(t, err)

		assert.True(t, strings.EqualFold(primaryDomain, dnsBootstrap.PrimarySRVBootstrap))
		assert.True(t, strings.EqualFold(backupDomain, dnsBootstrap.BackupSRVBootstrap))
		assert.Equal(t,
			strings.Replace("(algorand-<network>.network)", "<network>", string(network), -1),
			dnsBootstrap.DedupExp.String())
	})
}

func TestParseDNSBootstrapIDEmptySpaceURLsRejected(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, err := parseDNSBootstrap("  ", Testnet, false)
	assert.EqualError(t, err, bootstrapErrorEmpty)

	_, err2 := parseDNSBootstrap("", Mainnet, false)
	assert.EqualError(t, err2, bootstrapErrorEmpty)
}

func TestParseDNSBootstrapIDInvalidURLsRejected(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, err := parseDNSBootstrap("algo@%%@api^^.google.com/q?backup=api.google.net", Mainnet, false)

	assert.ErrorContains(t, err, bootstrapErrorInvalidFormat)
}

func TestParseDNSBootstrapIDInvalidQueryParamsRejected(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, err := parseDNSBootstrap("http://api.google.com/q?backup=api.google.net&dedup=%%b", Mainnet, false)

	assert.ErrorContains(t, err, bootstrapErrorParsingQueryParams)
}

func TestParseDNSBootstrapIDInvalidNameMacroPosition(t *testing.T) {
	partitiontest.PartitionTest(t)

	var dnsBootstrapIDWithInvalidNameMacroUsage = "<network>.algorand.network?backup=<network>.algorand.net&dedup=algorand-<name>.algorand-<network>.(network|net)"

	_, err := parseDNSBootstrap(dnsBootstrapIDWithInvalidNameMacroUsage, Mainnet, false)

	assert.ErrorContains(t, err, bootstrapErrorInvalidNameMacroUsage)
}

func TestParseDNSBootstrapIDInvalidDedupRegex(t *testing.T) {
	partitiontest.PartitionTest(t)

	var dnsBootstrapIDWithInvalidNameMacroUsage = "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.((network|net)"

	_, err := parseDNSBootstrap(dnsBootstrapIDWithInvalidNameMacroUsage, Mainnet, false)

	assert.ErrorContains(t, err, bootstrapDedupRegexDoesNotCompile)
}
