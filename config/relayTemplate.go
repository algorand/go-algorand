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

// Relay holds the per-node-instance configuration settings for the protocol.
// !!! WARNING !!!
//
// These versioned struct tags need to be maintained CAREFULLY and treated
// like UNIVERSAL CONSTANTS - they should not be modified once committed.
//
// New fields may be added to the Relay struct, along with a version tag
// denoting a new version. When doing so, also update the
// test/testdata/configs/config-relay-v{n}.json and call "make generate" to regenerate the constants.
//
// !!! WARNING !!!
type Relay struct {
	// Version tracks the current version of the defaults so we can migrate old -> new
	// This is specifically important whenever we decide to change the default value
	// for an existing parameter. This field tag must be updated any time we add a new version.
	Version uint32 `version[0]:"0"`

	// environmental (may be overridden)
	// When enabled, stores blocks indefinitely, otherwise, only the most recent blocks
	// are being kept around. ( the precise number of recent blocks depends on the consensus parameters )
	Archival bool `version[0]:"true"`

	// EnableLedgerService enables the ledger serving service. The functionality of this depends on NetAddress, which must also be provided.
	// This functionality is required for the catchpoint catchup.
	EnableLedgerService bool `version[0]:"true"`

	// EnableBlockService enables the block serving service. The functionality of this depends on NetAddress, which must also be provided.
	// This functionality is required for the catchup.
	EnableBlockService bool `version[0]:"false"`

	// NetAddress is set to 4160 (mainnet) by default. Use 4161 for testnet.
	NetAddress string `version[0]:"4160"`
}
