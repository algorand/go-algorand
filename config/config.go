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
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/codecs"
)

// Devnet identifies the 'development network' use for development and not generally accessible publicly
const Devnet protocol.NetworkID = "devnet"

// Betanet identifies the 'beta network' use for early releases of feature to the public prior to releasing these to mainnet/testnet
const Betanet protocol.NetworkID = "betanet"

// Alphanet identifies the 'alpha network' use for performance releases of feature/alphanet to the public prior to releasing these to mainnet/testnet
const Alphanet protocol.NetworkID = "alphanet"

// Devtestnet identifies the 'development network for tests' use for running tests against development and not generally accessible publicly
const Devtestnet protocol.NetworkID = "devtestnet"

// Testnet identifies the publicly-available test network
const Testnet protocol.NetworkID = "testnet"

// Mainnet identifies the publicly-available real-money network
const Mainnet protocol.NetworkID = "mainnet"

// GenesisJSONFile is the name of the genesis.json file
const GenesisJSONFile = "genesis.json"

// Filenames of config files within the configdir (e.g. ~/.algorand)

// ConfigFilename is the name of the config.json file where we store per-algod-instance settings
const ConfigFilename = "config.json"

// PhonebookFilename is the name of the phonebook configuration files - no longer used
const PhonebookFilename = "phonebook.json" // No longer used in product - still in tests

// LedgerFilenamePrefix is the prefix of the name of the ledger database files
const LedgerFilenamePrefix = "ledger"

// CrashFilename is the name of the agreement database file.
// It is used to recover from node crashes.
const CrashFilename = "crash.sqlite"

// StateProofFileName is the name of the state proof database file.
// It is used to track in-progress state proofs.
const StateProofFileName = "stateproof.sqlite"

// ParticipationRegistryFilename is the name of the participation registry database file.
// It is used for tracking participation key metadata.
const ParticipationRegistryFilename = "partregistry.sqlite"

// ConfigurableConsensusProtocolsFilename defines a set of consensus prototocols that
// are to be loaded from the data directory ( if present ), to override the
// built-in supported consensus protocols.
const ConfigurableConsensusProtocolsFilename = "consensus.json"

// The default gossip fanout setting when configured as a relay (here, as we
// do not expose in normal config so it is not in code generated local_defaults.go
const defaultRelayGossipFanout = 8

// LoadConfigFromDisk returns a Local config structure based on merging the defaults
// with settings loaded from the config file from the custom dir.  If the custom file
// cannot be loaded, the default config is returned (with the error from loading the
// custom file).
func LoadConfigFromDisk(custom string) (c Local, err error) {
	return loadConfigFromFile(filepath.Join(custom, ConfigFilename))
}

func loadConfigFromFile(configFile string) (c Local, err error) {
	c = defaultLocal
	c.Version = 0 // Reset to 0 so we get the version from the loaded file.
	c, err = mergeConfigFromFile(configFile, c)
	if err != nil {
		return
	}

	// Migrate in case defaults were changed
	// If a config file does not have version, it is assumed to be zero.
	// All fields listed in migrate() might be changed if an actual value matches to default value from a previous version.
	c, err = migrate(c)
	return
}

// GetDefaultLocal returns a copy of the current defaultLocal config
func GetDefaultLocal() Local {
	return defaultLocal
}

func GetRelayLocal() Local {
	return relayLocal
}

func mergeConfigFromDir(root string, source Local) (Local, error) {
	return mergeConfigFromFile(filepath.Join(root, ConfigFilename), source)
}

func mergeConfigFromFile(configpath string, source Local) (Local, error) {
	f, err := os.Open(configpath)
	if err != nil {
		return source, err
	}
	defer f.Close()

	err = loadConfig(f, &source)

	// For now, all relays (listening for incoming connections) are also Archival
	// We can change this logic in the future, but it's currently the sanest default.
	if source.NetAddress != "" {
		source.Archival = true
		source.EnableLedgerService = true
		source.EnableBlockService = true

		// If gossip fanout has not been explicitly overridden, use defaultRelayGossipFanout
		// rather then the default gossip fanout setting from defaultLocal
		if source.GossipFanout == defaultLocal.GossipFanout {
			source.GossipFanout = defaultRelayGossipFanout
		}
	}

	return source, err
}

func loadConfig(reader io.Reader, config *Local) error {
	dec := json.NewDecoder(reader)
	return dec.Decode(config)
}

type phonebookBlackWhiteList struct {
	Include []string
}

// LoadPhonebook returns a phonebook loaded from the provided directory, if it exists.
// NOTE: We no longer use phonebook for anything but tests, but users should be able to use it
func LoadPhonebook(datadir string) ([]string, error) {
	var entries []string
	path := filepath.Join(datadir, PhonebookFilename)
	f, rootErr := os.Open(path)
	if rootErr != nil {
		if !os.IsNotExist(rootErr) {
			return nil, rootErr
		}
	} else {
		defer f.Close()

		phonebook := phonebookBlackWhiteList{}
		dec := json.NewDecoder(f)
		err := dec.Decode(&phonebook)
		if err != nil {
			return nil, errors.New("error decoding phonebook! got error: " + err.Error())
		}
		entries = phonebook.Include
	}

	// get an initial list of peers
	return entries, rootErr
}

// SavePhonebookToDisk writes the phonebook into a root/PhonebookFilename file
func SavePhonebookToDisk(entries []string, root string) error {
	configpath := filepath.Join(root, PhonebookFilename)
	f, err := os.OpenFile(os.ExpandEnv(configpath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err == nil {
		defer f.Close()
		err = savePhonebook(entries, f)
	}
	return err
}

func savePhonebook(entries []string, w io.Writer) error {
	pb := phonebookBlackWhiteList{
		Include: entries,
	}
	enc := codecs.NewFormattedJSONEncoder(w)
	return enc.Encode(pb)
}

var globalConfigFileRoot string

// GetConfigFilePath retrieves the full path to a configuration file
// These are global configurations - not specific to data-directory / network.
func GetConfigFilePath(file string) (string, error) {
	rootPath, err := GetGlobalConfigFileRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(rootPath, file), nil
}

// GetGlobalConfigFileRoot returns the current root folder for global configuration files.
// This will likely only change for tests.
func GetGlobalConfigFileRoot() (string, error) {
	var err error
	if globalConfigFileRoot == "" {
		globalConfigFileRoot, err = GetDefaultConfigFilePath()
		if err == nil {
			dirErr := os.Mkdir(globalConfigFileRoot, os.ModePerm)
			if !os.IsExist(dirErr) {
				err = dirErr
			}
		}
	}
	return globalConfigFileRoot, err
}

// SetGlobalConfigFileRoot allows overriding the root folder for global configuration files.
// It returns the current one so it can be restored, if desired.
// This will likely only change for tests.
func SetGlobalConfigFileRoot(rootPath string) string {
	currentRoot := globalConfigFileRoot
	globalConfigFileRoot = rootPath
	return currentRoot
}

// GetDefaultConfigFilePath retrieves the default directory for global (not per-instance) config files
// By default we store in ~/.algorand/.
// This will likely only change for tests.
func GetDefaultConfigFilePath() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}
	if currentUser.HomeDir == "" {
		return "", errors.New("GetDefaultConfigFilePath fail - current user has no home directory")
	}
	return filepath.Join(currentUser.HomeDir, ".algorand"), nil
}

const (
	dnssecSRV = 1 << iota
	dnssecRelayAddr
	dnssecTelemetryAddr
)

const (
	txFilterRawMsg    = 1
	txFilterCanonical = 2
)

const (
	catchupValidationModeCertificate                 = 1
	catchupValidationModePaysetHash                  = 2
	catchupValidationModeVerifyTransactionSignatures = 4
	catchupValidationModeVerifyApplyData             = 8
)
