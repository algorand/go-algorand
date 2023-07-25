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

package datadir

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
)

var baseDataDirKey = "ALGORAND_DATA"

// dataDirDelegation maps a config key to a less specific key
// this way the chain of responsibility can be followed up to the most specific defined key
var dataDirDelegation = map[string]string{
	//TODO: these names are not correctly formatted
	"ALGORAND_DATA_HOT":               "ALGORAND_DATA",
	"ALGORAND_DATA_COLD":              "ALGORAND_DATA",
	"ALGORAND_DATA_LEDGER_TRACKERDB":  "ALGORAND_DATA_HOT",
	"ALGORAND_DATA_LEDGER_CATCHPOINT": "ALGORAND_DATA_COLD",
	"ALGORAND_DATA_AGREEMENT":         "ALGORAND_DATA_COLD",
}

type fileResources struct {
	genesisDirPath  string
	dataDirPath     string
	dataDirHotPath  string
	dataDirColdPath string
	trackerdbPath   string
	catchpointPath  string
}

// when loaded, store the genesis text for use by other packages
var genesisText string

var fr fileResources

func LoadGenesis(dataDir string, genesisPath string) (bookkeeping.Genesis, string, error) {
	if genesisPath == "" {
		genesisPath = filepath.Join(dataDir, config.GenesisJSONFile)
	}
	genText, err := os.ReadFile(genesisPath)
	if err != nil {
		return bookkeeping.Genesis{}, "", err
	}
	genesisText = string(genText)
	var genesis bookkeeping.Genesis
	err = protocol.DecodeJSON(genText, &genesis)
	if err != nil {
		return bookkeeping.Genesis{}, "", err
	}
	return genesis, string(genesisText), nil
}

func InitializeDataDirs(dataDirectory *string, dataDirsMap map[string]string, genesisFile *string) (config.Local, bookkeeping.Genesis, error) {
	// first, ensure data directory is defined and valid
	dataDir := ResolveDataDir(dataDirectory)
	if len(dataDir) == 0 {
		return config.Local{}, bookkeeping.Genesis{}, fmt.Errorf("data directory not specified")
	}
	// ensure path can be made absolute
	absolutePath, err := filepath.Abs(dataDir)
	if err != nil {
		return config.Local{}, bookkeeping.Genesis{}, err
	}
	// If data directory doesn't exist, we can't run
	if _, err := os.Stat(absolutePath); err != nil {
		return config.Local{}, bookkeeping.Genesis{}, err
	}
	// load the config
	cfg, err := config.LoadConfigFromDisk(absolutePath)
	if err != nil && !os.IsNotExist(err) {
		return config.Local{}, bookkeeping.Genesis{}, err
	}
	genesis, _, err := LoadGenesis(*dataDirectory, *genesisFile)
	if err != nil {
		return config.Local{}, bookkeeping.Genesis{}, err
	}

	// resolve data directory paths for each resource
	// TODO: should this be iterable so it can be a range loop?
	// the root data directory can't be specified in cfg, nor does it have a fallback
	fr.dataDirPath = resolve(dataDir, "ALGORAND_DATA", "", "")

	// hot and cold data directories fallback to the root directory
	fr.dataDirHotPath = resolve(dataDirsMap["ALGORAND_DATA_HOT"], "ALGORAND_DATA_HOT", cfg.HotDataDir, fr.dataDirPath)
	fr.dataDirColdPath = resolve(dataDirsMap["ALGORAND_DATA_COLD"], "ALGORAND_DATA_COLD", cfg.ColdDataDir, fr.dataDirPath)

	// these resources fallback to hot data directory
	// trackerdbPath can only be known once the Genesis ID is known, as the default location includes reference to it
	fr.trackerdbPath = "" //resolve(dataDirsMap["ALGORAND_DATA_LEDGER_TRACKERDB"], "ALGORAND_DATA_LEDGER_TRACKERDB", cfg.TrackerDbDir, fr.dataDirHotPath)

	// these resources fallback to cold data directory
	fr.catchpointPath = resolve(dataDirsMap["ALGORAND_DATA_LEDGER_CATCHPOINT"], "ALGORAND_DATA_LEDGER_CATCHPOINT", cfg.CatchpointDir, fr.dataDirColdPath)

	// the default genesis path is a folder named after the genesis ID in the root data directory
	fr.genesisDirPath = resolve(dataDirsMap["ALGORAND_DATA_LEDGER_CATCHPOINT"], "ALGORAND_DATA_LEDGER_CATCHPOINT", cfg.CatchpointDir, filepath.Join(fr.dataDirPath, genesis.ID()))

	fr.trackerdbPath = resolve(dataDirsMap["ALGORAND_DATA_LEDGER_TRACKERDB"], "ALGORAND_DATA_LEDGER_TRACKERDB", cfg.TrackerDbDir, fr.genesisDirPath)

	return cfg, genesis, nil
}

// InitialiseDataDirsWithGenesis sets the data paths which require the genesis ID to be known
func InitialiseDataDirsWithGenesis(genesisID string) {
	fr.genesisDirPath = filepath.Join(fr.dataDirPath, genesisID)
}

// TODO: func (fr *fileResources) Validate() error{
// this way we can check that all necessary paths are defined and valid

func resolve(cli string, env string, cfg string, fallback string) string {
	if cli != "" {
		return cli
	}
	envValue := os.Getenv(env)
	if envValue != "" {
		return envValue
	}
	if cfg != "" {
		return cfg
	}
	return fallback
}

// Get returns the stored content of an artifact (usually a path string), given a resource name.
// these names are collected from existing code
// once we have them all as we like them, we should consider changing this to be 1:1, or use a map
func Get(resource string) string {
	switch resource {
	case "absolutePath", "root", "dataDir":
		return fr.dataDirPath
	case "trackerdb":
		return fr.trackerdbPath
	case "genesisDir":
		return fr.genesisDirPath
	case "genesisText":
		return genesisText
	}
	return ""
}

func ResolveDataDir(dataDirectory *string) string {
	// Figure out what data directory to tell algod to use.
	// If not specified on cmdline with '-d', look for default in environment.
	var dir string
	if dataDirectory == nil || *dataDirectory == "" {
		dir = os.Getenv("ALGORAND_DATA")
	} else {
		dir = *dataDirectory
	}
	return dir
}
