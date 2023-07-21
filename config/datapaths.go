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
	"os"
	"path/filepath"
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

var fr fileResources

// genesis directory is the dataDir + genesisID
// can only be set once the genesisID is known (genesis file is loaded)
func SetGenesisDir(genesisID string) {
	fr.genesisDirPath = filepath.Join(fr.dataDirPath, genesisID)
}

func InitializeDataDirs(dataDirectory *string, dataDirsMap map[string]string, genesisFile *string) (cfg Local, retErr error) {
	// first, ensure data directory is defined and valid
	dataDir := ResolveDataDir(dataDirectory)
	if len(dataDir) == 0 {
		retErr = fmt.Errorf("data directory not specified")
		return
	}
	// ensure path can be made absolute
	absolutePath, absPathErr := filepath.Abs(dataDir)
	if absPathErr != nil {
		retErr = fmt.Errorf("can't convert data directory's path to absolute, %v", dataDir)
		return
	}
	// If data directory doesn't exist, we can't run
	if _, err := os.Stat(absolutePath); err != nil {
		retErr = err
		return
	}
	// load the config
	cfg, err := LoadConfigFromDisk(absolutePath)
	if err != nil && !os.IsNotExist(err) {
		retErr = err
		return
	}

	// resolve data directory paths for each resource
	// TODO: should this be iterable so it can be a range loop?
	// the root data directory can't be specified in cfg, nor does it have a fallback
	fr.dataDirPath = resolve(dataDir, "ALGORAND_DATA", "", "")

	// hot and cold data directories fallback to the root directory
	fr.dataDirHotPath = resolve(dataDirsMap["ALGORAND_DATA_HOT"], "ALGORAND_DATA_HOT", cfg.HotDataDir, fr.dataDirPath)
	fr.dataDirColdPath = resolve(dataDirsMap["ALGORAND_DATA_COLD"], "ALGORAND_DATA_COLD", cfg.ColdDataDir, fr.dataDirPath)

	// these resources fallback to hot data directory
	fr.trackerdbPath = resolve(dataDirsMap["ALGORAND_DATA_LEDGER_TRACKERDB"], "ALGORAND_DATA_LEDGER_TRACKERDB", cfg.TrackerDbDir, fr.dataDirHotPath)

	// these resources fallback to cold data directory
	fr.catchpointPath = resolve(dataDirsMap["ALGORAND_DATA_LEDGER_CATCHPOINT"], "ALGORAND_DATA_LEDGER_CATCHPOINT", cfg.CatchpointDir, fr.dataDirColdPath)

	return
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

// GetFileResource returns the path to a file resource, given a resource name.
// these names are collected from existing code
func GetFileResource(resource string) string {
	switch resource {
	case "absolutePath", "root", "dataDir":
		return fr.dataDirPath
	case "trackerdb":
		return fr.trackerdbPath
	case "genesisDir":
		return fr.genesisDirPath
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
