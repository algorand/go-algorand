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
	dataDirPath     string
	dataDirHotPath  string
	dataDirColdPath string
	trackerdbPath   string
	genesisPath     string
	genesisText     string
}

var fr fileResources

func InitializeDataDirs(dataDirectory *string, genesisFile *string) (cfg Local, retErr error) {
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
	return
}

// GetFileResource returns the path to a file resource, given a resource name.
// these names are collected from existing code
func GetFileResource(resource string) string {
	switch resource {
	case "absolutePath", "root", "dataDir":
		return fr.dataDirPath
	case "genesisText":
		return fr.genesisText
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
