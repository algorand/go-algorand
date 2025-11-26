// Copyright (C) 2019-2025 Algorand, Inc.
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
	"os"
	"path/filepath"
)

// DataDirs contains the list of data directories
var DataDirs []string

// ResolveDataDir determines the data directory to use.
// If not specified on cmdline with '-d', look for default in environment.
func ResolveDataDir() string {
	var dir string
	if (len(DataDirs) > 0) && (DataDirs[0] != "") {
		// calculate absolute path, see https://github.com/algorand/go-algorand/issues/589
		absDir, err := filepath.Abs(DataDirs[0])
		if err != nil {
			reportErrorf("Absolute path conversion error: %s", err)
		}
		dir = absDir
	}
	if dir == "" {
		dir = os.Getenv("ALGORAND_DATA")
	}
	return dir
}

// EnsureFirstDataDir retrieves the first data directory.
// Reports an Error and exits when no data directory can be found.
func EnsureFirstDataDir() string {
	dir := ResolveDataDir()
	if dir == "" {
		reportErrorln(errorNoDataDirectory)
	}
	return dir
}

// EnsureSingleDataDir retrieves the exactly one data directory that exists.
// Reports and Error and exits when more than one data directories are available.
func EnsureSingleDataDir() string {
	if len(DataDirs) > 1 {
		reportErrorln(errorOneDataDirSupported)
	}
	return EnsureFirstDataDir()
}

// MaybeSingleDataDir retrieves the exactly one data directory that exists.
// Returns empty string "" when than one data directories are available.
func MaybeSingleDataDir() string {
	if len(DataDirs) > 1 {
		return ""
	}
	return ResolveDataDir()
}

// GetDataDirs returns a list of available data directories as strings
// Reports and Error and exits when no data directories are available.
func GetDataDirs() (dirs []string) {
	if len(DataDirs) == 0 {
		reportErrorln(errorNoDataDirectory)
	}
	dirs = append(dirs, EnsureFirstDataDir())
	dirs = append(dirs, DataDirs[1:]...)
	return
}

// OnDataDirs (...)
func OnDataDirs(action func(dataDir string)) {
	dirs := GetDataDirs()
	doreport := len(dirs) > 1

	for _, dir := range dirs {
		if doreport {
			reportInfof(infoDataDir, dir)
		}
		action(dir)
	}
}
