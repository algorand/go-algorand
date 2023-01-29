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

import "os"

var DataDirs []string

func ResolveDataDir() string {
	// Figure out what data directory to tell algod to use.
	// If not specified on cmdline with '-d', look for default in environment.
	var dir string
	if len(DataDirs) > 0 {
		dir = DataDirs[0]
	}
	if dir == "" {
		dir = os.Getenv("ALGORAND_DATA")
	}
	return dir
}

func EnsureFirstDataDir() string {
	// Get the target data directory to work against,
	// then handle the scenario where no data directory is provided.
	dir := ResolveDataDir()
	if dir == "" {
		reportErrorln(errorNoDataDirectory)
	}
	return dir
}

func EnsureSingleDataDir() string {
	if len(DataDirs) > 1 {
		reportErrorln(errorOneDataDirSupported)
	}
	return EnsureFirstDataDir()
}

func GetDataDirs() (dirs []string) {
	if len(DataDirs) == 0 {
		reportErrorln(errorNoDataDirectory)
	}
	dirs = append(dirs, EnsureFirstDataDir())
	dirs = append(dirs, DataDirs[1:]...)
	return
}

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
