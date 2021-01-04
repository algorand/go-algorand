// Copyright (C) 2019-2021 Algorand, Inc.
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

package main

import "os"

var dataDirs []string

func resolveDataDir() string {
	// Figure out what data directory to tell algod to use.
	// If not specified on cmdline with '-d', look for default in environment.
	var dir string
	if len(dataDirs) > 0 {
		dir = dataDirs[0]
	}
	if dir == "" {
		dir = os.Getenv("ALGORAND_DATA")
	}
	return dir
}

func ensureFirstDataDir() string {
	// Get the target data directory to work against,
	// then handle the scenario where no data directory is provided.
	dir := resolveDataDir()
	if dir == "" {
		reportErrorln(errorNoDataDirectory)
	}
	return dir
}

func ensureSingleDataDir() string {
	if len(dataDirs) > 1 {
		reportErrorln(errorOneDataDirSupported)
	}
	return ensureFirstDataDir()
}

func getDataDirs() (dirs []string) {
	if len(dataDirs) == 0 {
		reportErrorln(errorNoDataDirectory)
	}
	dirs = append(dirs, ensureFirstDataDir())
	dirs = append(dirs, dataDirs[1:]...)
	return
}

func onDataDirs(action func(dataDir string)) {
	dirs := getDataDirs()
	report := len(dirs) > 1

	for _, dir := range dirs {
		if report {
			reportInfof(infoDataDir, dir)
		}
		action(dir)
	}
}
