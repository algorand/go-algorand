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

package libgoal

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// SystemConfig is the json object in $ALGORAND_DATA/system.json
type SystemConfig struct {
	// SharedServer is true if this is a daemon on a multiuser system.
	// If not shared, kmd and other files are often stored under $ALGORAND_DATA when otherwise they might go under $HOME/.algorand/
	SharedServer   bool `json:"shared_server,omitempty"`
	SystemdManaged bool `json:"systemd_managed,omitempty"`
}

// map data dir to loaded config
var systemConfigCache map[string]SystemConfig

func init() {
	systemConfigCache = make(map[string]SystemConfig)
}

// ReadSystemConfig read and parse $ALGORAND_DATA/system.json
func ReadSystemConfig(dataDir string) (sc SystemConfig, err error) {
	var ok bool
	sc, ok = systemConfigCache[dataDir]
	if ok {
		return
	}
	fin, err := os.Open(filepath.Join(dataDir, "system.json"))
	if _, isPathErr := err.(*os.PathError); isPathErr {
		// no file is fine, just return defaults
		err = nil
		return
	}
	if err != nil {
		return
	}
	dec := json.NewDecoder(fin)
	err = dec.Decode(&sc)
	if err == nil {
		systemConfigCache[dataDir] = sc
	}
	return
}

// AlgorandDataIsPrivate returns true if the algod data dir can be considered 'private' and we can store all related data there.
// Otherwise, some data will likely go under ${HOME}/.algorand/
func AlgorandDataIsPrivate(dataDir string) bool {
	if dataDir == "" {
		return true
	}
	sc, err := ReadSystemConfig(dataDir)
	if err != nil {
		return true
	}
	return !sc.SharedServer
}

// AlgorandDaemonSystemdManaged returns true if the algod process for a given data dir is managed by systemd
// if not, algod will be managed as an indivudal process for the dir
func AlgorandDaemonSystemdManaged(dataDir string) bool {
	if dataDir == "" {
		return false
	}
	sc, err := ReadSystemConfig(dataDir)
	if err != nil {
		return false
	}
	return sc.SystemdManaged
}
