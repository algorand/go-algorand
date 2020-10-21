// Copyright (C) 2019-2020 Algorand, Inc.
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

package remote

import (
	"encoding/json"
	"os"
)

// BuildConfig is the configuration input for `netgoal build`, for actually processing templates
type BuildConfig struct {
	NetworkName       string
	NetworkPort       string
	NetworkPort2      string
	NetworkPort3      string
	NetworkPort4      string
	APIEndpoint       string
	APIEndpoint2      string
	APIEndpoint3      string
	APIEndpoint4      string
	APIToken          string
	EnableTelemetry   bool
	TelemetryURI      string
	MetricsURI        string
	RunAsService      bool
	CrontabSchedule   string
	EnableAlgoh       bool
	DashboardEndpoint string
	MiscStringString  []string
}

// LoadBuildConfig loads a BuildConfig structure from a json file
func LoadBuildConfig(file string) (cfg BuildConfig, err error) {
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	err = dec.Decode(&cfg)
	return cfg, err
}
