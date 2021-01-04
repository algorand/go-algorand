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

package algoh

import (
	"io"

	"github.com/algorand/go-algorand/util/codecs"
)

// ConfigFilename is the name of algoh's config file
const ConfigFilename = "host-config.json"

// HostConfig is algoh's configuration structure
type HostConfig struct {
	SendBlockStats bool
	UploadOnError  bool
	DeadManTimeSec int64
	StatusDelayMS  int64
	StallDelayMS   int64
}

var defaultConfig = HostConfig{
	SendBlockStats: false,
	UploadOnError:  true,
	DeadManTimeSec: 120,
	StatusDelayMS:  500,
	StallDelayMS:   60 * 1000,
}

// LoadConfigFromFile loads the configuration from the specified file, merging into the default configuration.
func LoadConfigFromFile(file string) (cfg HostConfig, err error) {
	cfg = defaultConfig
	err = codecs.LoadObjectFromFile(file, &cfg)
	return cfg, err
}

// Save pretty-prints the configuration into the the specified file.
func (cfg HostConfig) Save(file string) error {
	prettyPrint := true
	return codecs.SaveObjectToFile(file, cfg, prettyPrint)
}

// Dump pretty-prints the configuration into the the specified stream.
func (cfg HostConfig) Dump(stream io.Writer) {
	enc := codecs.NewFormattedJSONEncoder(stream)
	enc.Encode(cfg)
}
