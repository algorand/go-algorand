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

package algoh

import (
	"io"

	"github.com/algorand/go-algorand/util/codecs"
)

// ConfigFilename is the name of algoh's config file
const ConfigFilename = "host-config.json"

// HostConfig is algoh's configuration structure
type HostConfig struct {
	// Send /Agreement/BlockStats messages to telemetry
	SendBlockStats bool

	// Upload log files to telemetry on error
	UploadOnError bool

	// Deadlock time in seconds
	DeadManTimeSec int64

	// Delay between status checks, in milliseconds
	StatusDelayMS int64

	// Delay between stall checks, in milliseconds
	StallDelayMS int64

	// Directory to store archived logs
	LogArchiveDir string

	// Maximum age of archived logs
	// This is a duration string, e.g. "24h", "1m", "1s"
	LogArchiveMaxAge string

	// Name of the log archive file
	LogArchiveName string

	// Directory to store main host.log
	LogFileDir string

	// Maximum size of the log file
	LogSizeLimit uint64

	// Logging level of messages
	MinLogLevel uint32
}

var defaultConfig = HostConfig{
	SendBlockStats:   false,
	UploadOnError:    true,
	DeadManTimeSec:   120,
	StatusDelayMS:    500,
	StallDelayMS:     60 * 1000,
	LogArchiveDir:    "",
	LogArchiveMaxAge: "",
	LogArchiveName:   "host.archive.log",
	LogFileDir:       "",
	LogSizeLimit:     1073741824,
	MinLogLevel:      3,
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
