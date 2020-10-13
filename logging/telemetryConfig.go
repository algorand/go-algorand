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

package logging

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"

	"github.com/algorand/go-algorand/config"
)

// TelemetryConfigFilename default file name for telemetry config "logging.config"
var TelemetryConfigFilename = "logging.config"

const hostnameLength = 255

// TelemetryOverride Determines whether an override value is set and what it's value is.
// The first return value is whether an override variable is found, if it is, the second is the override value.
func TelemetryOverride(env string) bool {
	env = strings.ToLower(env)

	if env == "1" || env == "true" {
		telemetryConfig.Enable = true
	}

	if env == "0" || env == "false" {
		telemetryConfig.Enable = false
	}

	return telemetryConfig.Enable
}

// createTelemetryConfig creates a new TelemetryConfig structure with a generated GUID and the appropriate Telemetry endpoint.
// Note: This should only be used/persisted when initially creating 'TelemetryConfigFilename'. Because the methods are called
//       from various tools and goal commands and affect the future default settings for telemetry, we need to inject
//       a "dev" branch check.
func createTelemetryConfig() *TelemetryConfig {
	enable := false

	return &TelemetryConfig{
		Enable:             enable,
		GUID:               uuid.NewV4().String(),
		URI:                "",
		MinLogLevel:        logrus.WarnLevel,
		ReportHistoryLevel: logrus.WarnLevel,
		// These credentials are here intentionally. Not a bug.
		UserName: "telemetry-v9",
		Password: "oq%$FA1TOJ!yYeMEcJ7D688eEOE#MGCu",
	}
}

// LoadTelemetryConfig loads the TelemetryConfig from the config file
func LoadTelemetryConfig(configPath string) (*TelemetryConfig, error) {
	return loadTelemetryConfig(configPath)
}

// Save saves the TelemetryConfig to the config file
func (cfg TelemetryConfig) Save(configPath string) error {
	f, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer f.Close()

	sanitizedCfg := cfg
	sanitizedCfg.FilePath = ""

	enc := json.NewEncoder(f)
	err = enc.Encode(sanitizedCfg)
	return err
}

// getHostName returns the HostName for telemetry (GUID:Name -- :Name is optional if blank)
func (cfg TelemetryConfig) getHostName() string {
	hostName := cfg.GUID
	if cfg.Enable && len(cfg.Name) > 0 {
		hostName += ":" + cfg.Name
	}
	return hostName
}

// getInstanceName allows us to distinguish between multiple instances running on the same node.
func (cfg TelemetryConfig) getInstanceName() string {
	p := config.GetCurrentVersion().DataDirectory
	hash := sha256.New()
	hash.Write([]byte(cfg.GUID))
	hash.Write([]byte(p))
	pathHash := sha256.Sum256(hash.Sum(nil))
	pathHashStr := base64.StdEncoding.EncodeToString(pathHash[:])

	// NOTE: We used to report HASH:DataDir but DataDir is Personally Identifiable Information (PII)
	// So we're removing it entirely to avoid GDPR issues.
	return fmt.Sprintf("%s", pathHashStr[:16])
}

// SanitizeTelemetryString applies sanitization rules and returns the sanitized string.
func SanitizeTelemetryString(input string, maxParts int) string {
	// Truncate to a reasonable size, allowing some undefined separator.
	maxReasonableSize := maxParts*hostnameLength + maxParts - 1
	if len(input) > maxReasonableSize {
		input = input[:maxReasonableSize]
	}
	return input
}

func loadTelemetryConfig(path string) (*TelemetryConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return createTelemetryConfig(), err
	}
	defer f.Close()
	cfg := createTelemetryConfig()
	dec := json.NewDecoder(f)
	err = dec.Decode(cfg)
	cfg.FilePath = path

	// Sanitize user-defined name.
	if len(cfg.Name) > 0 {
		cfg.Name = SanitizeTelemetryString(cfg.Name, 1)
	}

	initializeConfig(cfg)

	return cfg, err
}
