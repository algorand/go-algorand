// Copyright (C) 2019 Algorand, Inc.
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
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging/telemetryspec"
)

const telemetryPrefix = "/"
const telemetrySeparator = "/"

// EnableTelemetry configures and enables telemetry based on the config provided
func EnableTelemetry(cfg TelemetryConfig, l *logger) (err error) {
	telemetry, err := makeTelemetryState(cfg, createElasticHook)
	if err != nil {
		return
	}
	enableTelemetryState(telemetry, l)
	return
}

func enableTelemetryState(telemetry *telemetryState, l *logger) {
	l.loggerState.telemetry = telemetry
	// Hook our normal logging to send desired types to telemetry
	l.AddHook(telemetry.hook)
	// Wrap current logger Output writer to capture history
	l.setOutput(telemetry.wrapOutput(l.getOutput()))
}

func makeTelemetryState(cfg TelemetryConfig, hookFactory hookFactory) (*telemetryState, error) {
	history := createLogBuffer(cfg.LogHistoryDepth)
	if cfg.SessionGUID == "" {
		cfg.SessionGUID = uuid.NewV4().String()
	}
	hook, err := createTelemetryHook(cfg, history, hookFactory)
	if err != nil {
		return nil, err
	}

	telemetry := &telemetryState{
		history,
		createAsyncHook(hook, 32, 100),
	}
	return telemetry, nil
}

// EnsureTelemetryConfig creates a new TelemetryConfig structure with a generated GUID and the appropriate Telemetry endpoint
// Err will be non-nil if the file doesn't exist, or if error loading.
// Cfg will always be valid.
func EnsureTelemetryConfig(configDir *string, genesisID string) (TelemetryConfig, error) {
	cfg, _, err := EnsureTelemetryConfigCreated(configDir, genesisID)
	return cfg, err
}

// EnsureTelemetryConfigCreated is the same as EnsureTelemetryConfig but it also returns a bool indicating
// whether EnsureTelemetryConfig had to create the config.
func EnsureTelemetryConfigCreated(configDir *string, genesisID string) (TelemetryConfig, bool, error) {
	var configPath string
	if configDir == nil {
		var err error
		configPath, err = config.GetConfigFilePath(loggingFilename)
		if err != nil {
			cfg := createTelemetryConfig()
			initializeConfig(cfg)
			return cfg, true, err
		}
	} else {
		configPath = filepath.Join(*configDir, loggingFilename)
	}
	cfg, err := LoadTelemetryConfig(configPath)
	created := false
	if err != nil {
		err = nil
		created = true
		cfg = createTelemetryConfig()
		cfg.FilePath = configPath // Initialize our desired cfg.FilePath

		// There was no config file, create it.
		err = cfg.Save(configPath)
	}

	ch := config.GetCurrentVersion().Channel
	// Should not happen, but default to "dev" if channel is unspecified.
	if ch == "" {
		ch = "dev"
	}
	cfg.ChainID = fmt.Sprintf("%s-%s", ch, genesisID)

	initializeConfig(cfg)
	return cfg, created, err
}

// wrapOutput wraps the log writer so we can keep a history of
// the tail of the file to send with critical telemetry events when logged.
func (t *telemetryState) wrapOutput(out io.Writer) io.Writer {
	return t.history.wrapOutput(out)
}

func (t *telemetryState) logMetrics(l logger, category telemetryspec.Category, metrics telemetryspec.MetricDetails, details interface{}) {
	if metrics == nil {
		return
	}
	l = l.WithFields(logrus.Fields{
		"metrics": metrics,
	}).(logger)

	t.logTelemetry(l, buildMessage(string(category), string(metrics.Identifier())), details)
}

func (t *telemetryState) logEvent(l logger, category telemetryspec.Category, identifier telemetryspec.Event, details interface{}) {
	t.logTelemetry(l, buildMessage(string(category), string(identifier)), details)
}

func (t *telemetryState) logStartOperation(l logger, category telemetryspec.Category, identifier telemetryspec.Operation) TelemetryOperation {
	op := makeTelemetryOperation(t, category, identifier)
	t.logTelemetry(l, buildMessage(string(category), string(identifier), "Start"), nil)
	return op
}

func buildMessage(args ...string) string {
	message := telemetryPrefix + strings.Join(args, telemetrySeparator)
	return message
}

// logTelemetry explicitly only sends telemetry events to the cloud.
func (t *telemetryState) logTelemetry(l logger, message string, details interface{}) {
	if details != nil {
		l = l.WithFields(logrus.Fields{
			"details": details,
		}).(logger)
	}

	entry := l.entry.WithFields(Fields{
		"session":      l.GetTelemetrySession(),
		"instanceName": l.GetInstanceName(),
	})
	// Populate entry like logrus.entry.log() does
	entry.Time = time.Now()
	entry.Level = logrus.InfoLevel
	entry.Message = message

	t.hook.Fire(entry)
}

func (t *telemetryState) Close() {
	t.hook.Close()
}

func (t *telemetryState) Flush() {
	t.hook.Flush()
}
