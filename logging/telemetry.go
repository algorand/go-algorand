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

package logging

import (
	"fmt"
	"io"
	"os"
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
const logBufferDepth = 2

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

func makeLevels(min logrus.Level) []logrus.Level {
	levels := []logrus.Level{}
	for _, l := range []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
	} {
		if l <= min {
			levels = append(levels, l)
		}
	}
	return levels
}

func makeTelemetryState(cfg TelemetryConfig, hookFactory hookFactory) (*telemetryState, error) {
	telemetry := &telemetryState{}
	telemetry.history = createLogBuffer(logBufferDepth)
	if cfg.Enable {
		if cfg.SessionGUID == "" {
			cfg.SessionGUID = uuid.NewV4().String()
		}
		hook, err := createTelemetryHook(cfg, telemetry.history, hookFactory)
		if err != nil {
			return nil, err
		}
		telemetry.hook = createAsyncHookLevels(hook, 32, 100, makeLevels(cfg.MinLogLevel))
	} else {
		telemetry.hook = new(dummyHook)
	}
	telemetry.telemetryConfig = cfg
	return telemetry, nil
}

// ReadTelemetryConfigOrDefault reads telemetry config from file or defaults if no config file found.
func ReadTelemetryConfigOrDefault(dataDir *string, genesisID string) (cfg TelemetryConfig, err error) {
	err = nil
	if dataDir != nil && *dataDir != "" {
		configPath := filepath.Join(*dataDir, TelemetryConfigFilename)
		cfg, err = LoadTelemetryConfig(configPath)
	}
	if err != nil && os.IsNotExist(err) {
		var configPath string
		configPath, err = config.GetConfigFilePath(TelemetryConfigFilename)
		if err != nil {
			cfg = createTelemetryConfig()
			return
		}
		cfg, err = LoadTelemetryConfig(configPath)
	}
	if err != nil {
		cfg = createTelemetryConfig()
		if os.IsNotExist(err) {
			err = nil
		} else {
			return
		}
	}
	ch := config.GetCurrentVersion().Channel
	// Should not happen, but default to "dev" if channel is unspecified.
	if ch == "" {
		ch = "dev"
	}
	cfg.ChainID = fmt.Sprintf("%s-%s", ch, genesisID)
	return cfg, err
}

// EnsureTelemetryConfig creates a new TelemetryConfig structure with a generated GUID and the appropriate Telemetry endpoint
// Err will be non-nil if the file doesn't exist, or if error loading.
// Cfg will always be valid.
func EnsureTelemetryConfig(dataDir *string, genesisID string) (TelemetryConfig, error) {
	cfg, _, err := EnsureTelemetryConfigCreated(dataDir, genesisID)
	return cfg, err
}

// EnsureTelemetryConfigCreated is the same as EnsureTelemetryConfig but it also returns a bool indicating
// whether EnsureTelemetryConfig had to create the config.
func EnsureTelemetryConfigCreated(dataDir *string, genesisID string) (TelemetryConfig, bool, error) {
	configPath := ""
	var cfg TelemetryConfig
	var err error
	if dataDir != nil && *dataDir != "" {
		configPath = filepath.Join(*dataDir, TelemetryConfigFilename)
		cfg, err = LoadTelemetryConfig(configPath)
		if err != nil && os.IsNotExist(err) {
			// if it just didn't exist, try again at the other path
			configPath = ""
		}
	}
	if configPath == "" {
		configPath, err = config.GetConfigFilePath(TelemetryConfigFilename)
		if err != nil {
			cfg := createTelemetryConfig()
			return cfg, true, err
		}
		cfg, err = LoadTelemetryConfig(configPath)
	}
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

	if t.telemetryConfig.SendToLog {
		entry.Info(message)
	}
	t.hook.Fire(entry)
}

func (t *telemetryState) Close() {
	if t.hook != nil {
		t.hook.Close()
	}
}

func (t *telemetryState) Flush() {
	t.hook.Flush()
}
