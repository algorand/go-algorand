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
	"fmt"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/logging/telemetryspec"
)

type mockTelemetryHook struct {
	mu       *deadlock.Mutex
	levels   []logrus.Level
	_entries []string
	_data    []logrus.Fields
	cb       func(entry *logrus.Entry)
}

func makeMockTelemetryHook(level logrus.Level) mockTelemetryHook {
	levels := make([]logrus.Level, 0)
	for _, l := range []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
	} {
		if l <= level {
			levels = append(levels, l)
		}
	}
	h := mockTelemetryHook{
		levels: levels,
		mu:     &deadlock.Mutex{},
	}
	return h
}

type telemetryTestFixture struct {
	hook  mockTelemetryHook
	telem *telemetryState
	l     logger
}

func makeTelemetryTestFixture(minLevel logrus.Level) *telemetryTestFixture {
	return makeTelemetryTestFixtureWithConfig(minLevel, nil)
}

func makeTelemetryTestFixtureWithConfig(minLevel logrus.Level, cfg *TelemetryConfig) *telemetryTestFixture {
	f := &telemetryTestFixture{}
	var lcfg TelemetryConfig
	if cfg == nil {
		lcfg = createTelemetryConfig()
	} else {
		lcfg = *cfg
	}
	lcfg.Enable = true
	lcfg.MinLogLevel = minLevel
	f.hook = makeMockTelemetryHook(minLevel)
	f.l = Base().(logger)
	f.l.SetLevel(Debug) // Ensure logging doesn't filter anything out

	f.telem, _ = makeTelemetryState(lcfg, func(cfg TelemetryConfig) (hook logrus.Hook, err error) {
		return &f.hook, nil
	})
	f.l.loggerState.telemetry = f.telem
	return f
}

func (f *telemetryTestFixture) Flush() {
	f.telem.hook.Flush()
}

func (f *telemetryTestFixture) hookData() []logrus.Fields {
	f.Flush()
	return f.hook.data()
}

func (f *telemetryTestFixture) hookEntries() []string {
	f.Flush()
	return f.hook.entries()
}

func (h *mockTelemetryHook) Levels() []logrus.Level {
	return h.levels
}

func (h *mockTelemetryHook) Fire(entry *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h._entries = append(h._entries, entry.Message)
	h._data = append(h._data, entry.Data)
	if h.cb != nil {
		h.cb(entry)
	}
	return nil
}

func (h *mockTelemetryHook) data() []logrus.Fields {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h._data
}

func (h *mockTelemetryHook) entries() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h._entries
}

func TestCreateHookError(t *testing.T) {
	a := require.New(t)

	cfg := createTelemetryConfig()
	cfg.Enable = true
	telem, err := makeTelemetryState(cfg, func(cfg TelemetryConfig) (hook logrus.Hook, err error) {
		return nil, fmt.Errorf("failed")
	})

	a.Nil(telem)
	a.NotNil(err)
	a.Equal(err.Error(), "failed")
}

func TestTelemetryHook(t *testing.T) {
	a := require.New(t)
	f := makeTelemetryTestFixture(logrus.InfoLevel)

	a.NotNil(f.l.loggerState.telemetry)
	a.Zero(len(f.hookEntries()))

	f.telem.logMetrics(f.l, testString1, testMetrics{}, nil)
	f.telem.logEvent(f.l, testString1, testString2, nil)
	op := f.telem.logStartOperation(f.l, testString1, testString2)
	time.Sleep(1 * time.Millisecond)
	op.Stop(f.l, nil)

	entries := f.hookEntries()
	a.Equal(4, len(entries))
	a.Equal(buildMessage(testString1, testString2), entries[0])
	a.Equal(buildMessage(testString1, testString2), entries[1])
	a.Equal(buildMessage(testString1, testString2, "Start"), entries[2])
	a.Equal(buildMessage(testString1, testString2, "Stop"), entries[3])
	a.NotZero(f.hookData()[3]["duration"])
}

func TestNilMetrics(t *testing.T) {
	a := require.New(t)
	f := makeTelemetryTestFixture(logrus.InfoLevel)

	f.telem.logMetrics(f.l, testString1, nil, nil)

	a.Zero(len(f.hookEntries()))
}

func TestMultipleOperationStop(t *testing.T) {
	a := require.New(t)
	f := makeTelemetryTestFixture(logrus.InfoLevel)

	op := f.telem.logStartOperation(f.l, testString1, testString2)
	op.Stop(f.l, nil)

	// Start and stop should result in 2 entries
	a.Equal(2, len(f.hookEntries()))

	op.Stop(f.l, nil)

	// Calling stop again should not result in another entry
	a.Equal(2, len(f.hookEntries()))
}

func TestDetails(t *testing.T) {
	a := require.New(t)
	f := makeTelemetryTestFixture(logrus.InfoLevel)

	details := testMetrics{
		val: "value",
	}
	f.telem.logEvent(f.l, testString1, testString2, details)

	data := f.hookData()
	a.NotNil(data)
	a.Equal(details, data[0]["details"])
}

type testMetrics struct {
	val string
}

func (m testMetrics) Identifier() telemetryspec.Metric {
	return testString2
}

func TestMetrics(t *testing.T) {
	a := require.New(t)
	f := makeTelemetryTestFixture(logrus.InfoLevel)

	metrics := testMetrics{
		val: "value",
	}

	f.telem.logMetrics(f.l, testString1, metrics, nil)

	data := f.hookData()
	a.NotNil(data)
	a.Equal(metrics, data[0]["metrics"])
}

func TestLogHook(t *testing.T) {
	a := require.New(t)
	f := makeTelemetryTestFixture(logrus.InfoLevel)

	// Wire up our telemetry hook directly
	enableTelemetryState(f.telem, &f.l)
	a.True(f.l.GetTelemetryEnabled())

	// When we enable telemetry, we no longer send an event.
	a.Equal(0, len(f.hookEntries()))

	f.l.Warn("some error")

	// Now that we're hooked, we should see the log entry in telemetry too
	a.Equal(1, len(f.hookEntries()))
}

func TestLogLevels(t *testing.T) {
	runLogLevelsTest(t, logrus.DebugLevel, 7)
	runLogLevelsTest(t, logrus.InfoLevel, 6)
	runLogLevelsTest(t, logrus.WarnLevel, 5)
	runLogLevelsTest(t, logrus.ErrorLevel, 4)
	runLogLevelsTest(t, logrus.FatalLevel, 1)
	runLogLevelsTest(t, logrus.PanicLevel, 1)
}

func runLogLevelsTest(t *testing.T, minLevel logrus.Level, expected int) {
	a := require.New(t)
	f := makeTelemetryTestFixture(minLevel)
	enableTelemetryState(f.telem, &f.l)

	f.l.Debug("debug")
	f.l.Info("info")
	f.l.Warn("warn")
	f.l.Error("error")
	// f.l.Fatal("fatal") - can't call this - it will os.Exit()

	// Protect the call to log.Panic as we don't really want to crash
	func() {
		defer func() {
			if r := recover(); r != nil {
			}
		}()
		f.l.Panic("panic")
	}()

	// See if we got the expected number of entries
	a.Equal(expected, len(f.hookEntries()))
}

func TestLogHistoryLevels(t *testing.T) {
	a := require.New(t)
	cfg := createTelemetryConfig()
	cfg.MinLogLevel = logrus.DebugLevel
	cfg.ReportHistoryLevel = logrus.ErrorLevel

	f := makeTelemetryTestFixtureWithConfig(logrus.DebugLevel, &cfg)
	enableTelemetryState(f.telem, &f.l)

	f.l.Debug("debug")
	f.l.Info("info")
	f.l.Warn("warn")
	f.l.Error("error")
	// f.l.Fatal("fatal") - can't call this - it will os.Exit()
	// Protect the call to log.Panic as we don't really want to crash
	func() {
		defer func() {
			if r := recover(); r != nil {
			}
		}()
		f.l.Panic("panic")
	}()

	data := f.hookData()
	a.Nil(data[0]["log"]) // Debug
	a.Nil(data[1]["log"]) // Info
	a.Nil(data[2]["log"]) // Warn

	// Starting with Error level, we include log history.
	// Error also emits a debug.stack() log error, so each Error/Panic also create
	// a log entry.
	// We do not include log history with stack trace events as they're redundant

	a.Nil(data[3]["log"])    // Error - we start including log history (this is stack trace)
	a.NotNil(data[4]["log"]) // Error
	a.Nil(data[5]["log"])    // Panic - this is stack trace
	a.NotNil(data[6]["log"]) // Panic
}
