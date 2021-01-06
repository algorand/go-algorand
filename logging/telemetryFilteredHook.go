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
	"errors"
	"strings"

	"github.com/sirupsen/logrus"
)

type telemetryFilteredHook struct {
	telemetryConfig TelemetryConfig
	wrappedHook     logrus.Hook
	reportLogLevel  logrus.Level
	history         *logBuffer
	sessionGUID     string
	factory         hookFactory
	levels          []logrus.Level
}

// newFilteredTelemetryHook creates a hook filter for ensuring telemetry events are
// always included by the wrapped log hook.
func newTelemetryFilteredHook(cfg TelemetryConfig, hook logrus.Hook, reportLogLevel logrus.Level, history *logBuffer, sessionGUID string, factory hookFactory, levels []logrus.Level) (logrus.Hook, error) {
	filteredHook := &telemetryFilteredHook{
		cfg,
		hook,
		reportLogLevel,
		history,
		sessionGUID,
		factory,
		levels,
	}
	return filteredHook, nil
}

// Fire is required to implement logrus hook interface
func (hook *telemetryFilteredHook) Fire(entry *logrus.Entry) error {
	// Just in case
	if hook.wrappedHook == nil {
		return errors.New("the wrapped hook has not been initialized")
	}

	// Don't include log history when logging debug.Stack() - just pass it through.
	if entry.Level == logrus.ErrorLevel && strings.HasPrefix(entry.Message, stackPrefix) {
		return hook.wrappedHook.Fire(entry)
	}

	if entry.Level <= hook.reportLogLevel {
		// Logging entry at a level which should include log history
		// Create a new entry augmented with the history field.
		newEntry := entry.WithFields(Fields{"log": hook.history.string(), "session": hook.sessionGUID})
		newEntry.Time = entry.Time
		newEntry.Level = entry.Level
		newEntry.Message = entry.Message

		hook.history.trim() // trim history log so we don't keep sending a lot of redundant logs

		return hook.wrappedHook.Fire(newEntry)
	}

	// If we're not including log history and session GUID, create a new
	// entry that includes the session GUID, unless it is already present
	// (which it will be for regular telemetry events)
	var newEntry *logrus.Entry
	if _, has := entry.Data["session"]; has {
		newEntry = entry
	} else {
		newEntry = entry.WithField("session", hook.sessionGUID)
	}
	return hook.wrappedHook.Fire(newEntry)
}

// Levels Required for logrus hook interface
func (hook *telemetryFilteredHook) Levels() []logrus.Level {
	if hook.wrappedHook != nil {
		return hook.wrappedHook.Levels()
	}

	return hook.levels
}
