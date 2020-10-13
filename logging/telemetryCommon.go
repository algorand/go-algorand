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
	"sync"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/sirupsen/logrus"

	"github.com/algorand/go-algorand/logging/telemetryspec"
)

// TelemetryOperation wraps the context for an ongoing telemetry.StartOperation call
type TelemetryOperation struct {
	startTime      time.Time
	category       telemetryspec.Category
	identifier     telemetryspec.Operation
	telemetryState *telemetryState
	pending        int32
}

type telemetryHook interface {
	Fire(entry *logrus.Entry) error
	Levels() []logrus.Level
	Close()
	Flush()
	UpdateHookURI(uri string) (err error)

	appendEntry(entry *logrus.Entry) bool
	waitForEventAndReady() bool
}

type telemetryState struct {
	history   *logBuffer
	hook      telemetryHook
	sendToLog bool
}

// TelemetryConfig represents the configuration of Telemetry logging
type TelemetryConfig struct {
	Enable             bool
	SendToLog          bool
	URI                string
	Name               string
	GUID               string
	MinLogLevel        logrus.Level
	ReportHistoryLevel logrus.Level
	FilePath           string // Path to file on disk, if any
	ChainID            string `json:"-"`
	SessionGUID        string `json:"-"`
	UserName           string
	Password           string
}

type asyncTelemetryHook struct {
	deadlock.Mutex
	wrappedHook   logrus.Hook
	wg            sync.WaitGroup
	pending       []*logrus.Entry
	entries       chan *logrus.Entry
	quit          chan struct{}
	maxQueueDepth int
	levels        []logrus.Level
	ready         bool
	urlUpdate     chan bool
}

// A dummy noop type to get rid of checks like telemetry.hook != nil
type dummyHook struct{}

type hookFactory func(cfg *TelemetryConfig) (logrus.Hook, error)
