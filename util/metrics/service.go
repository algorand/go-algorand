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

// Package metrics provides a metric logging wrappers for Prometheus server.
package metrics

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"
)

var (
	// ErrMetricServiceAlreadyRunning Generated when we call Start and the metric service is already running
	ErrMetricServiceAlreadyRunning = errors.New("MetricService is already running")
	// ErrMetricServiceNotRunning is not currently running
	ErrMetricServiceNotRunning = errors.New("MetricService not running")
	// ErrMetricUnableToRegister unable to register
	ErrMetricUnableToRegister = errors.New("Unable to register metric")
)

var (
	// the duration of which we'll keep a metric in-memory and keep reporting it.
	// when a metric time expires, it would get removed.
	maxMetricRetensionDuration = time.Duration(5) * time.Minute
)

// MakeMetricService creates a new metrics server at the given endpoint.
func MakeMetricService(config *ServiceConfig) *MetricService {
	server := &MetricService{
		config: *config,
		done:   make(chan struct{}, 1),
	}
	if _, hasPid := server.config.Labels["pid"]; !hasPid {
		pid := os.Getpid()
		server.config.Labels["pid"] = strconv.FormatInt(int64(pid), 10)
	}
	if _, hasHost := server.config.Labels["host"]; !hasHost {
		if hostname, err := os.Hostname(); err == nil && len(hostname) > 0 {
			server.config.Labels["host"] = hostname
		}
	}
	return server
}

func (server *MetricService) startAsync(ctx context.Context) {
	defer close(server.done)
	metricsReporter := MakeMetricReporter(server.config)
	metricsReporter.ReporterLoop(ctx)
}

// Start starts the metric server
func (server *MetricService) Start(ctx context.Context) error {
	server.runningMu.Lock()
	defer server.runningMu.Unlock()
	if server.running {
		return ErrMetricServiceAlreadyRunning
	}
	var runContext context.Context
	runContext, server.cancel = context.WithCancel(ctx)
	go server.startAsync(runContext)
	server.running = true
	return nil
}

// Shutdown the running server
func (server *MetricService) Shutdown() error {
	// check if the service is running.
	server.runningMu.Lock()
	defer server.runningMu.Unlock()
	if !server.running {
		return ErrMetricServiceNotRunning
	}
	server.cancel()
	server.cancel = nil
	<-server.done
	server.running = false
	return nil
}
