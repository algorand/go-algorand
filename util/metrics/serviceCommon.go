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

	"github.com/algorand/go-deadlock"
)

// ServiceConfig would contain all the information we need in order to create a listening server endpoint.
// We might want to support rolling port numbers so that we could easily support multiple endpoints per machine.
// ( note that multiple endpoints per machine doesn't solve the question "how would the prometheus server figure that out")
type ServiceConfig struct {
	NodeExporterListenAddress string
	Labels                    map[string]string
	NodeExporterPath          string
}

// MetricService represent a single running metric server instance
type MetricService struct {
	config    ServiceConfig
	runningMu deadlock.Mutex
	running   bool
	cancel    context.CancelFunc
	done      chan struct{}
}
