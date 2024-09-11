// Copyright (C) 2019-2024 Algorand, Inc.
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

package metrics

import (
	"regexp"
	"strings"

	"github.com/algorand/go-deadlock"
)

// Metric represent any collectable metric
type Metric interface {
	// WriteMetric adds metrics in Prometheus exposition format to buf, including parentLabels tags if provided.
	WriteMetric(buf *strings.Builder, parentLabels string)
	// AddMetric adds metrics to a map, used for reporting in telemetry heartbeat messages.
	AddMetric(values map[string]float64)
}

// Registry represents a single set of metrics registry
type Registry struct {
	metrics   []Metric
	metricsMu deadlock.Mutex
}

var sanitizeTelemetryCharactersRegexp = regexp.MustCompile("(^[^a-zA-Z_]|[^a-zA-Z0-9_-])")

// sanitizeTelemetryName ensures a metric name reported to telemetry doesn't contain any
// non-alphanumeric characters (apart from - or _) and doesn't start with a number or a hyphen.
func sanitizeTelemetryName(name string) string {
	return sanitizeTelemetryCharactersRegexp.ReplaceAllString(name, "_")
}

// sanitizePrometheusName ensures a metric name reported to telemetry doesn't contain any
// non-alphanumeric characters (apart from _) and doesn't start with a number.
func sanitizePrometheusName(name string) string {
	return strings.ReplaceAll(sanitizeTelemetryName(name), "-", "_")
}
