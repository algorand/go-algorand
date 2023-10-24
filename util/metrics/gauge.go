// Copyright (C) 2019-2023 Algorand, Inc.
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
	"strconv"
	"strings"
	"sync/atomic"
)

// Gauge represent a single gauge variable.
type Gauge struct {
	value       atomic.Uint64
	name        string
	description string
}

// MakeGauge create a new gauge with the provided name and description.
func MakeGauge(metric MetricName) *Gauge {
	c := &Gauge{
		description: metric.Description,
		name:        metric.Name,
	}
	c.Register(nil)
	return c
}

// Register registers the gauge with the default/specific registry
func (gauge *Gauge) Register(reg *Registry) {
	if reg == nil {
		DefaultRegistry().Register(gauge)
	} else {
		reg.Register(gauge)
	}
}

// Deregister deregisters the gauge with the default/specific registry
func (gauge *Gauge) Deregister(reg *Registry) {
	if reg == nil {
		DefaultRegistry().Deregister(gauge)
	} else {
		reg.Deregister(gauge)
	}
}

// Add increases gauge by x
func (gauge *Gauge) Add(x uint64) {
	gauge.value.Add(x)
}

// Set sets gauge to x
func (gauge *Gauge) Set(x uint64) {
	gauge.value.Store(x)
}

// WriteMetric writes the metric into the output stream
func (gauge *Gauge) WriteMetric(buf *strings.Builder, parentLabels string) {
	buf.WriteString("# HELP ")
	buf.WriteString(gauge.name)
	buf.WriteString(" ")
	buf.WriteString(gauge.description)
	buf.WriteString("\n# TYPE ")
	buf.WriteString(gauge.name)
	buf.WriteString(" gauge\n")
	buf.WriteString(gauge.name)
	buf.WriteString("{")
	if len(parentLabels) > 0 {
		buf.WriteString(parentLabels)
	}
	buf.WriteString("} ")
	value := gauge.value.Load()
	buf.WriteString(strconv.FormatUint(value, 10))
	buf.WriteString("\n")
}

// AddMetric adds the metric into the map
func (gauge *Gauge) AddMetric(values map[string]float64) {
	value := gauge.value.Load()

	values[sanitizeTelemetryName(gauge.name)] = float64(value)
}
