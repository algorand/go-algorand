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
	"strings"
)

// Gauge represent a single gauge variable.
type Gauge struct {
	g couge
}

// MakeGauge create a new gauge with the provided name and description.
func MakeGauge(metric MetricName) *Gauge {
	c := makeGauge(metric)
	c.Register(nil)
	return c
}

// makeGauge create a new gauge with the provided name and description
// but does not register it with the default registry.
func makeGauge(metric MetricName) *Gauge {
	c := &Gauge{g: couge{
		values:        make([]*cougeValues, 0),
		description:   metric.Description,
		name:          metric.Name,
		labels:        make(map[string]int),
		valuesIndices: make(map[int]int),
	}}
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

// Set sets gauge to x
func (gauge *Gauge) Set(x uint64) {
	if gauge.g.intValue.Swap(x) == 0 {
		// This is the first Set. Create a dummy
		// counterValue for the no-labels value.
		// Dummy counterValue simplifies display in WriteMetric.
		gauge.g.setLabels(0, nil)
	}
}

// SetLabels sets gauge to x with labels
func (gauge *Gauge) SetLabels(x uint64, labels map[string]string) {
	gauge.g.setLabels(x, labels)
}

// WriteMetric writes the metric into the output stream
func (gauge *Gauge) WriteMetric(buf *strings.Builder, parentLabels string) {
	gauge.g.writeMetric(buf, "gauge", parentLabels)
}

// AddMetric adds the metric into the map
func (gauge *Gauge) AddMetric(values map[string]float64) {
	gauge.g.addMetric(values)
}

// GetUint64ValueForLabels returns the value of the counter for the given labels or 0 if it's not found.
func (gauge *Gauge) GetUint64ValueForLabels(labels map[string]string) uint64 {
	return gauge.g.getUint64ValueForLabels(labels)
}
