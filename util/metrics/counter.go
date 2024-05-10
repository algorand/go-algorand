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
	"time"
)

// Counter represent a single counter variable.
type Counter struct {
	c couge
}

// MakeCounter create a new counter with the provided name and description.
func MakeCounter(metric MetricName) *Counter {
	c := &Counter{c: couge{
		values:        make([]*cougeValues, 0),
		description:   metric.Description,
		name:          metric.Name,
		labels:        make(map[string]int),
		valuesIndices: make(map[int]int),
	}}
	c.Register(nil)
	return c
}

// NewCounter is a shortcut to MakeCounter in one shorter line.
func NewCounter(name, desc string) *Counter {
	return MakeCounter(MetricName{Name: name, Description: desc})
}

// Register registers the counter with the default/specific registry
func (counter *Counter) Register(reg *Registry) {
	if reg == nil {
		DefaultRegistry().Register(counter)
	} else {
		reg.Register(counter)
	}
}

// Deregister deregisters the counter with the default/specific registry
func (counter *Counter) Deregister(reg *Registry) {
	if reg == nil {
		DefaultRegistry().Deregister(counter)
	} else {
		reg.Deregister(counter)
	}
}

// Inc increases counter by 1
// Much faster if labels is nil or empty.
func (counter *Counter) Inc(labels map[string]string) {
	if len(labels) == 0 {
		counter.c.fastAddUint64(1)
	} else {
		counter.c.addLabels(1.0, labels)
	}
}

// AddUint64 increases counter by x
// If labels is nil this is much faster than if labels is not nil.
func (counter *Counter) AddUint64(x uint64, labels map[string]string) {
	if len(labels) == 0 {
		counter.c.fastAddUint64(x)
	} else {
		counter.c.addLabels(x, labels)
	}
}

// AddMicrosecondsSince increases counter by microseconds between Time t and now.
// Fastest if labels is nil
func (counter *Counter) AddMicrosecondsSince(t time.Time, labels map[string]string) {
	counter.AddUint64(uint64(time.Since(t).Microseconds()), labels)
}

// GetUint64Value returns the value of the counter.
func (counter *Counter) GetUint64Value() (x uint64) {
	return counter.c.intValue.Load()
}

// GetUint64ValueForLabels returns the value of the counter for the given labels or 0 if it's not found.
func (counter *Counter) GetUint64ValueForLabels(labels map[string]string) uint64 {
	return counter.c.getUint64ValueForLabels(labels)
}

// WriteMetric writes the metric into the output stream
func (counter *Counter) WriteMetric(buf *strings.Builder, parentLabels string) {
	counter.c.writeMetric(buf, "counter", parentLabels)
}

// AddMetric adds the metric into the map
func (counter *Counter) AddMetric(values map[string]float64) {
	counter.c.addMetric(values)
}
