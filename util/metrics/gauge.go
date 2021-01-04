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

package metrics

import (
	"math"
	"strconv"
	"strings"
	"time"
)

// MakeGauge create a new gauge with the provided name and description.
func MakeGauge(metric MetricName) *Gauge {
	c := &Gauge{
		description:   metric.Description,
		name:          metric.Name,
		labels:        make(map[string]int),
		valuesIndices: make(map[int]*gaugeValues),
	}
	c.Register(nil)
	return c
}

// TouchAll updates all the timestamps associated with this metric.
func (gauge *Gauge) TouchAll() {
	gauge.Lock()
	defer gauge.Unlock()
	for _, val := range gauge.valuesIndices {
		val.timestamp = time.Now()
	}
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
func (gauge *Gauge) Add(x float64, labels map[string]string) {
	gauge.Lock()
	defer gauge.Unlock()

	labelIndex := gauge.findLabelIndex(labels)

	// find where we have the same labels.
	if gaugeObj, has := gauge.valuesIndices[labelIndex]; !has {
		// we need to add a new gauge.
		val := &gaugeValues{
			gauge:     x,
			labels:    labels,
			timestamp: time.Now(),
		}
		val.createFormattedLabel()
		gauge.valuesIndices[labelIndex] = val
	} else {
		// update existing value.
		gaugeObj.gauge += x
		gaugeObj.timestamp = time.Now()
	}
}

// Set sets gauge to x
func (gauge *Gauge) Set(x float64, labels map[string]string) {
	gauge.Lock()
	defer gauge.Unlock()

	labelIndex := gauge.findLabelIndex(labels)

	// find where we have the same labels.
	if gaugeObj, has := gauge.valuesIndices[labelIndex]; !has {
		// we need to add a new gauge.
		val := &gaugeValues{
			gauge:     x,
			labels:    labels,
			timestamp: time.Now(),
		}
		val.createFormattedLabel()
		gauge.valuesIndices[labelIndex] = val
	} else {
		// update existing value.
		gaugeObj.gauge = x
		gaugeObj.timestamp = time.Now()
	}
}

func (gauge *Gauge) findLabelIndex(labels map[string]string) int {
	accumulatedIndex := 0
	for k, v := range labels {
		t := k + ":" + v
		// do we already have this key ( label ) in our map ?
		if i, has := gauge.labels[t]; has {
			// yes, we do. use this index.
			accumulatedIndex += i
		} else {
			// no, we don't have it.
			gauge.labels[t] = int(math.Exp2(float64(len(gauge.labels))))
			accumulatedIndex += gauge.labels[t]
		}
	}
	return accumulatedIndex
}

func (cv *gaugeValues) createFormattedLabel() {
	var buf strings.Builder
	if len(cv.labels) < 1 {
		return
	}
	for k, v := range cv.labels {
		buf.WriteString("," + k + "=\"" + v + "\"")
	}

	cv.formattedLabels = buf.String()[1:]
}

// filterExpiredMetrics scans the gauge.valuesIndices map and removing all the gauges that
// haven't been updated in the past <maxMetricRetensionDuration> units of time.
func (gauge *Gauge) filterExpiredMetrics() {
	// find out what the cut off date is
	metricRetensionThreshold := time.Now().Add(-maxMetricRetensionDuration)

	for gaugeKey, gaugeObj := range gauge.valuesIndices {
		if gaugeObj.timestamp.Before(metricRetensionThreshold) {
			delete(gauge.valuesIndices, gaugeKey)
		}
	}
}

// WriteMetric writes the metric into the output stream
func (gauge *Gauge) WriteMetric(buf *strings.Builder, parentLabels string) {
	gauge.Lock()
	defer gauge.Unlock()

	gauge.filterExpiredMetrics()

	if len(gauge.valuesIndices) < 1 {
		return
	}
	buf.WriteString("# HELP ")
	buf.WriteString(gauge.name)
	buf.WriteString(" ")
	buf.WriteString(gauge.description)
	buf.WriteString("\n# TYPE ")
	buf.WriteString(gauge.name)
	buf.WriteString(" gauge\n")
	for _, l := range gauge.valuesIndices {
		buf.WriteString(gauge.name)
		buf.WriteString("{")
		if len(parentLabels) > 0 {
			buf.WriteString(parentLabels)
			if len(l.formattedLabels) > 0 {
				buf.WriteString(",")
			}
		}
		buf.WriteString(l.formattedLabels)
		buf.WriteString("} ")
		buf.WriteString(strconv.FormatFloat(l.gauge, 'f', -1, 32))
		buf.WriteString("\n")
	}
}

// AddMetric adds the metric into the map
func (gauge *Gauge) AddMetric(values map[string]string) {
	gauge.Lock()
	defer gauge.Unlock()

	gauge.filterExpiredMetrics()

	if len(gauge.valuesIndices) < 1 {
		return
	}

	for _, l := range gauge.valuesIndices {
		values[gauge.name] = strconv.FormatFloat(l.gauge, 'f', -1, 32)
	}
}
