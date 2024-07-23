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

// Common code for COUnters and gaUGEs.

package metrics

import (
	"math"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/algorand/go-deadlock"
)

type couge struct {
	// Collects value for special fast-path with no labels through Inc(nil) AddUint64(x, nil)
	intValue atomic.Uint64

	deadlock.Mutex
	name          string
	description   string
	values        []*cougeValues
	labels        map[string]int // map each label ( i.e. httpErrorCode ) to an index.
	valuesIndices map[int]int
}

type cougeValues struct {
	value           uint64
	labels          map[string]string
	formattedLabels string
}

func (cv *cougeValues) createFormattedLabel() {
	var buf strings.Builder
	if len(cv.labels) < 1 {
		return
	}
	for k, v := range cv.labels {
		buf.WriteString("," + k + "=\"" + v + "\"")
	}

	cv.formattedLabels = buf.String()[1:]
}

func (cg *couge) findLabelIndex(labels map[string]string) int {
	accumulatedIndex := 0
	for k, v := range labels {
		t := k + ":" + v
		// do we already have this key ( label ) in our map ?
		if i, has := cg.labels[t]; has {
			// yes, we do. use this index.
			accumulatedIndex += i
		} else {
			// no, we don't have it.
			cg.labels[t] = int(math.Exp2(float64(len(cg.labels))))
			accumulatedIndex += cg.labels[t]
		}
	}
	return accumulatedIndex
}

func (cg *couge) fastAddUint64(x uint64) {
	if cg.intValue.Add(x) == x {
		// What we just added is the whole value, this
		// is the first Add. Create a dummy
		// counterValue for the no-labels value.
		// Dummy counterValue simplifies display in WriteMetric.
		cg.addLabels(0, nil)
	}
}

// addLabels increases counter by x
func (cg *couge) addLabels(x uint64, labels map[string]string) {
	cg.Lock()
	defer cg.Unlock()

	labelIndex := cg.findLabelIndex(labels)

	// find where we have the same labels.
	if counterIdx, has := cg.valuesIndices[labelIndex]; !has {
		// we need to add a new counter.
		val := &cougeValues{
			value:  x,
			labels: labels,
		}
		val.createFormattedLabel()
		cg.values = append(cg.values, val)
		cg.valuesIndices[labelIndex] = len(cg.values) - 1
	} else {
		// update existing value.
		cg.values[counterIdx].value += x
	}
}

// setLabels sets value to x
func (cg *couge) setLabels(x uint64, labels map[string]string) {
	cg.Lock()
	defer cg.Unlock()

	labelIndex := cg.findLabelIndex(labels)

	// find where we have the same labels.
	if counterIdx, has := cg.valuesIndices[labelIndex]; !has {
		// we need to set a new value.
		val := &cougeValues{
			value:  x,
			labels: labels,
		}
		val.createFormattedLabel()
		cg.values = append(cg.values, val)
		cg.valuesIndices[labelIndex] = len(cg.values) - 1
	} else {
		// update existing value.
		cg.values[counterIdx].value = x
	}
}

// getUint64ValueForLabels returns the value of the counter for the given labels or 0 if it's not found.
func (cg *couge) getUint64ValueForLabels(labels map[string]string) uint64 {
	cg.Lock()
	defer cg.Unlock()

	labelIndex := cg.findLabelIndex(labels)
	counterIdx, has := cg.valuesIndices[labelIndex]
	if !has {
		return 0
	}
	return cg.values[counterIdx].value
}

// writeMetric writes the metric into the output stream
func (cg *couge) writeMetric(buf *strings.Builder, metricType string, parentLabels string) {
	cg.Lock()
	defer cg.Unlock()

	buf.WriteString("# HELP ")
	buf.WriteString(cg.name)
	buf.WriteString(" ")
	buf.WriteString(cg.description)
	buf.WriteString("\n# TYPE ")
	buf.WriteString(cg.name)
	buf.WriteString(" " + metricType + "\n")
	// if counter is zero, report 0 using parentLabels and no tags
	if len(cg.values) == 0 {
		buf.WriteString(cg.name)
		if len(parentLabels) > 0 {
			buf.WriteString("{" + parentLabels + "}")
		}
		buf.WriteString(" " + strconv.FormatUint(cg.intValue.Load(), 10))
		buf.WriteString("\n")
		return
	}
	// otherwise iterate through values and write one line per label
	for _, l := range cg.values {
		buf.WriteString(cg.name)
		if len(parentLabels) > 0 || len(l.formattedLabels) > 0 {
			buf.WriteString("{")
			if len(parentLabels) > 0 {
				buf.WriteString(parentLabels)
				if len(l.formattedLabels) > 0 {
					buf.WriteString(",")
				}
			}
			buf.WriteString(l.formattedLabels)
			buf.WriteString("}")
		}
		value := l.value
		if len(l.labels) == 0 {
			value += cg.intValue.Load()
		}
		buf.WriteString(" " + strconv.FormatUint(value, 10))
		buf.WriteString("\n")
	}
}

// addMetric adds the metric into the map
func (cg *couge) addMetric(values map[string]float64) {
	cg.Lock()
	defer cg.Unlock()

	if len(cg.values) < 1 {
		return
	}

	for _, l := range cg.values {
		sum := l.value
		if len(l.labels) == 0 {
			sum += cg.intValue.Load()
		}
		var suffix string
		if len(l.formattedLabels) > 0 {
			suffix = ":" + l.formattedLabels
		}
		values[sanitizeTelemetryName(cg.name+suffix)] = float64(sum)
	}
}
