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
	"sync/atomic"
	"time"
)

// MakeCounter create a new counter with the provided name and description.
func MakeCounter(metric MetricName) *Counter {
	c := &Counter{
		values:        make([]*counterValues, 0),
		description:   metric.Description,
		name:          metric.Name,
		labels:        make(map[string]int),
		valuesIndices: make(map[int]int),
	}
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
	if labels == nil || len(labels) == 0 {
		counter.fastAddUint64(1)
	} else {
		counter.Add(1.0, labels)
	}
}

// Add increases counter by x
// For adding an integer, see AddUint64(x)
func (counter *Counter) Add(x float64, labels map[string]string) {
	counter.Lock()
	defer counter.Unlock()

	labelIndex := counter.findLabelIndex(labels)

	// find where we have the same labels.
	if counterIdx, has := counter.valuesIndices[labelIndex]; !has {
		// we need to add a new counter.
		val := &counterValues{
			counter: x,
			labels:  labels,
		}
		val.createFormattedLabel()
		counter.values = append(counter.values, val)
		counter.valuesIndices[labelIndex] = len(counter.values) - 1
	} else {
		// update existing value.
		counter.values[counterIdx].counter += x
	}
}

// AddUint64 increases counter by x
// If labels is nil this is much faster than Add()
// Calls through to Add() if labels is not nil.
func (counter *Counter) AddUint64(x uint64, labels map[string]string) {
	if labels == nil || len(labels) == 0 {
		counter.fastAddUint64(x)
	} else {
		counter.Add(float64(x), labels)
	}
}

// AddMicrosecondsSince increases counter by microseconds between Time t and now.
// Fastest if labels is nil
func (counter *Counter) AddMicrosecondsSince(t time.Time, labels map[string]string) {
	counter.AddUint64(uint64(time.Now().Sub(t).Microseconds()), labels)
}

func (counter *Counter) fastAddUint64(x uint64) {
	if atomic.AddUint64(&counter.intValue, x) == x {
		// What we just added is the whole value, this
		// is the first Add. Create a dummy
		// counterValue for the no-labels value.
		// Dummy counterValue simplifies display in WriteMetric.
		counter.Add(0, nil)
	}
}

func (counter *Counter) findLabelIndex(labels map[string]string) int {
	accumulatedIndex := 0
	for k, v := range labels {
		t := k + ":" + v
		// do we already have this key ( label ) in our map ?
		if i, has := counter.labels[t]; has {
			// yes, we do. use this index.
			accumulatedIndex += i
		} else {
			// no, we don't have it.
			counter.labels[t] = int(math.Exp2(float64(len(counter.labels))))
			accumulatedIndex += counter.labels[t]
		}
	}
	return accumulatedIndex
}

func (cv *counterValues) createFormattedLabel() {
	var buf strings.Builder
	if len(cv.labels) < 1 {
		return
	}
	for k, v := range cv.labels {
		buf.WriteString("," + k + "=\"" + v + "\"")
	}

	cv.formattedLabels = buf.String()[1:]
}

// WriteMetric writes the metric into the output stream
func (counter *Counter) WriteMetric(buf *strings.Builder, parentLabels string) {
	counter.Lock()
	defer counter.Unlock()

	if len(counter.values) < 1 {
		return
	}
	buf.WriteString("# HELP ")
	buf.WriteString(counter.name)
	buf.WriteString(" ")
	buf.WriteString(counter.description)
	buf.WriteString("\n# TYPE ")
	buf.WriteString(counter.name)
	buf.WriteString(" counter\n")
	for _, l := range counter.values {
		buf.WriteString(counter.name)
		buf.WriteString("{")
		if len(parentLabels) > 0 {
			buf.WriteString(parentLabels)
			if len(l.formattedLabels) > 0 {
				buf.WriteString(",")
			}
		}
		buf.WriteString(l.formattedLabels)
		buf.WriteString("} ")
		value := l.counter
		if len(l.labels) == 0 {
			value += float64(atomic.LoadUint64(&counter.intValue))
		}
		buf.WriteString(strconv.FormatFloat(value, 'f', -1, 32))
		buf.WriteString("\n")
	}
}

// AddMetric adds the metric into the map
func (counter *Counter) AddMetric(values map[string]string) {
	counter.Lock()
	defer counter.Unlock()

	if len(counter.values) < 1 {
		return
	}

	for _, l := range counter.values {
		sum := l.counter
		if len(l.labels) == 0 {
			sum += float64(atomic.LoadUint64(&counter.intValue))
		}

		values[counter.name] = strconv.FormatFloat(sum, 'f', -1, 32)
	}
}
