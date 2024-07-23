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
	"runtime/metrics"
	"strconv"
	"strings"

	"github.com/algorand/go-deadlock"
)

// defaultRuntimeMetrics contains all the Go runtime metrics, except histograms.
var defaultRuntimeMetrics = []string{
	"/gc/cycles/automatic:gc-cycles",
	"/gc/cycles/forced:gc-cycles",
	"/gc/cycles/total:gc-cycles",
	"/gc/heap/allocs:bytes",
	"/gc/heap/allocs:objects",
	"/gc/heap/frees:bytes",
	"/gc/heap/frees:objects",
	"/gc/heap/goal:bytes",
	"/gc/heap/objects:objects",
	"/gc/heap/tiny/allocs:objects",
	"/memory/classes/heap/free:bytes",
	"/memory/classes/heap/objects:bytes",
	"/memory/classes/heap/released:bytes",
	"/memory/classes/heap/stacks:bytes",
	"/memory/classes/heap/unused:bytes",
	"/memory/classes/metadata/mcache/free:bytes",
	"/memory/classes/metadata/mcache/inuse:bytes",
	"/memory/classes/metadata/mspan/free:bytes",
	"/memory/classes/metadata/mspan/inuse:bytes",
	"/memory/classes/metadata/other:bytes",
	"/memory/classes/os-stacks:bytes",
	"/memory/classes/other:bytes",
	"/memory/classes/profiling/buckets:bytes",
	"/memory/classes/total:bytes",
	"/sched/goroutines:goroutines",
}

// RuntimeMetrics gathers selected metrics from Go's builtin runtime.metrics package
// and makes them available as Prometheus metrics.
type RuntimeMetrics struct {
	descriptions []metrics.Description
	samples      []metrics.Sample
	deadlock.Mutex
}

// NewRuntimeMetrics creates a RuntimeMetrics object, provided a list of metric names matching
// names in Go's metrics.All(). Otherwise, a default list of runtime metrics will be used.
func NewRuntimeMetrics(enabledMetrics ...string) *RuntimeMetrics {
	enabled := make(map[string]bool)
	if len(enabledMetrics) == 0 {
		enabledMetrics = defaultRuntimeMetrics
	}
	for _, name := range enabledMetrics {
		enabled[name] = true
	}

	// create []metrics.Sample and get metric descriptions
	rm := &RuntimeMetrics{}
	descs := metrics.All()
	for _, desc := range descs {
		if enabled[desc.Name] {
			rm.descriptions = append(rm.descriptions, desc)
			rm.samples = append(rm.samples, metrics.Sample{Name: desc.Name})
		}
	}

	return rm
}

// WriteMetric writes runtime metrics to the output stream in prometheus exposition format.
func (rm *RuntimeMetrics) WriteMetric(buf *strings.Builder, parentLabels string) {
	rm.Lock()
	defer rm.Unlock()

	metrics.Read(rm.samples)
	for i, s := range rm.samples {
		name := "algod_go" + sanitizePrometheusName(s.Name)
		desc := rm.descriptions[i]

		buf.WriteString("# HELP " + name + " " + desc.Description + "\n")
		if desc.Cumulative {
			buf.WriteString("# TYPE " + name + " counter\n")
		} else {
			buf.WriteString("# TYPE " + name + " gauge\n")
		}
		buf.WriteString(name)
		if len(parentLabels) > 0 {
			buf.WriteString("{" + parentLabels + "}")
		}
		buf.WriteRune(' ')
		switch s.Value.Kind() {
		case metrics.KindUint64:
			buf.WriteString(strconv.FormatUint(s.Value.Uint64(), 10))
		case metrics.KindFloat64:
			buf.WriteString(strconv.FormatFloat(s.Value.Float64(), 'f', -1, 64))
		default:
		}
		buf.WriteRune('\n')
	}
}

// AddMetric adds runtime metrics to the map used for heartbeat metrics.
func (rm *RuntimeMetrics) AddMetric(m map[string]float64) {
	rm.Lock()
	defer rm.Unlock()

	metrics.Read(rm.samples)
	for _, s := range rm.samples {
		name := "go" + sanitizeTelemetryName(s.Name)

		switch s.Value.Kind() {
		case metrics.KindUint64:
			m[name] = float64(s.Value.Uint64())
		case metrics.KindFloat64:
			m[name] = s.Value.Float64()
		default:
		}
	}
}
