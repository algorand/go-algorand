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
	"strings"

	"github.com/algorand/go-deadlock"
)

var defaultRegistry *Registry

// MakeRegistry create a new metric registry
func MakeRegistry() *Registry {
	c := &Registry{
		metricsMu: deadlock.Mutex{},
	}
	return c
}

// DefaultRegistry retrieves the default registry
func DefaultRegistry() *Registry {
	return defaultRegistry
}

func init() {
	defaultRegistry = MakeRegistry()
}

// Register add the given metric to the registry
func (r *Registry) Register(metric Metric) {
	r.metricsMu.Lock()
	defer r.metricsMu.Unlock()
	r.metrics = append(r.metrics, metric)
}

// Deregister removes the given metric to the registry
func (r *Registry) Deregister(metric Metric) {
	for i, m := range r.metrics {
		if m == metric {
			r.metrics = append(r.metrics[:i], r.metrics[i+1:]...)
			return
		}
	}
}

// WriteMetrics will write all the metrics that were registered to this registry
func (r *Registry) WriteMetrics(buf *strings.Builder, parentLabels string) {
	r.metricsMu.Lock()
	defer r.metricsMu.Unlock()
	for _, m := range r.metrics {
		m.WriteMetric(buf, parentLabels)
	}
}

// AddMetrics will add all the metrics that were registered to this registry
func (r *Registry) AddMetrics(values map[string]string) {
	r.metricsMu.Lock()
	defer r.metricsMu.Unlock()
	for _, m := range r.metrics {
		m.AddMetric(values)
	}
}
