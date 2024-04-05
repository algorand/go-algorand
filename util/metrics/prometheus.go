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

// Functions for Prometheus metrics conversion to our internal data type
// suitable for further reporting

package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	iopc "github.com/prometheus/client_model/go"
)

type defaultPrometheusGatherer struct {
	names []string
}

// WriteMetric return prometheus converted to algorand format.
// Supports only counter and gauge types and ignores go_ metrics.
func (pg *defaultPrometheusGatherer) WriteMetric(buf *strings.Builder, parentLabels string) {
	metrics := collectPrometheusMetrics(pg.names)
	for _, metric := range metrics {
		metric.WriteMetric(buf, parentLabels)
	}
}

// AddMetric return prometheus data converted to algorand format.
// Supports only counter and gauge types and ignores go_ metrics.
func (pg *defaultPrometheusGatherer) AddMetric(values map[string]float64) {
	metrics := collectPrometheusMetrics(pg.names)
	for _, metric := range metrics {
		metric.AddMetric(values)
	}
}

func collectPrometheusMetrics(names []string) []Metric {
	var result []Metric
	var namesMap map[string]struct{}
	if len(names) > 0 {
		namesMap = make(map[string]struct{}, len(names))
		for _, name := range names {
			namesMap[name] = struct{}{}
		}
	}

	convertLabels := func(m *iopc.Metric) map[string]string {
		var labels map[string]string
		if lbls := m.GetLabel(); len(lbls) > 0 {
			labels = make(map[string]string, len(lbls))
			for _, lbl := range lbls {
				labels[lbl.GetName()] = lbl.GetValue()
			}
		}
		return labels
	}
	metrics, _ := prometheus.DefaultGatherer.Gather()
	for _, metric := range metrics {
		if strings.HasPrefix(metric.GetName(), "go_") {
			continue
		}
		if _, ok := namesMap[metric.GetName()]; len(namesMap) > 0 && ok || len(namesMap) == 0 {
			if metric.GetType() == iopc.MetricType_COUNTER && metric.GetMetric() != nil {
				counter := makeCounter(MetricName{metric.GetName(), metric.GetHelp()})
				ma := metric.GetMetric()
				for _, m := range ma {
					if m.GetCounter() == nil {
						continue
					}
					val := uint64(m.GetCounter().GetValue())
					labels := convertLabels(m)
					counter.AddUint64(val, labels)
				}
				result = append(result, counter)
			} else if metric.GetType() == iopc.MetricType_GAUGE && metric.GetMetric() != nil {
				gauge := makeGauge(MetricName{metric.GetName(), metric.GetHelp()})

				ma := metric.GetMetric()
				for _, m := range ma {
					if m.GetGauge() == nil {
						continue
					}
					val := uint64(m.GetGauge().GetValue())
					labels := convertLabels(m)
					gauge.SetLabels(val, labels)
				}
				result = append(result, gauge)
			}
		}
	}
	return result
}
