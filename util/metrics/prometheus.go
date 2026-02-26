// Copyright (C) 2019-2026 Algorand, Inc.
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
	"maps"
	"math"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	iopc "github.com/prometheus/client_model/go"
)

type defaultPrometheusGatherer struct {
	names []string
}

// WriteMetric return prometheus converted to algorand format.
// Supports counter, gauge, and histogram types and ignores go_ metrics.
func (pg *defaultPrometheusGatherer) WriteMetric(buf *strings.Builder, parentLabels string) {
	metrics := collectPrometheusMetrics(pg.names)
	for _, metric := range metrics {
		metric.WriteMetric(buf, parentLabels)
	}
}

// AddMetric return prometheus data converted to algorand format.
// Supports counter, gauge, and histogram types and ignores go_ metrics.
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
				counter := MakeCounterUnregistered(MetricName{metric.GetName(), metric.GetHelp()})
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
				gauge := MakeGaugeUnregistered(MetricName{metric.GetName(), metric.GetHelp()})

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
			} else if metric.GetType() == iopc.MetricType_HISTOGRAM && metric.GetMetric() != nil {
				result = append(result, convertPrometheusHistogram(metric, convertLabels)...)
			}
		}
	}
	return result
}

// statCounter stores single int64 value per stat with labels
type statCounter struct {
	name        string
	description string
	labels      []map[string]string
	values      []int64
}

// WriteMetric outputs Prometheus metrics for all labels/values in statCounter
func (st *statCounter) WriteMetric(buf *strings.Builder, parentLabels string) {
	name := sanitizePrometheusName(st.name)
	counter := MakeCounterUnregistered(MetricName{name, st.description})
	for i := 0; i < len(st.labels); i++ {
		counter.AddUint64(uint64(st.values[i]), st.labels[i])
	}
	counter.WriteMetric(buf, parentLabels)
}

// AddMetric outputs all statCounter's labels/values into a map
func (st *statCounter) AddMetric(values map[string]float64) {
	counter := MakeCounterUnregistered(MetricName{st.name, st.description})
	for i := 0; i < len(st.labels); i++ {
		counter.AddUint64(uint64(st.values[i]), st.labels[i])
	}
	counter.AddMetric(values)
}

// statDistribution stores single float64 sun value per stat with labels
type statDistribution struct {
	name        string
	description string
	labels      []map[string]string
	values      []float64
}

// WriteMetric outputs Prometheus metrics for all labels/values in statCounter
func (st *statDistribution) WriteMetric(buf *strings.Builder, parentLabels string) {
	name := sanitizePrometheusName(st.name)
	gauge := MakeGaugeUnregistered(MetricName{name, st.description})
	for i := 0; i < len(st.labels); i++ {
		gauge.SetLabels(uint64(st.values[i]), st.labels[i])
	}
	gauge.WriteMetric(buf, parentLabels)
}

// AddMetric outputs all statCounter's labels/values into a map
func (st *statDistribution) AddMetric(values map[string]float64) {
	gauge := MakeGaugeUnregistered(MetricName{st.name, st.description})
	for i := 0; i < len(st.labels); i++ {
		gauge.SetLabels(uint64(st.values[i]), st.labels[i])
	}
	gauge.AddMetric(values)
}

func convertPrometheusHistogram(metric *iopc.MetricFamily, convertLabels func(m *iopc.Metric) map[string]string) []Metric {
	// counters for bucket/count, and a gauge-like float holder for sum.
	buckets := statCounter{
		name:        metric.GetName() + "_bucket",
		description: metric.GetHelp(),
	}
	count := statCounter{
		name:        metric.GetName() + "_count",
		description: metric.GetHelp(),
	}
	sum := statDistribution{
		name:        metric.GetName() + "_sum",
		description: metric.GetHelp(),
	}

	var hasBuckets, hasCount, hasSum bool
	for _, m := range metric.GetMetric() {
		h := m.GetHistogram()
		if h == nil {
			continue
		}

		baseLabels := clonePrometheusMetricLabels(convertLabels(m))

		count.labels = append(count.labels, baseLabels)
		count.values = append(count.values, int64(h.GetSampleCount()))
		hasCount = true

		sum.labels = append(sum.labels, clonePrometheusMetricLabels(baseLabels))
		sum.values = append(sum.values, h.GetSampleSum())
		hasSum = true

		hasInfBucket := false
		for _, b := range h.GetBucket() {
			lbls := clonePrometheusMetricLabels(baseLabels)
			if lbls == nil {
				lbls = make(map[string]string, 1)
			}
			upperBound := b.GetUpperBound()
			if math.IsInf(upperBound, 1) {
				hasInfBucket = true
			}
			lbls["le"] = strconv.FormatFloat(upperBound, 'g', -1, 64)
			buckets.labels = append(buckets.labels, lbls)
			buckets.values = append(buckets.values, int64(b.GetCumulativeCount()))
			hasBuckets = true
		}

		// Prometheus exposition always has a +Inf bucket. Gathered DTO histograms
		// typically omit it because it is derivable from SampleCount.
		if !hasInfBucket {
			lbls := clonePrometheusMetricLabels(baseLabels)
			if lbls == nil {
				lbls = make(map[string]string, 1)
			}
			lbls["le"] = "+Inf"
			buckets.labels = append(buckets.labels, lbls)
			buckets.values = append(buckets.values, int64(h.GetSampleCount()))
			hasBuckets = true
		}
	}

	out := make([]Metric, 0, 3)
	if hasBuckets {
		out = append(out, &buckets)
	}
	if hasCount {
		out = append(out, &count)
	}
	if hasSum {
		out = append(out, &sum)
	}
	return out
}

func clonePrometheusMetricLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(labels))
	maps.Copy(cloned, labels)
	return cloned
}
