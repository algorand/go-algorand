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

// Functions for opencensus stats aggs conversion to our internal data type
// suitable for further reporting

package metrics

import (
	"context"
	"slices"
	"strings"

	"go.opencensus.io/metric/metricdata"
	"go.opencensus.io/metric/metricexport"
)

type defaultOpencensusGatherer struct {
	names []string
}

// WriteMetric return opencensus data converted to algorand format
func (og *defaultOpencensusGatherer) WriteMetric(buf *strings.Builder, parentLabels string) {
	metrics := collectOpenCensusMetrics(og.names)
	for _, metric := range metrics {
		metric.WriteMetric(buf, parentLabels)
	}
}

// AddMetric return opencensus data converted to algorand format
func (og *defaultOpencensusGatherer) AddMetric(values map[string]float64) {
	metrics := collectOpenCensusMetrics(og.names)
	for _, metric := range metrics {
		metric.AddMetric(values)
	}
}

type statExporter struct {
	names   map[string]struct{}
	metrics []Metric
}

func collectOpenCensusMetrics(names []string) []Metric {
	exporter := &statExporter{}
	if len(names) > 0 {
		exporter.names = make(map[string]struct{}, len(names))
		for _, name := range names {
			exporter.names[name] = struct{}{}
		}
	}
	reader := metricexport.NewReader()
	reader.ReadAndExport(exporter)

	return exporter.metrics
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
	counter := makeCounter(MetricName{name, st.description})
	for i := 0; i < len(st.labels); i++ {
		counter.AddUint64(uint64(st.values[i]), st.labels[i])
	}
	counter.WriteMetric(buf, parentLabels)
}

// AddMetric outputs all statCounter's labels/values into a map
func (st *statCounter) AddMetric(values map[string]float64) {
	counter := makeCounter(MetricName{st.name, st.description})
	for i := 0; i < len(st.labels); i++ {
		counter.AddUint64(uint64(st.values[i]), st.labels[i])
	}
	counter.AddMetric(values)
}

// statCounter stores single float64 sun value per stat with labels
type statDistribution struct {
	name        string
	description string
	labels      []map[string]string
	values      []float64
}

// WriteMetric outputs Prometheus metrics for all labels/values in statCounter
func (st *statDistribution) WriteMetric(buf *strings.Builder, parentLabels string) {
	name := sanitizePrometheusName(st.name)
	gauge := makeGauge(MetricName{name, st.description})
	for i := 0; i < len(st.labels); i++ {
		gauge.SetLabels(uint64(st.values[i]), st.labels[i])
	}
	gauge.WriteMetric(buf, parentLabels)
}

// AddMetric outputs all statCounter's labels/values into a map
func (st *statDistribution) AddMetric(values map[string]float64) {
	gauge := makeGauge(MetricName{st.name, st.description})
	for i := 0; i < len(st.labels); i++ {
		gauge.SetLabels(uint64(st.values[i]), st.labels[i])
	}
	gauge.AddMetric(values)
}

func (s *statExporter) ExportMetrics(ctx context.Context, data []*metricdata.Metric) error {
	labeler := func(lk []metricdata.LabelKey, lv []metricdata.LabelValue, ignores ...string) map[string]string {
		// default labeler concatenates labels
		labels := make(map[string]string, len(lk))
		for i := range lk {
			if lv[i].Present && (len(ignores) == 0 || len(ignores) > 0 && !slices.Contains(ignores, lk[i].Key)) {
				labels[lk[i].Key] = lv[i].Value
			}
		}
		return labels
	}

	for _, m := range data {
		if _, ok := s.names[m.Descriptor.Name]; len(s.names) > 0 && !ok {
			continue
		}
		if m.Descriptor.Type == metricdata.TypeCumulativeInt64 {
			counter := statCounter{
				name:        m.Descriptor.Name,
				description: m.Descriptor.Description,
			}
			for _, d := range m.TimeSeries {
				// ignore a known useless instance_id label
				labels := labeler(m.Descriptor.LabelKeys, d.LabelValues, "instance_id")
				counter.labels = append(counter.labels, labels)
				counter.values = append(counter.values, d.Points[0].Value.(int64))
			}

			s.metrics = append(s.metrics, &counter)
		} else if m.Descriptor.Type == metricdata.TypeCumulativeDistribution {
			// TODO: the metrics below cannot be integer gauge, and Sum statistic does not make any sense.
			// libp2p.io/dht/kad/outbound_request_latency
			// libp2p.io/dht/kad/inbound_request_latency
			// Ignore?
			dist := statDistribution{
				name:        m.Descriptor.Name,
				description: m.Descriptor.Description,
			}
			// check if we are processing a known DHT metric
			for _, d := range m.TimeSeries {
				label := labeler(m.Descriptor.LabelKeys, d.LabelValues, "instance_id")
				dist.labels = append(dist.labels, label)
				dist.values = append(dist.values, d.Points[0].Value.(*metricdata.Distribution).Sum)
			}
			s.metrics = append(s.metrics, &dist)
		}
	}
	return nil
}
