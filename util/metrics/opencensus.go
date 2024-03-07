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

// Functions for opencensus stats aggs stats to our internal data type
// suitable for further reporting

package metrics

import (
	"context"
	"strconv"
	"strings"

	"go.opencensus.io/metric/metricdata"
	"go.opencensus.io/metric/metricexport"
)

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

// WriteOpenCensusMetrics return opencensus data converted to algorand format
func WriteOpenCensusMetrics(buf *strings.Builder, parentLabels string, names ...string) {
	metrics := collectOpenCensusMetrics(names)
	for _, metric := range metrics {
		metric.WriteMetric(buf, parentLabels)
	}
}

// AddOpenCensusMetrics return opencensus data converted to algorand format
func AddOpenCensusMetrics(values map[string]float64, names ...string) {
	metrics := collectOpenCensusMetrics(names)
	for _, metric := range metrics {
		metric.AddMetric(values)
	}
}

// statCounter stores single int64 value per stat with labels
type statCounter struct {
	name        string
	description string
	labels      []string
	values      []int64
}

// WriteMetric outputs Prometheus metrics for all labels/values in statCounter
func (st *statCounter) WriteMetric(buf *strings.Builder, parentLabels string) {
	for i := 0; i < len(st.labels); i++ {
		name := sanitizePrometheusName(st.name + "_" + st.labels[i])
		buf.WriteString("# HELP ")
		buf.WriteString(name)
		buf.WriteString(" ")
		buf.WriteString(st.description)
		buf.WriteString("\n# TYPE ")
		buf.WriteString(name)
		buf.WriteString(" counter\n")
		buf.WriteString(name)
		if len(parentLabels) > 0 {
			buf.WriteString("{" + parentLabels + "}")
		}
		value := st.values[i]
		buf.WriteString(" " + strconv.FormatUint(uint64(value), 10))
		buf.WriteString("\n")
	}
}

// AddMetric outputs all statCounter's labels/values into a map
func (st *statCounter) AddMetric(values map[string]float64) {
	for i := 0; i < len(st.labels); i++ {
		name := sanitizePrometheusName(st.name + "_" + st.labels[i])
		values[name] = float64(st.values[i])
	}
}

// statCounter stores single float64 sun value per stat with labels
type statDistribution struct {
	name        string
	description string
	labels      []string
	values      []float64
}

// WriteMetric outputs Prometheus metrics for all labels/values in statCounter
func (st *statDistribution) WriteMetric(buf *strings.Builder, parentLabels string) {
	for i := 0; i < len(st.labels); i++ {
		name := sanitizePrometheusName(st.name + "_" + st.labels[i])
		buf.WriteString("# HELP ")
		buf.WriteString(name)
		buf.WriteString(" ")
		buf.WriteString(st.description)
		buf.WriteString("\n# TYPE ")
		buf.WriteString(name)
		buf.WriteString(" gauge\n")
		buf.WriteString(name)
		if len(parentLabels) > 0 {
			buf.WriteString("{" + parentLabels + "}")
		}
		value := st.values[i]
		buf.WriteString(" " + strconv.FormatFloat(value, 'f', 6, 64))
		buf.WriteString("\n")
	}
}

// AddMetric outputs all statCounter's labels/values into a map
func (st *statDistribution) AddMetric(values map[string]float64) {
	for i := 0; i < len(st.labels); i++ {
		name := sanitizePrometheusName(st.name + "_" + st.labels[i])
		values[name] = float64(st.values[i])
	}
}

func (s *statExporter) ExportMetrics(ctx context.Context, data []*metricdata.Metric) error {
	defaultLabeler := func(lv []metricdata.LabelValue) string {
		// default labeler concatenates labels
		var entries []string
		for i := range lv {
			if lv[i].Present {
				entries = append(entries, lv[i].Value)
			}
		}
		return strings.Join(entries, "_")
	}
	dhtLabeler := func(lv []metricdata.LabelValue) string {
		// dht labeler ignores instance_id and concatenates peer_id + message_type
		var entries []string
		for i := len(lv) - 1; i > 0; i-- {
			if lv[i].Present {
				entries = append(entries, lv[i].Value)
			}
		}
		return strings.Join(entries, "_")
	}

	for _, m := range data {
		if _, ok := s.names[m.Descriptor.Name]; len(s.names) > 0 && !ok {
			continue
		}
		labeler := defaultLabeler
		// guess DHT-specific stats format
		if len(m.Descriptor.LabelKeys) == 3 && m.Descriptor.LabelKeys[0].Key == "instance_id" &&
			m.Descriptor.LabelKeys[1].Key == "message_type" && m.Descriptor.LabelKeys[2].Key == "peer_id" {
			labeler = dhtLabeler
		}
		if m.Descriptor.Type == metricdata.TypeCumulativeInt64 {
			counter := statCounter{
				name:        m.Descriptor.Name,
				description: m.Descriptor.Description,
			}
			// check if we are processing a known DHT metric
			for _, d := range m.TimeSeries {
				label := labeler(d.LabelValues)
				counter.labels = append(counter.labels, label)
				counter.values = append(counter.values, d.Points[0].Value.(int64))
			}

			s.metrics = append(s.metrics, &counter)
		} else if m.Descriptor.Type == metricdata.TypeCumulativeDistribution {
			dist := statDistribution{
				name:        m.Descriptor.Name,
				description: m.Descriptor.Description,
			}
			// check if we are processing a known DHT metric
			for _, d := range m.TimeSeries {
				label := labeler(d.LabelValues)
				dist.labels = append(dist.labels, label)
				dist.values = append(dist.values, d.Points[0].Value.(*metricdata.Distribution).Sum)
			}
			s.metrics = append(s.metrics, &dist)
		}
	}
	return nil
}
