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
	"testing"
	"time"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestPrometheusMetrics(t *testing.T) {
	partitiontest.PartitionTest(t)

	const metricNamespace = "test_metric"

	// gauge vec with labels
	gaugeLabels := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricNamespace,
		Name:      "streams",
		Help:      "Number of Streams",
	}, []string{"dir", "scope", "protocol"})

	// gauge without labels
	gauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "protocols_count",
			Help:      "Protocols Count",
		},
	)

	// counter with labels
	counterLabels := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "identify_total",
			Help:      "Identify",
		},
		[]string{"dir"},
	)

	// counter without labels
	counter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "counter_total",
			Help:      "Counter",
		},
	)

	prometheus.DefaultRegisterer.MustRegister(gaugeLabels)
	prometheus.DefaultRegisterer.MustRegister(gauge)
	prometheus.DefaultRegisterer.MustRegister(counterLabels)
	prometheus.DefaultRegisterer.MustRegister(counter)

	defer prometheus.DefaultRegisterer.Unregister(gaugeLabels)
	defer prometheus.DefaultRegisterer.Unregister(gauge)
	defer prometheus.DefaultRegisterer.Unregister(counterLabels)
	defer prometheus.DefaultRegisterer.Unregister(counter)

	// set some values
	tags := []string{"outbound", "protocol", "/test/proto"}
	gaugeLabels.WithLabelValues(tags...).Set(float64(1))

	gauge.Set(float64(2))

	tags = []string{"inbound"}
	counterLabels.WithLabelValues(tags...).Add(float64(3))

	counter.Add(float64(4))

	// wait they collected and ready for gathering
	require.Eventually(t, func() bool {
		metrics := collectPrometheusMetrics(nil)
		return len(metrics) >= 4
	}, 5*time.Second, 100*time.Millisecond)

	metrics := collectPrometheusMetrics([]string{
		metricNamespace + "_streams",
		metricNamespace + "_protocols_count",
		metricNamespace + "_identify_total",
		metricNamespace + "_counter_total"})
	require.Len(t, metrics, 4)

	for _, m := range metrics {
		buf := strings.Builder{}
		m.WriteMetric(&buf, "")
		promValue := buf.String()
		if strings.Contains(promValue, metricNamespace+"_streams") {
			require.Contains(t, promValue, metricNamespace+"_streams gauge\n")
			require.Contains(t, promValue, metricNamespace+"_streams{")
			// map/labels order is not guaranteed
			require.Contains(t, promValue, "dir=\"outbound\"")
			require.Contains(t, promValue, "protocol=\"/test/proto\"")
			require.Contains(t, promValue, "scope=\"protocol\"")
			require.Contains(t, promValue, "} 1\n")
		} else if strings.Contains(promValue, metricNamespace+"_protocols_count") {
			require.Contains(t, promValue, metricNamespace+"_protocols_count gauge\n")
			require.Contains(t, promValue, metricNamespace+"_protocols_count 2\n")
		} else if strings.Contains(promValue, metricNamespace+"_identify_total") {
			require.Contains(t, promValue, metricNamespace+"_identify_total counter\n")
			require.Contains(t, promValue, metricNamespace+"_identify_total{dir=\"inbound\"} 3\n")
		} else if strings.Contains(promValue, metricNamespace+"_counter_total") {
			require.Contains(t, promValue, metricNamespace+"_counter_total counter\n")
			require.Contains(t, promValue, metricNamespace+"_counter_total 4\n")
		} else {
			require.Fail(t, "not expected metric", promValue)
		}

		values := make(map[string]float64)
		m.AddMetric(values)
		require.Len(t, values, 1)
	}

	// ensure the exported gatherer works
	reg := MakeRegistry()
	reg.Register(&PrometheusDefaultMetrics)
	defer reg.Deregister(&PrometheusDefaultMetrics)

	var buf strings.Builder
	reg.WriteMetrics(&buf, "")

	require.Contains(t, buf.String(), metricNamespace+"_streams")
	require.Contains(t, buf.String(), metricNamespace+"_protocols_count")
	require.Contains(t, buf.String(), metricNamespace+"_identify_total")
	require.Contains(t, buf.String(), metricNamespace+"_counter_total")
}
