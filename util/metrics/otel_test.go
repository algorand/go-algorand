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

package metrics

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestOTelPrometheusExporter verifies that OTEL instruments are visible through
// prometheus.DefaultGatherer after SetupOTelPrometheusExporter is called.
// Instruments under the kad-dht scope get a namespace prefix and have
// instance_id filtered out; other scopes are exported without modification.
func TestOTelPrometheusExporter(t *testing.T) {
	partitiontest.PartitionTest(t)

	err := SetupOTelPrometheusExporter()
	require.NoError(t, err)

	// Use the kad-dht scope so the view adds the namespace prefix.
	dhtMeter := otel.Meter("github.com/libp2p/go-libp2p-kad-dht")
	counter, err := dhtMeter.Int64Counter(
		"test_otel_sent_messages",
		metric.WithDescription("Test counter for OTEL-to-Prometheus bridge"),
	)
	require.NoError(t, err)

	ctx := context.Background()
	counter.Add(ctx, 5, metric.WithAttributes(
		attribute.String("message_type", "FIND_NODE"),
		attribute.String("peer_id", "test-peer"),
		attribute.String("instance_id", "0xdeadbeef"),
	))
	counter.Add(ctx, 3, metric.WithAttributes(
		attribute.String("message_type", "PUT_VALUE"),
		attribute.String("peer_id", "test-peer-2"),
		attribute.String("instance_id", "0xdeadbeef"),
	))

	hist, err := dhtMeter.Float64Histogram(
		"test_otel_request_latency",
		metric.WithDescription("Test histogram for OTEL-to-Prometheus bridge"),
	)
	require.NoError(t, err)
	hist.Record(ctx, 5, metric.WithAttributes(
		attribute.String("message_type", "FIND_NODE"),
		attribute.String("peer_id", "test-peer"),
	))
	hist.Record(ctx, 3, metric.WithAttributes(
		attribute.String("message_type", "PUT_VALUE"),
		attribute.String("peer_id", "test-peer-2"),
	))

	// Counter: the kad-dht scope view prepends libp2p_io_dht_kad_ and the
	// Prometheus exporter appends _total.
	const promName = "libp2p_io_dht_kad_test_otel_sent_messages_total"

	metrics := collectPrometheusMetrics([]string{promName})
	require.Len(t, metrics, 1)

	var buf strings.Builder
	metrics[0].WriteMetric(&buf, "")
	promValue := buf.String()

	require.Contains(t, promValue, promName)
	require.Contains(t, promValue, `message_type="FIND_NODE"`)
	require.Contains(t, promValue, `message_type="PUT_VALUE"`)
	require.Contains(t, promValue, `peer_id="test-peer"`)
	require.Contains(t, promValue, `peer_id="test-peer-2"`)
	require.Contains(t, promValue, "} 5\n")
	require.Contains(t, promValue, "} 3\n")

	// instance_id should be filtered out (high-cardinality pointer address).
	require.NotContains(t, promValue, "instance_id")

	// Verify it also works through the registry (the way algod actually exports metrics).
	reg := MakeRegistry()
	reg.Register(&PrometheusDefaultMetrics)
	defer reg.Deregister(&PrometheusDefaultMetrics)

	var regBuf strings.Builder
	reg.WriteMetrics(&regBuf, "")
	require.Contains(t, regBuf.String(), promName)

	// Histogram families should be converted into bucket/count/sum metrics.
	histMetrics := collectPrometheusMetrics([]string{"libp2p_io_dht_kad_test_otel_request_latency"})
	require.Len(t, histMetrics, 3)
	var histBuf strings.Builder
	for _, m := range histMetrics {
		m.WriteMetric(&histBuf, "")
	}
	histValue := histBuf.String()
	require.Contains(t, histValue, "libp2p_io_dht_kad_test_otel_request_latency_bucket")
	require.Contains(t, histValue, "libp2p_io_dht_kad_test_otel_request_latency_count")
	require.Contains(t, histValue, "libp2p_io_dht_kad_test_otel_request_latency_sum")
	require.Contains(t, histValue, `message_type="FIND_NODE"`)
	require.Contains(t, histValue, `message_type="PUT_VALUE"`)
	require.Contains(t, histValue, `le="+Inf"`)

	// Instruments on a non-kad-dht scope should NOT get the prefix.
	otherMeter := otel.Meter("github.com/algorand/go-algorand/test")
	otherCounter, err := otherMeter.Int64Counter(
		"test_other_scope_counter",
		metric.WithDescription("counter on a non-kad-dht scope"),
	)
	require.NoError(t, err)
	otherCounter.Add(ctx, 1)

	// Should appear under its original name, not prefixed.
	otherMetrics := collectPrometheusMetrics([]string{"test_other_scope_counter_total"})
	require.Len(t, otherMetrics, 1)
	prefixedOther := collectPrometheusMetrics([]string{"libp2p_io_dht_kad_test_other_scope_counter_total"})
	require.Len(t, prefixedOther, 0)
}
