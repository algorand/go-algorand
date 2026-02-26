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
	"fmt"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

var (
	otelSetupOnce sync.Once
	otelSetupErr  error
)

// SetupOTelPrometheusExporter initializes an OpenTelemetry MeterProvider backed
// by the Prometheus default registerer. After this call, any OTEL instruments
// (e.g. those in go-libp2p-kad-dht) will be visible through
// prometheus.DefaultGatherer and therefore collected by PrometheusDefaultMetrics.
// Safe to call multiple times; only the first call takes effect.
// If the first call fails, subsequent calls return the same error.
func SetupOTelPrometheusExporter() error {
	otelSetupOnce.Do(func() {
		exporter, err := otelprom.New(
			otelprom.WithNamespace("libp2p_io_dht_kad"),
		)
		if err != nil {
			otelSetupErr = fmt.Errorf("creating OTEL Prometheus exporter: %w", err)
			return
		}
		// Drop the instance_id attribute that kad-dht attaches to every metric
		// (a per-DHT-object pointer address). It is high-cardinality and useless
		// for aggregation -- the old OpenCensus bridge filtered it out too.
		dropInstanceID := sdkmetric.NewView(
			sdkmetric.Instrument{Name: "*"},
			sdkmetric.Stream{
				AttributeFilter: attribute.NewDenyKeysFilter("instance_id"),
			},
		)
		provider := sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(exporter),
			sdkmetric.WithView(dropInstanceID),
		)
		otel.SetMeterProvider(provider)
	})
	return otelSetupErr
}
