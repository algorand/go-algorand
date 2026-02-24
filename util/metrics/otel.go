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
		exporter, err := otelprom.New()
		if err != nil {
			otelSetupErr = fmt.Errorf("creating OTEL Prometheus exporter: %w", err)
			return
		}
		provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
		otel.SetMeterProvider(provider)
	})
	return otelSetupErr
}
