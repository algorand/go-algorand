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
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type GaugeTest struct {
	MetricTest
}

func TestMetricGauge(t *testing.T) {

	test := &GaugeTest{
		MetricTest: NewMetricTest(),
	}
	// create a http listener.
	port := test.createListener(":0")

	metricService := MakeMetricService(&ServiceConfig{
		NodeExporterListenAddress: fmt.Sprintf("localhost:%d", port),
		Labels: map[string]string{
			"host_name":  "host_one",
			"session_id": "AFX-229"},
	})
	metricService.Start(context.Background())

	gauge := MakeGauge(MetricName{Name: "metric_test_name1", Description: "this is the metric test for counter object"})

	for i := 0; i < 20; i++ {
		gauge.Set(float64(i*10), map[string]string{"pid": "123", "data_host": fmt.Sprintf("host%d", i%5)})
		// wait half-a cycle
		time.Sleep(test.sampleRate / 2)
	}

	// wait two reporting cycles to ensure we recieved all the messages.
	time.Sleep(test.sampleRate * 2)

	metricService.Shutdown()
	gauge.Deregister(nil)
	// test the metrics values.

	test.Lock()
	defer test.Unlock()

	// the the loop above we've created a single metric name with five diffrent labels set ( host0, host1 .. host 4)
	// let's see if we received all the 5 diffrent labels.
	require.Equal(t, 5, len(test.metrics), "Missing metric counts were reported.")

	// iterate through the metrics and check the each of the metrics reached it's correct count.
	for k, v := range test.metrics {
		if strings.Contains(k, "host0") {
			require.Equal(t, "150", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
		}
		if strings.Contains(k, "host1") {
			require.Equal(t, "160", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
		}
		if strings.Contains(k, "host2") {
			require.Equal(t, "170", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
		}
		if strings.Contains(k, "host3") {
			require.Equal(t, "180", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
		}
		if strings.Contains(k, "host4") {
			require.Equal(t, "190", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
		}
	}
}
