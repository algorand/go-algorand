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

package metrics

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

type GaugeTest struct {
	MetricTest
}

func TestMetricGauge(t *testing.T) {
	partitiontest.PartitionTest(t)

	test := &GaugeTest{
		MetricTest: NewMetricTest(),
	}
	// create a http listener.
	port := test.createListener("127.0.0.1:0")

	metricService := MakeMetricService(&ServiceConfig{
		NodeExporterListenAddress: fmt.Sprintf("localhost:%d", port),
		Labels: map[string]string{
			"host_name":  "host_one",
			"session_id": "AFX-229"},
	})
	metricService.Start(context.Background())
	gauges := make([]*Gauge, 3)
	for i := 0; i < 3; i++ {
		gauges[i] = MakeGauge(MetricName{Name: fmt.Sprintf("gauge_%d", i), Description: "this is the metric test for gauge object"})
	}
	for i := 0; i < 9; i++ {
		gauges[i%3].Set(uint64(i*100 + i))
		// wait half-a cycle
		time.Sleep(test.sampleRate / 2)
	}

	// wait two reporting cycles to ensure we received all the messages.
	time.Sleep(test.sampleRate * 2)

	metricService.Shutdown()
	for _, gauge := range gauges {
		gauge.Deregister(nil)
	}
	// test the metrics values.

	test.Lock()
	defer test.Unlock()
	// the the loop above we've created 3 separate gauges
	// let's see if we received all 3 metrics
	require.Equal(t, 3, len(test.metrics), "Missing metric counts were reported: %+v", test.metrics)

	// iterate through the metrics and check the each of the metrics reached it's correct count.
	for k, v := range test.metrics {
		if strings.Contains(k, "gauge_0") {
			require.Equal(t, "606", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
		}
		if strings.Contains(k, "gauge_1") {
			require.Equal(t, "707", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
		}
		if strings.Contains(k, "gauge_2") {
			require.Equal(t, "808", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
		}
	}
}

func TestGaugeLabels(t *testing.T) {
	partitiontest.PartitionTest(t)

	m := MakeGauge(MetricName{Name: "testname", Description: "testhelp"})
	m.Deregister(nil)

	m.SetLabels(1, map[string]string{"a": "b"})
	m.SetLabels(10, map[string]string{"c": "d"})
	m.SetLabels(2, map[string]string{"a": "b"})
	m.SetLabels(5, nil)

	require.Equal(t, uint64(2), m.GetUint64ValueForLabels(map[string]string{"a": "b"}))
	require.Equal(t, uint64(10), m.GetUint64ValueForLabels(map[string]string{"c": "d"}))

	buf := strings.Builder{}
	m.WriteMetric(&buf, "")
	res := buf.String()
	require.Contains(t, res, `testname{a="b"} 2`)
	require.Contains(t, res, `testname{c="d"} 10`)
	require.Contains(t, res, `testname 5`)
	require.Equal(t, 1, strings.Count(res, "# HELP testname testhelp"))
	require.Equal(t, 1, strings.Count(res, "# TYPE testname gauge"))

	buf = strings.Builder{}
	m.WriteMetric(&buf, `p1=v1,p2="v2"`)
	res = buf.String()
	require.Contains(t, res, `testname{p1=v1,p2="v2",a="b"} 2`)
	require.Contains(t, res, `testname{p1=v1,p2="v2",c="d"} 10`)

	m = MakeGauge(MetricName{Name: "testname2", Description: "testhelp2"})
	m.Deregister(nil)

	m.Set(101)
	buf = strings.Builder{}
	m.WriteMetric(&buf, "")
	res = buf.String()
	require.Contains(t, res, `testname2 101`)
}
