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

type CounterTest struct {
	MetricTest
}

func TestMetricCounter(t *testing.T) {
	partitiontest.PartitionTest(t)

	test := &CounterTest{
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

	counter := MakeCounter(MetricName{Name: "metric_test_name1", Description: "this is the metric test for counter object"})

	for i := 0; i < 20; i++ {
		counter.Inc(map[string]string{"pid": "123", "data_host": fmt.Sprintf("host%d", i%5)})
		// wait half-a cycle
		time.Sleep(test.sampleRate / 2)
	}
	// wait two reporting cycles to ensure we received all the messages.
	time.Sleep(test.sampleRate * 2)

	metricService.Shutdown()

	counter.Deregister(nil)
	// test the metrics values.

	test.Lock()
	defer test.Unlock()
	// the the loop above we've created a single metric name with five different labels set ( host0, host1 .. host 4)
	// let's see if we received all the 5 different labels.
	require.Equal(t, 5, len(test.metrics), "Missing metric counts were reported: %+v", test.metrics)

	for k, v := range test.metrics {
		// we have increased each one of the labels exactly 4 times. See that the counter was counting correctly.
		// ( counters starts at zero )
		require.Equal(t, "4", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
	}
}

func TestMetricCounterFastInts(t *testing.T) {
	partitiontest.PartitionTest(t)

	test := &CounterTest{
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

	counter := MakeCounter(MetricName{Name: "metric_test_name1", Description: "this is the metric test for counter object"})

	for i := 0; i < 20; i++ {
		counter.Inc(nil)
		// wait half-a cycle
		time.Sleep(test.sampleRate / 2)
	}
	counter.AddUint64(2, nil)
	// wait two reporting cycles to ensure we received all the messages.
	time.Sleep(test.sampleRate * 2)

	metricService.Shutdown()

	counter.Deregister(nil)
	// test the metrics values.

	test.Lock()
	defer test.Unlock()
	// the the loop above we've created a single metric name with five different labels set ( host0, host1 .. host 4)
	// let's see if we received all the 5 different labels.
	require.Equal(t, 1, len(test.metrics), "Missing metric counts were reported: %+v", test.metrics)

	for k, v := range test.metrics {
		// we have increased each one of the labels exactly 4 times. See that the counter was counting correctly.
		// ( counters starts at zero )
		require.Equal(t, "22", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
	}
}

func TestMetricCounterMixed(t *testing.T) {
	partitiontest.PartitionTest(t)

	test := &CounterTest{
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

	counter := MakeCounter(MetricName{Name: "metric_test_name1", Description: "this is the metric test for counter object"})

	counter.AddUint64(5, nil)
	counter.AddUint64(8, map[string]string{})
	for i := 0; i < 20; i++ {
		counter.Inc(nil)
		// wait half-a cycle
		time.Sleep(test.sampleRate / 2)
	}
	counter.AddUint64(2, nil)
	// wait two reporting cycles to ensure we received all the messages.
	time.Sleep(test.sampleRate * 2)

	metricService.Shutdown()

	counter.Deregister(nil)
	// test the metrics values.

	test.Lock()
	defer test.Unlock()
	// the the loop above we've created a single metric name with five different labels set ( host0, host1 .. host 4)
	// let's see if we received all the 5 different labels.
	require.Equal(t, 1, len(test.metrics), "Missing metric counts were reported: %+v", test.metrics)

	for k, v := range test.metrics {
		// we have increased each one of the labels exactly 4 times. See that the counter was counting correctly.
		// ( counters starts at zero )
		require.Equal(t, "35", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
	}
}

func TestCounterWriteMetric(t *testing.T) {
	partitiontest.PartitionTest(t)

	c := MakeCounter(MetricName{Name: "testname", Description: "testhelp"})
	c.Deregister(nil)

	// ensure 0 counters are still logged
	sbOut := strings.Builder{}
	c.WriteMetric(&sbOut, `host="myhost"`)
	expected := `# HELP testname testhelp
# TYPE testname counter
testname{host="myhost"} 0
`
	require.Equal(t, expected, sbOut.String())

	c.AddUint64(2, nil)
	// ensure non-zero counters are logged
	sbOut = strings.Builder{}
	c.WriteMetric(&sbOut, `host="myhost"`)
	expected = `# HELP testname testhelp
# TYPE testname counter
testname{host="myhost"} 2
`
	require.Equal(t, expected, sbOut.String())
}

func TestGetValue(t *testing.T) {
	partitiontest.PartitionTest(t)

	c := MakeCounter(MetricName{Name: "testname", Description: "testhelp"})
	c.Deregister(nil)

	require.Equal(t, uint64(0), c.GetUint64Value())
	c.Inc(nil)
	require.Equal(t, uint64(1), c.GetUint64Value())
	c.Inc(nil)
	require.Equal(t, uint64(2), c.GetUint64Value())
}

func TestGetValueForLabels(t *testing.T) {
	partitiontest.PartitionTest(t)

	c := MakeCounter(MetricName{Name: "testname", Description: "testhelp"})
	c.Deregister(nil)

	labels := map[string]string{"a": "b"}
	require.Equal(t, uint64(0), c.GetUint64ValueForLabels(labels))
	c.Inc(labels)
	require.Equal(t, uint64(1), c.GetUint64ValueForLabels(labels))
	c.Inc(labels)
	require.Equal(t, uint64(2), c.GetUint64ValueForLabels(labels))
	// confirm that the value is not shared between labels
	c.Inc(nil)
	require.Equal(t, uint64(2), c.GetUint64ValueForLabels(labels))
	labels2 := map[string]string{"a": "c"}
	c.Inc(labels2)
	require.Equal(t, uint64(1), c.GetUint64ValueForLabels(labels2))
}

func TestCounterLabels(t *testing.T) {
	partitiontest.PartitionTest(t)

	m := MakeCounter(MetricName{Name: "testname", Description: "testhelp"})
	m.Deregister(nil)

	m.AddUint64(1, map[string]string{"a": "b"})
	m.AddUint64(10, map[string]string{"c": "d"})
	m.AddUint64(1, map[string]string{"a": "b"})
	m.AddUint64(5, nil)

	require.Equal(t, uint64(2), m.GetUint64ValueForLabels(map[string]string{"a": "b"}))
	require.Equal(t, uint64(10), m.GetUint64ValueForLabels(map[string]string{"c": "d"}))

	buf := strings.Builder{}
	m.WriteMetric(&buf, "")
	res := buf.String()
	require.Contains(t, res, `testname{a="b"} 2`)
	require.Contains(t, res, `testname{c="d"} 10`)
	require.Contains(t, res, `testname 5`)
	require.Equal(t, 1, strings.Count(res, "# HELP testname testhelp"))
	require.Equal(t, 1, strings.Count(res, "# TYPE testname counter"))

	buf = strings.Builder{}
	m.WriteMetric(&buf, `p1=v1,p2="v2"`)
	res = buf.String()
	require.Contains(t, res, `testname{p1=v1,p2="v2",a="b"} 2`)
	require.Contains(t, res, `testname{p1=v1,p2="v2",c="d"} 10`)

	m = MakeCounter(MetricName{Name: "testname2", Description: "testhelp2"})
	m.Deregister(nil)

	m.AddUint64(101, nil)
	buf = strings.Builder{}
	m.WriteMetric(&buf, "")
	res = buf.String()
	require.Contains(t, res, `testname2 101`)
}
