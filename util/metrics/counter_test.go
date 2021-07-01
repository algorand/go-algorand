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
	"testing"
	"time"

	"github.com/algorand/go-algorand/testpartitioning"
	"github.com/stretchr/testify/require"
)

type CounterTest struct {
	MetricTest
}

func TestMetricCounter(t *testing.T) {
	testpartitioning.PartitionTest(t)

	test := &CounterTest{
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
	require.Equal(t, 5, len(test.metrics), "Missing metric counts were reported.")

	for k, v := range test.metrics {
		// we have increased each one of the labels exactly 4 times. See that the counter was counting correctly.
		// ( counters starts at zero )
		require.Equal(t, "4", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
	}
}

func TestMetricCounterFastInts(t *testing.T) {
	testpartitioning.PartitionTest(t)

	test := &CounterTest{
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
	require.Equal(t, 1, len(test.metrics), "Missing metric counts were reported.")

	for k, v := range test.metrics {
		// we have increased each one of the labels exactly 4 times. See that the counter was counting correctly.
		// ( counters starts at zero )
		require.Equal(t, "22", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
	}
}

func TestMetricCounterMixed(t *testing.T) {
	testpartitioning.PartitionTest(t)

	test := &CounterTest{
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

	counter := MakeCounter(MetricName{Name: "metric_test_name1", Description: "this is the metric test for counter object"})

	counter.Add(5.25, nil)
	counter.Add(8.25, map[string]string{})
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
	require.Equal(t, 1, len(test.metrics), "Missing metric counts were reported.")

	for k, v := range test.metrics {
		// we have increased each one of the labels exactly 4 times. See that the counter was counting correctly.
		// ( counters starts at zero )
		require.Equal(t, "35.5", v, fmt.Sprintf("The metric '%s' reached value '%s'", k, v))
	}
}
