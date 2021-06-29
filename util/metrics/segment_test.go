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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand/testpartitioning"
	"github.com/stretchr/testify/require"
)

type SegmentTest struct {
	MetricTest
}

func TestMetricSegment(t *testing.T) {
	testpartitioning.PartitionTest(t)

	const initialSleepDuration = 10 * time.Millisecond
	const maxSleepDuration = 4 * time.Second
	done := false
	for sleepDuration := initialSleepDuration; sleepDuration <= maxSleepDuration; sleepDuration *= 2 {
		done = testMetricSegmentHelper(t, sleepDuration)
		if done {
			break
		}
	}
	if !done {
		require.Fail(t, "test failed")
	}
}

func testMetricSegmentHelper(t *testing.T, functionTime time.Duration) bool {

	test := &SegmentTest{
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

	acceptedFunctionThreshold := 1.1 // 10 percent.
	segment := MakeSegment(&MetricName{Name: "test_segment_name1", Description: "this is the metric test for segment object"})
	segmentTest := func() {
		inst, _ := segment.EnterSegment(map[string]string{"pid": "123"})
		defer inst.LeaveSegment()
		time.Sleep(functionTime)
	}
	segmentTest()
	segmentTest()
	// wait two reporting cycles to ensure we received all the messages.
	time.Sleep(test.sampleRate * 2)

	metricService.Shutdown()

	segment.Deregister(nil)

	test.Lock()
	defer test.Unlock()

	// test the metrics values. see if we received all the 4 metrics back correctly.
	// we expect the get 4 metrics : test_segment_name1_sec, test_segment_name1_sec_total, test_segment_name1_total and test_segment_name1_concurrent
	// ( we don't know in which order they would appear, but the total count should be 4 )
	require.Equal(t, 4, len(test.metrics), "Missing metric counts were reported.")

	for k, v := range test.metrics {
		if strings.Contains(k, "test_segment_name1_sec{") {
			// should be around 400 milliseconds.
			if elapsedTime, err := strconv.ParseFloat(v, 64); err != nil {
				t.Fatalf("The metric '%s' has unexpected value of '%s'", k, v)
			} else {
				if elapsedTime < functionTime.Seconds() || elapsedTime > functionTime.Seconds()*acceptedFunctionThreshold {
					return false
				}
			}
		}
		if strings.Contains(k, "test_segment_name1_sec_total{") {
			// should be around 800 milliseconds.
			if elapsedTime, err := strconv.ParseFloat(v, 64); err != nil {
				t.Fatalf("The metric '%s' has unexpected value of '%s'", k, v)
			} else {
				if elapsedTime < 2*functionTime.Seconds() || elapsedTime > 2*functionTime.Seconds()*acceptedFunctionThreshold {
					return false
				}
			}
		}
		if strings.Contains(k, "test_segment_name1_total{") {
			// should be 2, since we had 2 calls.
			require.Equal(t, "2", v, "The metric '%s' has unexpected value of '%s'", k, v)
		}
	}
	return true
}
