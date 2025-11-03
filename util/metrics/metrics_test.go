// Copyright (C) 2019-2025 Algorand, Inc.
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
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"
)

type MetricTest struct {
	deadlock.Mutex
	metrics    map[string]string
	sampleRate time.Duration
}

func NewMetricTest() MetricTest {
	return MetricTest{
		metrics:    make(map[string]string),
		sampleRate: time.Duration(200) * time.Millisecond,
	}
}
func (p *MetricTest) createListener(endpoint string) int {
	listener, err := net.Listen("tcp", endpoint)
	if err != nil {
		panic(err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()

	mux.HandleFunc("/metrics", p.testMetricsHandler)

	// TODO: create a server object and tear it down at end of test
	go http.Serve(listener, mux)

	// wait until server is up and running.
	time.Sleep(100 * time.Millisecond)

	return port
}

func (p *MetricTest) testMetricsHandler(w http.ResponseWriter, r *http.Request) {
	// read the entire request:
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	lines := strings.SplitSeq(string(body), "\n")
	for line := range lines {
		if len(line) < 5 {
			continue
		}
		if line[0] == '#' {
			continue
		}
		metricParts := strings.Split(line, " ")
		if len(metricParts) < 2 {
			continue
		}
		func() {
			p.Lock()
			defer p.Unlock()
			p.metrics[metricParts[0]] = metricParts[1]
		}()

	}

	if len(body) == 0 && r.Method == "POST" {
		w.Header()["SampleRate"] = []string{fmt.Sprintf("%2.2f", p.sampleRate.Seconds())}
	}
	w.Write([]byte(""))
}

func TestSanitizeTelemetryName(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, tc := range []struct{ in, out string }{
		{in: "algod_counter_x", out: "algod_counter_x"},
		{in: "algod_counter_x{a=b}", out: "algod_counter_x_a_b_"},
		{in: "this_is1-a-name0", out: "this_is1-a-name0"},
		{in: "myMetricName1:a=yes", out: "myMetricName1_a_yes"},
		{in: "myMetricName1:a=yes,b=no", out: "myMetricName1_a_yes_b_no"},
		{in: "0myMetricName1", out: "_myMetricName1"},
		{in: "myMetricName1{hello=x}", out: "myMetricName1_hello_x_"},
		{in: "myMetricName1.moreNames-n.3", out: "myMetricName1_moreNames-n_3"},
		{in: "-my-metric-name", out: "_my-metric-name"},
		{in: `label-counter:label="a label value"`, out: "label-counter_label__a_label_value_"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			require.Equal(t, tc.out, sanitizeTelemetryName(tc.in))
		})
	}
}

func TestSanitizePrometheusName(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, tc := range []struct{ in, out string }{
		{in: "algod_counter_x", out: "algod_counter_x"},
		{in: "algod_counter_x{a=b}", out: "algod_counter_x_a_b_"},
		{in: "this_is1-a-name0", out: "this_is1_a_name0"},
		{in: "myMetricName1:a=yes", out: "myMetricName1_a_yes"},
		{in: "myMetricName1:a=yes,b=no", out: "myMetricName1_a_yes_b_no"},
		{in: "0myMetricName1", out: "_myMetricName1"},
		{in: "myMetricName1{hello=x}", out: "myMetricName1_hello_x_"},
		{in: "myMetricName1.moreNames-n.3", out: "myMetricName1_moreNames_n_3"},
		{in: "-my-metric-name", out: "_my_metric_name"},
		{in: `label-counter:label="a label value"`, out: "label_counter_label__a_label_value_"},
		{in: "go/gc/cycles/total:gc-cycles", out: "go_gc_cycles_total_gc_cycles"},
		{in: "go/gc/heap/allocs:bytes", out: "go_gc_heap_allocs_bytes"},
		{in: "go/gc/heap/allocs:objects", out: "go_gc_heap_allocs_objects"},
		{in: "go/memory/classes/os-stacks:bytes", out: "go_memory_classes_os_stacks_bytes"},
		{in: "go/memory/classes/heap/free:bytes", out: "go_memory_classes_heap_free_bytes"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			require.Equal(t, tc.out, sanitizePrometheusName(tc.in))
		})
	}
}
