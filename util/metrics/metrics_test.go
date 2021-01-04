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
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/algorand/go-deadlock"
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
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
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
