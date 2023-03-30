// Copyright (C) 2019-2023 Algorand, Inc.
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

package runner

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// MetricsCollector queries a /metrics endpoint for prometheus style metrics and saves metrics matching a pattern.
type MetricsCollector struct {
	// MetricsURL where metrics can be queried.
	MetricsURL string
	// Data is all of the results.
	Data []Entry
}

// Entry is the raw data pulled from the endpoint along with a timestamp.
type Entry struct {
	Timestamp time.Time
	Data      []string
}

// Collect fetches the metrics.
func (r *MetricsCollector) Collect(substrings ...string) error {
	metrics, err := r.getMetrics(substrings...)
	if err != nil {
		return err
	}

	if len(metrics) > 0 {
		entry := Entry{
			Timestamp: time.Now(),
			Data:      metrics,
		}
		r.Data = append(r.Data, entry)
	}

	return nil
}

func (r MetricsCollector) getMetrics(substrings ...string) (result []string, err error) {
	resp, err := http.Get(r.MetricsURL)
	if err != nil {
		err = fmt.Errorf("unable to read metrics url '%s'", r.MetricsURL)
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		str := scanner.Text()

		if strings.HasPrefix(str, "#") {
			continue
		}

		for _, substring := range substrings {
			if strings.Contains(str, substring) {
				result = append(result, str)
				break
			}
		}
	}

	if scanner.Err() != nil {
		err = fmt.Errorf("problem reading metrics response: %w", scanner.Err())
	}

	return
}
