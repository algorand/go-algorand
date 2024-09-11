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

package runner

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/tools/block-generator/generator"
)

const initialRound = 1234
const entryCount = 10

func makeDummyData() (time.Time, time.Duration, generator.Report, *MetricsCollector) {
	start := time.Now().Add(-10 * time.Minute)
	duration := time.Hour
	generatorReport := generator.Report{
		InitialRound: initialRound,
		Counters:     make(map[string]uint64),
		Transactions: make(map[generator.TxTypeID]generator.TxData),
	}
	collector := &MetricsCollector{Data: make([]Entry, entryCount)}
	return start, duration, generatorReport, collector
}

// makeMetrics creates a set of metrics for testing.
func makeMetrics(start time.Time) *MetricsCollector {
	collector := &MetricsCollector{}
	for i := 0; i <= entryCount; i++ {
		var data []string

		// should be converted to an average.
		data = append(data, fmt.Sprintf("import_time_sec_sum %d", i*100))
		data = append(data, fmt.Sprintf("import_time_sec_count %d", i))
		// should be converted to an average.
		data = append(data, fmt.Sprintf("imported_tx_per_block_sum %d", i*100))
		data = append(data, fmt.Sprintf("imported_tx_per_block_count %d", i))

		data = append(data, fmt.Sprintf("imported_round %d", i))
		collector.Data = append(collector.Data, Entry{
			Timestamp: start.Add(time.Duration(i) * time.Minute),
			Data:      data,
		})
	}
	return collector
}

func TestWriteReport_MissingMetrics(t *testing.T) {
	start, duration, generatorReport, collector := makeDummyData()
	var builder strings.Builder
	err := writeReport(&builder, t.Name(), start, duration, generatorReport, collector)
	require.ErrorContains(t, err, "metric incomplete or not found")
}

func TestWriterReport_Good(t *testing.T) {
	start, duration, generatorReport, _ := makeDummyData()
	collector := makeMetrics(start)

	generatorReport.Counters[generator.BlockTotalSizeBytes] = 1024
	generatorReport.Counters[generator.BlockgenGenerateTimeMS] = 0
	generatorReport.Counters[generator.CommitWaitTimeMS] = 1000
	generatorReport.Counters[generator.LedgerEvalTimeMS] = 2000
	generatorReport.Counters[generator.LedgerValidateTimeMS] = 3000

	var builder strings.Builder
	err := writeReport(&builder, t.Name(), start, duration, generatorReport, collector)
	require.NoError(t, err)

	report := builder.String()

	// both rounds of metrics are reported.
	assert.Contains(t, report, fmt.Sprintf("initial_round:%d", initialRound))
	assert.Contains(t, report, fmt.Sprintf("final_imported_round:%d", entryCount))
	assert.Contains(t, report, fmt.Sprintf("early_imported_round:%d", entryCount/5))

	// counters are reported.
	for k, v := range generatorReport.Counters {
		assert.Contains(t, report, fmt.Sprintf("%s:%d", k, v))
	}
}
