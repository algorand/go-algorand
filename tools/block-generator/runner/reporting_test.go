package runner

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/tools/block-generator/generator"
)

func makeDummyData() (time.Time, time.Duration, generator.Report, *MetricsCollector) {
	start := time.Now().Add(-10 * time.Minute)
	duration := time.Hour
	generatorReport := generator.Report{
		Counters:     make(map[string]uint64),
		Transactions: make(map[generator.TxTypeID]generator.TxData),
	}
	collector := &MetricsCollector{Data: make([]Entry, 10)}
	return start, duration, generatorReport, collector
}

// makeMetrics creates a set of metrics for testing.
func makeMetrics(start time.Time) *MetricsCollector {
	collector := &MetricsCollector{}
	for i := 0; i <= 10; i++ {
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
	generatorReport.Counters[generator.CommitWaitTimeMS] = 1000
	generatorReport.Counters[generator.LedgerEvalTimeMS] = 2000
	generatorReport.Counters[generator.LedgerValidateTimeMS] = 3000

	var builder strings.Builder
	err := writeReport(&builder, t.Name(), start, duration, generatorReport, collector)
	require.NoError(t, err)

	report := builder.String()

	// both rounds of metrics are reported.
	require.Contains(t, report, "final_imported_round:10")
	require.Contains(t, report, "early_imported_round:2")

	// counters are reported.
	for k, v := range generatorReport.Counters {
		require.Contains(t, report, fmt.Sprintf("%s:%d", k, v))
	}
}
