// +build telemetry

package metrics

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteAdd(t *testing.T) {
	// Test AddMetrics and WriteMetrics with a counter
	counter := MakeCounter(MetricName{Name: "gauge-name", Description: "gauge description"})
	counter.Add(12.34, nil)

	results := make(map[string]string)
	DefaultRegistry().AddMetrics(results)

	require.Equal(t, 1, len(results))
	require.True(t, hasKey(results, "gauge-name"))
	require.Equal(t, "12.34", results["gauge-name"])

	bufBefore := strings.Builder{}
	DefaultRegistry().WriteMetrics(&bufBefore, "label")
	require.True(t, bufBefore.Len() > 0)

	// Test that WriteMetrics does not change after adding a StringGauge
	stringGauge := MakeStringGauge()
	stringGauge.Set("string-key", "value")

	DefaultRegistry().AddMetrics(results)

	require.True(t, hasKey(results, "string-key"))
	require.Equal(t, "value", results["string-key"])
	require.True(t, hasKey(results, "gauge-name"))
	require.Equal(t, "12.34", results["gauge-name"])

	// not included in string builder
	bufAfter := strings.Builder{}
	DefaultRegistry().WriteMetrics(&bufAfter, "label")
	require.Equal(t, bufBefore.String(), bufAfter.String())

	stringGauge.Deregister(nil)
	counter.Deregister(nil)
}
