package metrics

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func hasKey(data map[string]string, key string) bool {
	_, ok := data[key]
	return ok
}

func TestMetricStringGauge(t *testing.T) {
	stringGauge := MakeStringGauge()
	stringGauge.Set("number-key", "1")
	stringGauge.Set("string-key", "value")

	results := make(map[string]string)
	DefaultRegistry().AddMetrics(results)

	// values are populated
	require.Equal(t, 2, len(results))
	require.True(t, hasKey(results, "number-key"))
	require.Equal(t, "1", results["number-key"])
	require.True(t, hasKey(results, "string-key"))
	require.Equal(t, "value", results["string-key"])

	// not included in string builder
	buf := strings.Builder{}
	DefaultRegistry().WriteMetrics(&buf, "not used")
	require.Equal(t, "", buf.String())

	stringGauge.Deregister(nil)
}
