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
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestWriteAdd(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Test AddMetrics and WriteMetrics with a counter
	counter := MakeCounter(MetricName{Name: "gauge-name", Description: "gauge description"})
	counter.AddUint64(12, nil)

	labelCounter := MakeCounter(MetricName{Name: "label-counter", Description: "counter with labels"})
	labelCounter.AddUint64(5, map[string]string{"label": "a label value"})

	results := make(map[string]float64)
	DefaultRegistry().AddMetrics(results)

	require.Equal(t, 2, len(results), "results", results)
	require.Contains(t, results, "gauge-name")
	require.InDelta(t, 12, results["gauge-name"], 0.01)
	require.Contains(t, results, "label-counter_label__a_label_value_")
	require.InDelta(t, 5, results["label-counter_label__a_label_value_"], 0.01)

	bufBefore := strings.Builder{}
	DefaultRegistry().WriteMetrics(&bufBefore, "label")
	require.True(t, bufBefore.Len() > 0)

	DefaultRegistry().AddMetrics(results)

	require.Contains(t, results, "gauge-name")
	require.InDelta(t, 12, results["gauge-name"], 0.01)

	// not included in string builder
	bufAfter := strings.Builder{}
	DefaultRegistry().WriteMetrics(&bufAfter, "label")
	require.Equal(t, bufBefore.String(), bufAfter.String())

	counter.Deregister(nil)
	labelCounter.Deregister(nil)
}
