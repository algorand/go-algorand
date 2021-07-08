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
	"strings"
	"testing"

	"github.com/algorand/go-algorand/testpartitioning"
	"github.com/stretchr/testify/require"
)

func hasKey(data map[string]string, key string) bool {
	_, ok := data[key]
	return ok
}

func TestMetricStringGauge(t *testing.T) {
	testpartitioning.PartitionTest(t)

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
