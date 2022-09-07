// Copyright (C) 2019-2022 Algorand, Inc.
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
	"bufio"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestRuntimeMetrics(t *testing.T) {
	partitiontest.PartitionTest(t)

	rm := NewRuntimeMetrics()
	var sb strings.Builder
	rm.WriteMetric(&sb, `host="x"`)
	scanner := bufio.NewScanner(strings.NewReader(sb.String()))

	// assert default metrics correctly created
	cur := 0
	for scanner.Scan() {
		curName := "algod_go" + defaultRuntimeMetrics[cur]
		curName = strings.ReplaceAll(curName, ":", "_")
		curName = strings.ReplaceAll(curName, "-", "_")
		curName = strings.ReplaceAll(curName, "/", "_")
		require.Regexp(t, `^# HELP `+curName, scanner.Text())
		require.True(t, scanner.Scan())
		require.Regexp(t, `^# TYPE `+curName, scanner.Text())
		require.True(t, scanner.Scan())
		require.Regexp(t, `^`+curName+`{host="x"}`, scanner.Text())
		cur++
	}
	require.NoError(t, scanner.Err())
	require.Len(t, defaultRuntimeMetrics, cur)

	m := make(map[string]float64)
	rm.AddMetric(m)
	for _, name := range defaultRuntimeMetrics {
		tname := strings.ReplaceAll(strings.ReplaceAll("go"+name, ":", "_"), "/", "_")
		require.Contains(t, m, tname)
	}
}
