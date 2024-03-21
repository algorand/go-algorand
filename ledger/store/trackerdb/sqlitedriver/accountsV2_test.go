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

package sqlitedriver

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestRowidsToChunkedArgs(t *testing.T) {
	partitiontest.PartitionTest(t)

	res := rowidsToChunkedArgs([]int64{1})
	require.Equal(t, 1, cap(res))
	require.Equal(t, 1, len(res))
	require.Equal(t, 1, cap(res[0]))
	require.Equal(t, 1, len(res[0]))
	require.Equal(t, []interface{}{int64(1)}, res[0])

	input := make([]int64, 999)
	for i := 0; i < len(input); i++ {
		input[i] = int64(i)
	}
	res = rowidsToChunkedArgs(input)
	require.Equal(t, 1, cap(res))
	require.Equal(t, 1, len(res))
	require.Equal(t, 999, cap(res[0]))
	require.Equal(t, 999, len(res[0]))
	for i := 0; i < len(input); i++ {
		require.Equal(t, interface{}(int64(i)), res[0][i])
	}

	input = make([]int64, 1001)
	for i := 0; i < len(input); i++ {
		input[i] = int64(i)
	}
	res = rowidsToChunkedArgs(input)
	require.Equal(t, 2, cap(res))
	require.Equal(t, 2, len(res))
	require.Equal(t, 999, cap(res[0]))
	require.Equal(t, 999, len(res[0]))
	require.Equal(t, 2, cap(res[1]))
	require.Equal(t, 2, len(res[1]))
	for i := 0; i < 999; i++ {
		require.Equal(t, interface{}(int64(i)), res[0][i])
	}
	j := 0
	for i := 999; i < len(input); i++ {
		require.Equal(t, interface{}(int64(i)), res[1][j])
		j++
	}

	input = make([]int64, 2*999)
	for i := 0; i < len(input); i++ {
		input[i] = int64(i)
	}
	res = rowidsToChunkedArgs(input)
	require.Equal(t, 2, cap(res))
	require.Equal(t, 2, len(res))
	require.Equal(t, 999, cap(res[0]))
	require.Equal(t, 999, len(res[0]))
	require.Equal(t, 999, cap(res[1]))
	require.Equal(t, 999, len(res[1]))
	for i := 0; i < 999; i++ {
		require.Equal(t, interface{}(int64(i)), res[0][i])
	}
	j = 0
	for i := 999; i < len(input); i++ {
		require.Equal(t, interface{}(int64(i)), res[1][j])
		j++
	}
}
