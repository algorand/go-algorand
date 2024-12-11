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

package util

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestMakeSet(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	s := MakeSet(1, 2, 3)
	require.True(t, s.Contains(1))
	require.True(t, s.Contains(2))
	require.True(t, s.Contains(3))
	require.False(t, s.Contains(4))

	s = MakeSet[int]()
	require.NotNil(t, s)
	require.False(t, s.Contains(1))
	require.False(t, s.Contains(4))
}

func TestSetAdd(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	s := MakeSet[int]()
	s.Add(6)
	require.False(t, s.Contains(1))
	require.True(t, s.Contains(6))
	s.Add(6)
	require.False(t, s.Contains(1))
	require.True(t, s.Contains(6))
}

func TestSetOps(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	empty := MakeSet[string]()
	abc := MakeSet("a", "b", "c")
	cde := MakeSet("c", "d", "e")

	require.Equal(t, abc, Union(abc))
	require.Equal(t, abc, Union(empty, abc))
	require.Equal(t, abc, Union(abc, empty, abc))
	require.NotNil(t, Union(empty, empty, empty))
	require.Equal(t, empty, Union(empty, empty, empty))

	require.Equal(t, abc, Intersection(abc, abc))
	require.NotNil(t, Intersection(abc, empty))
	require.Equal(t, empty, Intersection(abc, empty))
	require.Equal(t, empty, Intersection(empty, abc))
	require.Equal(t, MakeSet("c"), Intersection(abc, cde))
	require.Equal(t, MakeSet("c"), Intersection(cde, abc, cde))
}
