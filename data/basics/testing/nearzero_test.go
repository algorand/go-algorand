// Copyright (C) 2019-2025 Algorand, Inc.
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

package testing

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
)

func TestNearZeros(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := assert.New(t)
	a.Len(NearZeros(t, struct{}{}), 0)

	type one struct {
		B bool
	}
	a.Len(NearZeros(t, one{}), 1)

	type two struct {
		I int
		J int
	}
	a.Len(NearZeros(t, two{}), 2)

	// struct three has structs inside
	type three struct {
		One one
		Two two
	}
	a.Len(NearZeros(t, three{}), 3)

	// struct four has a pointer and an array
	type four struct {
		One   one
		Two   *two
		Array [3]int
	}
	a.Len(NearZeros(t, four{}), 4)

	// Show that Two is allocated (twice, once for I, once for J)
	count := 0
	for _, f := range NearZeros(t, four{}) {
		if f.Two != nil {
			count++
		}
	}
	a.Equal(2, count)

	// struct five has a slice
	type five struct {
		Two1  two
		Two2  two
		Slice []int
	}
	a.Len(NearZeros(t, five{}), 5)

	// Show that Slice is allocated once
	count = 0
	for _, f := range NearZeros(t, five{}) {
		if f.Slice != nil {
			count++
		}
	}
	a.Equal(1, count)

	// struct size has a slice of struct
	type six struct {
		Slice1 []one
		Slice2 []two
		Slice3 []three
	}
	a.Len(NearZeros(t, six{}), 6)

	// Show that Slice2 is allocated twice, in order to fill Slice2[0].{I,J}
	count = 0
	for _, f := range NearZeros(t, six{}) {
		if f.Slice2 != nil {
			count++
			a.True(f.Slice2[0].I > 0 || f.Slice2[0].J > 0)
		}
	}
	a.Equal(2, count)
}

func TestUnexported(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type unexported struct {
		a int
		B int
	}
	assert.Len(t, NearZeros(t, unexported{}), 1)
}

func TestMap(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type mapint struct {
		A map[int]int
	}
	assert.Len(t, NearZeros(t, mapint{}), 1)
	assert.Zero(t, NearZeros(t, mapint{})[0].A[1])

	type mapstring struct {
		A map[int]string
	}
	assert.Len(t, NearZeros(t, mapstring{}), 1)
	assert.Zero(t, NearZeros(t, mapstring{})[0].A[1])

	type mapstruct2 struct {
		A map[int]struct{ A, B, C int }
	}
	assert.Len(t, NearZeros(t, mapstruct2{}), 1)
	assert.Len(t, NearZeros(t, mapstruct2{})[0].A, 1)
	assert.Zero(t, NearZeros(t, mapstruct2{})[0].A[1])
}
