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

package basics

import (
	"math"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestFraction(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	third := Fraction{1, 3}
	a, b := third.Divvy(6)
	require.EqualValues(t, 2, a)
	require.EqualValues(t, 4, b)

	a, b = third.Divvy(10)
	require.EqualValues(t, 3, a)
	require.EqualValues(t, 7, b)
}

func TestFractionAvoidsOverflow(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	biggestEven := math.MaxUint64 - uint64(1)

	half := Fraction{biggestEven / 2, biggestEven} // should operate as 1/2 even on large numbers
	a, b := half.Divvy(6)
	require.EqualValues(t, 3, a)
	require.EqualValues(t, 3, b)

	a, b = half.Divvy(biggestEven)
	require.EqualValues(t, biggestEven/2, a)
	require.EqualValues(t, biggestEven/2, b)

	// ensure that overflow is avoided even if reduction isn't possible
	uhalf := Fraction{biggestEven / 2, math.MaxUint64} // should be just under half
	a, b = uhalf.Divvy(6)
	require.EqualValues(t, 2, a)
	require.EqualValues(t, 4, b)

	a, b = uhalf.Divvy(biggestEven)
	require.EqualValues(t, biggestEven/2-1, a)
	require.EqualValues(t, biggestEven/2+1, b)

	// and just to be super careful, ensure that there's also no reduction
	// between q and the denominator by using a q that is relatively prime to
	// math.MaxUint64

	// prove 23 is relatively prime to math.MaxUint64
	require.Positive(t, math.MaxUint64%23)

	a, b = uhalf.Divvy(23)
	require.EqualValues(t, 11, a)
	require.EqualValues(t, 12, b)

	one := Fraction{math.MaxUint64, math.MaxUint64}
	a, b = one.Divvy(math.MaxUint64)
	require.EqualValues(t, uint64(math.MaxUint64), a)
	require.EqualValues(t, 0, b)
}
