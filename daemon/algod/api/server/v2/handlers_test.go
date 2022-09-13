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

package v2

import (
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"math"
	"math/rand"
	"testing"
)

func TestApplicationBoxesMaxKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type example struct {
		requestedMax uint64
		algodMax     uint64
	}

	randomUint64 := func(min, max uint64) uint64 {
		r := rand.Uint64()
		if r > max {
			return max
		} else if r < min {
			return min
		}
		return r
	}

	equals := func(expected uint64, e example) {
		require.Equal(t, expected, applicationBoxesMaxKeys(e.requestedMax, e.algodMax), "failing example = %+v", e)
	}

	// Response size limited by request supplied value.
	{
		requestedMax := randomUint64(1, math.MaxUint64-1)
		algodMax := requestedMax + 1
		equals(requestedMax, example{requestedMax, algodMax})

		algodMax = uint64(0)
		equals(requestedMax, example{requestedMax, algodMax})
	}

	// Response size limited by algod max.
	{
		requestedMax := randomUint64(3, math.MaxUint64)
		algodMax := requestedMax - 2 // algodMax > 0
		equals(algodMax+1, example{requestedMax, algodMax})
	}

	// Response size _not_ limited
	{
		requestedMax := uint64(0)
		algodMax := uint64(0)
		equals(algodMax, example{requestedMax, algodMax})
	}
}
