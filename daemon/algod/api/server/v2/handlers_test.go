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
	"testing"
)

func TestApplicationBoxesMaxKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type example struct {
		requestedMax uint64
		algodMax     uint64
	}

	equals := func(expected uint64, e example) {
		require.Equal(t, expected, applicationBoxesMaxKeys(e.requestedMax, e.algodMax), "failing example = %+v", e)
	}

	// Response size limited by request supplied value.
	{
		requestedMax := uint64(5)
		algodMax := uint64(7)
		equals(requestedMax, example{requestedMax, algodMax})

		requestedMax = uint64(5)
		algodMax = uint64(0)
		equals(requestedMax, example{requestedMax, algodMax})
	}

	// Response size limited by algod max.
	{
		requestedMax := uint64(5)
		algodMax := uint64(1)
		equals(algodMax+1, example{requestedMax, algodMax})

		requestedMax = uint64(0)
		algodMax = uint64(1)
		equals(algodMax+1, example{requestedMax, algodMax})
	}

	// Response size _not_ limited
	{
		requestedMax := uint64(0)
		algodMax := uint64(0)
		equals(algodMax, example{requestedMax, algodMax})
	}
}
