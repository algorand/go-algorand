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
	"math"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestApplicationBoxesMaxKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Response size limited by request supplied value.
	require.Equal(t, uint64(5), applicationBoxesMaxKeys(5, 7))
	require.Equal(t, uint64(5), applicationBoxesMaxKeys(5, 0))

	// Response size limited by algod max.
	require.Equal(t, uint64(2), applicationBoxesMaxKeys(5, 1))
	require.Equal(t, uint64(2), applicationBoxesMaxKeys(0, 1))

	// Response size _not_ limited
	require.Equal(t, uint64(math.MaxUint64), applicationBoxesMaxKeys(0, 0))
}
