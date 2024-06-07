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

package ledger

import (
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestAcctOnline_ExpiredCirculationCacheBasic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cache := makeExpiredCirculationCache(1)

	expStake1 := basics.MicroAlgos{Raw: 123}
	cache.put(1, 2, expStake1)
	stake, ok := cache.get(1, 2)
	require.True(t, ok)
	require.Equal(t, expStake1, stake)

	stake, ok = cache.get(3, 4)
	require.False(t, ok)
	require.Equal(t, basics.MicroAlgos{}, stake)

	expStake2 := basics.MicroAlgos{Raw: 345}
	cache.put(3, 4, expStake2)

	stake, ok = cache.get(3, 4)
	require.True(t, ok)
	require.Equal(t, expStake2, stake)

	// ensure the old entry is still there
	stake, ok = cache.get(1, 2)
	require.True(t, ok)
	require.Equal(t, expStake1, stake)

	// add one more, should evict the first and keep the second
	expStake3 := basics.MicroAlgos{Raw: 567}
	cache.put(5, 6, expStake3)
	stake, ok = cache.get(5, 6)
	require.True(t, ok)
	require.Equal(t, expStake3, stake)

	stake, ok = cache.get(3, 4)
	require.True(t, ok)
	require.Equal(t, expStake2, stake)

	stake, ok = cache.get(1, 2)
	require.False(t, ok)
	require.Equal(t, basics.MicroAlgos{}, stake)
}
