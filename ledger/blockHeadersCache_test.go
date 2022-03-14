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

package ledger

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestBlockHeadersCache(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var cache blockHeadersCache
	cache.initialize()
	for i := basics.Round(1024); i < 1024+latestCacheSize; i++ {
		hdr := bookkeeping.BlockHeader{Round: i}
		cache.Put(i, hdr)
	}

	rnd := basics.Round(120)
	hdr := bookkeeping.BlockHeader{Round: rnd}
	cache.Put(rnd, hdr)

	_, exists := cache.Get(rnd)
	a.True(exists)

	_, exists = cache.lruCache.Get(rnd)
	a.True(exists)

	_, exists = cache.latestHeadersCache.Get(rnd)
	a.False(exists)
}

func TestLatestBlockHeadersCache(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var cache latestBlockHeadersCache
	for i := basics.Round(123); i < latestCacheSize; i++ {
		hdr := bookkeeping.BlockHeader{Round: i}
		cache.Put(i, hdr)
	}

	for i := basics.Round(0); i < 123; i++ {
		_, exists := cache.Get(i)
		a.False(exists)
	}

	for i := 123; i < latestCacheSize; i++ {
		hdr, exists := cache.Get(basics.Round(i))
		a.True(exists)
		a.Equal(basics.Round(i), hdr.Round)
	}
}
