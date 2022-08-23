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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestBlockHeaderCache(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var cache blockHeaderCache
	cache.initialize()
	for i := basics.Round(1024); i < 1024+latestHeaderCacheSize; i++ {
		hdr := bookkeeping.BlockHeader{Round: i}
		cache.put(hdr)
	}

	rnd := basics.Round(120)
	hdr := bookkeeping.BlockHeader{Round: rnd}
	cache.put(hdr)

	_, exists := cache.get(rnd)
	a.True(exists)

	_, exists = cache.lruCache.Get(rnd)
	a.True(exists)

	_, exists = cache.latestHeaderCache.get(rnd)
	a.False(exists)

	rnd = basics.Round(2048)
	hdr = bookkeeping.BlockHeader{Round: rnd}
	cache.put(hdr)

	_, exists = cache.latestHeaderCache.get(rnd)
	a.True(exists)

	_, exists = cache.lruCache.Get(rnd)
	a.True(exists)

}

func TestLatestBlockHeaderCache(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var cache latestBlockHeaderCache
	for i := basics.Round(123); i < latestHeaderCacheSize; i++ {
		hdr := bookkeeping.BlockHeader{Round: i}
		cache.put(hdr)
	}

	for i := basics.Round(0); i < 123; i++ {
		_, exists := cache.get(i)
		a.False(exists)
	}

	for i := basics.Round(123); i < latestHeaderCacheSize; i++ {
		hdr, exists := cache.get(i)
		a.True(exists)
		a.Equal(i, hdr.Round)
	}
}

func TestCacheSizeConsensus(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	a.Equal(uint64(latestHeaderCacheSize), config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval*2)
}
