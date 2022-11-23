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

package data

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-deadlock"

	"golang.org/x/crypto/blake2b"
)

func TestTxHandlerDigestCache(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const size = 20
	cache := makeDigestCache(size)
	require.Zero(t, cache.len())

	// add some unique random
	var ds [size]crypto.Digest
	for i := 0; i < size; i++ {
		crypto.RandBytes([]byte(ds[i][:]))
		exist := cache.checkAndPut(&ds[i])
		require.False(t, exist)

		exist = cache.check(&ds[i])
		require.True(t, exist)
	}

	require.Equal(t, size, cache.len())

	// try to re-add, ensure not added
	for i := 0; i < size; i++ {
		exist := cache.checkAndPut(&ds[i])
		require.True(t, exist)
	}

	require.Equal(t, size, cache.len())

	// add some more and ensure capacity switch
	var ds2 [size]crypto.Digest
	for i := 0; i < size; i++ {
		crypto.RandBytes(ds2[i][:])
		exist := cache.checkAndPut(&ds2[i])
		require.False(t, exist)

		exist = cache.check(&ds2[i])
		require.True(t, exist)
	}

	require.Equal(t, 2*size, cache.len())

	var d crypto.Digest
	crypto.RandBytes(d[:])
	exist := cache.checkAndPut(&d)
	require.False(t, exist)
	exist = cache.check(&d)
	require.True(t, exist)

	require.Equal(t, size+1, cache.len())

	// ensure hashes from the prev batch are still there
	for i := 0; i < size; i++ {
		exist := cache.check(&ds2[i])
		require.True(t, exist)
	}

	// ensure hashes from the first batch are gone
	for i := 0; i < size; i++ {
		exist := cache.check(&ds[i])
		require.False(t, exist)
	}
}

// TestTxHandlerSaltedCacheBasic is the same as TestTxHandlerDigestCache but for the salted cache
func TestTxHandlerSaltedCacheBasic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const size = 20
	cache := makeSaltedCache(context.Background(), size, 0)
	require.Zero(t, cache.len())

	// add some unique random
	var ds [size][8]byte
	for i := 0; i < size; i++ {
		crypto.RandBytes([]byte(ds[i][:]))
		exist := cache.checkAndPut(ds[i][:])
		require.False(t, exist)

		exist = cache.check(ds[i][:])
		require.True(t, exist)
	}

	require.Equal(t, size, cache.len())

	// try to re-add, ensure not added
	for i := 0; i < size; i++ {
		exist := cache.checkAndPut(ds[i][:])
		require.True(t, exist)
	}

	require.Equal(t, size, cache.len())

	// add some more and ensure capacity switch
	var ds2 [size][8]byte
	for i := 0; i < size; i++ {
		crypto.RandBytes(ds2[i][:])
		exist := cache.checkAndPut(ds2[i][:])
		require.False(t, exist)

		exist = cache.check(ds2[i][:])
		require.True(t, exist)
	}

	require.Equal(t, 2*size, cache.len())

	var d [8]byte
	crypto.RandBytes(d[:])
	exist := cache.checkAndPut(d[:])
	require.False(t, exist)
	exist = cache.check(d[:])
	require.True(t, exist)

	require.Equal(t, size+1, cache.len())

	// ensure hashes from the prev batch are still there
	for i := 0; i < size; i++ {
		exist := cache.check(ds2[i][:])
		require.True(t, exist)
	}

	// ensure hashes from the first batch are gone
	for i := 0; i < size; i++ {
		exist := cache.check(ds[i][:])
		require.False(t, exist)
	}
}

func TestTxHandlerSaltedCacheScheduled(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const size = 20
	updateInterval := 1000 * time.Microsecond
	cache := makeSaltedCache(context.Background(), size, updateInterval)
	require.Zero(t, cache.len())

	// add some unique random
	var ds [size][8]byte
	for i := 0; i < size; i++ {
		cache.mu.Lock()
		crypto.RandBytes([]byte(ds[i][:]))
		exist := cache.innerCheckAndPut(ds[i][:])
		require.False(t, exist)

		exist = cache.check(ds[i][:])
		require.True(t, exist)
		cache.mu.Unlock()

		if rand.Int()%2 == 0 {
			time.Sleep(updateInterval / 2)
		}
	}

	require.Greater(t, cache.len(), 0)
}

func TestTxHandlerSaltedCacheManual(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const size = 20
	cache := makeSaltedCache(context.Background(), 2*size, 0)
	require.Zero(t, cache.len())

	// add some unique random
	var ds [size][8]byte
	for i := 0; i < size; i++ {
		crypto.RandBytes([]byte(ds[i][:]))
		exist := cache.checkAndPut(ds[i][:])
		require.False(t, exist)
		exist = cache.check(ds[i][:])
		require.True(t, exist)
	}

	require.Equal(t, size, cache.len())

	// rotate and add more data
	cache.remix()

	var ds2 [size][8]byte
	for i := 0; i < size; i++ {
		crypto.RandBytes([]byte(ds2[i][:]))
		exist := cache.checkAndPut(ds2[i][:])
		require.False(t, exist)
		exist = cache.check(ds2[i][:])
		require.True(t, exist)
	}
	require.Equal(t, 2*size, cache.len())

	// ensure the old data still in
	for i := 0; i < size; i++ {
		exist := cache.check(ds[i][:])
		require.True(t, exist)
	}

	// rotate again, check only new data left
	cache.remix()
	require.Equal(t, size, cache.len())
	for i := 0; i < size; i++ {
		exist := cache.check(ds[i][:])
		require.False(t, exist)
		exist = cache.check(ds2[i][:])
		require.True(t, exist)
	}
}

// benchmark abstractions
type cachePusher interface {
	push()
}

type cacheMaker interface {
	make(size int) cachePusher
}

type digestCacheMaker struct{}
type saltedCacheMaker struct{}

func (m digestCacheMaker) make(size int) cachePusher {
	return &digestCachePusher{c: makeDigestCache(size)}
}
func (m saltedCacheMaker) make(size int) cachePusher {
	return &saltedCachePusher{c: makeSaltedCache(context.Background(), size, 0)}
}

type digestCachePusher struct {
	c *digestCache
}
type saltedCachePusher struct {
	c *txSaltedCache
}

func (p *digestCachePusher) push() {
	var d [crypto.DigestSize]byte
	crypto.RandBytes(d[:])
	h := crypto.Digest(blake2b.Sum256(d[:])) // digestCache does not hashes so calculate hash here
	p.c.checkAndPut(&h)
}

func (p *saltedCachePusher) push() {
	var d [crypto.DigestSize]byte
	crypto.RandBytes(d[:])
	p.c.checkAndPut(d[:]) // saltedCache hashes inside
}

func BenchmarkDigestCaches(b *testing.B) {
	deadlockDisable := deadlock.Opts.Disable
	deadlock.Opts.Disable = true
	defer func() {
		deadlock.Opts.Disable = deadlockDisable
	}()

	digestCacheMaker := digestCacheMaker{}
	saltedCacheMaker := saltedCacheMaker{}
	var benchmarks = []struct {
		maker      cacheMaker
		numThreads int
	}{
		{digestCacheMaker, 1},
		{saltedCacheMaker, 1},
		{digestCacheMaker, 4},
		{saltedCacheMaker, 4},
		{digestCacheMaker, 16},
		{saltedCacheMaker, 16},
		{digestCacheMaker, 128},
		{saltedCacheMaker, 128},
	}
	for _, bench := range benchmarks {
		b.Run(fmt.Sprintf("%T/threads=%d", bench.maker, bench.numThreads), func(b *testing.B) {
			benchmarkDigestCache(b, bench.maker, bench.numThreads)
		})
	}
}

func calcCacheSize(numIter int) int {
	size := numIter / 3 // in order to exercise map swaps
	if size == 0 {
		size++
	}
	return size
}

func benchmarkDigestCache(b *testing.B, m cacheMaker, numThreads int) {
	p := m.make(calcCacheSize(b.N))
	numHashes := b.N / numThreads // num hashes per goroutine
	// b.Logf("inserting %d (%d) values in %d threads into cache of size %d", b.N, numHashes, numThreads, calcCacheSize(b.N))
	var wg sync.WaitGroup
	wg.Add(numThreads)
	for i := 0; i < numThreads; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numHashes; j++ {
				p.push()
			}
		}()
	}
	wg.Wait()
}
