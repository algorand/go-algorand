// Copyright (C) 2019-2023 Algorand, Inc.
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
	require.Zero(t, cache.Len())

	// add some unique random
	var ds [size]crypto.Digest
	for i := 0; i < size; i++ {
		crypto.RandBytes([]byte(ds[i][:]))
		exist := cache.CheckAndPut(&ds[i])
		require.False(t, exist)

		exist = cache.check(&ds[i])
		require.True(t, exist)
	}

	require.Equal(t, size, cache.Len())

	// try to re-add, ensure not added
	for i := 0; i < size; i++ {
		exist := cache.CheckAndPut(&ds[i])
		require.True(t, exist)
	}

	require.Equal(t, size, cache.Len())

	// add some more and ensure capacity switch
	var ds2 [size]crypto.Digest
	for i := 0; i < size; i++ {
		crypto.RandBytes(ds2[i][:])
		exist := cache.CheckAndPut(&ds2[i])
		require.False(t, exist)

		exist = cache.check(&ds2[i])
		require.True(t, exist)
	}

	require.Equal(t, 2*size, cache.Len())

	var d crypto.Digest
	crypto.RandBytes(d[:])
	exist := cache.CheckAndPut(&d)
	require.False(t, exist)
	exist = cache.check(&d)
	require.True(t, exist)

	require.Equal(t, size+1, cache.Len())

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

	// check deletion works
	for i := 0; i < size; i++ {
		cache.Delete(&ds[i])
		cache.Delete(&ds2[i])
	}

	require.Equal(t, 1, cache.Len())

	cache.Delete(&d)
	require.Equal(t, 0, cache.Len())
}

func (c *txSaltedCache) check(msg []byte) bool {
	_, _, _, found := c.innerCheck(msg)
	return found
}

// TestTxHandlerSaltedCacheBasic is the same as TestTxHandlerDigestCache but for the salted cache
func TestTxHandlerSaltedCacheBasic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const size = 20
	cache := makeSaltedCache(size)
	cache.Start(context.Background(), 0)
	require.Zero(t, cache.Len())

	// add some unique random
	var ds [size][8]byte
	var ks [size]*crypto.Digest
	var exist bool
	for i := 0; i < size; i++ {
		crypto.RandBytes([]byte(ds[i][:]))
		ks[i], _, exist = cache.CheckAndPut(ds[i][:], struct{}{})
		require.False(t, exist)
		require.NotEmpty(t, ks[i])

		exist = cache.check(ds[i][:])
		require.True(t, exist)
	}

	require.Equal(t, size, cache.Len())

	// try to re-add, ensure not added
	for i := 0; i < size; i++ {
		k, _, exist := cache.CheckAndPut(ds[i][:], struct{}{})
		require.True(t, exist)
		require.NotEmpty(t, k)
	}

	require.Equal(t, size, cache.Len())

	// add some more and ensure capacity switch
	var ds2 [size][8]byte
	var ks2 [size]*crypto.Digest
	for i := 0; i < size; i++ {
		crypto.RandBytes(ds2[i][:])
		ks2[i], _, exist = cache.CheckAndPut(ds2[i][:], struct{}{})
		require.False(t, exist)
		require.NotEmpty(t, ks2[i])

		exist = cache.check(ds2[i][:])
		require.True(t, exist)
	}

	require.Equal(t, 2*size, cache.Len())

	var d [8]byte
	crypto.RandBytes(d[:])
	k, _, exist := cache.CheckAndPut(d[:], struct{}{})
	require.False(t, exist)
	require.NotEmpty(t, k)
	exist = cache.check(d[:])
	require.True(t, exist)

	require.Equal(t, size+1, cache.Len())

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

	// check deletion works
	for i := 0; i < size; i++ {
		cache.DeleteByKey(ks[i])
		cache.DeleteByKey(ks2[i])
	}

	require.Equal(t, 1, cache.Len())

	cache.DeleteByKey(k)
	require.Equal(t, 0, cache.Len())
}

func TestTxHandlerSaltedCacheScheduled(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const size = 20
	updateInterval := 1000 * time.Microsecond
	cache := makeSaltedCache(size)
	cache.Start(context.Background(), updateInterval)
	require.Zero(t, cache.Len())

	// add some unique random
	var ds [size][8]byte
	for i := 0; i < size; i++ {
		crypto.RandBytes([]byte(ds[i][:]))
		k, _, exist := cache.CheckAndPut(ds[i][:], struct{}{})
		require.False(t, exist)
		require.NotEmpty(t, k)

		if rand.Int()%2 == 0 {
			time.Sleep(updateInterval / 2)
		}
	}

	require.Less(t, cache.Len(), size)
}

func TestTxHandlerSaltedCacheManual(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const size = 20
	cache := makeSaltedCache(2 * size)
	cache.Start(context.Background(), 0)
	require.Zero(t, cache.Len())

	// add some unique random
	var ds [size][8]byte
	for i := 0; i < size; i++ {
		crypto.RandBytes([]byte(ds[i][:]))
		k, _, exist := cache.CheckAndPut(ds[i][:], struct{}{})
		require.False(t, exist)
		require.NotEmpty(t, k)
		exist = cache.check(ds[i][:])
		require.True(t, exist)
	}

	require.Equal(t, size, cache.Len())

	// rotate and add more data
	cache.Remix()

	var ds2 [size][8]byte
	for i := 0; i < size; i++ {
		crypto.RandBytes([]byte(ds2[i][:]))
		k, _, exist := cache.CheckAndPut(ds2[i][:], struct{}{})
		require.False(t, exist)
		require.NotEmpty(t, k)
		exist = cache.check(ds2[i][:])
		require.True(t, exist)
	}
	require.Equal(t, 2*size, cache.Len())

	// ensure the old data still in
	for i := 0; i < size; i++ {
		exist := cache.check(ds[i][:])
		require.True(t, exist)
	}

	// rotate again, check only new data left
	cache.Remix()

	require.Equal(t, size, cache.Len())
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
	scp := &saltedCachePusher{c: makeSaltedCache(size)}
	scp.c.Start(context.Background(), 0)
	return scp
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
	p.c.CheckAndPut(&h)
}

func (p *saltedCachePusher) push() {
	var d [crypto.DigestSize]byte
	crypto.RandBytes(d[:])
	p.c.CheckAndPut(d[:], struct{}{}) // saltedCache hashes inside
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

// TestTxHandlerSaltedCacheValues checks values are stored correctly
func TestTxHandlerSaltedCacheValues(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const size = 2
	cache := makeSaltedCache(size)
	cache.Start(context.Background(), 0)
	require.Zero(t, cache.Len())

	smapLenEqual := func(t *testing.T, smap *sync.Map, expectedLen int) {
		t.Helper()
		actualLen := 0
		smap.Range(func(_, _ interface{}) bool {
			actualLen++
			return true
		})
		require.Equal(t, expectedLen, actualLen)
	}

	smapContains := func(t *testing.T, smap *sync.Map, key interface{}) {
		t.Helper()
		_, ok := smap.Load(key)
		require.True(t, ok)
	}

	type snd struct {
		id int
	}

	d, v, p, found := cache.innerCheck([]byte{1})
	require.False(t, found)
	require.Nil(t, p)
	require.Nil(t, v)
	require.NotNil(t, d)
	require.NotEmpty(t, d)

	// add a value, ensure it can be found
	d1, v1, found := cache.CheckAndPut([]byte{1}, snd{id: 1})
	require.False(t, found)
	require.NotNil(t, d1)
	require.NotEmpty(t, d1)
	d, v, p, found = cache.innerCheck([]byte{1})
	require.True(t, found)
	require.NotNil(t, p)
	require.NotNil(t, v)
	require.NotNil(t, d)
	require.Equal(t, *d, *d1)
	require.Equal(t, p, &cache.cur)
	require.Equal(t, *p, cache.cur)
	require.Len(t, *p, 1)
	smapLenEqual(t, v, 1)
	require.Equal(t, v, v1)
	smapContains(t, v, snd{id: 1})
	d, v, found = cache.CheckAndPut([]byte{1}, snd{id: 1})
	require.True(t, found)
	require.NotNil(t, d)
	require.NotEmpty(t, d)
	require.Equal(t, *d, *d1)
	require.Equal(t, v, v1)
	require.Len(t, cache.cur, 1)
	smapLenEqual(t, cache.cur[*d], 1)
	require.Nil(t, cache.prev)

	// add a value with different sender
	dt, vt, found := cache.CheckAndPut([]byte{1}, snd{id: 2})
	require.True(t, found)
	require.NotNil(t, dt)
	require.NotEmpty(t, dt)
	require.Nil(t, cache.prev)
	d, v, p, found = cache.innerCheck([]byte{1})
	require.True(t, found)
	require.NotNil(t, p)
	require.NotNil(t, v)
	require.NotNil(t, d)
	require.Equal(t, *d, *dt)
	require.Equal(t, *d, *d1)
	require.Equal(t, v, vt)
	require.Equal(t, p, &cache.cur)
	require.Len(t, *p, 1)
	smapLenEqual(t, v, 2)
	smapContains(t, v, snd{id: 1})
	smapContains(t, v, snd{id: 2})

	// add one more value to full cache.cur
	d2, v2, found := cache.CheckAndPut([]byte{2}, snd{id: 1})
	require.False(t, found)
	require.NotNil(t, d2)
	require.NotEmpty(t, d2)
	smapLenEqual(t, v2, 1)
	require.Len(t, cache.cur, 2)
	smapLenEqual(t, cache.cur[*d1], 2)
	smapLenEqual(t, cache.cur[*d2], 1)
	require.Nil(t, cache.prev)

	// adding new value would trigger cache swap
	// first ensure new sender for seen message does not trigger a swap
	dt, vt, found = cache.CheckAndPut([]byte{2}, snd{id: 2})
	require.True(t, found)
	require.NotNil(t, dt)
	require.NotEmpty(t, dt)
	require.Equal(t, *d2, *dt)
	smapLenEqual(t, vt, 2)
	require.Len(t, cache.cur, 2)
	smapLenEqual(t, cache.cur[*d1], 2)
	smapLenEqual(t, cache.cur[*d2], 2)
	require.Nil(t, cache.prev)

	// add a new value triggers a swap
	d3, v3, found := cache.CheckAndPut([]byte{3}, snd{id: 1})
	require.False(t, found)
	require.NotNil(t, d2)
	require.NotEmpty(t, d2)
	smapLenEqual(t, v3, 1)
	require.Len(t, cache.cur, 1)
	smapLenEqual(t, cache.cur[*d3], 1)
	require.Len(t, cache.prev, 2)
	smapLenEqual(t, cache.prev[*d1], 2)
	smapLenEqual(t, cache.prev[*d2], 2)

	// add a sender into old (prev) value
	dt, vt, found = cache.CheckAndPut([]byte{2}, snd{id: 3})
	require.True(t, found)
	require.NotNil(t, dt)
	require.NotEmpty(t, dt)
	require.Equal(t, *d2, *dt)
	require.Len(t, cache.cur, 1)
	smapLenEqual(t, cache.cur[*d3], 1)
	require.Len(t, cache.prev, 2)
	smapLenEqual(t, cache.prev[*d1], 2)
	smapLenEqual(t, cache.prev[*d2], 3)
	d, v, p, found = cache.innerCheck([]byte{2})
	require.True(t, found)
	require.NotNil(t, p)
	require.NotNil(t, v)
	require.NotNil(t, d)
	require.Equal(t, *d, *dt)
	require.Equal(t, *d, *d2)
	require.Equal(t, p, &cache.prev)
	require.Len(t, *p, 2)
	smapLenEqual(t, v, 3)
	require.Equal(t, vt, v)
	smapContains(t, v, snd{id: 3})
}
