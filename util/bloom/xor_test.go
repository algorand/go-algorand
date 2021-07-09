// Copyright (C) 2019-2021 Algorand, Inc.
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

package bloom

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"runtime"
	"testing"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/xorfilter"
	"github.com/stretchr/testify/require"
)

func TestXorBloom(t *testing.T) {
	t.Parallel()
	numElementsCases := []int{2000, 20000, 200000}
	fpRateCases := []float64{0.0042} //, 0.00001, 0.0000001}
	numFP := []int{100, 25, 5}
	if testing.Short() {
		numElementsCases = []int{2000, 20000}
		numFP = []int{100, 25}
	}
	for _, numElements := range numElementsCases {
		for i, fpRate := range fpRateCases {
			actualRate := estimateFalsePositiveRateXor(t, numElements, numFP[i])
			if actualRate < fpRate {
				t.Logf("\tOK: numElements=%v want %v, got %v", numElements, fpRate, actualRate)
				continue
			}

			t.Errorf("numElements=%v want %v, got %v", numElements, fpRate, actualRate)
		}
	}
}

// like bloom_test.go estimateFalsePositiveRate()
// based on "github.com/willf/bloom"
func estimateFalsePositiveRateXor(t *testing.T, numAdded int, numFP int) float64 {
	var xf XorFilter
	maxDuration := 5 * time.Second
	if testing.Short() {
		maxDuration = 100 * time.Millisecond
	}
	x := make([]byte, 8)
	for i := 0; i < numAdded; i++ {
		binary.BigEndian.PutUint32(x, uint32(i))
		xf.Set(x)
	}

	xord, err := xf.MarshalBinary()
	require.NoError(t, err)
	var nxf XorFilter8
	err = nxf.UnmarshalBinary(xord)
	require.NoError(t, err)

	start := time.Now()
	falsePositives := 0
	numRounds := 0
	for i := 0; falsePositives < numFP; i++ {
		binary.BigEndian.PutUint32(x, uint32(numAdded+i+1))
		if nxf.Test(x) {
			falsePositives++
		}
		numRounds++
		if numRounds%10000 == 0 {
			dt := time.Now().Sub(start)
			if dt > maxDuration {
				t.Logf("t %s > max duration %s without finding false positive rate", dt, maxDuration)
				break
			}
		}
	}

	return float64(falsePositives) / float64(numRounds)
}

func TestByte32FalsePositive(t *testing.T) {
	t.Parallel()
	var filterSizes = []int{1000, 5000, 10000, 50000, 100000}
	for _, filterSetSize := range filterSizes {
		//const filterSetSize = 100000
		txids := make([][]byte, filterSetSize)
		store := make([]byte, 32*filterSetSize)
		rand.Read(store)
		for i := 0; i < filterSetSize; i++ {
			txids[i] = store[i*32 : (i+1)*32]
		}

		notIn := func(t []byte) bool {
			for _, v := range txids {
				if bytes.Equal(t, v) {
					return false
				}
			}
			return true
		}

		var xf XorFilter

		fpRate := 0.01
		//fpRate := 0.004
		numBits, numHashes := Optimal(filterSetSize, fpRate)
		bf := New(numBits, numHashes, 0x12345678)

		for _, v := range txids {
			xf.Set(v)
			bf.Set(v)
		}

		xord, err := xf.MarshalBinary()
		require.NoError(t, err)
		var nxf XorFilter
		err = nxf.UnmarshalBinary(xord)
		require.NoError(t, err)

		bloomData, err := bf.MarshalBinary()
		require.NoError(t, err)

		t.Logf("filter for %d * [32]byte, bloom %d bytes, xor8 %d bytes",
			filterSetSize, len(bloomData), len(xord))

		xfalsePositives := 0
		bfalsePositives := 0
		const testN = 100000
		var tt [32]byte
		for i := 0; i < testN; i++ {
			rand.Read(tt[:])
			xhit := nxf.Test(tt[:])
			bhit := bf.Test(tt[:])
			if xhit || bhit {
				falsePositive := notIn(tt[:])
				if xhit && falsePositive {
					xfalsePositives++
				}
				if bhit && falsePositive {
					bfalsePositives++
				}
			}
		}

		t.Logf("false positives bloom %d/%d, xor %d/%d", bfalsePositives, testN, xfalsePositives, testN)
		bfp := float64(bfalsePositives) / float64(testN)
		xfp := float64(xfalsePositives) / float64(testN)
		if bfp > (fpRate * 1.2) {
			t.Errorf("bloom false positive too high: %f", bfp)
		}
		if xfp > (fpRate * 1.2) {
			t.Errorf("xor false positive too high: %f", xfp)
		}
	}
}

type GenericFilterFactory func() GenericFilter

func memTestFilter(t *testing.T, filterFactory GenericFilterFactory, filterSetSize int) {
	// setup
	txids := make([][]byte, filterSetSize)
	store := make([]byte, 32*filterSetSize)
	rand.Read(store)
	for i := 0; i < filterSetSize; i++ {
		txids[i] = store[i*32 : (i+1)*32]
	}
	runtime.GC()

	var memAfterSetup runtime.MemStats
	runtime.ReadMemStats(&memAfterSetup)

	f := filterFactory()
	for _, v := range txids {
		f.Set(v)
	}
	data, err := f.MarshalBinary()
	require.NoError(t, err)

	var memAfterSerialize runtime.MemStats
	runtime.ReadMemStats(&memAfterSerialize)

	nf := filterFactory()
	err = nf.UnmarshalBinary(data)
	require.NoError(t, err)

	var memAfterDeserialize runtime.MemStats
	runtime.ReadMemStats(&memAfterDeserialize)

	t.Logf("build mem[%d]: %s", filterSetSize, memDelta(&memAfterSetup, &memAfterSerialize))
	t.Logf("load  mem[%d]: %s", filterSetSize, memDelta(&memAfterSerialize, &memAfterDeserialize))
}

func memDelta(a, b *runtime.MemStats) string {
	dMallocs := b.Mallocs - a.Mallocs
	dFrees := b.Frees - a.Frees
	dAllocated := b.HeapAlloc - a.HeapAlloc
	return fmt.Sprintf("%d mallocs, %d frees, %d bytes allocated", dMallocs, dFrees, dAllocated)
}

func TestMemXor(t *testing.T) {
	t.Parallel()
	var xb xorfilter.Builder
	xff := func() GenericFilter {
		xf := NewXor(5000, &xb)
		return xf
	}
	memTestFilter(t, xff, 5000)
	memTestFilter(t, xff, 5000)
}

func TestMemBloom(t *testing.T) {
	t.Parallel()
	fpRate := 0.004
	filterSetSize := 5000
	numBits, numHashes := Optimal(filterSetSize, fpRate)
	bff := func() GenericFilter {
		return New(numBits, numHashes, 0x12345678)
	}
	memTestFilter(t, bff, filterSetSize)
}

// BenchmarkCreateLargeXorFilter should have the same structure as bloom_test.go BenchmarkCreateLargeBloomFilter
func BenchmarkCreateLargeXorFilter(b *testing.B) {
	// dialing mu=25000; 3 servers; so each mailbox is 75000 real and 75000 noise
	// for a total of 150000 elements in the dialing bloom filter
	var xb xorfilter.Builder
	for i := 0; i < b.N; i++ {
		xf := NewXor(largeFilterElements, &xb)
		x := make([]byte, 8)
		for i := uint32(0); i < uint32(largeFilterElements); i++ {
			binary.BigEndian.PutUint32(x, i)
			xf.Set(x)
		}
		xf.MarshalBinary()
	}
}

// See Also BenchmarkBloomFilterTest
func BenchmarkXorFilterTest(b *testing.B) {
	// sizeBits, numHashes := Optimal(filterTestElements, 0.01)
	// prefix := uint32(0)
	// bf := New(sizeBits, numHashes, prefix)
	var xf XorFilter
	dataset := make([][]byte, filterTestElements)
	for n := 0; n < filterTestElements; n++ {
		hash := crypto.Hash([]byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)})
		dataset[n] = hash[:]
	}
	// set half of them.
	for n := 0; n < filterTestElements/2; n++ {
		xf.Set(dataset[n])
	}

	xord, err := xf.MarshalBinary()
	require.NoError(b, err)
	var nxf XorFilter
	err = nxf.UnmarshalBinary(xord)
	require.NoError(b, err)

	b.ResetTimer()
	for x := 0; x < b.N; x++ {
		nxf.Test(dataset[x%filterTestElements])
	}
}
