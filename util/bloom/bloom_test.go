// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bloom

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"encoding/json"
	"log"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
)

func TestBitset(t *testing.T) {
	f := New(1024, 4, 1234)
	for i := uint32(0); i < 1024; i++ {
		if f.test(i) {
			t.Fatalf("bit %d should not be set: %#v", i, f.data)
		}
		f.set(i)
		if !f.test(i) {
			t.Fatalf("bit %d should be set", i)
		}
	}
}

func TestFilter(t *testing.T) {
	f := New(1024, 4, 1234)
	if f.Test([]byte("foo")) {
		t.Fatalf("foo not expected")
	}
	f.Set([]byte("foo"))
	if !f.Test([]byte("foo")) {
		t.Fatalf("foo expected")
	}
}

func TestOptimal(t *testing.T) {
	numElementsCases := []int{2000, 20000, 200000}
	fpRateCases := []float64{0.001, 0.00001, 0.0000001}
	// increasing numFP can reduce error, but makes the tests take longer
	numFP := []int{100, 25, 5}

	if testing.Short() {
		numElementsCases = []int{2000, 200000}
		fpRateCases = []float64{0.001, 0.00001}
		numFP = []int{100, 25}
	}

	for _, numElements := range numElementsCases {
		for i, fpRate := range fpRateCases {
			numBits, numHashes := Optimal(numElements, fpRate)
			f := New(numBits, numHashes, 1234)
			actualRate := f.estimateFalsePositiveRate(uint32(numElements), numFP[i])
			if actualRate < fpRate {
				if testing.Verbose() {
					log.Printf("\tok: numElements=%v want %v, got %v", numElements, fpRate, actualRate)
				}
				continue
			}
			ok, err := closeEnough(fpRate, actualRate, 0.20)
			if ok {
				if testing.Verbose() {
					log.Printf("\tok: numElements=%v want %v, got %v (%.2f%% error)", numElements, fpRate, actualRate, err*100)
				}
				continue
			}

			t.Fatalf("numElements=%v want %v, got %v (%.2f%% error)", numElements, fpRate, actualRate, err*100)
		}
	}
}

func closeEnough(a, b, maxerr float64) (bool, float64) {
	var relerr float64
	if math.Abs(b) > math.Abs(a) {
		relerr = math.Abs((a - b) / b)
	} else {
		relerr = math.Abs((a - b) / a)
	}
	if relerr <= maxerr {
		return true, relerr
	}
	return false, relerr
}

// based on "github.com/willf/bloom"
func (f *Filter) estimateFalsePositiveRate(numAdded uint32, numFP int) float64 {
	x := make([]byte, 4)
	for i := uint32(0); i < numAdded; i++ {
		binary.BigEndian.PutUint32(x, i)
		f.Set(x)
	}

	falsePositives := 0
	numRounds := 0
	for i := uint32(0); falsePositives < numFP; i++ {
		binary.BigEndian.PutUint32(x, numAdded+i+1)
		if f.Test(x) {
			falsePositives++
		}
		numRounds++
	}

	return float64(falsePositives) / float64(numRounds)
}

func TestOptimalSize(t *testing.T) {
	// These are the parameters we use in the Alpenhorn paper.
	numElements := 150000
	numBits, numHashes := Optimal(numElements, 1e-10)
	f := New(numBits, numHashes, 1234)
	bs, _ := f.MarshalBinary()
	bitsPerElement := math.Ceil(float64(len(bs)) * 8.0 / float64(numElements))
	if bitsPerElement != 48 {
		t.Fatalf("got %v bits per element, want %v", bitsPerElement, 48)
	}
}

func TestIncompressible(t *testing.T) {
	numElements := 150000
	numBits, numHashes := Optimal(numElements, 1e-10)
	filter := New(numBits, numHashes, 1234)
	x := make([]byte, 4)
	for i := uint32(0); i < uint32(numElements); i++ {
		binary.BigEndian.PutUint32(x, i)
		filter.Set(x)
	}
	filterBytes, _ := filter.MarshalBinary()

	compressed := new(bytes.Buffer)
	w, _ := flate.NewWriter(compressed, 9)
	w.Write(filterBytes)
	w.Close()
	if compressed.Len() < len(filterBytes)*99/100 {
		t.Fatalf("Compressed %d -> %d", len(filterBytes), compressed.Len())
	}
}

func TestMarshalJSON(t *testing.T) {
	filter := New(1000, 6, 1234)
	filter.Set([]byte("hello"))
	data, err := json.Marshal(filter)
	if err != nil {
		t.Fatal(err)
	}

	filter2, err := UnmarshalJSON(data)
	if err != nil {
		t.Fatal(err)
	}

	if !filter2.Test([]byte("hello")) {
		t.Fatal("item not in filter")
	}

	if filter.numHashes != filter2.numHashes {
		t.Fatalf("numHashes differ: %d != %d", filter.numHashes, filter2.numHashes)
	}
	if !bytes.Equal(filter.data, filter2.data) {
		t.Fatalf("filter bytes differ")
	}
}

func BenchmarkCreateLargeFilter(b *testing.B) {
	// dialing mu=25000; 3 servers; so each mailbox is 75000 real and 75000 noise
	// for a total of 150000 elements in the dialing bloom filter
	numElements := 150000
	for i := 0; i < b.N; i++ {
		numBits, numHashes := Optimal(numElements, 1e-10)
		f := New(numBits, numHashes, 1234)
		x := make([]byte, 4)
		for i := uint32(0); i < uint32(numElements); i++ {
			binary.BigEndian.PutUint32(x, i)
			f.Set(x)
		}
	}
}

func TestMaxHashes(t *testing.T) {
	// These are the parameters we use in the Alpenhorn paper.
	numElements := 150000
	_, numHashes := Optimal(numElements, 1e-100)
	if numHashes > maxHashes {
		t.Fatalf("too many hashes")
	}

	filter := New(1000, 6, 1234)
	filter.Set([]byte("hello"))

	filter.numHashes = maxHashes
	data, err := json.Marshal(filter)
	if err != nil {
		t.Fatal(err)
	}

	filter, err = UnmarshalJSON(data)
	if err != nil {
		t.Fatal(err)
	}

	filter.numHashes = maxHashes + 1
	data, err = json.Marshal(filter)
	if err != nil {
		t.Fatal(err)
	}

	filter, err = UnmarshalJSON(data)
	if err == nil {
		t.Fatal("unmarshal: too many hashes")
	}
}

// The goal of the TestEmptyFilter is to ensure that if we receive any subset of a bloom filter
// unmarshaled data stream, we can still call Test safely. If the unmarshaling fails, that's ok.
// This test was implemented as an attempt to ensure that the data member is always non-empty.
func TestEmptyFilter(t *testing.T) {
	blm := New(200, 16, 1234)
	marshaled, _ := blm.MarshalBinary()
	for i := 0; i < len(marshaled); i++ {
		f, err := UnmarshalBinary(marshaled[0:i])
		if err != nil {
			continue
		}
		f.Test([]byte{1, 2, 3, 4, 5})
	}
}

// TestBinaryMarshalLength tests various sizes of bloom filters and ensures that the encoded binary
// size is equal to the one reported by BinaryMarshalLength.
func TestBinaryMarshalLength(t *testing.T) {
	for _, elementCount := range []int{2, 16, 1024, 32768, 5101, 100237, 144539} {
		for _, falsePositiveRate := range []float64{0.2, 0.1, 0.01, 0.001, 0.00001, 0.0000001} {
			sizeBits, numHashes := Optimal(elementCount, falsePositiveRate)
			filter := New(sizeBits, numHashes, 1234)
			require.NotNil(t, filter)
			bytes, err := filter.MarshalBinary()
			require.NoError(t, err)
			require.NotZero(t, len(bytes))
			calculatedBytesLength := BinaryMarshalLength(elementCount, falsePositiveRate)
			require.Equal(t, calculatedBytesLength, int64(len(bytes)))
		}
	}
}

func TestBloomFilterMemoryConsumption(t *testing.T) {
	t.Run("Set", func(t *testing.T) {
		N := 1000000
		sizeBits, numHashes := Optimal(N, 0.01)
		prefix := uint32(0)
		bf := New(sizeBits, numHashes, prefix)

		dataset := make([][]byte, N)
		for n := 0; n < N; n++ {
			hash := crypto.Hash([]byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)})
			dataset[n] = hash[:]
		}

		result := testing.Benchmark(func(b *testing.B) {
			// start this test with 10K iterations.
			if b.N < 10000 {
				b.N = 10000
			}

			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				bf.Set(dataset[n%N])
			}
		})

		// make sure the memory allocated is less than 1 byte / iteration.
		require.LessOrEqual(t, uint64(result.MemBytes), uint64(result.N))
	})
	t.Run("Test", func(t *testing.T) {
		N := 1000000
		sizeBits, numHashes := Optimal(N, 0.01)
		prefix := uint32(0)
		bf := New(sizeBits, numHashes, prefix)

		dataset := make([][]byte, N)
		for n := 0; n < N; n++ {
			hash := crypto.Hash([]byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)})
			dataset[n] = hash[:]
		}

		// set half of them.
		for n := 0; n < N/2; n++ {
			bf.Set(dataset[n])
		}
		result := testing.Benchmark(func(b *testing.B) {
			// start this test with 10K iterations.
			if b.N < 1000000 {
				b.N = 1000000
			}

			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				bf.Test(dataset[n%N])
			}
		})

		// make sure the memory allocated is less than 1 byte / iteration.
		require.LessOrEqual(t, uint64(result.MemBytes), uint64(result.N))
	})
}
