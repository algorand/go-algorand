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

package network

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
   "github.com/algorand/go-algorand/testPartitioning"
)

func TestLimitedReaderSlurper(t *testing.T) {
   testPartitioning.PartitionTest(t)

	for _, arraySize := range []uint64{30000, 90000, 200000} {
		// create a random bytes array.
		bytesBlob := make([]byte, arraySize)
		crypto.RandBytes(bytesBlob[:])
		for baseBufferSize := uint64(0); baseBufferSize < uint64(len(bytesBlob)); baseBufferSize += 731 {
			for _, maxSize := range []uint64{arraySize - 10000, arraySize, arraySize + 10000} {
				buffer := bytes.NewBuffer(bytesBlob)
				reader := MakeLimitedReaderSlurper(baseBufferSize, maxSize)
				err := reader.Read(buffer)
				if maxSize < uint64(len(bytesBlob)) {
					require.Equal(t, ErrIncomingMsgTooLarge, err)
					continue
				}

				require.NoError(t, err)
				bytes := reader.Bytes()
				require.Equal(t, bytesBlob, bytes)
			}
		}
	}
}

type fuzzReader struct {
	pos int
	buf []byte
}

func (f *fuzzReader) Read(b []byte) (n int, err error) {
	s := int(crypto.RandUint64() % 19)
	if s > len(b) {
		s = len(b)
	}
	if f.pos >= len(f.buf) {
		return 0, io.EOF
	}
	if f.pos+s >= len(f.buf) {
		// we want a chunk that ends at ( or after ) the end of the data.
		n = len(f.buf) - f.pos
		err = io.EOF
	} else {
		n = s
	}
	copy(b, f.buf[f.pos:f.pos+n])
	f.pos += n
	return
}

func TestLimitedReaderSlurper_FuzzedBlippedSource(t *testing.T) {
   testPartitioning.PartitionTest(t)

	arraySize := uint64(300000)
	bytesBlob := make([]byte, arraySize)
	crypto.RandBytes(bytesBlob[:])
	for i := 0; i < 500; i++ {
		for _, maxSize := range []uint64{arraySize - 10000, arraySize, arraySize + 10000} {
			reader := MakeLimitedReaderSlurper(512, maxSize)
			err := reader.Read(&fuzzReader{buf: bytesBlob})
			if maxSize < uint64(len(bytesBlob)) {
				require.Equal(t, ErrIncomingMsgTooLarge, err, "i: %d\nmaxSize: %d", i, maxSize)
				continue
			}
			require.NoError(t, err)
			bytes := reader.Bytes()
			require.Equal(t, bytesBlob, bytes)
		}
	}
}

func benchmarkLimitedReaderSlurper(b *testing.B, arraySize uint64) {
	bytesBlob := make([]byte, arraySize)
	crypto.RandBytes(bytesBlob[:])
	readers := make([]*LimitedReaderSlurper, b.N)
	buffers := make([]*bytes.Buffer, b.N)
	for i := 0; i < b.N; i++ {
		buffers[i] = bytes.NewBuffer(bytesBlob)
		readers[i] = MakeLimitedReaderSlurper(1024, 1024*1024)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := readers[i]
		err := reader.Read(buffers[i])
		require.NoError(b, err)
		reader.Bytes()
		reader.Reset()
	}
}
func BenchmarkLimitedReaderSlurper(b *testing.B) {
	for _, arraySize := range []uint64{200, 2048, 300000} {
		b.Run(fmt.Sprintf("%dbytes_message", arraySize), func(b *testing.B) {
			benchmarkLimitedReaderSlurper(b, arraySize)
		})
	}
}

func TestLimitedReaderSlurperMemoryConsumption(t *testing.T) {
   testPartitioning.PartitionTest(t)

	for _, arraySize := range []uint64{1024, 2048, 65536, 1024 * 1024} {
		result := testing.Benchmark(func(b *testing.B) {
			benchmarkLimitedReaderSlurper(b, arraySize)
		})
		require.True(t, uint64(result.AllocedBytesPerOp()) < 2*arraySize+allocationStep, "AllocedBytesPerOp:%d\nmessage size:%d", result.AllocedBytesPerOp(), arraySize)
	}
}

func TestLimitedReaderSlurperBufferAllocations(t *testing.T) {
   testPartitioning.PartitionTest(t)

	for baseAllocation := uint64(512); baseAllocation < 100000; baseAllocation += 2048 {
		for maxAllocation := uint64(512); maxAllocation < 100000; maxAllocation += 512 {
			lrs := MakeLimitedReaderSlurper(baseAllocation, maxAllocation)
			// check to see if the allocated buffers count is exactly what needed to match the allocation needs.
			allocationNeeds := 1
			remainingBytes := int64(maxAllocation - baseAllocation)
			for remainingBytes > 0 {
				allocationNeeds++
				remainingBytes -= int64(allocationStep)
			}
			require.Equal(t, allocationNeeds, len(lrs.buffers))

		}
	}
}
