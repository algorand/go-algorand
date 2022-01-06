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

package txnsync

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// A unique length that we can use to identify non-default allocated buffers
var uniqueLength int = messageBufferDefaultInitialSize + 482
var uniqueIdentifier int = 50

// Stamp a byte buffer with a unique identifier, assumes a capacity of at least unique_length
func stampBuffer(i int, buf *[]byte) {
	if cap(*buf) < uniqueLength {
		return
	}

	*buf = (*buf)[:cap(*buf)]

	for j := 0; j < i; j++ {
		(*buf)[uniqueLength-1-j] = byte(j)
	}

}

func validBuffer(i int, buf *[]byte) bool {

	if cap(*buf) != uniqueLength {
		return false
	}

	*buf = (*buf)[:cap(*buf)]

	for j := 0; j < i; j++ {
		if (*buf)[uniqueLength-1-j] != byte(j) {
			return false
		}
	}

	return true
}

// TestMessageBuffersPool tests that a buffer pool can be retrieved and has proper length/capacity properties
func TestMessageBuffersPool(t *testing.T) {

	partitiontest.PartitionTest(t)

	foundBuffer := false

	for retryCount := 0; retryCount < 10; retryCount++ {

		// Let's put a bunch of uniquely identifiable buffers in the global pool
		for i := 0; i < 10; i++ {

			bytes := make([]byte, 0, uniqueLength)
			stampBuffer(uniqueIdentifier, &bytes)

			releaseMessageBuffer(bytes)
		}

		collector := [][]byte{}

		// Let's try to get at least one buffer that is uniquely identifiable over a period of time
		for i := 0; i < 10000; i++ {
			byte := getMessageBuffer()

			collector = append(collector, byte)

			if validBuffer(uniqueIdentifier, &byte) {
				foundBuffer = true
				break
			}

			time.Sleep(500 * time.Microsecond)
		}

		for _, b := range collector {
			releaseMessageBuffer(b)
		}

		if foundBuffer {
			// If we found a buffer, we passed the test
			break
		}

		// Otherwise, let's start all over again
	}

	require.True(t, foundBuffer)

}

// TestTxIDSlicePool tests that the transaction id pool can be retrieved and has proper length/capacity properties
func TestTxIDSlicePool(t *testing.T) {
	partitiontest.PartitionTest(t)
	maxTestCount := 200
	for testCount := 0; testCount < maxTestCount; testCount++ {
		for i := 10; i < 100; i += 10 {
			txIDs := getTxIDSliceBuffer(i)
			require.Equal(t, 0, len(txIDs))
			require.GreaterOrEqual(t, cap(txIDs), i)
			releaseTxIDSliceBuffer(txIDs)
		}

		// Test that one of the previous buffers can be reused
		// We can assess this because all the previous buffers created
		// had a capacity greater than 10, so if one of these buffers
		// has a buffer size of at least 10 (when we asked for 5), we can
		// be assured that we have reused a previous buffer
		txIDs := getTxIDSliceBuffer(5)
		require.Equal(t, 0, len(txIDs))
		require.GreaterOrEqual(t, cap(txIDs), 5)
		if cap(txIDs) < 10 {
			// repeat this test again. it looks like the GC collected all the content
			// of the pool and forced us to allocate a new buffer.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		releaseTxIDSliceBuffer(txIDs)
		return
	}
	require.FailNow(t, "failed to get a 5 entries buffer from slice pool")
}
