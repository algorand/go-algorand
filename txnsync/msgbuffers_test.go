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

package txnsync

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestMessageBuffersPool tests that a buffer pool can be retrieved and has proper length/capacity properties
func TestMessageBuffersPool(t *testing.T) {
	partitiontest.PartitionTest(t)

	for i := 0; i < 10; i++ {
		bytes := getMessageBuffer()
		require.Equal(t, 0, len(bytes))
		require.GreaterOrEqual(t, cap(bytes), messageBufferDefaultInitialSize)

		releaseMessageBuffer(bytes)
	}

}

// TestTxIDSlicePool tests that the transaction id pool can be retrieved and has proper length/capacity properties
func TestTxIDSlicePool(t *testing.T) {
	partitiontest.PartitionTest(t)

	for i := 10; i < 100; i += 10 {
		txIDs := getTxIDSliceBuffer(i)
		require.Equal(t, 0, len(txIDs))
		require.GreaterOrEqual(t, cap(txIDs), i)
		releaseTxIDSliceBuffer(txIDs)

	}

	// Test that one of the previous buffers can be reused
	txIDs := getTxIDSliceBuffer(5)
	require.Equal(t, 0, len(txIDs))
	require.GreaterOrEqual(t, cap(txIDs), 5)
	releaseTxIDSliceBuffer(txIDs)

}
