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

package agreement

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCredentialHistoryStore(t *testing.T) {
	size := 5
	buffer := newCredentialArrivalHistory(size)
	// last store call overwrites the first one
	for i := 0; i < size+1; i++ {
		buffer.store(time.Duration(i))
	}

	require.True(t, buffer.isFull())
	require.Equal(t, time.Duration(size), buffer.history[0])
	for i := 1; i < size; i++ {
		require.Equal(t, time.Duration(i), buffer.history[i])
	}
}

func TestCredentialHistoryReset(t *testing.T) {
	size := 5
	buffer := newCredentialArrivalHistory(size)
	// last store call overwrites the first one
	for i := 0; i < size+1; i++ {
		buffer.store(time.Duration(i))
	}

	require.Equal(t, time.Duration(size), buffer.history[0])
	for i := 1; i < size; i++ {
		require.Equal(t, time.Duration(i), buffer.history[i])
	}
	require.True(t, buffer.isFull())
	buffer.reset()
	require.False(t, buffer.isFull())
	buffer.store(time.Duration(100))
	require.Equal(t, time.Duration(100), buffer.history[0])
}

func TestCredentialHistoryIsFull(t *testing.T) {
	var buffer *credentialArrivalHistory
	require.False(t, buffer.isFull())

	size := 5
	buffer = newCredentialArrivalHistory(size)
	require.False(t, buffer.isFull())

	for i := 0; i < size+10; i++ {
		buffer.store(time.Duration(i))
		if i < size-1 {
			require.False(t, buffer.isFull())
		} else {
			require.True(t, buffer.isFull())
		}
	}
}

func TestOrderStatistics(t *testing.T) {
	size := 5
	buffer := newCredentialArrivalHistory(size)
	require.False(t, buffer.isFull())

	for i := 0; i < size; i++ {
		buffer.store(time.Duration(size - i))
	}
	require.True(t, buffer.isFull())

	for i := 0; i < size; i++ {
		require.Equal(t, time.Duration(i+1), buffer.orderStatistics(i))
	}
}
