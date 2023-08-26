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
