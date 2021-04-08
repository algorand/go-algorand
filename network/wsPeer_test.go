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
	"encoding/binary"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestCheckSlowWritingPeer(t *testing.T) {
	now := time.Now()
	peer := wsPeer{
		intermittentOutgoingMessageEnqueueTime: 0,
	}
	require.Equal(t, peer.CheckSlowWritingPeer(now), false)

	peer.intermittentOutgoingMessageEnqueueTime = now.UnixNano()
	require.Equal(t, peer.CheckSlowWritingPeer(now), false)

	peer.intermittentOutgoingMessageEnqueueTime = now.Add(-maxMessageQueueDuration * 2).UnixNano()
	require.Equal(t, peer.CheckSlowWritingPeer(now), true)

}

// TestGetRequestNonce tests if unique values are generated each time
func TestGetRequestNonce(t *testing.T) {
	numValues := 1000
	peer := wsPeer{}
	valueChannel := make(chan uint64, numValues)
	for x := 0; x < numValues; x++ {
		go func() {
			ans := peer.getRequestNonce()
			val, _ := binary.Uvarint(ans)
			valueChannel <- val
		}()
	}

	// Timeout
	maxWait := time.After(2 * time.Second)

	// check if all the values are unique
	seenValue := make([]bool, numValues+1)
	for x := 0; x < numValues; x++ {
		select {
		case val := <-valueChannel:
			require.Equal(t, false, seenValue[val])
			seenValue[val] = true
		case <-maxWait:
			break
		}
	}
	// Check if all the values were generated
	for x := 1; x <= numValues; x++ {
		require.Equal(t, true, seenValue[x])
	}
}

func TestDefaultMessageTagsLength(t *testing.T) {
	for tag := range defaultSendMessageTags {
		require.Equal(t, 2, len(tag))
	}
}

// TestRequestNonceOffset ensures that the requestNonce is on a 64-bit
// offset, which is needed so that we can use atomic on arm platform.
func TestAtomicVariablesAligment(t *testing.T) {
	p := wsPeer{}
	require.True(t, (unsafe.Offsetof(p.requestNonce)%8) == 0)
	require.True(t, (unsafe.Offsetof(p.lastPacketTime)%8) == 0)
	require.True(t, (unsafe.Offsetof(p.intermittentOutgoingMessageEnqueueTime)%8) == 0)
}
