// Copyright (C) 2019-2020 Algorand, Inc.
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

// TestGetNonce tests if the values are incremented correctly
func TestGetNonce(t *testing.T) {
	peer := wsPeer{}
	doneChannel := make(chan bool, 1)
	for x := 0; x < 200; x++ {
		go func() {
			ans := peer.getNonce()
			val, _ := binary.Uvarint(ans)
			if val == 200 {
				doneChannel <- true
			}
		}()
	}
	maxWait := time.After(2 * time.Second)
	done := false
	select {
	case <-doneChannel:
		done = true
	case <-maxWait:
	}
	require.Equal(t, true, done)
	twentyOne := peer.getNonce()
	val, _ := binary.Uvarint(twentyOne)
	require.Equal(t, uint64(201), val)
}
