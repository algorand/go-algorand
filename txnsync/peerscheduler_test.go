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
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestBasics tests that the push, pop, len, swap and less functions perform appropriately
func TestBasics(t *testing.T) {
	partitiontest.PartitionTest(t)

	ps := peerScheduler{}

	require.Equal(t, 0, ps.Len())

	peers := []Peer{
		Peer{
			lastSentMessageSequenceNumber: 123,
		},
		Peer{
			lastSentMessageSequenceNumber: 456,
		},
	}

	ps.Push(peerBucket{&peers[0], 0 * time.Millisecond})
	ps.Push(peerBucket{&peers[1], 1 * time.Millisecond})

	require.Equal(t, 2, ps.Len())

	require.Equal(t, uint64(123), ps.peers[0].peer.lastSentMessageSequenceNumber)
	require.Equal(t, uint64(456), ps.peers[1].peer.lastSentMessageSequenceNumber)
	require.True(t, ps.Less(0, 1))

	ps.Swap(0, 1)
	require.Equal(t, uint64(123), ps.peers[1].peer.lastSentMessageSequenceNumber)
	require.Equal(t, uint64(456), ps.peers[0].peer.lastSentMessageSequenceNumber)
	require.True(t, ps.Less(1, 0))

	backPeer := ps.Pop().(peerBucket)

	require.Equal(t, uint64(123), backPeer.peer.lastSentMessageSequenceNumber)

	backPeer = ps.Pop().(peerBucket)

	require.Equal(t, uint64(456), backPeer.peer.lastSentMessageSequenceNumber)

	require.Equal(t, 0, ps.Len())
}

// TestSchedulerBasics tests the basic scheduler helper functions
func TestSchedulerBasics(t *testing.T) {
	partitiontest.PartitionTest(t)

	ps := peerScheduler{}

	peers := []Peer{
		Peer{
			lastSentMessageSequenceNumber: 123,
		},
		Peer{
			lastSentMessageSequenceNumber: 456,
		},
		Peer{
			lastSentMessageSequenceNumber: 789,
		},
	}

	require.Equal(t, 0*time.Millisecond, ps.nextDuration())
	ps.schedulerPeer(&peers[0], 2*time.Millisecond)
	ps.schedulerPeer(&peers[1], 1*time.Millisecond)
	ps.schedulerPeer(&peers[2], 3*time.Millisecond)

	require.Equal(t, 3, ps.Len())

	require.Equal(t, 1*time.Millisecond, ps.nextDuration())

	require.Equal(t, 3*time.Millisecond, ps.peerDuration(&peers[2]))
	require.Equal(t, 2, ps.Len())

	require.Equal(t, 1*time.Millisecond, ps.peerDuration(&peers[1]))
	require.Equal(t, 1, ps.Len())

	require.Equal(t, 2*time.Millisecond, ps.peerDuration(&peers[0]))
	require.Equal(t, 0, ps.Len())

	require.Equal(t, 0*time.Millisecond, ps.peerDuration(&peers[0]))
}

// TestScheduleNewRound tests the scheduleNewRound method
func TestScheduleNewRound(t *testing.T) {
	partitiontest.PartitionTest(t)

	ps := peerScheduler{
		node: &mockNodeConnector{},
	}

	peers := []Peer{
		Peer{
			lastSentMessageSequenceNumber: 123,
		},
		Peer{
			lastSentMessageSequenceNumber: 456,
		},
		Peer{
			lastSentMessageSequenceNumber: 789,
		},
	}

	peers2 := []Peer{
		Peer{
			lastSentMessageSequenceNumber: 321,
		},
		Peer{
			lastSentMessageSequenceNumber: 654,
		},
		Peer{
			lastSentMessageSequenceNumber: 987,
		},
		Peer{
			lastSentMessageSequenceNumber: 146,
		},
	}

	ps.schedulerPeer(&peers[0], 2*time.Millisecond)
	ps.schedulerPeer(&peers[1], 1*time.Millisecond)
	ps.schedulerPeer(&peers[2], 3*time.Millisecond)
	require.Equal(t, 3, ps.Len())

	ps.scheduleNewRound([]*Peer{&peers2[0], &peers2[1], &peers2[2], &peers2[3]})
	require.Equal(t, 4, ps.Len())

}

// TestNextPeers tests that the nextPeers function
func TestNextPeers(t *testing.T) {
	partitiontest.PartitionTest(t)

	ps := peerScheduler{
		node: &mockNodeConnector{},
	}

	peers := []Peer{
		Peer{
			lastSentMessageSequenceNumber: 1,
		},
		Peer{
			lastSentMessageSequenceNumber: 2,
		},
		Peer{
			lastSentMessageSequenceNumber: 3,
		},
	}

	ps.schedulerPeer(&peers[0], 1*time.Millisecond)
	ps.schedulerPeer(&peers[1], 2*time.Millisecond)
	ps.schedulerPeer(&peers[1], 2*time.Millisecond)
	ps.schedulerPeer(&peers[2], 2*time.Millisecond)

	require.Equal(t, 4, ps.Len())

	outPeers := ps.nextPeers()

	require.Equal(t, 3, ps.Len())
	require.Equal(t, 1, len(outPeers))
	require.Equal(t, uint64(1), outPeers[0].lastSentMessageSequenceNumber)

	outPeers = ps.nextPeers()

	require.Equal(t, 0, ps.Len())
	require.Equal(t, 2, len(outPeers))
	require.Equal(t, uint64(3), outPeers[0].lastSentMessageSequenceNumber)
	require.Equal(t, uint64(2), outPeers[1].lastSentMessageSequenceNumber)

}
