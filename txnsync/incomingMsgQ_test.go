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

// fillMessageQueue fills the message queue with the given message.
func (imq *incomingMessageQueue) fillMessageQueue(msg incomingMessage) {
	imq.enqueuedPeersMu.Lock()
	for i := 0; i < maxPeersCount; i++ {
		msgEntry := imq.freelist.dequeueHead()
		msgEntry.msg = msg
		imq.messages.enqueueTail(msgEntry)
	}
	if msg.peer == nil {
		imq.peerlessCount += maxPeersCount
	}
	imq.enqueuedPeersCond.Signal()
	imq.enqueuedPeersMu.Unlock()

	// wait for a single message to be consumed by the message pump.
	for {
		imq.enqueuedPeersMu.Lock()
		if !imq.freelist.empty() {
			break
		}
		imq.enqueuedPeersMu.Unlock()
		time.Sleep(time.Millisecond)
	}
	for !imq.freelist.empty() {
		msgEntry := imq.freelist.dequeueHead()
		msgEntry.msg = msg
		imq.messages.enqueueTail(msgEntry)
	}
	imq.enqueuedPeersCond.Signal()
	imq.enqueuedPeersMu.Unlock()
}

// count counts teh number of messages in the list
func (ml *queuedMsgList) count() int {
	first := ml.head
	cur := first
	count := 0
	for cur != nil {
		next := cur.next
		if next == first {
			next = nil
		}
		count++
		cur = next
	}
	return count
}

// validateLinking test to see the the entries in the list are correctly connected.
func (ml *queuedMsgList) validateLinking(t *testing.T) {
	cur := ml.head
	if cur == nil {
		return
	}
	seen := make(map[*queuedMsgEntry]bool)
	list := make([]*queuedMsgEntry, 0)
	for {
		if seen[cur] {
			break
		}
		seen[cur] = true
		require.NotNil(t, cur.prev)
		require.NotNil(t, cur.next)
		list = append(list, cur)
		cur = cur.next
	}
	for i := range list {
		require.Equal(t, list[i], list[(i+len(list)-1)%len(list)].next)
		require.Equal(t, list[i], list[(i+1)%len(list)].prev)
	}
}

// TestMsgQCounts tests the message queue add/remove manipulations
func TestMsgQCounts(t *testing.T) {
	partitiontest.PartitionTest(t)

	var list queuedMsgList
	list.initialize(7)
	list.validateLinking(t)
	require.Equal(t, 7, list.count())
	list.dequeueHead()
	list.validateLinking(t)
	require.Equal(t, 6, list.count())
	var anotherList queuedMsgList
	anotherList.initialize(4)
	require.Equal(t, 4, anotherList.count())
	list.enqueueTail(anotherList.head)
	list.validateLinking(t)
	require.Equal(t, 10, list.count())
}

// TestMsgQFiltering tests the message queue filtering
func TestMsgQFiltering(t *testing.T) {
	partitiontest.PartitionTest(t)

	item1 := &queuedMsgEntry{}
	item2 := &queuedMsgEntry{}
	item3 := &queuedMsgEntry{}
	item1.next = item1
	item1.prev = item1
	item2.next = item2
	item2.prev = item2
	item3.next = item3
	item3.prev = item3

	var list queuedMsgList
	list.enqueueTail(item1)
	list.enqueueTail(item2)
	list.enqueueTail(item3)

	// test removing head.
	removedItem1 := list.filterRemove(func(msg *queuedMsgEntry) bool {
		return msg == item1
	})
	require.Equal(t, item1, removedItem1)
	require.Equal(t, 2, list.count())

	// test removing tail
	removedItem3 := list.filterRemove(func(msg *queuedMsgEntry) bool {
		return msg == item3
	})
	require.Equal(t, item3, removedItem3)
	require.Equal(t, 1, list.count())

	// test removing last item
	removedItem2 := list.filterRemove(func(msg *queuedMsgEntry) bool {
		return msg == item2
	})
	require.Equal(t, item2, removedItem2)
	require.True(t, list.empty())
}
