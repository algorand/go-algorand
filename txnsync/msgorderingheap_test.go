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
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMessageOrderingHeap_PushPopSwapLess(t *testing.T) {
	a := require.New(t)

	heap := messageOrderingHeap{}

	msg1 := messageHeapItem{sequenceNumber: 1}
	msg2 := messageHeapItem{sequenceNumber: 2}
	msg3 := messageHeapItem{sequenceNumber: 3}

	a.Equal(len(heap.messages), 0)
	heap.Push(msg1)
	heap.Push(msg2)
	a.Equal(len(heap.messages), int(2))
	a.Equal(heap.Len(), int(2))

	a.True(heap.Less(0, 1))

	res := heap.Pop().(messageHeapItem)
	a.Equal(res.sequenceNumber, uint64(2))
	a.Equal(len(heap.messages), int(1))
	a.Equal(heap.Len(), int(1))
	a.Equal(heap.messages[0].sequenceNumber, uint64(1))
	heap.Push(msg2)
	heap.Push(msg3)
	heap.Swap(0, 1)
	a.Equal(heap.messages[0].sequenceNumber, uint64(2))
	a.Equal(heap.messages[1].sequenceNumber, uint64(1))

	a.False(heap.Less(0, 1))
}

func TestEnqueueHeapPop(t *testing.T) {
	a := require.New(t)

	heap := messageOrderingHeap{}

	for i := messageOrderingHeapLimit - 1; i >= 0; i-- {
		a.Nil(heap.enqueue(incomingMessage{sequenceNumber: uint64(i)}))
	}

	a.Equal(heap.Len(), int(messageOrderingHeapLimit))
	a.Equal(heap.enqueue(incomingMessage{}), errHeapReachedCapacity)
	a.Equal(heap.Len(), int(messageOrderingHeapLimit))

	for i := 0; i < messageOrderingHeapLimit; i++ {
		msg, err := heap.pop()
		a.Nil(err)
		a.Equal(msg.sequenceNumber, uint64(i))
	}

	_, err := heap.pop()

	a.Equal(heap.Len(), int(0))
	a.Equal(err, errHeapEmpty)

}

func TestPopSequence(t *testing.T) {

	a := require.New(t)

	heap := messageOrderingHeap{}

	_, _, err := heap.popSequence(0)

	a.Equal(err, errHeapEmpty)
	for i := messageOrderingHeapLimit - 1; i >= 0; i-- {
		a.Nil(heap.enqueue(incomingMessage{sequenceNumber: uint64(i)}))
	}
	a.Equal(heap.Len(), messageOrderingHeapLimit)
	_, heapSeqNum, err := heap.popSequence(3)
	a.Equal(heap.Len(), messageOrderingHeapLimit)
	a.Equal(heapSeqNum, uint64(0), errSequenceNumberMismatch)

	msg, heapSeqNum, err := heap.popSequence(0)

	a.NotNil(msg)
	a.Equal(heap.Len(), messageOrderingHeapLimit-1)
	a.Equal(msg.sequenceNumber, uint64(0))
	a.Equal(heapSeqNum, uint64(0))
	a.Nil(err)

}

func TestMultiThreaded(t *testing.T) {

	a := require.New(t)

	heap := messageOrderingHeap{}

	startChan := make(chan struct{})

	var wg sync.WaitGroup

	fxn := func(value int, heap *messageOrderingHeap, start chan struct{}, wg *sync.WaitGroup) {
		defer wg.Done()
		// Wait for the start
		<-start
		_ = heap.enqueue(incomingMessage{sequenceNumber: uint64(value)})
	}

	for i := 0; i < messageOrderingHeapLimit; i++ {
		wg.Add(1)
		go fxn(i, &heap, startChan, &wg)
	}

	// Tell all goroutines to go
	close(startChan)

	wg.Wait()

	a.Equal(heap.Len(), int(messageOrderingHeapLimit))
	a.Equal(heap.enqueue(incomingMessage{}), errHeapReachedCapacity)
	a.Equal(heap.Len(), int(messageOrderingHeapLimit))

	for i := 0; i < messageOrderingHeapLimit; i++ {
		msg, err := heap.pop()
		a.Nil(err)
		a.Equal(msg.sequenceNumber, uint64(i))
	}

	_, err := heap.pop()

	a.Equal(heap.Len(), int(0))
	a.Equal(err, errHeapEmpty)

}
