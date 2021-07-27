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
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-deadlock"
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

	loopCount := 1000
	numThreads := 100
	itemsPerThread := 10

	totalItems := numThreads * itemsPerThread

	var (
		heap      messageOrderingHeap
		startChan chan struct{}
		wg        sync.WaitGroup
	)

	peers := []Peer{
		{},
		{},
		{},
		{},
		{},
	}

	genTxnGrp := func(value int) []transactions.SignedTxGroup {

		if value%2 == 0 {
			return []transactions.SignedTxGroup{
				{
					GroupTransactionID: transactions.Txid{byte(value % 255)},
				},
			}
		}

		return []transactions.SignedTxGroup{
			{
				GroupTransactionID: transactions.Txid{byte(value % 255)},
			},
			{
				GroupTransactionID: transactions.Txid{byte(value + 1%255)},
			},
		}
	}

	encodeMsg := func(value int, peers []Peer) incomingMessage {

		rval := incomingMessage{
			sequenceNumber:    uint64(value),
			peer:              &peers[value%len(peers)],
			encodedSize:       value + 874,
			transactionGroups: genTxnGrp(value),
		}

		return rval
	}

	validateMsg := func(message incomingMessage) bool {
		val := int(message.sequenceNumber)

		if message.peer != &peers[val%len(peers)] {
			return false
		}

		if message.encodedSize != val+874 {
			return false
		}

		if !reflect.DeepEqual(message.transactionGroups, genTxnGrp(val)) {
			return false
		}

		return true

	}

	fxn := func(values []int, heap *messageOrderingHeap, start chan struct{}, wg *sync.WaitGroup,
		enqueuedMtx *deadlock.Mutex, enqueuedList *[]int) {
		defer wg.Done()
		// Wait for the start
		<-start

		for _, value := range values {
			msg := encodeMsg(value, peers)
			err := heap.enqueue(msg)

			if err == nil {
				(*enqueuedMtx).Lock()
				*enqueuedList = append(*enqueuedList, value)
				(*enqueuedMtx).Unlock()
			}
		}

	}

	for i := 0; i < loopCount; i++ {

		var enqueuedList []int
		var enqueuedMtx deadlock.Mutex

		var masterList []int

		for i := 0; i < totalItems; i++ {
			masterList = append(masterList, i)
		}

		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(masterList), func(i, j int) { masterList[i], masterList[j] = masterList[j], masterList[i] })

		heap = messageOrderingHeap{}
		startChan = make(chan struct{})

		currentIdx := 0

		for j := 0; j < numThreads; j++ {
			wg.Add(1)

			randomList := masterList[currentIdx : currentIdx+itemsPerThread]
			currentIdx = currentIdx + itemsPerThread

			go fxn(randomList, &heap, startChan, &wg, &enqueuedMtx, &enqueuedList)
		}

		// Tell all goroutines to go
		close(startChan)

		wg.Wait()

		a.Equal(heap.Len(), int(messageOrderingHeapLimit))
		a.Equal(heap.enqueue(incomingMessage{}), errHeapReachedCapacity)
		a.Equal(heap.Len(), int(messageOrderingHeapLimit))

		sort.Ints(enqueuedList)

		for _, val := range enqueuedList {

			msg, sequenceNumber, err := heap.popSequence(uint64(val))
			a.Nil(err)
			a.Equal(sequenceNumber, uint64(val))
			a.True(validateMsg(msg))
		}

		a.Equal(heap.Len(), int(0))
	}

}
