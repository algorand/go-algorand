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
	"container/heap"
	"errors"

	"github.com/algorand/go-deadlock"
)

var errHeapEmpty = errors.New("message ordering heap is empty")
var errHeapReachedCapacity = errors.New("message ordering heap reached capacity")
var errSequenceNumberMismatch = errors.New("sequence number mismatch")

const messageOrderingHeapLimit = 128

type messageHeapItem incomingMessage

type messageOrderingHeap struct {
	mu       deadlock.Mutex
	messages []messageHeapItem
}

// Push implements heap.Interface
func (p *messageOrderingHeap) Push(x interface{}) {
	entry := x.(messageHeapItem)
	p.messages = append(p.messages, entry)
}

// Pop implements heap.Interface
func (p *messageOrderingHeap) Pop() interface{} {
	end := len(p.messages) - 1
	res := p.messages[end]
	p.messages[end] = messageHeapItem{}
	p.messages = p.messages[0:end]
	return res
}

// Len implements heap.Interface
func (p *messageOrderingHeap) Len() int {
	return len(p.messages)
}

// Swap implements heap.Interface
func (p *messageOrderingHeap) Swap(i, j int) {
	p.messages[i], p.messages[j] = p.messages[j], p.messages[i]
}

// Less implements heap.Interface
func (p *messageOrderingHeap) Less(i, j int) bool {
	return p.messages[i].sequenceNumber < p.messages[j].sequenceNumber
}

func (p *messageOrderingHeap) enqueue(msg incomingMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	msg.nextSequenceNumber = msg.sequenceNumber + 1
	if len(p.messages) >= messageOrderingHeapLimit {
		// try compressing the msgorderingheap first
		p.compact()
		if len(p.messages) >= messageOrderingHeapLimit {
			// return an error if still can't enqueue
			return errHeapReachedCapacity
		}
	}
	heap.Push(p, messageHeapItem(msg))
	return nil
}

func (p *messageOrderingHeap) popSequence(sequenceNumber uint64) (msg incomingMessage, heapSequenceNumber uint64, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.popSequenceUnsafe(sequenceNumber)
}

func (p *messageOrderingHeap) popSequenceUnsafe(sequenceNumber uint64) (msg incomingMessage, heapSequenceNumber uint64, err error) {
	if len(p.messages) == 0 {
		return incomingMessage{}, 0, errHeapEmpty
	}
	if p.messages[0].sequenceNumber != sequenceNumber {
		return incomingMessage{}, p.messages[0].sequenceNumber, errSequenceNumberMismatch
	}
	entry := heap.Pop(p).(messageHeapItem)
	return incomingMessage(entry), sequenceNumber, nil
}

func (p *messageOrderingHeap) pop() (msg incomingMessage, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.popUnsafe()
}

func (p *messageOrderingHeap) popUnsafe() (msg incomingMessage, err error) {
	if len(p.messages) == 0 {
		return incomingMessage{}, errHeapEmpty
	}
	entry := heap.Pop(p).(messageHeapItem)
	return incomingMessage(entry), nil
}

func (p *messageOrderingHeap) compact() {
	compressedEntry, err := p.popUnsafe()
	if err != nil {
		return
	}
	expectedSeqNum := compressedEntry.nextSequenceNumber
	for len(p.messages) != 0 {
		nextEntry, _, err := p.popSequenceUnsafe(expectedSeqNum)
		// compress only consecutive messages
		if err != nil {
			break
		}
		// use oldest transaction groups if possible
		if compressedEntry.transactionGroups != nil {
			nextEntry.transactionGroups = compressedEntry.transactionGroups
		}
		if nextEntry.bloomFilter == nil {
			nextEntry.bloomFilter = compressedEntry.bloomFilter
		}
		nextEntry.sequenceNumber = compressedEntry.sequenceNumber
		compressedEntry = nextEntry
		expectedSeqNum = compressedEntry.nextSequenceNumber
	}
	// return compressed message to heap
	heap.Push(p, messageHeapItem(compressedEntry))
}
