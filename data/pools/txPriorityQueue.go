// Copyright (C) 2019 Algorand, Inc.
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

package pools

import (
	"container/heap"

	"github.com/algorand/go-algorand/data/transactions"
)

type txPriorityQueue struct {
	pq         priorityQueue
	txToPQItem map[transactions.Txid]*item
}

func makeTxPriorityQueue(sizeHint int) (tpq *txPriorityQueue) {
	tpq = &txPriorityQueue{
		pq:         make(priorityQueue, 0, sizeHint),
		txToPQItem: make(map[transactions.Txid]*item, sizeHint),
	}
	heap.Init(&tpq.pq)
	return tpq
}

func (tpq txPriorityQueue) Len() int {
	return len(tpq.pq)
}

func (tpq txPriorityQueue) getMin() (transactions.Txid, transactions.TxnPriority) {
	return tpq.pq.GetMin()
}

func (tpq *txPriorityQueue) Pop() transactions.Txid {
	curr := heap.Pop(&tpq.pq).(*item)
	delete(tpq.txToPQItem, curr.value)
	return curr.value
}

type prioritizable interface {
	ID() transactions.Txid
	Priority() transactions.TxnPriority
}

func (tpq *txPriorityQueue) Push(tx prioritizable) bool {
	if _, hasTx := tpq.txToPQItem[tx.ID()]; hasTx {
		return false
	}

	item := item{value: tx.ID(), priority: tx.Priority()}
	heap.Push(&tpq.pq, &item)
	tpq.txToPQItem[item.value] = &item
	return true
}

func (tpq *txPriorityQueue) Remove(txid transactions.Txid) {
	item, hasItem := tpq.txToPQItem[txid]
	if !hasItem {
		return
	}
	tpq.pq.Remove(item.index)
	delete(tpq.txToPQItem, txid)
}

// internal data structures for maintaining the heap

// code sourced from godoc container/heap example

// An Item is something we manage in a priority queue.
type item struct {
	// The value of the item; arbitrary.
	value transactions.Txid

	// The priority of the item in the queue.
	priority transactions.TxnPriority

	// The index of the item in the heap.
	// The index is needed by update and is maintained by the heap.Interface methods.
	index int
}

// A priorityQueue implements heap.Interface and holds Items.
// this is a minimum priority queue
type priorityQueue []*item

func (pq priorityQueue) Len() int { return len(pq) }

func (pq priorityQueue) Less(i, j int) bool {
	return pq[i].priority.LessThan(pq[j].priority)
}

func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *priorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*item)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	item.index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

func (pq *priorityQueue) Remove(index int) {
	heap.Remove(pq, index)
}

func (pq priorityQueue) GetMin() (transactions.Txid, transactions.TxnPriority) {
	if pq.Len() == 0 {
		return transactions.Txid{}, transactions.TxnPriority(0)
	}
	return pq[0].value, pq[0].priority
}
