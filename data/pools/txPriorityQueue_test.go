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
	"math/rand"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func TestPriorityQueue(t *testing.T) {
	N := 1000
	txpq := make(priorityQueue, 0)
	heap.Init(&txpq)
	everything := make([]item, N, N)

	for i := 0; i < N; i++ {
		var id transactions.Txid
		rand.Read(id[:])
		priority := rand.Uint64()

		item := item{
			value:    id,
			priority: transactions.TxnPriority(priority),
		}
		heap.Push(&txpq, &item)
		everything[i] = item
	}

	sort.SliceStable(everything, func(i, j int) bool {
		return everything[i].priority.LessThan(everything[j].priority)
	})

	_, minpriority := txpq.GetMin()
	require.Equal(t, minpriority, everything[0].priority)

	i := 0
	for txpq.Len() > 0 {
		curr := heap.Pop(&txpq).(*item)
		require.Equal(t, everything[i].value, curr.value)
		i++
	}
}

func TestPriorityQueueRemove(t *testing.T) {
	N := 1000
	txpq := make(priorityQueue, 0)
	heap.Init(&txpq)
	everything := make([]*item, N, N)

	for i := 0; i < N; i++ {
		var id transactions.Txid
		rand.Read(id[:])
		priority := rand.Uint64()

		item := item{
			value:    id,
			priority: transactions.TxnPriority(priority),
		}
		heap.Push(&txpq, &item)
		everything[i] = &item
	}

	require.Equal(t, txpq.Len(), N)
	sort.SliceStable(everything, func(i, j int) bool {
		return everything[i].priority.LessThan(everything[j].priority)
	})
	txpq.Remove(everything[N/2].index)
	require.Equal(t, txpq.Len(), N-1)

	i := 0
	for txpq.Len() > 0 {
		if i == N/2 {
			i++
		}
		curr := heap.Pop(&txpq).(*item)
		require.Equal(t, everything[i].value, curr.value)
		i++
	}
}

func TestTxPriorityQueue(t *testing.T) {
	N := 1000
	txpq := makeTxPriorityQueue(N)

	everything := make([]item, 10*N+1, 10*N+1)

	zerotx := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.PaymentTx,
		},
	}
	zerotx.InitCaches()
	require.True(t, txpq.Push(&zerotx))
	require.False(t, txpq.Push(&zerotx))
	for i := 0; i < 10*N; i++ {
		priority := rand.Uint64() % (1 << 32)

		tx := transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Fee: basics.MicroAlgos{Raw: priority},
				},
			},
		}
		tx.InitCaches()
		txpq.Push(&tx)
		item := item{
			value:    tx.ID(),
			priority: tx.Priority(),
		}
		everything[i] = item
	}

	everything[10*N] = item{
		value:    zerotx.ID(),
		priority: zerotx.Priority(),
	}

	sort.SliceStable(everything, func(i, j int) bool {
		return everything[i].priority.LessThan(everything[j].priority)
	})

	require.Equal(t, 10*N+1, txpq.Len())
	require.Equal(t, 10*N+1, len(everything))

	require.False(t, txpq.Push(&zerotx))

	i := 0
	for txpq.Len() > 0 {
		require.Equal(t, everything[i].value, txpq.Pop())
		i++
	}
}

func TestTxPriorityQueueRemove(t *testing.T) {
	N := 1000
	txpq := makeTxPriorityQueue(N)

	everything := make([]item, N, N)
	for i := 0; i < N; i++ {
		priority := rand.Uint64() % (1 << 32)

		tx := transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Fee: basics.MicroAlgos{Raw: priority},
				},
			},
		}
		tx.InitCaches()
		txpq.Push(&tx)
		item := item{
			value:    tx.ID(),
			priority: tx.Priority(),
		}
		everything[i] = item
	}

	sort.SliceStable(everything, func(i, j int) bool {
		return everything[i].priority.LessThan(everything[j].priority)
	})

	require.Equal(t, N, txpq.Len())

	txpq.Remove(everything[N/2].value)
	require.Equal(t, txpq.Len(), N-1)

	i := 0
	for txpq.Len() > 0 {
		if i == N/2 {
			i++
		}
		require.Equal(t, everything[i].value, txpq.Pop())
		i++
	}

}
