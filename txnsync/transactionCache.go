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
	"sort"

	"github.com/algorand/go-algorand/data/transactions"
)

const cachedEntriesPerMap = 917

// transactionCache is a cache of recently sent transactions ids, allowing to limit the size of the historical kept transactions.
// transactionCache has FIFO replacement.
// implementation is a simple cyclic-buffer with a map to accelerate lookups.
// internally, it's being manages as two tier cache, where the long-term cache is bigger and requires acknowledgements.
type transactionCache struct {
	shortTermCache  shortTermTransactionCache
	longTermCache   longTermTransactionCache
	ackPendingTxids []ackPendingTxids
}

type ackPendingTxids struct {
	txids []transactions.Txid
	seq   uint64
}

type shortTermTransactionCache struct {
	size            int
	transactionsIDs []transactions.Txid
	transactionsMap map[transactions.Txid]bool
	oldest          int
}

type longTermTransactionCache struct {
	current         int
	transactionsMap []map[transactions.Txid]bool
}

func makeTransactionCache(shortTermSize, longTermSize, pendingAckTxids int) *transactionCache {
	txnCache := &transactionCache{
		shortTermCache: shortTermTransactionCache{
			size:            shortTermSize,
			transactionsIDs: make([]transactions.Txid, shortTermSize, shortTermSize),
			transactionsMap: make(map[transactions.Txid]bool, shortTermSize),
		},
		ackPendingTxids: make([]ackPendingTxids, 0, pendingAckTxids),
		longTermCache: longTermTransactionCache{
			transactionsMap: make([]map[transactions.Txid]bool, (longTermSize+cachedEntriesPerMap-1)/cachedEntriesPerMap),
		},
	}
	for i := range txnCache.longTermCache.transactionsMap {
		txnCache.longTermCache.transactionsMap[i] = make(map[transactions.Txid]bool, cachedEntriesPerMap)
	}
	return txnCache
}

func (lru *transactionCache) add(txid transactions.Txid) {
	lru.shortTermCache.add(txid)
}

func (lru *transactionCache) addSlice(txids []transactions.Txid, msgSeq uint64) {
	for _, txid := range txids {
		lru.shortTermCache.add(txid)
	}
	// verify that the new msgSeq is bigger than the previous we have.
	if len(lru.ackPendingTxids) > 0 {
		if lru.ackPendingTxids[len(lru.ackPendingTxids)-1].seq >= msgSeq {
			return
		}
	}

	if len(lru.ackPendingTxids) == cap(lru.ackPendingTxids) {
		// clear out the entry at lru.ackPendingTxids[0] so that the GC could reclaim it.
		lru.ackPendingTxids[0] = ackPendingTxids{}
		lru.ackPendingTxids = append(lru.ackPendingTxids[1:], ackPendingTxids{txids: txids, seq: msgSeq})
	} else {
		lru.ackPendingTxids = append(lru.ackPendingTxids, ackPendingTxids{txids: txids, seq: msgSeq})
	}
}

func (lru *transactionCache) contained(txid transactions.Txid) bool {
	return lru.shortTermCache.contained(txid) || lru.longTermCache.contained(txid)
}

func (lru *transactionCache) reset() {
	lru.shortTermCache.reset()
}

func (lru *transactionCache) acknowledge(seqs []uint64) {
	for _, seq := range seqs {
		i := sort.Search(len(lru.ackPendingTxids), func(i int) bool {
			return lru.ackPendingTxids[i].seq >= seq
		})
		// if not found, skip it.
		if i >= len(lru.ackPendingTxids) || seq != lru.ackPendingTxids[i].seq {
			continue
		}
		lru.longTermCache.add(lru.ackPendingTxids[i].txids)
		// clear out the entry at lru.ackPendingTxids[i] so that the GC could reclaim it.
		lru.ackPendingTxids[i] = ackPendingTxids{}
		// and delete the entry from the array
		lru.ackPendingTxids = append(lru.ackPendingTxids[:i], lru.ackPendingTxids[i+1:]...)
	}
}

func (st *shortTermTransactionCache) add(txid transactions.Txid) {
	if st.transactionsMap[txid] {
		return
	}
	mapLen := len(st.transactionsMap)
	if mapLen >= st.size {
		// we reached size, delete the oldest entry.
		delete(st.transactionsMap, st.transactionsIDs[st.oldest])
		st.transactionsIDs[st.oldest] = txid
		st.transactionsMap[txid] = true
		st.oldest = (st.oldest + 1) % st.size
		return
	}
	st.transactionsIDs[mapLen] = txid
	st.transactionsMap[txid] = true
}

func (st *shortTermTransactionCache) contained(txid transactions.Txid) bool {
	return st.transactionsMap[txid]
}

func (st *shortTermTransactionCache) reset() {
	st.transactionsMap = make(map[transactions.Txid]bool, st.size)
	st.oldest = 0
}

func (lt *longTermTransactionCache) contained(txid transactions.Txid) bool {
	for i := lt.current; i >= 0; i-- {
		if lt.transactionsMap[i][txid] {
			return true
		}
	}
	for i := len(lt.transactionsMap) - 1; i > lt.current; i-- {
		if lt.transactionsMap[i][txid] {
			return true
		}
	}
	return false
}

func (lt *longTermTransactionCache) add(slice []transactions.Txid) {
	for {
		availableEntries := cachedEntriesPerMap - len(lt.transactionsMap[lt.current])
		if len(slice) <= availableEntries {
			// just add them all.
			for _, txid := range slice {
				lt.transactionsMap[lt.current][txid] = true
			}
			return
		}

		// otherwise, add as many as we can fit -
		for i := 0; i < availableEntries; i++ {
			lt.transactionsMap[lt.current][slice[i]] = true
		}

		// remove the ones we've alread added from the slice.
		slice = slice[availableEntries:]

		// move to the next map.
		lt.current = (lt.current + 1) % len(lt.transactionsMap)

		// if full, reset bucket.
		if len(lt.transactionsMap[lt.current]) >= cachedEntriesPerMap {
			// reset.
			lt.transactionsMap[lt.current] = make(map[transactions.Txid]bool, cachedEntriesPerMap)
		}
	}
}
