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
	"time"

	"github.com/algorand/go-algorand/data/transactions"
)

// cachedEntriesPerMap is the number of entries the longTermTransactionCache will have in each of it's
// buckets.
const cachedEntriesPerMap = 917

// cacheHistoryDuration is the time we will keep a transaction in the cache, assuming that the cache
// storage would not get recycled first. When applied to transactions maps in the longTermTransactionCache, this
// applies to the timestamp of the most recent transaction in the map.
const cacheHistoryDuration = 10 * time.Second

// transactionCache is a cache of recently sent transactions ids, allowing to limit the size of the historical kept transactions.
// transactionCache has FIFO replacement.
// implementation is a simple cyclic-buffer with a map to accelerate lookups.
// internally, it's being manages as two tier cache, where the long-term cache is bigger and requires acknowledgements.
//msgp:ignore transactionCache
type transactionCache struct {
	shortTermCache  shortTermTransactionCache
	longTermCache   longTermTransactionCache
	ackPendingTxids []ackPendingTxids
}

//msgp:ignore ackPendingTxids
type ackPendingTxids struct {
	txids     []transactions.Txid
	seq       uint64
	timestamp time.Duration
}

//msgp:ignore shortTermTransactionCache
type shortTermTransactionCache struct {
	size            int
	transactionsIDs []transactions.Txid
	transactionsMap map[transactions.Txid]bool
	oldest          int
}

//msgp:ignore longTermTransactionCache
type longTermTransactionCache struct {
	current         int
	transactionsMap []map[transactions.Txid]bool
	timestamps      []time.Duration
}

// makeTransactionCache creates the transaction cache
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
			timestamps:      make([]time.Duration, (longTermSize+cachedEntriesPerMap-1)/cachedEntriesPerMap),
		},
	}
	// initialize only the first entry; the rest would be created dynamically.
	txnCache.longTermCache.transactionsMap[0] = make(map[transactions.Txid]bool, cachedEntriesPerMap)
	return txnCache
}

// add adds a single trasaction ID to the short term cache.
func (lru *transactionCache) add(txid transactions.Txid) {
	lru.shortTermCache.add(txid)
}

// addSlice adds a slice to both the short term cache as well as the pending ack transaction ids.
func (lru *transactionCache) addSlice(txids []transactions.Txid, msgSeq uint64, timestamp time.Duration) {
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
		lru.ackPendingTxids = append(lru.ackPendingTxids[1:], ackPendingTxids{txids: txids, seq: msgSeq, timestamp: timestamp})
	} else {
		lru.ackPendingTxids = append(lru.ackPendingTxids, ackPendingTxids{txids: txids, seq: msgSeq, timestamp: timestamp})
	}

	// clear the entries that are too old.
	lastValidEntry := -1
	for i, entry := range lru.ackPendingTxids {
		if entry.timestamp < timestamp-cacheHistoryDuration {
			lastValidEntry = i
		} else {
			break
		}
	}
	if lastValidEntry >= 0 {
		// copy the elements
		var i int
		for i = 0; i < len(lru.ackPendingTxids)-1-lastValidEntry; i++ {
			lru.ackPendingTxids[i] = lru.ackPendingTxids[i+lastValidEntry+1]
		}
		// clear the rest of the entries.
		for ; i < len(lru.ackPendingTxids); i++ {
			lru.ackPendingTxids[i] = ackPendingTxids{}
		}
		// reset the slice
		lru.ackPendingTxids = lru.ackPendingTxids[:len(lru.ackPendingTxids)-lastValidEntry-1]
	}
}

// contained checks if a given transaction ID is contained in either the short term or long term cache
func (lru *transactionCache) contained(txid transactions.Txid) bool {
	return lru.shortTermCache.contained(txid) || lru.longTermCache.contained(txid)
}

// reset clears the short term cache
func (lru *transactionCache) reset() {
	lru.shortTermCache.reset()
}

// acknowledge process a given slice of previously sent message sequence numbers. The transaction IDs that
// were previously sent with these sequence numbers are being added to the long term cache.
func (lru *transactionCache) acknowledge(seqs []uint64) {
	for _, seq := range seqs {
		i := sort.Search(len(lru.ackPendingTxids), func(i int) bool {
			return lru.ackPendingTxids[i].seq >= seq
		})
		// if not found, skip it.
		if i >= len(lru.ackPendingTxids) || seq != lru.ackPendingTxids[i].seq {
			continue
		}
		lru.longTermCache.add(lru.ackPendingTxids[i].txids, lru.ackPendingTxids[i].timestamp)
		lru.longTermCache.prune(lru.ackPendingTxids[i].timestamp - cacheHistoryDuration)
		// clear out the entry at lru.ackPendingTxids[i] so that the GC could reclaim it.
		lru.ackPendingTxids[i] = ackPendingTxids{}
		// and delete the entry from the array
		lru.ackPendingTxids = append(lru.ackPendingTxids[:i], lru.ackPendingTxids[i+1:]...)
	}
}

// add a given transaction ID to the short term cache.
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

// contained checks if the given transaction id presents in the short term cache
func (st *shortTermTransactionCache) contained(txid transactions.Txid) bool {
	return st.transactionsMap[txid]
}

// reset clears the short term cache
func (st *shortTermTransactionCache) reset() {
	st.transactionsMap = make(map[transactions.Txid]bool, st.size)
	st.oldest = 0
}

// contained checks if the given transaction id presents in the log term cache
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

// add a given slice of transaction IDs to the long term transaction cache, at a given timestamp.
func (lt *longTermTransactionCache) add(slice []transactions.Txid, timestamp time.Duration) {
	for {
		lt.timestamps[lt.current] = timestamp
		availableEntries := cachedEntriesPerMap - len(lt.transactionsMap[lt.current])
		txMap := lt.transactionsMap[lt.current]
		if txMap == nil {
			txMap = make(map[transactions.Txid]bool, cachedEntriesPerMap)
		}
		if len(slice) <= availableEntries {
			// just add them all.
			for _, txid := range slice {
				txMap[txid] = true
			}
			lt.transactionsMap[lt.current] = txMap
			return
		}

		// otherwise, add as many as we can fit -
		for i := 0; i < availableEntries; i++ {
			txMap[slice[i]] = true
		}
		lt.transactionsMap[lt.current] = txMap

		// remove the ones we've alread added from the slice.
		slice = slice[availableEntries:]

		// move to the next map.
		lt.current = (lt.current + 1) % len(lt.transactionsMap)

		// if full, reset bucket.
		if len(lt.transactionsMap[lt.current]) >= cachedEntriesPerMap || lt.transactionsMap[lt.current] == nil {
			// reset.
			lt.transactionsMap[lt.current] = make(map[transactions.Txid]bool, cachedEntriesPerMap)
		}
	}
}

// prune the long term cache by clearing out all the cached transaction IDs maps that are dated before the given
// timestamp
func (lt *longTermTransactionCache) prune(timestamp time.Duration) {
	// find the index of the first entry where the timestamp is still valid.
	latestValidIndex := sort.Search(len(lt.transactionsMap), func(i int) bool {
		arrayIndex := (i + lt.current + 1) % len(lt.transactionsMap)
		return lt.timestamps[arrayIndex] > timestamp
	})

	// find the first non-empty map index.
	firstValidIndex := sort.Search(len(lt.transactionsMap), func(i int) bool {
		arrayIndex := (i + lt.current + 1) % len(lt.transactionsMap)
		return lt.timestamps[arrayIndex] != time.Duration(0)
	})

	for i := firstValidIndex - 1; i < latestValidIndex; i++ {
		arrayIndex := (i + lt.current + 1) % len(lt.transactionsMap)
		lt.timestamps[arrayIndex] = time.Duration(0)
		lt.transactionsMap[lt.current] = nil
	}
}
