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
// buckets. When looking up an entry, we don't want to have too many entries, hence, the number of maps we
// maintain shouldn't be too high. On the flip side, keeping small number of maps means that we drop out
// large portion of our cache. The number 917 here was picked as a sufficiently large prime number, which
// would mean that if longTermRecentTransactionsSentBufferLength=15K, then we would have about 16 maps.
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

//msgp:ignore shortTermCacheEntry
type shortTermCacheEntry struct {
	txid transactions.Txid
	prev *shortTermCacheEntry
	next *shortTermCacheEntry
}

//msgp:ignore shortTermTransactionCache
type shortTermTransactionCache struct {
	size            int
	first           *shortTermCacheEntry
	free            *shortTermCacheEntry
	transactionsMap map[transactions.Txid]*shortTermCacheEntry
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
			transactionsMap: make(map[transactions.Txid]*shortTermCacheEntry, shortTermSize),
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
		// roll this array without reallocation.
		copy(lru.ackPendingTxids, lru.ackPendingTxids[1:])
		// update the last entry of the array.
		lru.ackPendingTxids[len(lru.ackPendingTxids)-1] = ackPendingTxids{txids: txids, seq: msgSeq, timestamp: timestamp}
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

/*
first           shortTermCacheEntry
free            shortTermCacheEntry
transactionsMap map[transactions.Txid]bool
*/
func (ce *shortTermCacheEntry) detach() bool {
	if ce.next == ce.prev {
		return false
	}
	ce.prev.next = ce.next
	ce.next.prev = ce.prev
	return true
}

func (ce *shortTermCacheEntry) addToList(firstListEntry *shortTermCacheEntry) {
	lastListEntry := firstListEntry.prev
	lastListEntry.next = ce
	firstListEntry.prev = ce
	ce.prev = lastListEntry
	ce.next = firstListEntry
}

// add a given transaction ID to the short term cache.
func (st *shortTermTransactionCache) add(txid transactions.Txid) {
	entry, exists := st.transactionsMap[txid]
	if exists {
		// promote
		if entry.detach() {
			// there are other elements on the list.
			if entry == st.first {
				st.first = entry.next
			}
			// add to the end of the list.
			entry.addToList(st.first)
		} else {
			// no other elements on the list -
			// nothing to do in this case.
		}
		return
	}

	mapLen := len(st.transactionsMap)
	if mapLen >= st.size {
		// we reached size, delete the oldest entry.
		t := st.first

		// disconnect the current one; no need to test return code since we know
		// there will be more elements on the list.
		t.detach()

		// replace the first entry with the next one.
		st.first = t.next

		// delete the current value from the map.
		delete(st.transactionsMap, t.txid)

		// copy the new transaction id into the existing object.
		copy(t.txid[:], txid[:])

		// place the new entry as the last entry on the list.
		t.addToList(st.first)

		// add the new entry to the map
		st.transactionsMap[txid] = t
		return
	}

	// grab an entry from the free list ( if any )
	entry = st.free
	if entry != nil {
		if entry.detach() {
			st.free = entry.next
		} else {
			st.free = nil
		}
	} else {
		// the free list doesn't have an entry - allocate a new one.
		entry = &shortTermCacheEntry{
			txid: txid,
		}
	}
	if st.first == nil {
		st.first = entry
		entry.next = entry
		entry.prev = entry
	} else {
		entry.addToList(st.first)
	}
	st.transactionsMap[txid] = entry
}

// contained checks if the given transaction id presents in the short term cache
func (st *shortTermTransactionCache) contained(txid transactions.Txid) bool {
	return st.transactionsMap[txid] != nil
}

// reset clears the short term cache
func (st *shortTermTransactionCache) reset() {
	if st.first == nil {
		return
	}
	st.transactionsMap = make(map[transactions.Txid]*shortTermCacheEntry, st.size)
	if st.free == nil {
		st.free = st.first
		st.first = nil
		return
	}
	used := st.first
	free := st.free
	free.prev.next = used
	used.prev.next = free
	lastFree := free.prev
	free.prev = used.prev
	used.prev = lastFree
	st.first = nil
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

		// remove the ones we've already added from the slice.
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
