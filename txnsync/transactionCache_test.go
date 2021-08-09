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
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

  "github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestTransactionCache General smoke test for the transaction cache
func TestTransactionCache(t *testing.T) {
	partitiontest.PartitionTest(t)

	var txid transactions.Txid
	a := makeTransactionCache(5, 10, 20)
	// add 5
	for i := 0; i < 5; i++ {
		txid[0] = byte(i)
		a.add(txid)
	}

	// all 5 still there
	for i := 0; i < 5; i++ {
		txid[0] = byte(i)
		require.True(t, a.contained(txid))
	}

	// repeatedly adding existing data doesn't lose anything
	txid[0] = 1
	a.add(txid)
	a.add(txid)
	a.add(txid)
	for i := 0; i < 5; i++ {
		txid[0] = byte(i)
		require.True(t, a.contained(txid))
	}

	// adding a sixth forgets the first
	txid[0] = 5
	a.add(txid)
	for i := 1; i < 6; i++ {
		txid[0] = byte(i)
		require.True(t, a.contained(txid))
	}
	txid[0] = 0
	require.False(t, a.contained(txid))

	// adding a seventh forgets the second
	txid[0] = 6
	a.add(txid)
	for i := 2; i < 7; i++ {
		txid[0] = byte(i)
		require.True(t, a.contained(txid))
	}
	txid[0] = 1
	require.False(t, a.contained(txid))
}

// TestTransactionCacheAddSlice tests addSlice functionality of the transaction cache
func TestTransactionCacheAddSlice(t *testing.T) {
	partitiontest.PartitionTest(t)

	tc := makeTransactionCache(5, 10, 20)
	curTimestamp := time.Duration(0)
	msgSeq := uint64(0)
	slice := make([]transactions.Txid, 10)
	for i := 0; i < 50; i++ {
		tc.addSlice(slice, msgSeq, curTimestamp)
		curTimestamp += cacheHistoryDuration / 10
		msgSeq++
		require.LessOrEqual(t, len(tc.ackPendingTxids), 11)
	}
	curTimestamp += cacheHistoryDuration
	tc.addSlice(slice, msgSeq, curTimestamp)
	require.LessOrEqual(t, len(tc.ackPendingTxids), 1)
}

// TestAddSliceSeqReturn Tests that if the ackPendingTxIds is bigger that the msgSeq then we return
func TestAddSliceSeqReturn(t *testing.T) {
  partitiontest.PartitionTest(t)

	tc := makeTransactionCache(5, 10, 20)
	curTimestamp := time.Duration(cacheHistoryDuration)
	msgSeq := uint64(1)
	slice := make([]transactions.Txid, 10)
	tc.addSlice(slice, msgSeq, curTimestamp)

	tcLen := len(tc.ackPendingTxids)

	tc.addSlice(slice, 0, curTimestamp)
	require.Equal(t, tcLen, len(tc.ackPendingTxids))
	msgSeq++
	tc.addSlice(slice, msgSeq, curTimestamp+(cacheHistoryDuration/10))
	require.Equal(t, tcLen+1, len(tc.ackPendingTxids))

}

// TestAddSliceCapacity tests that we correctly copy the ackPendingTxids when at capacity
func TestAddSliceCapacity(t *testing.T) {
  partitiontest.PartitionTest(t)
	tc := makeTransactionCache(5, 10, 5)

	curTimestamp := time.Duration(0)
	msgSeq := uint64(0)
	slice := make([]transactions.Txid, 10)
	for i := 0; i < 50; i++ {
		tc.addSlice(slice, msgSeq, curTimestamp)
		curTimestamp += cacheHistoryDuration / 10
		msgSeq++
		require.LessOrEqual(t, len(tc.ackPendingTxids), 6)
	}

}

// TestShortTermCacheReset tests that the short term cache is reset
func TestShortTermCacheReset(t *testing.T) {
  partitiontest.PartitionTest(t)
	tc := makeTransactionCache(5, 10, 5)
	require.Equal(t, 0, tc.shortTermCache.oldest)
	require.Equal(t, 0, len(tc.shortTermCache.transactionsMap))

	var txid transactions.Txid
	for i := 0; i < 6; i++ {
		txid[0] = byte(i)
		tc.add(txid)
	}

	require.Equal(t, 1, tc.shortTermCache.oldest)
	require.Equal(t, 5, len(tc.shortTermCache.transactionsMap))

	tc.reset()

	require.Equal(t, 0, tc.shortTermCache.oldest)
	require.Equal(t, 0, len(tc.shortTermCache.transactionsMap))
}

// TestCacheAcknowledge tests that the acknowledge function correctly adds entries
func TestCacheAcknowledge(t *testing.T) {
  partitiontest.PartitionTest(t)
	tc := makeTransactionCache(5, 10, 5)

	curTimestamp := time.Duration(0)
	msgSeq := uint64(0)
	slice := make([]transactions.Txid, 10)
	for i := 0; i < 5; i++ {
		tc.addSlice(slice, msgSeq, curTimestamp)
		curTimestamp += cacheHistoryDuration / 20
		msgSeq++
		require.LessOrEqual(t, len(tc.ackPendingTxids), 5)
	}

	require.Equal(t, 1, len(tc.longTermCache.transactionsMap))
	require.Equal(t, 0, tc.longTermCache.current)

	// The 10 is purposely past the range for the checking
	seqs := []uint64{10, 1, 2, 3}
	tc.acknowledge(seqs)
	require.Equal(t, 2, len(tc.ackPendingTxids))
	require.Equal(t, uint64(0), tc.ackPendingTxids[0].seq)
	require.Equal(t, uint64(4), tc.ackPendingTxids[1].seq)

}

// TestCacheAddAndContains tests adding to the long term cache and if we can test if it contains it
func TestCacheAddAndContains(t *testing.T) {
  partitiontest.PartitionTest(t)
	tc := makeTransactionCache(5, 2*cachedEntriesPerMap, 5)

	// We want two scenarios: Smaller than cachedEntriesPerMap and bigger
	smallSlice := make([]transactions.Txid, cachedEntriesPerMap/2)

	// Fill with random numbers
	for i := 0; i < cachedEntriesPerMap/2; i++ {
		tx := &smallSlice[i]
		tx[0] = byte((i + 37) % 255)
		tx[1] = byte((i + 2) % 255)
		tx[2] = byte((i + 42) % 255)
		tx[3] = byte((i + 23) % 255)
	}

	bigSlice := make([]transactions.Txid, 2*cachedEntriesPerMap)

	// Fill with sequential numbers
	for i := 0; i < 2*cachedEntriesPerMap; i++ {
		tx := &bigSlice[i]
		bs := []byte(strconv.Itoa(i))
		d := crypto.Hash(bs)

		*tx = transactions.Txid(d)
	}

	curTimestamp := time.Duration(0)

	ltc := &tc.longTermCache
	require.Equal(t, 2, len(ltc.transactionsMap))

	require.Equal(t, 0, ltc.current)

	ltc.add(smallSlice, curTimestamp)

	require.Equal(t, 0, ltc.current)

	sliceMap := make(map[transactions.Txid]bool)
	for _, txid := range smallSlice {
		sliceMap[txid] = true
	}

	require.True(t, reflect.DeepEqual(sliceMap, ltc.transactionsMap[0]))

	ltc.add(bigSlice, curTimestamp)

	// Given that we already added small slice, we should "overflow"
	// and expect that the transaction map contains a modified version of big slice

	slice := bigSlice
	for {
		availableEntries := cachedEntriesPerMap - len(sliceMap)
		if len(slice) <= availableEntries {
			for _, txid := range slice {
				sliceMap[txid] = true
			}
			break
		}

		for i := 0; i < availableEntries; i++ {
			sliceMap[slice[i]] = true
		}

		slice = slice[availableEntries:]

		if len(sliceMap) >= cachedEntriesPerMap {
			sliceMap = make(map[transactions.Txid]bool)
		}

	}

	require.Equal(t, 0, ltc.current)
	require.True(t, reflect.DeepEqual(sliceMap, ltc.transactionsMap[0]))

	bs := []byte(strconv.Itoa(cachedEntriesPerMap))
	d := crypto.Hash(bs)
	targetTxID := transactions.Txid(d)

	require.True(t, ltc.contained(targetTxID))

}
