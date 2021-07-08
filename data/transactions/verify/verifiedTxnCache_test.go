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

package verify

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/testpartitioning"
)

func TestAddingToCache(t *testing.T) {
	testpartitioning.PartitionTest(t)

	icache := MakeVerifiedTransactionCache(500)
	impl := icache.(*verifiedTransactionCache)
	_, signedTxn, secrets, addrs := generateTestObjects(10, 5, 50)
	txnGroups := generateTransactionGroups(signedTxn, secrets, addrs)
	groupCtx, err := PrepareGroupContext(txnGroups[0], blockHeader)
	require.NoError(t, err)
	impl.Add(txnGroups[0], groupCtx)
	// make it was added.
	for _, txn := range txnGroups[0] {
		ctx, has := impl.buckets[impl.base][txn.ID()]
		require.True(t, has)
		require.Equal(t, ctx, groupCtx)
	}
}

func TestBucketCycling(t *testing.T) {
	testpartitioning.PartitionTest(t)

	bucketCount := 3
	icache := MakeVerifiedTransactionCache(entriesPerBucket * bucketCount)
	impl := icache.(*verifiedTransactionCache)
	_, signedTxn, _, _ := generateTestObjects(entriesPerBucket*bucketCount*2, bucketCount, 0)

	require.Equal(t, entriesPerBucket*bucketCount*2, len(signedTxn))
	groupCtx, err := PrepareGroupContext([]transactions.SignedTxn{signedTxn[0]}, blockHeader)
	require.NoError(t, err)

	// fill up the cache with entries.
	for i := 0; i < entriesPerBucket*(bucketCount+1); i++ {
		impl.Add([]transactions.SignedTxn{signedTxn[i]}, groupCtx)
		// test to see that the base is sliding when bucket get filled up.
		require.Equal(t, i/entriesPerBucket, impl.base)
	}

	for i, bucket := range impl.buckets {
		require.Equalf(t, entriesPerBucket, len(bucket), "bucket %d doesn't contain expected number of entries. base = %d", i, impl.base)
	}

	// -- all buckets are full at this point --
	// add one additional item which would flush the bottom bucket.
	impl.Add([]transactions.SignedTxn{signedTxn[len(signedTxn)-1]}, groupCtx)
	require.Equal(t, 0, impl.base)
	require.Equal(t, 1, len(impl.buckets[0]))
}

func TestGetUnverifiedTranscationGroups50(t *testing.T) {
	testpartitioning.PartitionTest(t)

	size := 300
	icache := MakeVerifiedTransactionCache(size * 2)
	impl := icache.(*verifiedTransactionCache)
	_, signedTxn, secrets, addrs := generateTestObjects(size*2, 10+size/1000, 0)
	txnGroups := generateTransactionGroups(signedTxn, secrets, addrs)

	expectedUnverifiedGroups := make([][]transactions.SignedTxn, 0, len(txnGroups)/2)
	// add every even transaction to the cache.
	for i := 0; i < len(txnGroups); i++ {

		if i%2 == 0 {
			expectedUnverifiedGroups = append(expectedUnverifiedGroups, txnGroups[i])
		} else {
			groupCtx, _ := PrepareGroupContext(txnGroups[i], blockHeader)
			impl.Add(txnGroups[i], groupCtx)
		}
	}

	unverifiedGroups := impl.GetUnverifiedTranscationGroups(txnGroups, spec, protocol.ConsensusCurrentVersion)
	require.Equal(t, len(expectedUnverifiedGroups), len(unverifiedGroups))
}

func BenchmarkGetUnverifiedTranscationGroups50(b *testing.B) {
	if b.N < 20000 {
		b.N = 20000
	}
	icache := MakeVerifiedTransactionCache(b.N * 2)
	impl := icache.(*verifiedTransactionCache)
	_, signedTxn, secrets, addrs := generateTestObjects(b.N*2, 10+b.N/1000, 0)
	txnGroups := generateTransactionGroups(signedTxn, secrets, addrs)

	queryTxnGroups := make([][]transactions.SignedTxn, 0, b.N)
	// add every even transaction to the cache.
	for i := 0; i < len(txnGroups); i++ {
		if i%2 == 1 {
			queryTxnGroups = append(queryTxnGroups, txnGroups[i])
		} else {
			groupCtx, _ := PrepareGroupContext(txnGroups[i], blockHeader)
			impl.Add(txnGroups[i], groupCtx)
		}
	}

	b.ResetTimer()
	startTime := time.Now()
	measuringMultipler := 1000
	for i := 0; i < measuringMultipler; i++ {
		impl.GetUnverifiedTranscationGroups(queryTxnGroups, spec, protocol.ConsensusCurrentVersion)
	}
	duration := time.Now().Sub(startTime)
	// calculate time per 10K verified entries:
	t := int(duration*10000) / (measuringMultipler * b.N)
	b.ReportMetric(float64(t)/float64(time.Millisecond), "ms/10K_cache_compares")

}

func TestUpdatePinned(t *testing.T) {
	testpartitioning.PartitionTest(t)

	size := entriesPerBucket
	icache := MakeVerifiedTransactionCache(size * 10)
	impl := icache.(*verifiedTransactionCache)
	_, signedTxn, secrets, addrs := generateTestObjects(size*2, 10, 0)
	txnGroups := generateTransactionGroups(signedTxn, secrets, addrs)

	// insert half of the entries.
	for i := 0; i < len(txnGroups); i++ {
		groupCtx, _ := PrepareGroupContext(txnGroups[i], blockHeader)
		impl.Add(txnGroups[i], groupCtx)
	}

	// pin the first half.
	for i := 0; i < len(txnGroups)/2; i++ {
		require.NoError(t, impl.Pin(txnGroups[i]))
	}

	pinnedTxns := make(map[transactions.Txid]transactions.SignedTxn)
	for i := len(txnGroups) / 4; i < len(txnGroups)*3/4; i++ {
		for _, txn := range txnGroups[i] {
			pinnedTxns[txn.ID()] = txn
		}
	}
	require.NoError(t, impl.UpdatePinned(pinnedTxns))
}

func TestPinningTransactions(t *testing.T) {
	testpartitioning.PartitionTest(t)

	size := entriesPerBucket
	icache := MakeVerifiedTransactionCache(size)
	impl := icache.(*verifiedTransactionCache)
	_, signedTxn, secrets, addrs := generateTestObjects(size*2, 10, 0)
	txnGroups := generateTransactionGroups(signedTxn, secrets, addrs)

	// insert half of the entries.
	for i := 0; i < len(txnGroups)/2; i++ {
		groupCtx, _ := PrepareGroupContext(txnGroups[i], blockHeader)
		impl.Add(txnGroups[i], groupCtx)
	}

	// try to pin a previously added entry.
	require.NoError(t, impl.Pin(txnGroups[0]))

	// try to pin an entry that was not added.
	require.Error(t, impl.Pin(txnGroups[len(txnGroups)-1]))

}
