// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// The status cache is a retention structure: an entry lives until it is cycled out, which
// at the default TxPoolSize of 75000 (150000 entries across cur+prev) takes on the order
// of a day on mainnet. What matters is therefore the resident cost of a full cache, not
// the cost of filling it, so these benchmarks measure live heap per cached entry.

const statusMembenchEntries = 20000

// liveHeap reports the live heap once the collector has settled. Two cycles are needed
// because the first can leave finalizable objects uncollected.
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// makeStatusCacheTxn builds a payment transaction of the shape the status cache actually
// holds: one that failed to make it into a block, carrying a note and a signature.
func makeStatusCacheTxn(i int) transactions.SignedTxn {
	var sig crypto.Signature
	crypto.RandBytes(sig[:])
	var sender, receiver basics.Address
	crypto.RandBytes(sender[:])
	crypto.RandBytes(receiver[:])
	note := make([]byte, 16)
	crypto.RandBytes(note)

	return transactions.SignedTxn{
		Sig: sig,
		Txn: transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:     sender,
				Fee:        basics.MicroAlgos{Raw: 1000},
				FirstValid: basics.Round(i),
				LastValid:  basics.Round(i + 1000),
				Note:       note,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: receiver,
				Amount:   basics.MicroAlgos{Raw: uint64(i)},
			},
		},
	}
}

// BenchmarkStatusCacheResidentSize reports the live heap a full status cache holds, in
// bytes per entry.
//
// To translate into a node footprint, multiply by 2*TxPoolSize: the cache keeps a cur and
// a prev map of TxPoolSize entries each, so the default 75000 allows 150000 live entries.
func BenchmarkStatusCacheResidentSize(b *testing.B) {
	var perEntry, totalMB float64
	for i := 0; i < b.N; i++ {
		perEntry, totalMB = measureStatusCache()
	}
	b.ReportMetric(perEntry, "bytes/entry")
	b.ReportMetric(totalMB, "total-MB")
	b.ReportMetric(perEntry*150000/(1024*1024), "MB-def-cap")
}

// measureStatusCache fills a cache and returns the bytes it retains per entry, and in
// total. The transactions are built inside the loop and go out of scope before the final
// measurement, so what remains on the heap is exactly what the cache is holding on to.
func measureStatusCache() (perEntry, totalMB float64) {
	const errMsg = "transaction already in ledger"

	// sized so nothing is cycled out mid-run, and allocated before the baseline snapshot
	// so the empty maps are excluded and only the entries are counted
	sc := makeStatusCache(statusMembenchEntries * 2)

	empty := liveHeap()
	for i := 0; i < statusMembenchEntries; i++ {
		sc.put(makeStatusCacheTxn(i), errMsg)
	}
	full := liveHeap()
	runtime.KeepAlive(sc)

	retained := full - empty
	return float64(retained) / float64(statusMembenchEntries), float64(retained) / (1024 * 1024)
}

// BenchmarkStatusCachePut measures the insert path, which now pays for encoding.
func BenchmarkStatusCachePut(b *testing.B) {
	txns := make([]transactions.SignedTxn, 1024)
	for i := range txns {
		txns[i] = makeStatusCacheTxn(i)
	}
	sc := makeStatusCache(b.N + 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sc.put(txns[i%len(txns)], "transaction already in ledger")
	}
}

// BenchmarkStatusCacheCheckHit measures a lookup that finds an entry, which now pays for
// decoding.
func BenchmarkStatusCacheCheckHit(b *testing.B) {
	sc := makeStatusCache(4096)
	txns := make([]transactions.SignedTxn, 1024)
	ids := make([]transactions.Txid, len(txns))
	for i := range txns {
		txns[i] = makeStatusCacheTxn(i)
		ids[i] = txns[i].ID()
		sc.put(txns[i], "transaction already in ledger")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, found := sc.check(ids[i%len(ids)])
		if !found {
			b.Fatal("expected a hit")
		}
	}
}

// BenchmarkStatusCacheCheckMiss measures a lookup that finds nothing. Every REST query
// for a transaction that is neither pending nor recently failed lands here, so it is the
// common case for /v2/transactions/pending/{txid}.
func BenchmarkStatusCacheCheckMiss(b *testing.B) {
	sc := makeStatusCache(4096)
	for i := 0; i < 1024; i++ {
		sc.put(makeStatusCacheTxn(i), "transaction already in ledger")
	}
	misses := make([]transactions.Txid, 1024)
	for i := range misses {
		crypto.RandBytes(misses[i][:])
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, found := sc.check(misses[i%len(misses)]); found {
			b.Fatal("unexpected hit")
		}
	}
}

// TestStatusCacheRoundTrip checks that what goes into the cache comes back out unchanged,
// that a miss reports itself as one, and that a miss does not fabricate a transaction.
func TestStatusCacheRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)

	sc := makeStatusCache(64)

	stxn := makeStatusCacheTxn(1)
	sc.put(stxn, "some error")

	got, gotErr, found := sc.check(stxn.ID())
	require.True(t, found)
	require.Equal(t, "some error", gotErr)
	require.Equal(t, stxn, got)

	var absent transactions.Txid
	crypto.RandBytes(absent[:])
	got, gotErr, found = sc.check(absent)
	require.False(t, found, "a transaction that was never cached must not be found")
	require.Empty(t, gotErr)
	require.Equal(t, transactions.SignedTxn{}, got, "a miss must not return a transaction")
}
