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

package verify

import (
	"fmt"
	"runtime"
	"slices"
	"testing"
	"time"
	"unique"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestAddingToCache(t *testing.T) {
	partitiontest.PartitionTest(t)

	icache := MakeVerifiedTransactionCache(500)
	impl := icache.(*verifiedTransactionCache)
	_, signedTxn, secrets, addrs := generateTestObjects(10, 5, 0, 50)
	txnGroups := generateTransactionGroups(protoMaxGroupSize, signedTxn, secrets, addrs)
	groupCtx, err := PrepareGroupContext(txnGroups[0], blockHeader, nil, nil)
	require.NoError(t, err)
	impl.Add(groupCtx)
	// make it was added.
	for _, txn := range txnGroups[0] {
		ctx, has := impl.buckets[impl.base][txn.ID()]
		require.True(t, has)
		require.Equal(t, ctx, &verifiedTxnCtx{
			vctx: unique.Make(verificationContext{
				specAddrs:        groupCtx.specAddrs,
				consensusVersion: groupCtx.consensusVersion,
			}),
			sigs: txnAuth{
				sig:      txn.Sig,
				authAddr: txn.AuthAddr,
				msig:     nil,
				lsig:     nil,
				pqsig:    nil,
			},
		})
	}
}

// TestAddingToCacheOutOfLineSigs covers the authorization material the cache keeps out of
// line. Lsig and PQsig are stored behind pointers because almost no transaction carries
// either, so both the present and the absent case need checking.
func TestAddingToCacheOutOfLineSigs(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signedTxns, _, _ := generateTestObjects(1, 2, 0, 50)

	// a contract-account logicsig, which is the shape essentially all of them have:
	// a program and arguments, with no delegation signature
	contractLsig := transactions.SignedTxn{Txn: signedTxns[0].Txn}
	contractLsig.Lsig.Logic = []byte{0x06, 0x81, 0x01}
	contractLsig.Lsig.Args = [][]byte{[]byte("arg0"), []byte("arg1")}

	tests := []struct {
		name string
		stxn transactions.SignedTxn
	}{
		{"lsig", contractLsig},
		{"pqsig", makePQSignedTxn(t, 20)},
		{"lsig-delegated-by-pqsig", makePQDelegatedLogicSigTxn(t, 21)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			icache := MakeVerifiedTransactionCache(500)
			impl := icache.(*verifiedTransactionCache)

			group := []transactions.SignedTxn{test.stxn}
			groupCtx, err := PrepareGroupContext(group, blockHeader, nil, nil)
			require.NoError(t, err)
			impl.Add(groupCtx)

			ctx, has := impl.buckets[impl.base][group[0].ID()]
			require.True(t, has)

			if test.stxn.Lsig.Blank() {
				require.Nil(t, ctx.sigs.lsig)
			} else {
				require.NotNil(t, ctx.sigs.lsig, "a present Lsig must be stored")
				require.Equal(t, test.stxn.Lsig, *ctx.sigs.lsig)
			}
			if test.stxn.PQsig.Blank() {
				require.Nil(t, ctx.sigs.pqsig)
			} else {
				require.NotNil(t, ctx.sigs.pqsig, "a present PQsig must be stored")
				require.Equal(t, test.stxn.PQsig, *ctx.sigs.pqsig)
			}

			// the entry keeps its own copy: PrepareGroupContext retains the caller's
			// slice, so storing a pointer into it would let later edits rewrite history
			group[0].Lsig.Sig[0]++
			group[0].Lsig.Logic = []byte{0xff}
			group[0].PQsig.Salt++
			if ctx.sigs.lsig != nil {
				require.Equal(t, test.stxn.Lsig, *ctx.sigs.lsig, "cached Lsig aliases the caller")
			}
			if ctx.sigs.pqsig != nil {
				require.Equal(t, test.stxn.PQsig, *ctx.sigs.pqsig, "cached PQsig aliases the caller")
			}
		})
	}
}

func TestBucketCycling(t *testing.T) {
	partitiontest.PartitionTest(t)

	bucketCount := 3
	entriesPerBucket := 100
	icache := MakeVerifiedTransactionCache(entriesPerBucket * (bucketCount - 1))
	impl := icache.(*verifiedTransactionCache)
	_, signedTxn, _, _ := generateTestObjects(entriesPerBucket*bucketCount*2, bucketCount, 0, 0)

	require.Equal(t, entriesPerBucket*bucketCount*2, len(signedTxn))

	// fill up the cache with entries.
	for i := 0; i < entriesPerBucket*bucketCount; i++ {
		txnGroup := []transactions.SignedTxn{signedTxn[i]}
		groupCtx, err := PrepareGroupContext(txnGroup, blockHeader, nil, nil)
		require.NoError(t, err)
		impl.Add(groupCtx)
		// test to see that the base is sliding when bucket get filled up.
		require.Equal(t, i/entriesPerBucket, impl.base)
	}

	for i, bucket := range impl.buckets {
		require.Equalf(t, entriesPerBucket, len(bucket), "bucket %d doesn't contain expected number of entries. base = %d", i, impl.base)
	}

	// -- all buckets are full at this point --
	// add one additional item which would flush the bottom bucket.
	txnGroup := []transactions.SignedTxn{signedTxn[len(signedTxn)-1]}
	groupCtx, err := PrepareGroupContext(txnGroup, blockHeader, nil, nil)
	require.NoError(t, err)
	impl.Add(groupCtx)
	require.Equal(t, 0, impl.base)
	require.Equal(t, 1, len(impl.buckets[0]))
}

func TestGetUnverifiedTransactionGroups50(t *testing.T) {
	partitiontest.PartitionTest(t)

	size := 300
	icache := MakeVerifiedTransactionCache(size * 2)
	impl := icache.(*verifiedTransactionCache)
	_, signedTxn, secrets, addrs := generateTestObjects(size*2, 10+size/1000, 0, 0)
	txnGroups := generateTransactionGroups(protoMaxGroupSize, signedTxn, secrets, addrs)

	expectedUnverifiedGroups := make([][]transactions.SignedTxn, 0, len(txnGroups)/2)
	// add every even transaction to the cache.
	for i := 0; i < len(txnGroups); i++ {

		if i%2 == 0 {
			expectedUnverifiedGroups = append(expectedUnverifiedGroups, txnGroups[i])
		} else {
			groupCtx, _ := PrepareGroupContext(txnGroups[i], blockHeader, nil, nil)
			impl.Add(groupCtx)
		}
	}

	unverifiedGroups := impl.GetUnverifiedTransactionGroups(txnGroups, spec, protocol.ConsensusCurrentVersion)
	require.Equal(t, len(expectedUnverifiedGroups), len(unverifiedGroups))
}

func TestGetUnverifiedTransactionGroupsPQSigProofChanges(t *testing.T) {
	partitiontest.PartitionTest(t)

	blkHdr := createDummyBlockHeader(protocol.ConsensusFuture)
	cache := MakeVerifiedTransactionCache(10)
	dummyLedger := DummyLedgerForSignature{}

	stxn := makePQSignedTxn(t, 20)
	group := []transactions.SignedTxn{stxn}
	_, err := TxnGroup(group, &blkHdr, cache, &dummyLedger)
	require.NoError(t, err)

	unverifiedGroups := cache.GetUnverifiedTransactionGroups([][]transactions.SignedTxn{group}, spec, blkHdr.CurrentProtocol)
	require.Empty(t, unverifiedGroups)

	clone := func(stxn transactions.SignedTxn) transactions.SignedTxn {
		stxn.PQsig.PublicKey = slices.Clone(stxn.PQsig.PublicKey)
		stxn.PQsig.Signature = slices.Clone(stxn.PQsig.Signature)
		return stxn
	}

	tests := []struct {
		name   string
		mutate func(*transactions.SignedTxn)
	}{
		{
			name: "signature",
			mutate: func(stxn *transactions.SignedTxn) {
				stxn.PQsig.Signature[0] ^= 1
			},
		},
		{
			name: "public-key",
			mutate: func(stxn *transactions.SignedTxn) {
				stxn.PQsig.PublicKey[0] ^= 1
			},
		},
		{
			name: "salt",
			mutate: func(stxn *transactions.SignedTxn) {
				stxn.PQsig.Salt ^= 1
			},
		},
		{
			name: "scheme",
			mutate: func(stxn *transactions.SignedTxn) {
				stxn.PQsig.Scheme = protocol.PQScheme{'x', '1'}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := clone(stxn)
			test.mutate(&mutated)
			require.Equal(t, stxn.ID(), mutated.ID())

			unverifiedGroups := cache.GetUnverifiedTransactionGroups([][]transactions.SignedTxn{{mutated}}, spec, blkHdr.CurrentProtocol)
			require.Len(t, unverifiedGroups, 1)
			require.Equal(t, []transactions.SignedTxn{mutated}, unverifiedGroups[0])
		})
	}
}

func BenchmarkGetUnverifiedTransactionGroups50(b *testing.B) {
	if b.N < 20000 {
		b.N = 20000
	}
	icache := MakeVerifiedTransactionCache(b.N * 2)
	impl := icache.(*verifiedTransactionCache)
	_, signedTxn, secrets, addrs := generateTestObjects(b.N*2, 10+b.N/1000, 0, 0)
	txnGroups := generateTransactionGroups(protoMaxGroupSize, signedTxn, secrets, addrs)

	queryTxnGroups := make([][]transactions.SignedTxn, 0, b.N)
	// add every even transaction to the cache.
	for i := 0; i < len(txnGroups); i++ {
		if i%2 == 1 {
			queryTxnGroups = append(queryTxnGroups, txnGroups[i])
		} else {
			groupCtx, _ := PrepareGroupContext(txnGroups[i], blockHeader, nil, nil)
			impl.Add(groupCtx)
		}
	}

	b.ResetTimer()
	startTime := time.Now()
	measuringMultipler := 1000
	for i := 0; i < measuringMultipler; i++ {
		impl.GetUnverifiedTransactionGroups(queryTxnGroups, spec, protocol.ConsensusCurrentVersion)
	}
	duration := time.Since(startTime)
	// calculate time per 10K verified entries:
	t := int(duration*10000) / (measuringMultipler * b.N)
	b.ReportMetric(float64(t)/float64(time.Millisecond), "ms/10K_cache_compares")

}

func TestUpdatePinned(t *testing.T) {
	partitiontest.PartitionTest(t)

	size := 100
	icache := MakeVerifiedTransactionCache(size * 10)
	impl := icache.(*verifiedTransactionCache)
	_, signedTxn, secrets, addrs := generateTestObjects(size*2, 10, 0, 0)
	txnGroups := generateTransactionGroups(protoMaxGroupSize, signedTxn, secrets, addrs)

	// insert some entries.
	for i := 0; i < len(txnGroups); i++ {
		groupCtx, _ := PrepareGroupContext(txnGroups[i], blockHeader, nil, nil)
		impl.Add(groupCtx)
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
	partitiontest.PartitionTest(t)

	size := 100
	icache := MakeVerifiedTransactionCache(size)
	impl := icache.(*verifiedTransactionCache)
	_, signedTxn, secrets, addrs := generateTestObjects(size*2, 10, 0, 0)
	txnGroups := generateTransactionGroups(protoMaxGroupSize, signedTxn, secrets, addrs)

	// insert half of the entries.
	for i := 0; i < len(txnGroups)/2; i++ {
		groupCtx, _ := PrepareGroupContext(txnGroups[i], blockHeader, nil, nil)
		impl.Add(groupCtx)
	}

	// try to pin a previously added entry.
	require.NoError(t, impl.Pin(txnGroups[0]))

	// try to pin an entry that was not added.
	require.Error(t, impl.Pin(txnGroups[len(txnGroups)-1]))
}

// TestGetUnverifiedTransactionGroupsAuthChanges checks that a cached transaction whose
// authorization material has been altered is reported as unverified.
func TestGetUnverifiedTransactionGroupsAuthChanges(t *testing.T) {
	partitiontest.PartitionTest(t)

	blkHdr := createDummyBlockHeader()
	cache := MakeVerifiedTransactionCache(50)

	_, signedTxns, secrets, addrs := generateTestObjects(2, 2, 0, 50)
	group := generateTransactionGroups(1, signedTxns, secrets, addrs)[0]
	groupCtx, err := PrepareGroupContext(group, &blkHdr, nil, nil)
	require.NoError(t, err)
	cache.Add(groupCtx)

	// the unmodified group is cached
	require.Empty(t, cache.GetUnverifiedTransactionGroups([][]transactions.SignedTxn{group}, groupCtx.specAddrs, groupCtx.consensusVersion))

	tests := []struct {
		name   string
		mutate func(*transactions.SignedTxn)
	}{
		{"sig", func(stxn *transactions.SignedTxn) { stxn.Sig[0] ^= 1 }},
		{"auth-addr", func(stxn *transactions.SignedTxn) { stxn.AuthAddr[0] ^= 1 }},
		{"msig-version", func(stxn *transactions.SignedTxn) { stxn.Msig.Version ^= 1 }},
		{"lsig-logic", func(stxn *transactions.SignedTxn) { stxn.Lsig.Logic = []byte{0x06, 0x81, 0x01} }},
		{"lsig-args", func(stxn *transactions.SignedTxn) { stxn.Lsig.Args = [][]byte{[]byte("arg")} }},
		{"lsig-sig", func(stxn *transactions.SignedTxn) { stxn.Lsig.Sig[0] ^= 1 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := group[0]
			test.mutate(&mutated)
			require.Equal(t, group[0].ID(), mutated.ID())

			unverifiedGroups := cache.GetUnverifiedTransactionGroups(
				[][]transactions.SignedTxn{{mutated}}, groupCtx.specAddrs, groupCtx.consensusVersion)
			require.Len(t, unverifiedGroups, 1, "altered authorization was accepted as already-verified")
			require.Equal(t, []transactions.SignedTxn{mutated}, unverifiedGroups[0])
		})
	}
}

// BenchmarkVerifiedCacheRetention reports the marginal live heap each cached
// transaction costs: pre-sized maps are filled without triggering growth or bucket
// rotation, and the empty-container cost is measured separately and excluded, so the
// reported figure is the retained value.
// To translate a bytes/txn figure into a node footprint, multiply by the cache capacity,
// which is 1.5x the configured VerifiedTranscationsCacheSize: the implementation keeps
// three buckets of (size+1)/2 entries. At the default 150000 that is 225000 entries.
func BenchmarkVerifiedCacheRetention(b *testing.B) {
	for _, groupSize := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("gs=%d", groupSize), func(b *testing.B) {
			var perTxn, totalMB float64
			for i := 0; i < b.N; i++ {
				perTxn, totalMB = measureRetention(b, groupSize)
			}
			b.ReportMetric(perTxn, "bytes/txn")
			b.ReportMetric(totalMB, "MB")
			b.ReportMetric(perTxn*225000/(1024*1024), "MB-def-cap")
		})
	}
}

// liveHeap reports the live heap once the collector has settled. Two cycles are needed
// because the first can leave finalizable objects uncollected.
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// generateGroupContexts builds signed transaction groups totalling at least numTxns
// transactions and prepares a GroupContext for each, exactly as the verification path
// does before handing them to the cache.
func generateGroupContexts(tb testing.TB, maxGroupSize, numTxns int) ([]*GroupContext, int) {
	groupCtxs := make([]*GroupContext, 0, numTxns)
	total := 0
	for total < numTxns {
		// generate in chunks so no single signing pass dominates
		_, signedTxns, secrets, addrs := generateTestObjects(1024, 64, total, 50)
		for _, group := range generateTransactionGroups(maxGroupSize, signedTxns, secrets, addrs) {
			groupCtx, err := PrepareGroupContext(group, blockHeader, nil, nil)
			require.NoError(tb, err)
			groupCtxs = append(groupCtxs, groupCtx)
			total += len(group)
			if total >= numTxns {
				break
			}
		}
	}
	return groupCtxs, total
}

// measureRetention fills one container and returns bytes retained per transaction and in
// total. The GroupContexts and their transactions go out of scope before the final
// measurement, so only what the container itself holds is counted.
func measureRetention(tb testing.TB, groupSize int) (perTxn, totalMB float64) {
	// sized so that every entry fits without map growth or bucket rotation
	const membenchTxns = 20000
	cache := MakeVerifiedTransactionCache(membenchTxns * 3)

	// the empty containers are already allocated, so their fixed cost is excluded
	empty := liveHeap()

	total := func() int {
		groupCtxs, total := generateGroupContexts(tb, groupSize, membenchTxns)
		for _, groupCtx := range groupCtxs {
			cache.Add(groupCtx)
		}
		return total
	}()

	full := liveHeap()
	runtime.KeepAlive(cache)

	retained := full - empty
	return float64(retained) / float64(total), float64(retained) / (1024 * 1024)
}

// TestAddingToCacheBlankLsigNilVsEmpty checks that the cache does not collapse a nil
// LogicSig field with a non-nil empty one. LogicSig.Blank() treats both as empty, but
// LogicSig.Equal() -- the comparison the cache actually performs -- distinguishes them
// via safeSliceCheck, so compressing the entry on Blank() would report a hit for a
// transaction that a full comparison rejects.
func TestAddingToCacheBlankLsigNilVsEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)

	var nilLsig, emptyLsig transactions.LogicSig
	emptyLsig.Logic = []byte{}
	require.True(t, nilLsig.Blank())
	require.True(t, emptyLsig.Blank(), "Blank() does not distinguish nil from empty")
	require.False(t, nilLsig.Equal(&emptyLsig), "Equal() does distinguish them")

	_, signedTxns, secrets, addrs := generateTestObjects(2, 2, 0, 50)
	group := generateTransactionGroups(1, signedTxns, secrets, addrs)[0]

	cached := group[0]
	cached.Lsig.Logic = []byte{} // blank, but not nil
	probe := cached
	probe.Lsig.Logic = nil // blank, and nil
	require.Equal(t, cached.ID(), probe.ID(), "the cache key must be identical")

	cache := MakeVerifiedTransactionCache(50)
	groupCtx, err := PrepareGroupContext([]transactions.SignedTxn{cached}, blockHeader, nil, nil)
	require.NoError(t, err)
	cache.Add(groupCtx)

	// the transaction as cached is still recognised
	require.Empty(t, cache.GetUnverifiedTransactionGroups(
		[][]transactions.SignedTxn{{cached}}, groupCtx.specAddrs, groupCtx.consensusVersion))

	// the nil-valued form is a different LogicSig and must not inherit the verification
	require.Len(t, cache.GetUnverifiedTransactionGroups(
		[][]transactions.SignedTxn{{probe}}, groupCtx.specAddrs, groupCtx.consensusVersion), 1,
		"a LogicSig that Equal() rejects was reported as already verified")
}

// TestAddingToCacheBlankMsigNilVsEmpty pins down the multisig counterpart of
// TestAddingToCacheBlankLsigNilVsEmpty test above, which points the opposite way.
//
// MultisigSig.Blank() tests Subsigs != nil, while MultisigSig.Equal() compares len(), so
// a non-nil empty Subsigs is NOT blank yet IS equal to the zero value -- the mirror image
// of LogicSig, where Blank() is the lenient one. The cache compresses on Blank(), so such
// a transaction is stored out of line and a later nil-valued one is reported as a miss
// even though Equal() would accept it.
func TestAddingToCacheBlankMsigNilVsEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)

	// the asymmetry this test exists to document
	var emptyMsig crypto.MultisigSig
	emptyMsig.Subsigs = []crypto.MultisigSubsig{}
	require.False(t, emptyMsig.Blank(), "Blank() tests Subsigs != nil, so an empty slice is not blank")
	require.True(t, emptyMsig.Equal(crypto.MultisigSig{}), "Equal() compares len(), so it accepts the zero value")

	_, signedTxns, secrets, addrs := generateTestObjects(2, 2, 0, 50)
	group := generateTransactionGroups(1, signedTxns, secrets, addrs)[0]

	cached := group[0]
	cached.Msig.Subsigs = []crypto.MultisigSubsig{} // not blank, but equal to the zero value

	mutated := cached
	mutated.Msig.Subsigs = nil // blank, and still equal to the zero value
	require.Equal(t, cached.ID(), mutated.ID(), "the cache key must be identical")
	require.True(t, cached.Msig.Equal(mutated.Msig), "Equal() cannot tell these apart")

	cache := MakeVerifiedTransactionCache(50)
	groupCtx, err := PrepareGroupContext([]transactions.SignedTxn{cached}, blockHeader, nil, nil)
	require.NoError(t, err)
	cache.Add(groupCtx)

	// the transaction as cached is still recognised
	require.Empty(t, cache.GetUnverifiedTransactionGroups(
		[][]transactions.SignedTxn{{cached}}, groupCtx.specAddrs, groupCtx.consensusVersion))

	// the nil-valued form is reported as unverified: the conservative direction
	require.Len(t, cache.GetUnverifiedTransactionGroups(
		[][]transactions.SignedTxn{{mutated}}, groupCtx.specAddrs, groupCtx.consensusVersion), 1,
		"compressing on Blank() must report a miss rather than inherit the verification")
}

// TestGetUnverifiedTransactionGroupsContextChanges checks that a cached verification is
// not reused when the external state it depended on has changed. The special addresses
// and the consensus version are interned together into one handle, so this also guards
// against that composite collapsing two distinct contexts onto the same handle.
func TestGetUnverifiedTransactionGroupsContextChanges(t *testing.T) {
	partitiontest.PartitionTest(t)

	_, signedTxns, secrets, addrs := generateTestObjects(4, 4, 0, 50)
	group := generateTransactionGroups(1, signedTxns, secrets, addrs)[0]

	cache := MakeVerifiedTransactionCache(50)
	groupCtx, err := PrepareGroupContext(group, blockHeader, nil, nil)
	require.NoError(t, err)
	cache.Add(groupCtx)

	cachedSpec := groupCtx.specAddrs
	cachedProto := groupCtx.consensusVersion
	payset := [][]transactions.SignedTxn{group}

	// control: queried under the very context it was verified in, it is a hit
	require.Empty(t, cache.GetUnverifiedTransactionGroups(payset, cachedSpec, cachedProto),
		"the group must be recognised under its own verification context")

	otherFeeSink := cachedSpec.FeeSink
	otherFeeSink[0]++
	otherRewardsPool := cachedSpec.RewardsPool
	otherRewardsPool[0]++

	tests := []struct {
		name      string
		specAddrs transactions.SpecialAddresses
		proto     protocol.ConsensusVersion
	}{
		{
			name:      "fee-sink",
			specAddrs: transactions.SpecialAddresses{FeeSink: otherFeeSink, RewardsPool: cachedSpec.RewardsPool},
			proto:     cachedProto,
		},
		{
			name:      "rewards-pool",
			specAddrs: transactions.SpecialAddresses{FeeSink: cachedSpec.FeeSink, RewardsPool: otherRewardsPool},
			proto:     cachedProto,
		},
		{
			name:      "consensus-version",
			specAddrs: cachedSpec,
			proto:     protocol.ConsensusFuture,
		},
		{
			name:      "all-three",
			specAddrs: transactions.SpecialAddresses{FeeSink: otherFeeSink, RewardsPool: otherRewardsPool},
			proto:     protocol.ConsensusFuture,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NotEqual(t, unique.Make(verificationContext{specAddrs: cachedSpec, consensusVersion: cachedProto}),
				unique.Make(verificationContext{specAddrs: test.specAddrs, consensusVersion: test.proto}),
				"the changed context must intern to a different handle")

			unverified := cache.GetUnverifiedTransactionGroups(payset, test.specAddrs, test.proto)
			require.Len(t, unverified, 1, "a cached verification was reused under a changed context")
			require.Equal(t, group, unverified[0])
		})
	}

	// and the original context still hits afterwards: querying under a different context
	// must not disturb the entry
	require.Empty(t, cache.GetUnverifiedTransactionGroups(payset, cachedSpec, cachedProto))
}
