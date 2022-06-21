// Copyright (C) 2019-2022 Algorand, Inc.
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

package ledger

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestOnlineAccountsCacheBasic(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var oac onlineAccountsCache
	const maxCacheSize = 10
	oac.init(nil, maxCacheSize)

	addr := basics.Address(crypto.Hash([]byte{byte(0)}))

	roundsNum := 50
	for i := 0; i < roundsNum; i++ {
		acct := cachedOnlineAccount{
			updRound:              basics.Round(i),
			baseOnlineAccountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}, baseVotingData: baseVotingData{VoteLastValid: 1000}},
		}
		written := oac.writeFront(addr, acct)
		require.True(t, written)
	}

	// verify that all these onlineaccounts are truly there.
	for i := 0; i < roundsNum; i++ {
		acct, has := oac.read(addr, basics.Round(i))
		require.True(t, has)
		require.Equal(t, basics.Round(i), acct.updRound)
		require.Equal(t, uint64(i), acct.MicroAlgos.Raw)
	}

	for i := proto.MaxBalLookback; i < uint64(roundsNum)+proto.MaxBalLookback; i++ {
		acct := cachedOnlineAccount{
			updRound:              basics.Round(i),
			baseOnlineAccountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: i}, baseVotingData: baseVotingData{VoteLastValid: 1000}},
		}
		written := oac.writeFront(addr, acct)
		require.True(t, written)
	}

	oac.prune(basics.Round(proto.MaxBalLookback - 1))

	// verify that all these accounts are truly there.
	acct, has := oac.read(addr, basics.Round(proto.MaxBalLookback-1))
	require.True(t, has)
	require.Equal(t, basics.Round(roundsNum-1), acct.updRound)
	require.Equal(t, uint64(roundsNum-1), acct.MicroAlgos.Raw)

	for i := proto.MaxBalLookback; i < uint64(roundsNum)+proto.MaxBalLookback; i++ {
		acct, has := oac.read(addr, basics.Round(i))
		require.True(t, has)
		require.Equal(t, basics.Round(i), acct.updRound)
		require.Equal(t, uint64(i), acct.MicroAlgos.Raw)
	}

	_, has = oac.read(addr, basics.Round(0))
	require.False(t, has)

	// attempt to insert a value with the updRound less than latest, expect it to have ignored
	acct = cachedOnlineAccount{
		updRound:              basics.Round(uint64(roundsNum) + proto.MaxBalLookback - 1),
		baseOnlineAccountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: 100}, baseVotingData: baseVotingData{VoteLastValid: 1000}},
	}
	written := oac.writeFront(addr, acct)
	require.False(t, written)
}

func TestOnlineAccountsCachePruneOffline(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var oac onlineAccountsCache
	const maxCacheSize = 10
	oac.init(nil, maxCacheSize)

	addr := basics.Address(crypto.Hash([]byte{byte(0)}))

	roundsNum := 50
	for i := 0; i < roundsNum; i++ {
		acct := cachedOnlineAccount{
			updRound:              basics.Round(i),
			baseOnlineAccountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}, baseVotingData: baseVotingData{VoteLastValid: 1000}},
		}
		oac.writeFront(addr, acct)
	}
	acct := cachedOnlineAccount{
		updRound:              basics.Round(roundsNum),
		baseOnlineAccountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(roundsNum)}},
	}
	oac.writeFront(addr, acct)

	_, has := oac.read(addr, basics.Round(proto.MaxBalLookback))
	require.True(t, has)

	oac.prune(basics.Round(proto.MaxBalLookback))

	_, has = oac.read(addr, basics.Round(proto.MaxBalLookback))
	require.False(t, has)
}

func TestOnlineAccountsCacheMaxEntries(t *testing.T) {
	var oac onlineAccountsCache
	const maxCacheSize = 10
	oac.init(nil, maxCacheSize)
	var lastAddr basics.Address
	for i := 0; i < maxCacheSize; i++ {
		lastAddr = ledgertesting.RandomAddress()
		acct := cachedOnlineAccount{
			updRound:              basics.Round(i),
			baseOnlineAccountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(i)}, baseVotingData: baseVotingData{VoteLastValid: 1000}},
		}
		written := oac.writeFront(lastAddr, acct)
		require.True(t, written)
	}

	acct := cachedOnlineAccount{
		updRound:              basics.Round(100),
		baseOnlineAccountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(100)}, baseVotingData: baseVotingData{VoteLastValid: 1000}},
	}
	written := oac.writeFront(ledgertesting.RandomAddress(), acct)
	require.False(t, written)

	require.Equal(t, maxCacheSize, len(oac.accounts))
	require.True(t, oac.full())

	// set one to be expired
	acct = cachedOnlineAccount{
		updRound:              basics.Round(maxCacheSize),
		baseOnlineAccountData: baseOnlineAccountData{MicroAlgos: basics.MicroAlgos{Raw: uint64(100)}, baseVotingData: baseVotingData{}},
	}
	written = oac.writeFront(lastAddr, acct)
	require.True(t, written)

	// prune too old => no effect
	oac.prune(maxCacheSize)
	require.Equal(t, maxCacheSize, len(oac.accounts))
	require.True(t, oac.full())

	// remove one online entry that also trigger removal the offline remaining entry as well
	oac.prune(maxCacheSize + 1)
	require.Equal(t, maxCacheSize-1, len(oac.accounts))
	require.False(t, oac.full())

	// ensure not written
	oac.writeFrontIfExist(ledgertesting.RandomAddress(), acct)
	require.Equal(t, maxCacheSize-1, len(oac.accounts))
	require.False(t, oac.full())

	// write a new address, check writeFrontIfExist after
	addr := ledgertesting.RandomAddress()
	written = oac.writeFront(addr, acct)
	require.True(t, written)
	require.Equal(t, 1, oac.accounts[addr].Len())
	acct.updRound++
	oac.writeFrontIfExist(addr, acct)
	require.Equal(t, 2, oac.accounts[addr].Len())
}

var benchmarkOnlineAccountsCacheReadResult cachedOnlineAccount

func benchmarkOnlineAccountsCacheRead(b *testing.B, historyLength int) {
	// Create multiple accounts to simulate real usage and avoid excessive memory caching.
	const numAccounts = 1000

	makeAddress := func(i int) (addr basics.Address) {
		addr[0] = byte(i)
		return
	}

	var cache onlineAccountsCache
	cache.init(nil, numAccounts)

	// Iterate over rounds in the outer loop and accounts in the inner loop.
	// This has large (negative) impact on lookup performance since an account's
	// linked list nodes will not reside in memory consecutively.
	for i := 1; i <= historyLength; i++ {
		for j := 0; j < numAccounts; j++ {
			cache.writeFront(makeAddress(j), cachedOnlineAccount{updRound: basics.Round(i)})
		}
	}

	// Prevent the benchmark from using too few iterations. That would make the
	// preparation stage above non-negligible.
	minN := 100
	if b.N < minN {
		b.N = minN
	}

	var r cachedOnlineAccount
	for i := 0; i < b.N; i++ {
		for j := 0; j < numAccounts; j++ {
			r, _ = cache.read(makeAddress(j), basics.Round(historyLength))
		}
	}

	// Prevent compiler from optimizing the code.
	benchmarkOnlineAccountsCacheReadResult = r
}

// A typical history length.
func BenchmarkOnlineAccountsCacheRead320(b *testing.B) {
	benchmarkOnlineAccountsCacheRead(b, 320)
}

// A worst case history length when state proofs are delayed.
func BenchmarkOnlineAccountsCacheRead2560(b *testing.B) {
	benchmarkOnlineAccountsCacheRead(b, 2560)
}
