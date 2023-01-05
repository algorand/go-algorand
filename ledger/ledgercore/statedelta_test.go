// Copyright (C) 2019-2023 Algorand, Inc.
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

package ledgercore

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func randomAddress() basics.Address {
	var addr basics.Address
	crypto.RandBytes(addr[:])
	return addr
}

func TestAccountDeltas(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	ad := AccountDeltas{}
	data, ok := ad.GetData(basics.Address{})
	a.False(ok)
	a.Equal(AccountData{}, data)

	addr := randomAddress()
	data, ok = ad.GetData(addr)
	a.False(ok)
	a.Equal(AccountData{}, data)

	a.Zero(ad.Len())
	a.Panics(func() { ad.GetByIdx(0) })

	a.Equal([]basics.Address{}, ad.ModifiedAccounts())

	sample1 := AccountData{AccountBaseData: AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 123}}}
	ad.Upsert(addr, sample1)
	data, ok = ad.GetData(addr)
	a.True(ok)
	a.Equal(sample1, data)

	a.Equal(1, ad.Len())
	address, data := ad.GetByIdx(0)
	a.Equal(addr, address)
	a.Equal(sample1, data)

	sample2 := AccountData{AccountBaseData: AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 456}}}
	ad.Upsert(addr, sample2)
	data, ok = ad.GetData(addr)
	a.True(ok)
	a.Equal(sample2, data)

	a.Equal(1, ad.Len())
	address, data = ad.GetByIdx(0)
	a.Equal(addr, address)
	a.Equal(sample2, data)

	a.Equal([]basics.Address{addr}, ad.ModifiedAccounts())

	ad2 := AccountDeltas{}
	ad2.Upsert(addr, sample2)
	ad.MergeAccounts(ad2)
	a.Equal(1, ad.Len())
	address, data = ad.GetByIdx(0)
	a.Equal(addr, address)
	a.Equal(sample2, data)

	addr1 := randomAddress()
	ad2.Upsert(addr1, sample1)
	ad.MergeAccounts(ad2)
	a.Equal(2, ad.Len())
	address, data = ad.GetByIdx(0)
	a.Equal(addr, address)
	a.Equal(sample2, data)
	address, data = ad.GetByIdx(1)
	a.Equal(addr1, address)
	a.Equal(sample1, data)
}

func TestMakeStateDeltaMaps(t *testing.T) {
	partitiontest.PartitionTest(t)

	sd := MakeStateDelta(nil, 0, 23000, basics.Round(2))
	require.Nil(t, sd.Txleases)
	require.Nil(t, sd.Creatables)
	require.Nil(t, sd.KvMods)

	sd.AddTxLease(Txlease{}, basics.Round(10))
	require.Len(t, sd.Txleases, 1)
	sd.AddCreatable(basics.CreatableIndex(5), ModifiedCreatable{})
	require.Len(t, sd.Creatables, 1)
	sd.AddKvMod("key", KvValueDelta{Data: []byte("value")})
	require.Len(t, sd.KvMods, 1)

	txLeaseMap := make(map[Txlease]basics.Round)
	txLeaseMap[Txlease{}] = basics.Round(10)
	require.Equal(t, sd.Txleases, txLeaseMap)

	creatableMap := make(map[basics.CreatableIndex]ModifiedCreatable)
	creatableMap[basics.CreatableIndex(5)] = ModifiedCreatable{}
	require.Equal(t, sd.Creatables, creatableMap)

	kvModMap := make(map[string]KvValueDelta)
	kvModMap["key"] = KvValueDelta{Data: []byte("value")}
	require.Equal(t, sd.KvMods, kvModMap)

}

func TestStateDeltaReset(t *testing.T) {
	partitiontest.PartitionTest(t)

	txid := transactions.Transaction{}.ID()
	sd := MakeStateDelta(&bookkeeping.BlockHeader{}, 123, 456, basics.Round(789))
	// populate StateDelta maps with some data
	sd.Txids[txid] = IncludedTransactions{LastValid: basics.Round(30)}
	sd.AddTxLease(Txlease{}, basics.Round(10))
	sd.AddCreatable(basics.CreatableIndex(5), ModifiedCreatable{})
	sd.AddKvMod("key", KvValueDelta{Data: []byte("value")})

	// populate AccountDelta maps with some data
	sd.Accts.acctsCache[randomAddress()] = 1
	sd.Accts.appResourcesCache = make(map[AccountApp]int)
	sd.Accts.appResourcesCache[AccountApp{Address: randomAddress()}] = 2
	sd.Accts.assetResourcesCache = make(map[AccountAsset]int)
	sd.Accts.assetResourcesCache[AccountAsset{Address: randomAddress()}] = 3

	sd.Reset()

	// StateDeltas simple fields
	require.Zero(t, sd.Hdr)
	require.Zero(t, sd.StateProofNext)
	require.Zero(t, sd.PrevTimestamp)
	require.Zero(t, sd.Totals)

	// required allocated maps
	require.NotZero(t, sd.Txids)
	require.Empty(t, sd.Txids)

	// optional allocated maps
	require.Empty(t, sd.Txleases)
	require.Empty(t, sd.KvMods)
	require.Empty(t, sd.Creatables)

	// check AccountDeltas
	require.NotZero(t, sd.Accts)

	// required AccountDeltas fields
	require.NotZero(t, sd.Accts.Accts)
	require.Empty(t, sd.Accts.Accts)
	require.NotZero(t, sd.Accts.acctsCache)
	require.Empty(t, sd.Accts.acctsCache)

	// optional AccountDeltas fields
	require.Empty(t, sd.Accts.AppResources)
	require.Empty(t, sd.Accts.AssetResources)
	require.Empty(t, sd.Accts.assetResourcesCache)
	require.Empty(t, sd.Accts.appResourcesCache)

}

func TestStateDeltaReflect(t *testing.T) {
	partitiontest.PartitionTest(t)

	stateDeltaFieldNames := map[string]struct{}{
		"Accts":          {},
		"KvMods":         {},
		"Txids":          {},
		"Txleases":       {},
		"Creatables":     {},
		"Hdr":            {},
		"StateProofNext": {},
		"PrevTimestamp":  {},
		"initialHint":    {},
		"Totals":         {},
	}

	sd := StateDelta{}
	v := reflect.ValueOf(sd)
	st := v.Type()
	for i := 0; i < v.NumField(); i++ {
		reflectedStateDeltaName := st.Field(i).Name
		require.Containsf(t, stateDeltaFieldNames, reflectedStateDeltaName, "new field:\"%v\" added to StateDelta, please update StateDelta.Reset() to handle it before fixing the test", reflectedStateDeltaName)
	}
}

func TestAccountDeltaReflect(t *testing.T) {
	partitiontest.PartitionTest(t)

	AccountDeltaFieldNames := map[string]struct{}{
		"Accts":               {},
		"acctsCache":          {},
		"AppResources":        {},
		"appResourcesCache":   {},
		"AssetResources":      {},
		"assetResourcesCache": {},
	}

	sd := AccountDeltas{}
	v := reflect.ValueOf(sd)
	st := v.Type()
	for i := 0; i < v.NumField(); i++ {
		reflectedAccountDeltaName := st.Field(i).Name
		require.Containsf(t, AccountDeltaFieldNames, reflectedAccountDeltaName, "new field:\"%v\" added to AccountDeltas, please update AccountDeltas.reset() to handle it before fixing the test", reflectedAccountDeltaName)
	}
}

func BenchmarkMakeStateDelta(b *testing.B) {
	hint := 23000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MakeStateDelta(nil, 0, hint, 0)
	}
}

func BenchmarkBalanceRecord(b *testing.B) {
	hint := 23000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x := make([]basics.BalanceRecord, 0, hint*2)
		if len(x) > 0 {
			return
		}
	}
}

func BenchmarkAcctCache(b *testing.B) {
	hint := 23000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x := make(map[basics.Address]int, hint*2)
		if len(x) > 0 {
			return
		}
	}
}

func BenchmarkCreatables(b *testing.B) {
	hint := 23000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x := make(map[basics.CreatableIndex]ModifiedCreatable, hint)
		if len(x) > 0 {
			return
		}
	}
}

func BenchmarkTxLeases(b *testing.B) {
	hint := 23000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x := make(map[Txlease]basics.Round, hint)
		if len(x) > 0 {
			return
		}
	}
}
