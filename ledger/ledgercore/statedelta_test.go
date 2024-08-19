// Copyright (C) 2019-2024 Algorand, Inc.
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

	"github.com/stretchr/testify/assert"
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

func TestAccountDeltasMergeAccountsOrder(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	addr1 := randomAddress()
	data1 := AccountData{AccountBaseData: AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 111}}}
	addr2 := randomAddress()
	data2 := AccountData{AccountBaseData: AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 222}}}
	addr3 := randomAddress()
	data3 := AccountData{AccountBaseData: AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 333}}}
	addr4 := randomAddress()
	data4 := AccountData{AccountBaseData: AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 444}}}

	asset1 := basics.AssetIndex(100)
	asset1Params := AssetParamsDelta{
		Params: &basics.AssetParams{Total: 1},
	}
	asset2 := basics.AssetIndex(200)
	asset2Params := AssetParamsDelta{
		Params: &basics.AssetParams{Total: 2},
	}
	asset3 := basics.AssetIndex(300)
	asset3Params := AssetParamsDelta{
		Params: &basics.AssetParams{Total: 3},
	}
	asset4 := basics.AssetIndex(400)
	asset4Params := AssetParamsDelta{
		Params: &basics.AssetParams{Total: 4},
	}

	app1 := basics.AppIndex(101)
	app1Params := AppParamsDelta{
		Params: &basics.AppParams{ApprovalProgram: []byte("app1")},
	}
	app2 := basics.AppIndex(201)
	app2Params := AppParamsDelta{
		Params: &basics.AppParams{ApprovalProgram: []byte("app2")},
	}
	app3 := basics.AppIndex(301)
	app3Params := AppParamsDelta{
		Params: &basics.AppParams{ApprovalProgram: []byte("app3")},
	}
	app4 := basics.AppIndex(401)
	app4Params := AppParamsDelta{
		Params: &basics.AppParams{ApprovalProgram: []byte("app4")},
	}

	var ad1 AccountDeltas
	ad1.Upsert(addr1, data1)
	ad1.Upsert(addr2, data2)
	ad1.UpsertAssetResource(addr1, asset1, asset1Params, AssetHoldingDelta{})
	ad1.UpsertAssetResource(addr2, asset2, asset2Params, AssetHoldingDelta{})
	ad1.UpsertAppResource(addr1, app1, app1Params, AppLocalStateDelta{})
	ad1.UpsertAppResource(addr2, app2, app2Params, AppLocalStateDelta{})

	var ad2 AccountDeltas
	ad2.Upsert(addr3, data3)
	ad2.Upsert(addr4, data4)
	ad2.UpsertAssetResource(addr3, asset3, asset3Params, AssetHoldingDelta{})
	ad2.UpsertAssetResource(addr4, asset4, asset4Params, AssetHoldingDelta{})
	ad2.UpsertAppResource(addr3, app3, app3Params, AppLocalStateDelta{})
	ad2.UpsertAppResource(addr4, app4, app4Params, AppLocalStateDelta{})

	// Iterate to ensure deterministic order
	for i := 0; i < 10; i++ {
		var merged AccountDeltas
		merged.MergeAccounts(ad1)
		merged.MergeAccounts(ad2)

		var expectedAccounts []BalanceRecord
		expectedAccounts = append(expectedAccounts, ad1.Accts...)
		expectedAccounts = append(expectedAccounts, ad2.Accts...)
		require.Equal(t, expectedAccounts, merged.Accts)

		var expectedAppResources []AppResourceRecord
		expectedAppResources = append(expectedAppResources, ad1.AppResources...)
		expectedAppResources = append(expectedAppResources, ad2.AppResources...)
		require.Equal(t, expectedAppResources, merged.AppResources)

		var expectedAssetResources []AssetResourceRecord
		expectedAssetResources = append(expectedAssetResources, ad1.AssetResources...)
		expectedAssetResources = append(expectedAssetResources, ad2.AssetResources...)
		require.Equal(t, expectedAssetResources, merged.AssetResources)
	}
}

func TestAccountDeltasDehydrateAndHydrate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	addr1 := randomAddress()
	data1 := AccountData{AccountBaseData: AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 111}}}
	addr2 := randomAddress()
	data2 := AccountData{AccountBaseData: AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 222}}}

	asset1 := basics.AssetIndex(100)
	asset1Params := AssetParamsDelta{
		Params: &basics.AssetParams{Total: 1},
	}
	asset2 := basics.AssetIndex(200)
	asset2Params := AssetParamsDelta{
		Params: &basics.AssetParams{Total: 2},
	}

	app1 := basics.AppIndex(101)
	app1Params := AppParamsDelta{
		Params: &basics.AppParams{ApprovalProgram: []byte("app1")},
	}
	app2 := basics.AppIndex(201)
	app2Params := AppParamsDelta{
		Params: &basics.AppParams{ApprovalProgram: []byte("app2")},
	}

	var ad AccountDeltas
	ad.Upsert(addr1, data1)
	ad.Upsert(addr2, data2)
	ad.UpsertAssetResource(addr1, asset1, asset1Params, AssetHoldingDelta{})
	ad.UpsertAssetResource(addr2, asset2, asset2Params, AssetHoldingDelta{})
	ad.UpsertAppResource(addr1, app1, app1Params, AppLocalStateDelta{})
	ad.UpsertAppResource(addr2, app2, app2Params, AppLocalStateDelta{})

	var adCopy AccountDeltas
	adCopy.Upsert(addr1, data1)
	adCopy.Upsert(addr2, data2)
	adCopy.UpsertAssetResource(addr1, asset1, asset1Params, AssetHoldingDelta{})
	adCopy.UpsertAssetResource(addr2, asset2, asset2Params, AssetHoldingDelta{})
	adCopy.UpsertAppResource(addr1, app1, app1Params, AppLocalStateDelta{})
	adCopy.UpsertAppResource(addr2, app2, app2Params, AppLocalStateDelta{})

	shallowAd := AccountDeltas{
		Accts: []BalanceRecord{
			{
				Addr:        addr1,
				AccountData: data1,
			},
			{
				Addr:        addr2,
				AccountData: data2,
			},
		},
		acctsCache: make(map[basics.Address]int),
		AssetResources: []AssetResourceRecord{
			{
				Aidx:   asset1,
				Addr:   addr1,
				Params: asset1Params,
			},
			{
				Aidx:   asset2,
				Addr:   addr2,
				Params: asset2Params,
			},
		},
		assetResourcesCache: make(map[AccountAsset]int),
		AppResources: []AppResourceRecord{
			{
				Aidx:   app1,
				Addr:   addr1,
				Params: app1Params,
			},
			{
				Aidx:   app2,
				Addr:   addr2,
				Params: app2Params,
			},
		},
		appResourcesCache: make(map[AccountApp]int),
	}

	require.Equal(t, adCopy, ad)       // should be identical
	require.NotEqual(t, shallowAd, ad) // shallowAd has empty internal fields

	ad.Dehydrate()

	// Dehydration empties the internal fields
	require.Equal(t, shallowAd, ad)
	require.NotEqual(t, adCopy, ad)

	ad.Hydrate()

	// Hydration restores the internal fields
	require.Equal(t, adCopy, ad)
	require.NotEqual(t, shallowAd, ad)

	t.Run("NewFieldDetection", func(t *testing.T) {
		v := reflect.ValueOf(&ad).Elem()
		st := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			structField := st.Field(i)
			isContainer := field.Kind() == reflect.Map || field.Kind() == reflect.Slice
			if isContainer || !structField.IsExported() {
				assert.False(t, v.Field(i).IsZero(), "new container or private field \"%v\" added to AccountDeltas, please update AccountDeltas.Hydrate() and .Dehydrate() to handle it before fixing the test", structField.Name)
			}
		}
	})
}

func TestStateDeltaDehydrateAndHydrate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	addr := randomAddress()
	data := AccountData{AccountBaseData: AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 111}}}

	asset := basics.AssetIndex(100)
	assetParams := AssetParamsDelta{
		Params: &basics.AssetParams{Total: 1},
	}

	app := basics.AppIndex(101)
	appParams := AppParamsDelta{
		Params: &basics.AppParams{ApprovalProgram: []byte("app1")},
	}

	prevTimestamp := int64(77)
	stateProofNextRound := basics.Round(88)
	var hdr bookkeeping.BlockHeader

	sd := MakeStateDelta(&hdr, prevTimestamp, 10, stateProofNextRound)
	sd.Accts.Upsert(addr, data)
	sd.Accts.UpsertAssetResource(addr, asset, assetParams, AssetHoldingDelta{})
	sd.Accts.UpsertAppResource(addr, app, appParams, AppLocalStateDelta{})
	sd.AddKvMod("key", KvValueDelta{Data: []byte("value")})
	sd.AddCreatable(100, ModifiedCreatable{
		Ctype:   basics.AssetCreatable,
		Created: true,
		Creator: addr,
	})
	sd.AddTxLease(Txlease{Sender: addr, Lease: [32]byte{1, 2, 3}}, 2000)
	sd.Txids = map[transactions.Txid]IncludedTransactions{
		{5, 4, 3}: {
			LastValid: 5,
		},
	}

	sdCopy := MakeStateDelta(&hdr, prevTimestamp, 10, stateProofNextRound)
	sdCopy.Accts.Upsert(addr, data)
	sdCopy.Accts.UpsertAssetResource(addr, asset, assetParams, AssetHoldingDelta{})
	sdCopy.Accts.UpsertAppResource(addr, app, appParams, AppLocalStateDelta{})
	sdCopy.AddKvMod("key", KvValueDelta{Data: []byte("value")})
	sdCopy.AddCreatable(100, ModifiedCreatable{
		Ctype:   basics.AssetCreatable,
		Created: true,
		Creator: addr,
	})
	sdCopy.AddTxLease(Txlease{Sender: addr, Lease: [32]byte{1, 2, 3}}, 2000)
	sdCopy.Txids = map[transactions.Txid]IncludedTransactions{
		{5, 4, 3}: {
			LastValid: 5,
		},
	}

	shallowSd := StateDelta{
		PrevTimestamp:  prevTimestamp,
		StateProofNext: stateProofNextRound,
		Hdr:            &hdr,
		Accts: AccountDeltas{
			Accts: []BalanceRecord{
				{
					Addr:        addr,
					AccountData: data,
				},
			},
			acctsCache: make(map[basics.Address]int),
			AssetResources: []AssetResourceRecord{
				{
					Aidx:   asset,
					Addr:   addr,
					Params: assetParams,
				},
			},
			assetResourcesCache: make(map[AccountAsset]int),
			AppResources: []AppResourceRecord{
				{
					Aidx:   app,
					Addr:   addr,
					Params: appParams,
				},
			},
			appResourcesCache: make(map[AccountApp]int),
		},
		KvMods: map[string]KvValueDelta{
			"key": {Data: []byte("value")},
		},
		Creatables: map[basics.CreatableIndex]ModifiedCreatable{
			100: {
				Ctype:   basics.AssetCreatable,
				Created: true,
				Creator: addr,
			},
		},
		Txleases: map[Txlease]basics.Round{
			{addr, [32]byte{1, 2, 3}}: 2000,
		},
		Txids: map[transactions.Txid]IncludedTransactions{
			{5, 4, 3}: {
				LastValid: 5,
			},
		},
	}

	require.Equal(t, sdCopy, sd)       // should be identical
	require.NotEqual(t, shallowSd, sd) // shallowSd has empty internal fields

	sd.Dehydrate()

	// Dehydration empties the internal fields
	require.Equal(t, shallowSd, sd)
	require.NotEqual(t, sdCopy, sd)

	sd.Hydrate()

	// Hydration restores the internal fields, except for initialHint
	require.NotEqual(t, sdCopy.initialHint, sd.initialHint)
	sd.initialHint = sdCopy.initialHint
	require.Equal(t, sdCopy, sd)
	require.NotEqual(t, shallowSd, sd)

	t.Run("NewFieldDetection", func(t *testing.T) {
		v := reflect.ValueOf(&sd).Elem()
		st := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			structField := st.Field(i)
			isContainer := field.Kind() == reflect.Map || field.Kind() == reflect.Slice
			if isContainer || !structField.IsExported() {
				assert.False(t, v.Field(i).IsZero(), "new container or private field \"%v\" added to StateDelta, please update StateDelta.Hydrate() and .Dehydrate() to handle it before fixing the test", structField.Name)
			}
		}
	})
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
		assert.Containsf(t, stateDeltaFieldNames, reflectedStateDeltaName, "new field:\"%v\" added to StateDelta, please update StateDelta.Reset() to handle it before fixing the test", reflectedStateDeltaName)
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
		assert.Containsf(t, AccountDeltaFieldNames, reflectedAccountDeltaName, "new field:\"%v\" added to AccountDeltas, please update AccountDeltas.reset() to handle it before fixing the test", reflectedAccountDeltaName)
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
