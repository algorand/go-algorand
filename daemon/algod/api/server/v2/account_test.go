// Copyright (C) 2019-2025 Algorand, Inc.
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

package v2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/basics/testing/roundtrip"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// makeAccountConverters creates conversion functions for round-trip testing between
// basics.AccountData and model.Account.
func makeAccountConverters(t *testing.T, addrStr string, round basics.Round, proto *config.ConsensusParams, withoutRewards basics.MicroAlgos) (
	toModel func(basics.AccountData) model.Account,
	toBasics func(model.Account) basics.AccountData,
) {
	toModel = func(ad basics.AccountData) model.Account {
		converted, err := AccountDataToAccount(addrStr, &ad, round, proto, withoutRewards)
		require.NoError(t, err)
		return converted
	}
	toBasics = func(acc model.Account) basics.AccountData {
		converted, err := AccountToAccountData(&acc)
		require.NoError(t, err)
		return converted
	}
	return toModel, toBasics
}

func TestAccount(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto := config.Consensus[protocol.ConsensusFuture]
	appIdx1 := basics.AppIndex(1)
	appIdx2 := basics.AppIndex(2)
	assetIdx1 := basics.AssetIndex(3)
	assetIdx2 := basics.AssetIndex(4)
	round := basics.Round(2)

	appParams1 := basics.AppParams{
		ApprovalProgram: []byte{1},
		StateSchemas: basics.StateSchemas{
			GlobalStateSchema: basics.StateSchema{NumUint: 1},
			LocalStateSchema:  basics.StateSchema{NumByteSlice: 5},
		},
	}
	appParams2 := basics.AppParams{
		ApprovalProgram: []byte{2},
		StateSchemas: basics.StateSchemas{
			GlobalStateSchema: basics.StateSchema{NumUint: 2},
		},
		ExtraProgramPages: 1,
		Version:           2,
	}

	totalAppSchema := basics.StateSchema{
		NumUint:      appParams1.GlobalStateSchema.NumUint + appParams2.GlobalStateSchema.NumUint,
		NumByteSlice: appParams1.GlobalStateSchema.NumByteSlice + appParams2.GlobalStateSchema.NumByteSlice,
	}
	totalAppExtraPages := appParams1.ExtraProgramPages + appParams2.ExtraProgramPages

	assetParams1 := basics.AssetParams{
		Total:         100,
		DefaultFrozen: false,
		UnitName:      "unit1",
		Decimals:      0,
	}
	assetParams2 := basics.AssetParams{
		Total:         200,
		DefaultFrozen: true,
		UnitName:      "unit2",
		Decimals:      6,
		MetadataHash:  [32]byte{1},
	}
	copy(assetParams2.MetadataHash[:], []byte("test2"))
	a := basics.AccountData{
		Status:             basics.Online,
		MicroAlgos:         basics.MicroAlgos{Raw: 80000000},
		RewardedMicroAlgos: basics.MicroAlgos{Raw: ^uint64(0)},
		RewardsBase:        0,
		AppParams:          map[basics.AppIndex]basics.AppParams{appIdx1: appParams1, appIdx2: appParams2},
		TotalAppSchema:     totalAppSchema,
		TotalExtraAppPages: totalAppExtraPages,
		AppLocalStates: map[basics.AppIndex]basics.AppLocalState{
			appIdx1: {
				Schema: basics.StateSchema{NumUint: 10},
				KeyValue: basics.TealKeyValue{
					"uint":  basics.TealValue{Type: basics.TealUintType, Uint: 1},
					"bytes": basics.TealValue{Type: basics.TealBytesType, Bytes: "value1"},
				},
			},
			appIdx2: {
				Schema: basics.StateSchema{NumUint: 10},
				KeyValue: basics.TealKeyValue{
					"uint":  basics.TealValue{Type: basics.TealUintType, Uint: 2},
					"bytes": basics.TealValue{Type: basics.TealBytesType, Bytes: "value2"},
				},
			},
		},
		AssetParams: map[basics.AssetIndex]basics.AssetParams{assetIdx1: assetParams1, assetIdx2: assetParams2},
	}
	b := a.WithUpdatedRewards(proto.RewardUnit, 100)

	addr := basics.Address{}.String()
	toModel, toBasics := makeAccountConverters(t, addr, round, &proto, a.MicroAlgos)

	conv := toModel(b)
	require.Equal(t, addr, conv.Address)
	require.Equal(t, b.MicroAlgos.Raw, conv.Amount)
	require.Equal(t, a.MicroAlgos.Raw, conv.AmountWithoutPendingRewards)
	require.NotNil(t, conv.AppsTotalSchema)
	require.Equal(t, totalAppSchema.NumUint, conv.AppsTotalSchema.NumUint)
	require.Equal(t, totalAppSchema.NumByteSlice, conv.AppsTotalSchema.NumByteSlice)
	require.NotNil(t, conv.AppsTotalExtraPages)
	require.Equal(t, uint64(totalAppExtraPages), *conv.AppsTotalExtraPages)

	verifyCreatedApp := func(index int, appIdx basics.AppIndex, params basics.AppParams) {
		require.Equal(t, appIdx, (*conv.CreatedApps)[index].Id)
		require.Equal(t, params.ApprovalProgram, (*conv.CreatedApps)[index].Params.ApprovalProgram)
		if params.Version != 0 {
			require.NotNil(t, (*conv.CreatedApps)[index].Params.Version)
			require.Equal(t, params.Version, *(*conv.CreatedApps)[index].Params.Version)
		} else {
			require.Nil(t, (*conv.CreatedApps)[index].Params.Version)
		}
		if params.ExtraProgramPages != 0 {
			require.NotNil(t, (*conv.CreatedApps)[index].Params.ExtraProgramPages)
			require.Equal(t, uint64(params.ExtraProgramPages), *(*conv.CreatedApps)[index].Params.ExtraProgramPages)
		} else {
			require.Nil(t, (*conv.CreatedApps)[index].Params.ExtraProgramPages)
		}
		require.NotNil(t, (*conv.CreatedApps)[index].Params.GlobalStateSchema)
		require.Equal(t, params.GlobalStateSchema.NumUint, (*conv.CreatedApps)[index].Params.GlobalStateSchema.NumUint)
		require.Equal(t, params.GlobalStateSchema.NumByteSlice, (*conv.CreatedApps)[index].Params.GlobalStateSchema.NumByteSlice)
		require.NotNil(t, (*conv.CreatedApps)[index].Params.LocalStateSchema)
		require.Equal(t, params.LocalStateSchema.NumUint, (*conv.CreatedApps)[index].Params.LocalStateSchema.NumUint)
		require.Equal(t, params.LocalStateSchema.NumByteSlice, (*conv.CreatedApps)[index].Params.LocalStateSchema.NumByteSlice)
	}

	require.NotNil(t, conv.CreatedApps)
	require.Equal(t, 2, len(*conv.CreatedApps))
	verifyCreatedApp(0, appIdx1, appParams1)
	verifyCreatedApp(1, appIdx2, appParams2)

	appRoundTrip := func(idx basics.AppIndex, params basics.AppParams) {
		roundtrip.Check(t, params,
			func(ap basics.AppParams) model.Application {
				return AppParamsToApplication(addr, idx, &ap)
			},
			func(app model.Application) basics.AppParams {
				converted, err := ApplicationParamsToAppParams(&app.Params)
				require.NoError(t, err)
				return converted
			})
	}

	appRoundTrip(appIdx1, appParams1)
	appRoundTrip(appIdx2, appParams2)

	makeTKV := func(k string, v interface{}) model.TealKeyValue {
		value := model.TealValue{}
		switch v.(type) {
		case int:
			value.Uint = uint64(v.(int))
			value.Type = uint64(basics.TealUintType)
		case string:
			value.Bytes = b64(v.(string))
			value.Type = uint64(basics.TealBytesType)
		default:
			panic(fmt.Sprintf("Unknown teal type %v", t))
		}
		return model.TealKeyValue{
			Key:   b64(k),
			Value: value,
		}
	}

	verifyAppLocalState := func(index int, appIdx basics.AppIndex, numUints, numByteSlices uint64, keyValues model.TealKeyValueStore) {
		require.Equal(t, appIdx, (*conv.AppsLocalState)[index].Id)
		require.Equal(t, numUints, (*conv.AppsLocalState)[index].Schema.NumUint)
		require.Equal(t, numByteSlices, (*conv.AppsLocalState)[index].Schema.NumByteSlice)
		require.Equal(t, len(keyValues), len(*(*conv.AppsLocalState)[index].KeyValue))
		for i, keyValue := range keyValues {
			require.Equal(t, keyValue, (*(*conv.AppsLocalState)[index].KeyValue)[i])
		}
	}

	require.NotNil(t, conv.AppsLocalState)
	require.Equal(t, 2, len(*conv.AppsLocalState))
	verifyAppLocalState(0, appIdx1, 10, 0, model.TealKeyValueStore{makeTKV("bytes", "value1"), makeTKV("uint", 1)})
	verifyAppLocalState(1, appIdx2, 10, 0, model.TealKeyValueStore{makeTKV("bytes", "value2"), makeTKV("uint", 2)})

	verifyCreatedAsset := func(index int, assetIdx basics.AssetIndex, params basics.AssetParams) {
		require.Equal(t, assetIdx, (*conv.CreatedAssets)[index].Index)
		require.Equal(t, params.Total, (*conv.CreatedAssets)[index].Params.Total)
		require.NotNil(t, (*conv.CreatedAssets)[index].Params.DefaultFrozen)
		require.Equal(t, params.DefaultFrozen, *(*conv.CreatedAssets)[index].Params.DefaultFrozen)
		require.NotNil(t, (*conv.CreatedAssets)[index].Params.UnitName)
		require.Equal(t, params.UnitName, *(*conv.CreatedAssets)[index].Params.UnitName)
		if params.MetadataHash == ([32]byte{}) {
			require.Nil(t, (*conv.CreatedAssets)[index].Params.MetadataHash)
		} else {
			require.NotNil(t, (*conv.CreatedAssets)[index].Params.MetadataHash)
			require.Equal(t, params.MetadataHash[:], *(*conv.CreatedAssets)[index].Params.MetadataHash)
		}
	}

	require.NotNil(t, conv.CreatedAssets)
	require.Equal(t, 2, len(*conv.CreatedAssets))
	verifyCreatedAsset(0, assetIdx1, assetParams1)
	verifyCreatedAsset(1, assetIdx2, assetParams2)

	// Verify round-trip conversion works for the manually constructed account
	c := toBasics(toModel(b))
	require.Equal(t, b, c)

	t.Run("IsDeterministic", func(t *testing.T) {
		// convert the same account a few more times to make sure we always
		// produce the same model.Account
		for i := 0; i < 10; i++ {
			anotherConv, err := AccountDataToAccount(addr, &b, round, &proto, a.MicroAlgos)
			require.NoError(t, err)

			require.Equal(t, protocol.EncodeJSON(conv), protocol.EncodeJSON(anotherConv))
		}
	})
}

func TestAccountRandomRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, simple := range []bool{true, false} {
		accts := ledgertesting.RandomAccounts(20, simple)
		for addr, acct := range accts {
			round := basics.Round(2)
			proto := config.Consensus[protocol.ConsensusFuture]
			toModel, toBasics := makeAccountConverters(t, addr.String(), round, &proto, acct.MicroAlgos)
			// Test the randomly-generated account round-trips correctly
			c := toBasics(toModel(acct))
			require.Equal(t, acct, c)
		}
	}
}

func TestConvertTealKeyValueRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("nil input", func(t *testing.T) {
		require.Nil(t, convertTKVToGenerated(nil))
		result, err := convertGeneratedTKV(nil)
		require.NoError(t, err)
		require.Nil(t, result)
	})

	t.Run("empty map treated as nil", func(t *testing.T) {
		empty := basics.TealKeyValue{}
		require.Nil(t, convertTKVToGenerated(&empty))
		result, err := convertGeneratedTKV(convertTKVToGenerated(&empty))
		require.NoError(t, err)
		require.Nil(t, result)
	})

	t.Run("round-trip non-empty map", func(t *testing.T) {
		kv := basics.TealKeyValue{
			"alpha": {Type: basics.TealUintType, Uint: 17},
			"beta":  {Type: basics.TealBytesType, Bytes: "\x00\x01binary"},
		}

		toGenerated := func(val basics.TealKeyValue) *model.TealKeyValueStore {
			return convertTKVToGenerated(&val)
		}
		toBasics := func(store *model.TealKeyValueStore) basics.TealKeyValue {
			converted, err := convertGeneratedTKV(store)
			require.NoError(t, err)
			return converted
		}

		// Test the manually constructed map round-trips correctly
		result := toBasics(toGenerated(kv))
		require.Equal(t, kv, result)
	})
}

func TestAppLocalStateRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	appIdx := basics.AppIndex(42)
	cases := map[string]basics.AppLocalState{
		"empty kv": {
			Schema:   basics.StateSchema{NumUint: 1, NumByteSlice: 0},
			KeyValue: nil,
		},
		"mixed kv": {
			Schema: basics.StateSchema{NumUint: 2, NumByteSlice: 3},
			KeyValue: basics.TealKeyValue{
				"counter": {Type: basics.TealUintType, Uint: 99},
				"note":    {Type: basics.TealBytesType, Bytes: "hello world"},
			},
		},
	}

	for name, state := range cases {
		t.Run(name, func(t *testing.T) {
			modelState := AppLocalState(state, appIdx)
			modelStates := []model.ApplicationLocalState{modelState}

			acc := model.Account{
				Status:         basics.Offline.String(),
				Amount:         0,
				AppsLocalState: &modelStates,
			}

			ad, err := AccountToAccountData(&acc)
			require.NoError(t, err)

			require.NotNil(t, ad.AppLocalStates)
			got, ok := ad.AppLocalStates[appIdx]
			require.True(t, ok)
			require.Equal(t, state.Schema, got.Schema)
			require.Equal(t, state.KeyValue, got.KeyValue)
		})
	}
}
