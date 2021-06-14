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

package v2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

func TestAccount(t *testing.T) {
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
	}
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
	b := a.WithUpdatedRewards(proto, 100)

	addr := basics.Address{}.String()
	conv, err := AccountDataToAccount(addr, &b, map[basics.AssetIndex]string{}, round, a.MicroAlgos)
	require.NoError(t, err)
	require.Equal(t, addr, conv.Address)
	require.Equal(t, b.MicroAlgos.Raw, conv.Amount)
	require.Equal(t, a.MicroAlgos.Raw, conv.AmountWithoutPendingRewards)

	verifyCreatedApp := func(index int, appIdx basics.AppIndex, params basics.AppParams) {
		require.Equal(t, uint64(appIdx), (*conv.CreatedApps)[index].Id)
		require.Equal(t, params.ApprovalProgram, (*conv.CreatedApps)[index].Params.ApprovalProgram)
		require.Equal(t, params.GlobalStateSchema.NumUint, (*conv.CreatedApps)[index].Params.GlobalStateSchema.NumUint)
		require.Equal(t, params.GlobalStateSchema.NumByteSlice, (*conv.CreatedApps)[index].Params.GlobalStateSchema.NumByteSlice)
		require.Equal(t, params.LocalStateSchema.NumUint, (*conv.CreatedApps)[index].Params.LocalStateSchema.NumUint)
		require.Equal(t, params.LocalStateSchema.NumByteSlice, (*conv.CreatedApps)[index].Params.LocalStateSchema.NumByteSlice)
	}

	require.NotNil(t, conv.CreatedApps)
	require.Equal(t, 2, len(*conv.CreatedApps))
	verifyCreatedApp(0, appIdx1, appParams1)
	verifyCreatedApp(1, appIdx2, appParams2)

	makeTKV := func(k string, v interface{}) generated.TealKeyValue {
		value := generated.TealValue{}
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
		return generated.TealKeyValue{
			Key:   b64(k),
			Value: value,
		}
	}

	verifyAppLocalState := func(index int, appIdx basics.AppIndex, numUints, numByteSlices uint64, keyValues generated.TealKeyValueStore) {
		require.Equal(t, uint64(appIdx), (*conv.AppsLocalState)[index].Id)
		require.Equal(t, numUints, (*conv.AppsLocalState)[index].Schema.NumUint)
		require.Equal(t, numByteSlices, (*conv.AppsLocalState)[index].Schema.NumByteSlice)
		require.Equal(t, len(keyValues), len(*(*conv.AppsLocalState)[index].KeyValue))
		for i, keyValue := range keyValues {
			require.Equal(t, keyValue, (*(*conv.AppsLocalState)[index].KeyValue)[i])
		}
	}

	require.NotNil(t, conv.AppsLocalState)
	require.Equal(t, 2, len(*conv.AppsLocalState))
	verifyAppLocalState(0, appIdx1, 10, 0, generated.TealKeyValueStore{makeTKV("bytes", "value1"), makeTKV("uint", 1)})
	verifyAppLocalState(1, appIdx2, 10, 0, generated.TealKeyValueStore{makeTKV("bytes", "value2"), makeTKV("uint", 2)})

	verifyCreatedAsset := func(index int, assetIdx basics.AssetIndex, params basics.AssetParams) {
		require.Equal(t, uint64(assetIdx), (*conv.CreatedAssets)[index].Index)
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

	c, err := AccountToAccountData(&conv)
	require.NoError(t, err)
	require.Equal(t, b, c)

	t.Run("IsDeterministic", func(t *testing.T) {
		// convert the same account a few more times to make sure we always
		// produce the same generated.Account
		for i := 0; i < 10; i++ {
			anotherConv, err := AccountDataToAccount(addr, &b, map[basics.AssetIndex]string{}, round, a.MicroAlgos)
			require.NoError(t, err)

			require.Equal(t, protocol.EncodeJSON(conv), protocol.EncodeJSON(anotherConv))
		}
	})
}
