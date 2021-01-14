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
	}
	assetParams2 := basics.AssetParams{
		Total:         200,
		DefaultFrozen: true,
		UnitName:      "unit2",
	}
	copy(assetParams2.MetadataHash[:], "test2")
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
	require.Equal(t, conv.Address, addr)
	require.Equal(t, conv.Amount, b.MicroAlgos.Raw)
	require.Equal(t, conv.AmountWithoutPendingRewards, a.MicroAlgos.Raw)

	require.NotNil(t, conv.CreatedApps)
	require.Equal(t, 2, len(*conv.CreatedApps))
	for _, app := range *conv.CreatedApps {
		var params basics.AppParams
		if app.Id == uint64(appIdx1) {
			params = appParams1
		} else if app.Id == uint64(appIdx2) {
			params = appParams2
		} else {
			require.Fail(t, fmt.Sprintf("app idx %d not in [%d, %d]", app.Id, appIdx1, appIdx2))
		}
		require.Equal(t, params.ApprovalProgram, app.Params.ApprovalProgram)
		require.Equal(t, params.GlobalStateSchema.NumUint, app.Params.GlobalStateSchema.NumUint)
		require.Equal(t, params.GlobalStateSchema.NumByteSlice, app.Params.GlobalStateSchema.NumByteSlice)
	}

	require.NotNil(t, conv.AppsLocalState)
	require.Equal(t, 2, len(*conv.AppsLocalState))
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
	for _, ls := range *conv.AppsLocalState {
		require.Equal(t, uint64(10), ls.Schema.NumUint)
		require.Equal(t, uint64(0), ls.Schema.NumByteSlice)
		require.Equal(t, 2, len(*ls.KeyValue))
		var value1 generated.TealKeyValue
		var value2 generated.TealKeyValue
		if ls.Id == uint64(appIdx1) {
			value1 = makeTKV("uint", 1)
			value2 = makeTKV("bytes", "value1")
		} else if ls.Id == uint64(appIdx2) {
			value1 = makeTKV("uint", 2)
			value2 = makeTKV("bytes", "value2")
		} else {
			require.Fail(t, fmt.Sprintf("local state app idx %d not in [%d, %d]", ls.Id, appIdx1, appIdx2))
		}
		require.Contains(t, *ls.KeyValue, value1)
		require.Contains(t, *ls.KeyValue, value2)
	}

	require.NotNil(t, conv.CreatedAssets)
	require.Equal(t, 2, len(*conv.CreatedAssets))
	for _, asset := range *conv.CreatedAssets {
		var params basics.AssetParams
		if asset.Index == uint64(assetIdx1) {
			params = assetParams1
		} else if asset.Index == uint64(assetIdx2) {
			params = assetParams2
		} else {
			require.Fail(t, fmt.Sprintf("asset idx %d not in [%d, %d]", asset.Index, assetIdx1, assetIdx2))
		}
		require.Equal(t, params.Total, asset.Params.Total)
		require.NotNil(t, asset.Params.DefaultFrozen)
		require.Equal(t, params.DefaultFrozen, *asset.Params.DefaultFrozen)
		require.NotNil(t, asset.Params.UnitName)
		require.Equal(t, params.UnitName, *asset.Params.UnitName)
		if asset.Params.MetadataHash != nil {
			require.Equal(t, params.MetadataHash[:], *asset.Params.MetadataHash)
		}
	}

	c, err := AccountToAccountData(&conv)
	require.NoError(t, err)
	require.Equal(t, b, c)
}
