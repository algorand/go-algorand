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

package trackerdb

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestResourcesDataApp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(t)

	rd := ResourcesData{}
	a.False(rd.IsApp())
	a.True(rd.IsEmpty())

	rd = MakeResourcesData(1)
	a.False(rd.IsApp())
	a.False(rd.IsHolding())
	a.False(rd.IsOwning())
	a.True(rd.IsEmpty())

	// check empty
	appParamsEmpty := basics.AppParams{}
	rd = ResourcesData{}
	rd.SetAppParams(appParamsEmpty, false)
	a.True(rd.IsApp())
	a.True(rd.IsOwning())
	a.True(rd.IsEmptyAppFields())
	a.False(rd.IsEmpty())
	a.Equal(appParamsEmpty, rd.GetAppParams())

	appLocalEmpty := basics.AppLocalState{}
	rd = ResourcesData{}
	rd.SetAppLocalState(appLocalEmpty)
	a.True(rd.IsApp())
	a.True(rd.IsHolding())
	a.True(rd.IsEmptyAppFields())
	a.False(rd.IsEmpty())
	a.Equal(appLocalEmpty, rd.GetAppLocalState())

	// check both empty
	rd = ResourcesData{}
	rd.SetAppLocalState(appLocalEmpty)
	rd.SetAppParams(appParamsEmpty, true)
	a.True(rd.IsApp())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.True(rd.IsEmptyAppFields())
	a.False(rd.IsEmpty())
	a.Equal(appParamsEmpty, rd.GetAppParams())
	a.Equal(appLocalEmpty, rd.GetAppLocalState())

	// Since some steps use randomly generated input, the test is run N times
	// to cover a larger search space of inputs.
	for i := 0; i < 1000; i++ {
		// check empty states + non-empty params
		appParams := ledgertesting.RandomAppParams()
		rd = ResourcesData{}
		rd.SetAppLocalState(appLocalEmpty)
		rd.SetAppParams(appParams, true)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.True(rd.IsHolding())
		a.False(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())
		a.Equal(appParams, rd.GetAppParams())
		a.Equal(appLocalEmpty, rd.GetAppLocalState())

		appState := ledgertesting.RandomAppLocalState()
		rd.SetAppLocalState(appState)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.True(rd.IsHolding())
		a.False(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())
		a.Equal(appParams, rd.GetAppParams())
		a.Equal(appState, rd.GetAppLocalState())

		// check ClearAppLocalState
		rd.ClearAppLocalState()
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.False(rd.IsHolding())
		a.False(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())
		a.Equal(appParams, rd.GetAppParams())
		a.Equal(appLocalEmpty, rd.GetAppLocalState())

		// check ClearAppParams
		rd.SetAppLocalState(appState)
		rd.ClearAppParams()
		a.True(rd.IsApp())
		a.False(rd.IsOwning())
		a.True(rd.IsHolding())
		if appState.Schema.NumEntries() == 0 {
			a.True(rd.IsEmptyAppFields())
		} else {
			a.False(rd.IsEmptyAppFields())
		}
		a.False(rd.IsEmpty())
		a.Equal(appParamsEmpty, rd.GetAppParams())
		a.Equal(appState, rd.GetAppLocalState())

		// check both clear
		rd.ClearAppLocalState()
		a.False(rd.IsApp())
		a.False(rd.IsOwning())
		a.False(rd.IsHolding())
		a.True(rd.IsEmptyAppFields())
		a.True(rd.IsEmpty())
		a.Equal(appParamsEmpty, rd.GetAppParams())
		a.Equal(appLocalEmpty, rd.GetAppLocalState())

		// check params clear when non-empty params and empty holding
		rd = ResourcesData{}
		rd.SetAppLocalState(appLocalEmpty)
		rd.SetAppParams(appParams, true)
		rd.ClearAppParams()
		a.True(rd.IsApp())
		a.False(rd.IsOwning())
		a.True(rd.IsHolding())
		a.True(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())
		a.Equal(appParamsEmpty, rd.GetAppParams())
		a.Equal(appLocalEmpty, rd.GetAppLocalState())

		rd = ResourcesData{}
		rd.SetAppLocalState(appLocalEmpty)
		a.True(rd.IsEmptyAppFields())
		a.True(rd.IsApp())
		a.False(rd.IsEmpty())
		a.Equal(rd.ResourceFlags, ResourceFlagsEmptyApp)
		rd.ClearAppLocalState()
		a.False(rd.IsApp())
		a.True(rd.IsEmptyAppFields())
		a.True(rd.IsEmpty())
		a.Equal(rd.ResourceFlags, ResourceFlagsNotHolding)

		// check migration flow (AccountDataResources)
		// 1. both exist and empty
		rd = MakeResourcesData(0)
		rd.SetAppLocalState(appLocalEmpty)
		rd.SetAppParams(appParamsEmpty, true)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.True(rd.IsHolding())
		a.True(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())

		// 2. both exist and not empty
		rd = MakeResourcesData(0)
		rd.SetAppLocalState(appState)
		rd.SetAppParams(appParams, true)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.True(rd.IsHolding())
		a.False(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())

		// 3. both exist: holding not empty, param is empty
		rd = MakeResourcesData(0)
		rd.SetAppLocalState(appState)
		rd.SetAppParams(appParamsEmpty, true)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.True(rd.IsHolding())
		if appState.Schema.NumEntries() == 0 {
			a.True(rd.IsEmptyAppFields())
		} else {
			a.False(rd.IsEmptyAppFields())
		}
		a.False(rd.IsEmpty())

		// 4. both exist: holding empty, param is not empty
		rd = MakeResourcesData(0)
		rd.SetAppLocalState(appLocalEmpty)
		rd.SetAppParams(appParams, true)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.True(rd.IsHolding())
		a.False(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())

		// 5. holding does not exist and params is empty
		rd = MakeResourcesData(0)
		rd.SetAppParams(appParamsEmpty, false)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.False(rd.IsHolding())
		a.True(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())

		// 6. holding does not exist and params is not empty
		rd = MakeResourcesData(0)
		rd.SetAppParams(appParams, false)
		a.True(rd.IsApp())
		a.True(rd.IsOwning())
		a.False(rd.IsHolding())
		a.False(rd.IsEmptyAppFields())
		a.False(rd.IsEmpty())

		// 7. holding exist and not empty and params does not exist
		rd = MakeResourcesData(0)
		rd.SetAppLocalState(appState)
		a.True(rd.IsApp())
		a.False(rd.IsOwning())
		a.True(rd.IsHolding())
		if appState.Schema.NumEntries() == 0 {
			a.True(rd.IsEmptyAppFields())
		} else {
			a.False(rd.IsEmptyAppFields())
		}
		a.False(rd.IsEmpty())

		// 8. both do not exist
		rd = MakeResourcesData(0)
		a.False(rd.IsApp())
		a.False(rd.IsOwning())
		a.False(rd.IsHolding())
		a.True(rd.IsEmptyAppFields())
		a.True(rd.IsEmpty())
	}
}

func TestResourcesDataAsset(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	rd := ResourcesData{}
	a.False(rd.IsAsset())
	a.True(rd.IsEmpty())

	rd = MakeResourcesData(1)
	a.False(rd.IsAsset())
	a.False(rd.IsHolding())
	a.False(rd.IsOwning())
	a.True(rd.IsEmpty())

	// check empty
	assetParamsEmpty := basics.AssetParams{}
	rd = ResourcesData{}
	rd.SetAssetParams(assetParamsEmpty, false)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParamsEmpty, rd.GetAssetParams())

	assetHoldingEmpty := basics.AssetHolding{}
	rd = ResourcesData{}
	rd.SetAssetHolding(assetHoldingEmpty)
	a.True(rd.IsAsset())
	a.True(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetHoldingEmpty, rd.GetAssetHolding())

	// check both empty
	rd = ResourcesData{}
	rd.SetAssetHolding(assetHoldingEmpty)
	rd.SetAssetParams(assetParamsEmpty, true)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParamsEmpty, rd.GetAssetParams())
	a.Equal(assetHoldingEmpty, rd.GetAssetHolding())

	// check empty states + non-empty params
	assetParams := ledgertesting.RandomAssetParams()
	rd = ResourcesData{}
	rd.SetAssetHolding(assetHoldingEmpty)
	rd.SetAssetParams(assetParams, true)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParams, rd.GetAssetParams())
	a.Equal(assetHoldingEmpty, rd.GetAssetHolding())

	assetHolding := ledgertesting.RandomAssetHolding(true)
	rd.SetAssetHolding(assetHolding)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParams, rd.GetAssetParams())
	a.Equal(assetHolding, rd.GetAssetHolding())

	// check ClearAssetHolding
	rd.ClearAssetHolding()
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.False(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParams, rd.GetAssetParams())
	a.Equal(assetHoldingEmpty, rd.GetAssetHolding())

	// check ClearAssetParams
	rd.SetAssetHolding(assetHolding)
	rd.ClearAssetParams()
	a.True(rd.IsAsset())
	a.False(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParamsEmpty, rd.GetAssetParams())
	a.Equal(assetHolding, rd.GetAssetHolding())

	// check both clear
	rd.ClearAssetHolding()
	a.False(rd.IsAsset())
	a.False(rd.IsOwning())
	a.False(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.True(rd.IsEmpty())
	a.Equal(assetParamsEmpty, rd.GetAssetParams())
	a.Equal(assetHoldingEmpty, rd.GetAssetHolding())

	// check params clear when non-empty params and empty holding
	rd = ResourcesData{}
	rd.SetAssetHolding(assetHoldingEmpty)
	rd.SetAssetParams(assetParams, true)
	rd.ClearAssetParams()
	a.True(rd.IsAsset())
	a.False(rd.IsOwning())
	a.True(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())
	a.Equal(assetParamsEmpty, rd.GetAssetParams())
	a.Equal(assetHoldingEmpty, rd.GetAssetHolding())

	rd = ResourcesData{}
	rd.SetAssetHolding(assetHoldingEmpty)
	a.True(rd.IsEmptyAssetFields())
	a.True(rd.IsAsset())
	a.False(rd.IsEmpty())
	a.Equal(rd.ResourceFlags, ResourceFlagsEmptyAsset)
	rd.ClearAssetHolding()
	a.False(rd.IsAsset())
	a.True(rd.IsEmptyAssetFields())
	a.True(rd.IsEmpty())
	a.Equal(rd.ResourceFlags, ResourceFlagsNotHolding)

	// check migration operations (AccountDataResources)
	// 1. both exist and empty
	rd = MakeResourcesData(0)
	rd.SetAssetHolding(assetHoldingEmpty)
	rd.SetAssetParams(assetParamsEmpty, true)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 2. both exist and not empty
	rd = MakeResourcesData(0)
	rd.SetAssetHolding(assetHolding)
	rd.SetAssetParams(assetParams, true)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 3. both exist: holding not empty, param is empty
	rd = MakeResourcesData(0)
	rd.SetAssetHolding(assetHolding)
	rd.SetAssetParams(assetParamsEmpty, true)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 4. both exist: holding empty, param is not empty
	rd = MakeResourcesData(0)
	rd.SetAssetHolding(assetHoldingEmpty)
	rd.SetAssetParams(assetParams, true)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 5. holding does not exist and params is empty
	rd = MakeResourcesData(0)
	rd.SetAssetParams(assetParamsEmpty, false)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.False(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 6. holding does not exist and params is not empty
	rd = MakeResourcesData(0)
	rd.SetAssetParams(assetParams, false)
	a.True(rd.IsAsset())
	a.True(rd.IsOwning())
	a.False(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 7. holding exist and not empty and params does not exist
	rd = MakeResourcesData(0)
	rd.SetAssetHolding(assetHolding)
	a.True(rd.IsAsset())
	a.False(rd.IsOwning())
	a.True(rd.IsHolding())
	a.False(rd.IsEmptyAssetFields())
	a.False(rd.IsEmpty())

	// 8. both do not exist
	rd = MakeResourcesData(0)
	a.False(rd.IsAsset())
	a.False(rd.IsOwning())
	a.False(rd.IsHolding())
	a.True(rd.IsEmptyAssetFields())
	a.True(rd.IsEmpty())
}

// TestResourcesDataSetData checks combinations of old/new values when
// updating resourceData from resourceDelta
func TestResourcesDataSetData(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	type deltaCode int
	const (
		tri deltaCode = iota + 1
		del
		emp
		act
	)

	// apply deltas encoded as deltaCode to a base ResourcesData for both apps and assets
	apply := func(t *testing.T, base ResourcesData, testType basics.CreatableType, pcode, hcode deltaCode) ResourcesData {
		if testType == basics.AssetCreatable {
			var p ledgercore.AssetParamsDelta
			var h ledgercore.AssetHoldingDelta
			switch pcode {
			case tri:
				break
			case del:
				p = ledgercore.AssetParamsDelta{Deleted: true}
			case emp:
				p = ledgercore.AssetParamsDelta{Params: &basics.AssetParams{}}
			case act:
				p = ledgercore.AssetParamsDelta{Params: &basics.AssetParams{Total: 1000}}
			default:
				t.Logf("invalid pcode: %d", pcode)
				t.Fail()
			}
			switch hcode {
			case tri:
				break
			case del:
				h = ledgercore.AssetHoldingDelta{Deleted: true}
			case emp:
				h = ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{}}
			case act:
				h = ledgercore.AssetHoldingDelta{Holding: &basics.AssetHolding{Amount: 555}}
			default:
				t.Logf("invalid hcode: %d", hcode)
				t.Fail()
			}
			base.SetAssetData(p, h)
		} else {
			var p ledgercore.AppParamsDelta
			var h ledgercore.AppLocalStateDelta
			switch pcode {
			case tri:
				break
			case del:
				p = ledgercore.AppParamsDelta{Deleted: true}
			case emp:
				p = ledgercore.AppParamsDelta{Params: &basics.AppParams{}}
			case act:
				p = ledgercore.AppParamsDelta{Params: &basics.AppParams{ClearStateProgram: []byte{4, 5, 6}}}
			default:
				t.Logf("invalid pcode: %d", pcode)
				t.Fail()
			}
			switch hcode {
			case tri:
				break
			case del:
				h = ledgercore.AppLocalStateDelta{Deleted: true}
			case emp:
				h = ledgercore.AppLocalStateDelta{LocalState: &basics.AppLocalState{}}
			case act:
				h = ledgercore.AppLocalStateDelta{LocalState: &basics.AppLocalState{Schema: basics.StateSchema{NumByteSlice: 5}}}
			default:
				t.Logf("invalid hcode: %d", hcode)
				t.Fail()
			}
			base.SetAppData(p, h)
		}

		return base
	}

	itb := func(i int) (b bool) {
		return i != 0
	}

	type testcase struct {
		p             deltaCode
		h             deltaCode
		isAsset       int
		isOwning      int
		isHolding     int
		isEmptyFields int
		isEmpty       int
	}

	empty := func(testType basics.CreatableType) ResourcesData {
		return MakeResourcesData(0)
	}
	emptyParamsNoHolding := func(testType basics.CreatableType) ResourcesData {
		rd := MakeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetParams(basics.AssetParams{}, false)
		} else {
			rd.SetAppParams(basics.AppParams{}, false)
		}
		return rd
	}
	emptyParamsEmptyHolding := func(testType basics.CreatableType) ResourcesData {
		rd := MakeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetHolding(basics.AssetHolding{})
			rd.SetAssetParams(basics.AssetParams{}, true)
		} else {
			rd.SetAppLocalState(basics.AppLocalState{})
			rd.SetAppParams(basics.AppParams{}, true)
		}
		return rd
	}
	emptyParamsNotEmptyHolding := func(testType basics.CreatableType) ResourcesData {
		rd := MakeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetHolding(basics.AssetHolding{Amount: 111})
			rd.SetAssetParams(basics.AssetParams{}, true)
		} else {
			rd.SetAppLocalState(basics.AppLocalState{Schema: basics.StateSchema{NumUint: 10}})
			rd.SetAppParams(basics.AppParams{}, true)
		}
		return rd
	}
	paramsNoHolding := func(testType basics.CreatableType) ResourcesData {
		rd := MakeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetParams(basics.AssetParams{Total: 222}, false)
		} else {
			rd.SetAppParams(basics.AppParams{ApprovalProgram: []byte{1, 2, 3}}, false)
		}
		return rd
	}
	paramsEmptyHolding := func(testType basics.CreatableType) ResourcesData {
		rd := MakeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetHolding(basics.AssetHolding{})
			rd.SetAssetParams(basics.AssetParams{Total: 222}, true)
		} else {
			rd.SetAppLocalState(basics.AppLocalState{})
			rd.SetAppParams(basics.AppParams{ApprovalProgram: []byte{1, 2, 3}}, true)
		}
		return rd
	}
	paramsAndHolding := func(testType basics.CreatableType) ResourcesData {
		rd := MakeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetHolding(basics.AssetHolding{Amount: 111})
			rd.SetAssetParams(basics.AssetParams{Total: 222}, true)
		} else {
			rd.SetAppLocalState(basics.AppLocalState{Schema: basics.StateSchema{NumUint: 10}})
			rd.SetAppParams(basics.AppParams{ApprovalProgram: []byte{1, 2, 3}}, true)
		}
		return rd
	}
	noParamsEmptyHolding := func(testType basics.CreatableType) ResourcesData {
		rd := MakeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetHolding(basics.AssetHolding{})
		} else {
			rd.SetAppLocalState(basics.AppLocalState{})
		}
		return rd
	}
	noParamsNotEmptyHolding := func(testType basics.CreatableType) ResourcesData {
		rd := MakeResourcesData(0)
		if testType == basics.AssetCreatable {
			rd.SetAssetHolding(basics.AssetHolding{Amount: 111})
		} else {
			rd.SetAppLocalState(basics.AppLocalState{Schema: basics.StateSchema{NumUint: 10}})
		}
		return rd
	}

	var tests = []struct {
		name      string
		baseRD    func(testType basics.CreatableType) ResourcesData
		testcases []testcase
	}{
		{
			"empty_base", empty,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 0, 0, 0, 1, 1},
				{del, tri, 0, 0, 0, 1, 1},
				{emp, tri, 1, 1, 0, 1, 0},
				{act, tri, 1, 1, 0, 0, 0},

				{tri, del, 0, 0, 0, 1, 1},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 0, 1, 1, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 0, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},

		{
			"empty_params_no_holding", emptyParamsNoHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 1, 0, 1, 0},
				{del, tri, 0, 0, 0, 1, 1},
				{emp, tri, 1, 1, 0, 1, 0},
				{act, tri, 1, 1, 0, 0, 0},

				{tri, del, 1, 1, 0, 1, 0},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 1, 1, 1, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 1, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"empty_params_empty_holding", emptyParamsEmptyHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 1, 1, 1, 0},
				{del, tri, 1, 0, 1, 1, 0},
				{emp, tri, 1, 1, 1, 1, 0},
				{act, tri, 1, 1, 1, 0, 0},

				{tri, del, 1, 1, 0, 1, 0},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 1, 1, 1, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 1, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"empty_params_not_empty_holding", emptyParamsNotEmptyHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 1, 1, 0, 0},
				{del, tri, 1, 0, 1, 0, 0},
				{emp, tri, 1, 1, 1, 0, 0},
				{act, tri, 1, 1, 1, 0, 0},

				{tri, del, 1, 1, 0, 1, 0},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 1, 1, 1, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 1, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"params_no_holding", paramsNoHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 1, 0, 0, 0},
				{del, tri, 0, 0, 0, 1, 1},
				{emp, tri, 1, 1, 0, 1, 0},
				{act, tri, 1, 1, 0, 0, 0},

				{tri, del, 1, 1, 0, 0, 0},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 1, 1, 0, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 1, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"params_empty_holding", paramsEmptyHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 1, 1, 0, 0},
				{del, tri, 1, 0, 1, 1, 0},
				{emp, tri, 1, 1, 1, 1, 0},
				{act, tri, 1, 1, 1, 0, 0},

				{tri, del, 1, 1, 0, 0, 0},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 1, 1, 0, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 1, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"params_and_holding", paramsAndHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 1, 1, 0, 0},
				{del, tri, 1, 0, 1, 0, 0},
				{emp, tri, 1, 1, 1, 0, 0},
				{act, tri, 1, 1, 1, 0, 0},

				{tri, del, 1, 1, 0, 0, 0},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 1, 1, 0, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 1, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"no_params_empty_holding", noParamsEmptyHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 0, 1, 1, 0},
				{del, tri, 1, 0, 1, 1, 0},
				{emp, tri, 1, 1, 1, 1, 0},
				{act, tri, 1, 1, 1, 0, 0},

				{tri, del, 0, 0, 0, 1, 1},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 0, 1, 1, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 0, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
		{
			"no_params_not_empty_holding", noParamsNotEmptyHolding,
			[]testcase{
				// IsAsset, IsOwning, IsHolding, IsEmptyAssetFields, IsEmpty
				{tri, tri, 1, 0, 1, 0, 0},
				{del, tri, 1, 0, 1, 0, 0},
				{emp, tri, 1, 1, 1, 0, 0},
				{act, tri, 1, 1, 1, 0, 0},

				{tri, del, 0, 0, 0, 1, 1},
				{del, del, 0, 0, 0, 1, 1},
				{emp, del, 1, 1, 0, 1, 0},
				{act, del, 1, 1, 0, 0, 0},

				{tri, emp, 1, 0, 1, 1, 0},
				{del, emp, 1, 0, 1, 1, 0},
				{emp, emp, 1, 1, 1, 1, 0},
				{act, emp, 1, 1, 1, 0, 0},

				{tri, act, 1, 0, 1, 0, 0},
				{del, act, 1, 0, 1, 0, 0},
				{emp, act, 1, 1, 1, 0, 0},
				{act, act, 1, 1, 1, 0, 0},
			},
		},
	}
	for _, testType := range []basics.CreatableType{basics.AssetCreatable, basics.AppCreatable} {
		for _, test := range tests {
			var testTypeStr string
			if testType == basics.AssetCreatable {
				testTypeStr = "asset"
			} else {
				testTypeStr = "app"
			}
			t.Run(fmt.Sprintf("test_%s_%s", testTypeStr, test.name), func(t *testing.T) {
				for i, ts := range test.testcases {
					t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
						rd := test.baseRD(testType)
						rd = apply(t, rd, testType, ts.p, ts.h)
						if testType == basics.AssetCreatable {
							a.Equal(itb(ts.isAsset), rd.IsAsset())
							a.Equal(itb(ts.isEmptyFields), rd.IsEmptyAssetFields())
							a.False(rd.IsApp())
							a.True(rd.IsEmptyAppFields())
						} else {
							a.Equal(itb(ts.isAsset), rd.IsApp())
							a.Equal(itb(ts.isEmptyFields), rd.IsEmptyAppFields())
							a.False(rd.IsAsset())
							a.True(rd.IsEmptyAssetFields())
						}
						a.Equal(itb(ts.isOwning), rd.IsOwning())
						a.Equal(itb(ts.isHolding), rd.IsHolding())
						a.Equal(itb(ts.isEmpty), rd.IsEmpty())
					})
				}
			})
		}
	}
}

// TestResourceDataRoundtripConversion ensures that basics.AppLocalState, basics.AppParams,
// basics.AssetHolding, and basics.AssetParams can be converted to resourcesData and back without
// losing any data. It uses reflection to be sure that no new fields are omitted.
//
// In other words, this test makes sure any new fields in basics.AppLocalState, basics.AppParams,
// basics.AssetHolding, or basics.AssetParam also get added to resourcesData.
func TestResourceDataRoundtripConversion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("basics.AppLocalState", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 1000; i++ {
			randObj, _ := protocol.RandomizeObject(&basics.AppLocalState{})
			basicsAppLocalState := *randObj.(*basics.AppLocalState)

			var data ResourcesData
			data.SetAppLocalState(basicsAppLocalState)
			roundTripAppLocalState := data.GetAppLocalState()

			require.Equal(t, basicsAppLocalState, roundTripAppLocalState)
		}
	})

	t.Run("basics.AppParams", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 1000; i++ {
			randObj, _ := protocol.RandomizeObject(&basics.AppParams{})
			basicsAppParams := *randObj.(*basics.AppParams)

			for _, haveHoldings := range []bool{true, false} {
				var data ResourcesData
				data.SetAppParams(basicsAppParams, haveHoldings)
				roundTripAppParams := data.GetAppParams()

				require.Equal(t, basicsAppParams, roundTripAppParams)
			}
		}
	})

	t.Run("basics.AssetHolding", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 1000; i++ {
			randObj, _ := protocol.RandomizeObject(&basics.AssetHolding{})
			basicsAssetHolding := *randObj.(*basics.AssetHolding)

			var data ResourcesData
			data.SetAssetHolding(basicsAssetHolding)
			roundTripAssetHolding := data.GetAssetHolding()

			require.Equal(t, basicsAssetHolding, roundTripAssetHolding)
		}
	})

	t.Run("basics.AssetParams", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 1000; i++ {
			randObj, _ := protocol.RandomizeObject(&basics.AssetParams{})
			basicsAssetParams := *randObj.(*basics.AssetParams)

			for _, haveHoldings := range []bool{true, false} {
				var data ResourcesData
				data.SetAssetParams(basicsAssetParams, haveHoldings)
				roundTripAssetParams := data.GetAssetParams()

				require.Equal(t, basicsAssetParams, roundTripAssetParams)
			}
		}
	})
}

// TestBaseAccountDataRoundtripConversion ensures that baseAccountData can be converted to
// ledgercore.AccountData and basics.AccountData and back without losing any data. It uses
// reflection to be sure that no new fields are omitted.
//
// In other words, this test makes sure any new fields in baseAccountData also get added to
// ledgercore.AccountData and basics.AccountData. You should add a manual override in this test if
// the field really only belongs in baseAccountData.
func TestBaseAccountDataRoundtripConversion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("ledgercore.AccountData", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 1000; i++ {
			randObj, _ := protocol.RandomizeObject(&BaseAccountData{})
			baseAccount := *randObj.(*BaseAccountData)

			ledgercoreAccount := baseAccount.GetLedgerCoreAccountData()
			var roundTripAccount BaseAccountData
			roundTripAccount.SetCoreAccountData(&ledgercoreAccount)

			// Manually set UpdateRound, since it is lost in GetLedgerCoreAccountData
			roundTripAccount.UpdateRound = baseAccount.UpdateRound

			require.Equal(t, baseAccount, roundTripAccount)
		}
	})

	t.Run("basics.AccountData", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 1000; i++ {
			randObj, _ := protocol.RandomizeObject(&BaseAccountData{})
			baseAccount := *randObj.(*BaseAccountData)

			basicsAccount := baseAccount.GetAccountData()
			var roundTripAccount BaseAccountData
			roundTripAccount.SetAccountData(&basicsAccount)

			// Manually set UpdateRound, since it is lost in GetAccountData
			roundTripAccount.UpdateRound = baseAccount.UpdateRound

			// Manually set resources, since resource information is lost in GetAccountData
			roundTripAccount.TotalAssetParams = baseAccount.TotalAssetParams
			roundTripAccount.TotalAssets = baseAccount.TotalAssets
			roundTripAccount.TotalAppLocalStates = baseAccount.TotalAppLocalStates
			roundTripAccount.TotalAppParams = baseAccount.TotalAppParams

			require.Equal(t, baseAccount, roundTripAccount)
		}
	})
}

// TestBasicsAccountDataRoundtripConversion ensures that basics.AccountData can be converted to
// baseAccountData and back without losing any data. It uses reflection to be sure that this test is
// always up-to-date with new fields.
//
// In other words, this test makes sure any new fields in basics.AccountData also get added to
// baseAccountData.
func TestBasicsAccountDataRoundtripConversion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for i := 0; i < 1000; i++ {
		randObj, _ := protocol.RandomizeObject(&basics.AccountData{})
		basicsAccount := *randObj.(*basics.AccountData)

		var baseAccount BaseAccountData
		baseAccount.SetAccountData(&basicsAccount)
		roundTripAccount := baseAccount.GetAccountData()

		// Manually set resources, since GetAccountData doesn't attempt to restore them
		roundTripAccount.AssetParams = basicsAccount.AssetParams
		roundTripAccount.Assets = basicsAccount.Assets
		roundTripAccount.AppLocalStates = basicsAccount.AppLocalStates
		roundTripAccount.AppParams = basicsAccount.AppParams

		require.Equal(t, basicsAccount, roundTripAccount)
		require.Equal(t, uint64(len(roundTripAccount.AssetParams)), baseAccount.TotalAssetParams)
		require.Equal(t, uint64(len(roundTripAccount.Assets)), baseAccount.TotalAssets)
		require.Equal(t, uint64(len(roundTripAccount.AppLocalStates)), baseAccount.TotalAppLocalStates)
		require.Equal(t, uint64(len(roundTripAccount.AppParams)), baseAccount.TotalAppParams)
	}
}

// TestLedgercoreAccountDataRoundtripConversion ensures that ledgercore.AccountData can be converted
// to baseAccountData and back without losing any data. It uses reflection to be sure that no new
// fields are omitted.
//
// In other words, this test makes sure any new fields in ledgercore.AccountData also get added to
// baseAccountData.
func TestLedgercoreAccountDataRoundtripConversion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for i := 0; i < 1000; i++ {
		randObj, _ := protocol.RandomizeObject(&ledgercore.AccountData{})
		ledgercoreAccount := *randObj.(*ledgercore.AccountData)

		var baseAccount BaseAccountData
		baseAccount.SetCoreAccountData(&ledgercoreAccount)
		roundTripAccount := baseAccount.GetLedgerCoreAccountData()

		require.Equal(t, ledgercoreAccount, roundTripAccount)
	}
}

func TestBaseAccountDataIsEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	positiveTesting := func(t *testing.T) {
		var ba BaseAccountData
		require.True(t, ba.IsEmpty())
		for i := 0; i < 20; i++ {
			h := crypto.Hash([]byte{byte(i)})
			rnd := binary.BigEndian.Uint64(h[:])
			ba.UpdateRound = rnd
			require.True(t, ba.IsEmpty())
		}
	}
	var empty BaseAccountData
	negativeTesting := func(t *testing.T) {
		for i := 0; i < 10000; i++ {
			randObj, _ := protocol.RandomizeObjectField(&BaseAccountData{})
			ba := randObj.(*BaseAccountData)
			if *ba == empty || ba.UpdateRound != 0 {
				continue
			}
			require.False(t, ba.IsEmpty(), "base account : %v", ba)
		}
	}
	structureTesting := func(t *testing.T) {
		encoding, err := json.Marshal(&empty)
		zeros32 := "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
		expectedEncoding := `{"Status":0,"MicroAlgos":{"Raw":0},"RewardsBase":0,"RewardedMicroAlgos":{"Raw":0},"AuthAddr":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ","TotalAppSchemaNumUint":0,"TotalAppSchemaNumByteSlice":0,"TotalExtraAppPages":0,"TotalAssetParams":0,"TotalAssets":0,"TotalAppParams":0,"TotalAppLocalStates":0,"TotalBoxes":0,"TotalBoxBytes":0,"IncentiveEligible":false,"LastProposed":0,"LastHeartbeat":0,"VoteID":[` + zeros32 + `],"SelectionID":[` + zeros32 + `],"VoteFirstValid":0,"VoteLastValid":0,"VoteKeyDilution":0,"StateProofID":[` + zeros32 + `,` + zeros32 + `],"UpdateRound":0}`
		require.NoError(t, err)
		require.Equal(t, expectedEncoding, string(encoding))
	}
	t.Run("Positive", positiveTesting)
	t.Run("Negative", negativeTesting)
	t.Run("Structure", structureTesting)
}

func TestBaseOnlineAccountDataIsEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	positiveTesting := func(t *testing.T) {
		var ba BaseOnlineAccountData
		require.True(t, ba.IsEmpty())
		require.True(t, ba.IsVotingEmpty())
		ba.MicroAlgos.Raw = 100
		require.True(t, ba.IsVotingEmpty())
		ba.RewardsBase = 200
		require.True(t, ba.IsVotingEmpty())
	}
	var empty BaseOnlineAccountData
	negativeTesting := func(t *testing.T) {
		for i := 0; i < 10; i++ {
			randObj, _ := protocol.RandomizeObjectField(&BaseOnlineAccountData{})
			ba := randObj.(*BaseOnlineAccountData)
			if *ba == empty {
				continue
			}
			require.False(t, ba.IsEmpty(), "base account : %v", ba)
			break
		}
		{
			var ba BaseOnlineAccountData
			ba.MicroAlgos.Raw = 100
			require.False(t, ba.IsEmpty())
		}
		{
			var ba BaseOnlineAccountData
			ba.RewardsBase = 200
			require.False(t, ba.IsEmpty())
		}
	}
	structureTesting := func(t *testing.T) {
		encoding, err := json.Marshal(&empty)
		zeros32 := "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
		expectedEncoding := `{"VoteID":[` + zeros32 + `],"SelectionID":[` + zeros32 + `],"VoteFirstValid":0,"VoteLastValid":0,"VoteKeyDilution":0,"StateProofID":[` + zeros32 + `,` + zeros32 + `],"LastProposed":0,"LastHeartbeat":0,"IncentiveEligible":false,"MicroAlgos":{"Raw":0},"RewardsBase":0}`
		require.NoError(t, err)
		require.Equal(t, expectedEncoding, string(encoding))
	}
	t.Run("Positive", positiveTesting)
	t.Run("Negative", negativeTesting)
	t.Run("Structure", structureTesting)

}

func TestBaseOnlineAccountDataGettersSetters(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	addr := ledgertesting.RandomAddress()
	data := ledgertesting.RandomAccountData(1)
	data.Status = basics.Online
	crypto.RandBytes(data.VoteID[:])
	crypto.RandBytes(data.SelectionID[:])
	crypto.RandBytes(data.StateProofID[:])
	data.VoteFirstValid = basics.Round(crypto.RandUint64())
	data.VoteLastValid = basics.Round(crypto.RandUint64()) // int64 is the max sqlite can store
	data.VoteKeyDilution = crypto.RandUint64()

	var ba BaseOnlineAccountData
	ad := ledgercore.ToAccountData(data)
	ba.SetCoreAccountData(&ad)

	require.Equal(t, data.MicroAlgos, ba.MicroAlgos)
	require.Equal(t, data.RewardsBase, ba.RewardsBase)
	require.Equal(t, data.VoteID, ba.VoteID)
	require.Equal(t, data.SelectionID, ba.SelectionID)
	require.Equal(t, data.VoteFirstValid, ba.VoteFirstValid)
	require.Equal(t, data.VoteLastValid, ba.VoteLastValid)
	require.Equal(t, data.VoteKeyDilution, ba.VoteKeyDilution)
	require.Equal(t, data.StateProofID, ba.StateProofID)

	normBalance := basics.NormalizedOnlineAccountBalance(basics.Online, data.RewardsBase, data.MicroAlgos, proto.RewardUnit)
	require.Equal(t, normBalance, ba.NormalizedOnlineBalance(proto.RewardUnit))
	oa := ba.GetOnlineAccount(addr, normBalance)

	require.Equal(t, addr, oa.Address)
	require.Equal(t, ba.MicroAlgos, oa.MicroAlgos)
	require.Equal(t, ba.RewardsBase, oa.RewardsBase)
	require.Equal(t, normBalance, oa.NormalizedOnlineBalance)
	require.Equal(t, ba.VoteFirstValid, oa.VoteFirstValid)
	require.Equal(t, ba.VoteLastValid, oa.VoteLastValid)
	require.Equal(t, ba.StateProofID, oa.StateProofID)

	rewardsLevel := uint64(1)
	microAlgos, _, _ := basics.WithUpdatedRewards(
		proto.RewardUnit, basics.Online, oa.MicroAlgos, basics.MicroAlgos{}, ba.RewardsBase, rewardsLevel,
	)
	oad := ba.GetOnlineAccountData(proto.RewardUnit, rewardsLevel)

	require.Equal(t, microAlgos, oad.MicroAlgosWithRewards)
	require.Equal(t, ba.VoteID, oad.VoteID)
	require.Equal(t, ba.SelectionID, oad.SelectionID)
	require.Equal(t, ba.StateProofID, oad.StateProofID)
	require.Equal(t, ba.VoteFirstValid, oad.VoteFirstValid)
	require.Equal(t, ba.VoteLastValid, oad.VoteLastValid)
	require.Equal(t, ba.VoteKeyDilution, oad.VoteKeyDilution)
}

func TestBaseVotingDataGettersSetters(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	data := ledgertesting.RandomAccountData(1)
	data.Status = basics.Online
	crypto.RandBytes(data.VoteID[:])
	crypto.RandBytes(data.SelectionID[:])
	crypto.RandBytes(data.StateProofID[:])
	data.VoteFirstValid = basics.Round(crypto.RandUint64())
	data.VoteLastValid = basics.Round(crypto.RandUint64()) // int64 is the max sqlite can store
	data.VoteKeyDilution = crypto.RandUint64()

	var bv BaseVotingData
	require.True(t, bv.IsEmpty())

	ad := ledgercore.ToAccountData(data)
	bv.SetCoreAccountData(&ad)

	require.False(t, bv.IsEmpty())
	require.Equal(t, data.VoteID, bv.VoteID)
	require.Equal(t, data.SelectionID, bv.SelectionID)
	require.Equal(t, data.VoteFirstValid, bv.VoteFirstValid)
	require.Equal(t, data.VoteLastValid, bv.VoteLastValid)
	require.Equal(t, data.VoteKeyDilution, bv.VoteKeyDilution)
	require.Equal(t, data.StateProofID, bv.StateProofID)
}

func TestBaseOnlineAccountDataReflect(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Equal(t, 7, reflect.TypeFor[BaseOnlineAccountData]().NumField(), "update all getters and setters for baseOnlineAccountData and change the field count")
}

func TestBaseVotingDataReflect(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Equal(t, 7, reflect.TypeFor[BaseVotingData]().NumField(), "update all getters and setters for baseVotingData and change the field count")
}

// TestBaseAccountDataDecodeEmpty ensures no surprises when decoding nil/empty data.
func TestBaseAccountDataDecodeEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var b BaseAccountData

	err := protocol.Decode([]byte{}, &b)
	require.Error(t, err)

	err = protocol.Decode(nil, &b)
	require.Error(t, err)

	err = protocol.Decode([]byte{0x80}, &b)
	require.NoError(t, err)
}
