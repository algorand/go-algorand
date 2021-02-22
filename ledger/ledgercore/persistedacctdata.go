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

package ledgercore

import (
	"github.com/algorand/go-algorand/data/basics"
)

// MaxHoldingGroupSize specifies maximum size of AssetsHoldingGroup
const MaxHoldingGroupSize = 256

// AssetsHoldingGroup is a metadata for asset group data (AssetsHoldingGroupData)
// that is stored separately
type AssetsHoldingGroup struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// assets count in the group
	Count uint32 `codec:"c"`

	// Smallest AssetIndex in the group
	MinAssetIndex basics.AssetIndex `codec:"m"`

	// The delta is relative to MinAssetIndex
	DeltaMaxAssetIndex uint64 `codec:"d"`

	// A foreign key to the accountext table to the appropriate AssetsHoldingGroupData entry
	// AssetGroupKey is 0 for newly created entries and filled after persisting to DB
	AssetGroupKey int64 `codec:"k"`

	// groupData is an actual group data
	//msgp:ignore groupData
	groupData AssetsHoldingGroupData

	// loaded indicates either groupData loaded or not
	//msgp:ignore loaded
	loaded bool
}

// AssetsHoldingGroupData is an actual asset holding data
type AssetsHoldingGroupData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// offset relative to MinAssetIndex and differential afterward
	// assetId1 = AmountsAssetIndicesOffsets[0] + MinAssetIndex and assetIdx1 == MinAssetIndex
	// assetId2 = AmountsAssetIndicesOffsets[1] + assetIdx1
	// assetId3 = AmountsAssetIndicesOffsets[2] + assetIdx2
	AssetOffsets []basics.AssetIndex `codec:"ao,allocbound=MaxHoldingGroupSize"`

	// Holding amount
	// same number of elements as in AmountsAssetIndicesOffsets
	Amounts []uint64 `codec:"a,allocbound=MaxHoldingGroupSize"`

	// Holding "frozen" flag
	// same number of elements as in AmountsAssetIndicesOffsets
	Frozens []bool `codec:"f,allocbound=MaxHoldingGroupSize"`
}

// ExtendedAssetHolding is AccountData's extension for storing asset holdings
type ExtendedAssetHolding struct {
	_struct struct{}             `codec:",omitempty,omitemptyarray"`
	Count   uint32               `codec:"c"`
	Groups  []AssetsHoldingGroup `codec:"gs,allocbound=4096"` // 1M asset holdings

	//msgp:ignore loaded
	loaded bool
}

// PersistedAccountData represents actual data stored in DB
type PersistedAccountData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	basics.AccountData
	ExtendedAssetHolding ExtendedAssetHolding `codec:"eash"`
}

// SortAssetIndex is a copy from data/basics/sort.go
//msgp:ignore SortAssetIndex
//msgp:sort basics.AssetIndex SortAssetIndex
type SortAssetIndex []basics.AssetIndex

func (a SortAssetIndex) Len() int           { return len(a) }
func (a SortAssetIndex) Less(i, j int) bool { return a[i] < a[j] }
func (a SortAssetIndex) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// SortAppIndex is a copy from data/basics/sort.go
//msgp:ignore SortAppIndex
//msgp:sort basics.AppIndex SortAppIndex
type SortAppIndex []basics.AppIndex

func (a SortAppIndex) Len() int           { return len(a) }
func (a SortAppIndex) Less(i, j int) bool { return a[i] < a[j] }
func (a SortAppIndex) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// EncodedMaxAssetsPerAccount is a copy from basics package to resolve deps in msgp-generated file
var EncodedMaxAssetsPerAccount = basics.EncodedMaxAssetsPerAccount

// EncodedMaxAppLocalStates is a copy from basics package to resolve deps in msgp-generated file
var EncodedMaxAppLocalStates = basics.EncodedMaxAppLocalStates

// EncodedMaxAppParams is a copy from basics package to resolve deps in msgp-generated file
var EncodedMaxAppParams = basics.EncodedMaxAppParams
