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
	"fmt"
	"sort"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// MaxHoldingGroupSize specifies maximum number of entries in AssetsHoldingGroup.groupData
const MaxHoldingGroupSize = 256 // 256 entries take approx 3473 bytes

// MaxParamsGroupSize specifies maximum number of entries in AssetsParamsGroup.groupData
const MaxParamsGroupSize = 14 // 14 entries take approx 3665 bytes

// AssetGroupDesc is asset group descriptor
type AssetGroupDesc struct {
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
}

// AssetsHoldingGroup is a metadata for asset group data (AssetsHoldingGroupData)
// that is stored separately
type AssetsHoldingGroup struct {
	AssetGroupDesc
	// groupData is an actual group data
	groupData AssetsHoldingGroupData
	// loaded indicates either groupData loaded or not
	loaded bool
}

// AssetsParamsGroup is a metadata for asset group data (AssetsParamsGroupData)
// that is stored separately
type AssetsParamsGroup struct {
	AssetGroupDesc
	// groupData is an actual group data
	groupData AssetsParamsGroupData
	// loaded indicates either groupData loaded or not
	loaded bool
}

// AssetsCommonGroupData is common data type for Holding and Params storing AssetOffsets data
type AssetsCommonGroupData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// offset relative to MinAssetIndex and differential afterward
	// assetId1 = AssetOffsets[0] + MinAssetIndex and assetIdx1 == MinAssetIndex
	// assetId2 = AssetOffsets[1] + assetIdx1
	// assetId3 = AssetOffsets[2] + assetIdx2
	AssetOffsets []basics.AssetIndex `codec:"ao,omitemptyarray,allocbound=MaxHoldingGroupSize"`
}

// AssetsParamsGroupData is an actual asset param data
type AssetsParamsGroupData struct {
	AssetsCommonGroupData

	// same number of elements as in AssetOffsets
	Totals         []uint64         `codec:"t,omitemptyarray,allocbound=MaxParamsGroupSize"`
	Decimals       []uint32         `codec:"d,omitemptyarray,allocbound=MaxParamsGroupSize"`
	DefaultFrozens []bool           `codec:"f,omitemptyarray,allocbound=MaxParamsGroupSize"`
	UnitNames      []string         `codec:"u,omitemptyarray,allocbound=MaxParamsGroupSize"`
	AssetNames     []string         `codec:"n,omitemptyarray,allocbound=MaxParamsGroupSize"`
	URLs           []string         `codec:"l,omitemptyarray,allocbound=MaxParamsGroupSize"`
	MetadataHash   [][32]byte       `codec:"h,omitemptyarray,allocbound=MaxParamsGroupSize"`
	Managers       []basics.Address `codec:"m,omitemptyarray,allocbound=MaxParamsGroupSize"`
	Reserves       []basics.Address `codec:"r,omitemptyarray,allocbound=MaxParamsGroupSize"`
	Freezes        []basics.Address `codec:"z,omitemptyarray,allocbound=MaxParamsGroupSize"`
	Clawbacks      []basics.Address `codec:"c,omitemptyarray,allocbound=MaxParamsGroupSize"`
}

// AssetsHoldingGroupData is an actual asset holding data
type AssetsHoldingGroupData struct {
	AssetsCommonGroupData

	// same number of elements as in AssetOffsets
	Amounts []uint64 `codec:"a,omitemptyarray,allocbound=MaxHoldingGroupSize"`
	Frozens []bool   `codec:"f,omitemptyarray,allocbound=MaxHoldingGroupSize"`
}

const maxEncodedGroupsSize = 4096

// ExtendedAssetHolding is AccountData's extension for storing asset holding
type ExtendedAssetHolding struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Count  uint32               `codec:"c"`
	Groups []AssetsHoldingGroup `codec:"gs,omitemptyarray,allocbound=maxEncodedGroupsSize"` // 1M holdings
}

// ExtendedAssetParams is AccountData's extension for storing asset params
type ExtendedAssetParams struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Count  uint32              `codec:"c"`
	Groups []AssetsParamsGroup `codec:"gs,omitemptyarray,allocbound=maxEncodedGroupsSize"` // TODO, 1M params
}

// PersistedAccountData represents actual data stored in DB
type PersistedAccountData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	basics.AccountData
	ExtendedAssetHolding ExtendedAssetHolding `codec:"eah,omitempty"`
	ExtendedAssetParams  ExtendedAssetParams  `codec:"eap,omitempty"`
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

// AbstractAssetGroupData abstacts common properties for Holding and Params group data
type AbstractAssetGroupData interface {
	Find(aidx basics.AssetIndex, base basics.AssetIndex) int
	AssetDeltaValue(ai int) basics.AssetIndex
}

// AbstractAssetGroup represets interface for Holding and Params group
type AbstractAssetGroup interface {
	MinAsset() basics.AssetIndex
	MaxAsset() basics.AssetIndex
	HasSpace() bool
	Loaded() bool
	GroupData() AbstractAssetGroupData
	AssetCount() uint32
	AssetAt(ai int) basics.AssetIndex
	Update(ai int, data interface{})
	Encode() []byte
	Key() int64
	SetKey(key int64)
	Reset()
	// Fetch loads group data using fetcher into a map provided assets argument
	Fetch(fetcher func(int64) ([]byte, basics.Round, error), assets interface{}) (basics.Round, error)

	delete(ai int)
	slice(pos uint32, maxDelta uint64)
	groupFromPosition(pos uint32, length uint32, capacity uint32, minAssetIndex basics.AssetIndex, maxDelta uint64) interface{}
	mergeIn(other AbstractAssetGroup, pos uint32) (delta basics.AssetIndex)
	sliceRight(pos uint32, delta basics.AssetIndex)
}

// AbstractAssetGroupList enables operations on concrete Holding or Params groups
type AbstractAssetGroupList interface {
	// Get returns abstract group
	Get(gi int) AbstractAssetGroup
	// Len returns number of groups in the list
	Len() int
	// Totals returns number of assets inside all the the groups
	Total() uint32
	// Reset initializes group to hold count assets in length groups
	Reset(count uint32, length int)
	// Assign assigns to value group to group[gi]
	Assign(gi int, group interface{})
	// ReleaseGroup removes group gi from the groups list
	ReleaseGroup(gi int)

	// FindGroup returns group index where asset aidx belongs to, or -1 otherwise
	FindGroup(aidx basics.AssetIndex, startIdx int) int
	// FindAsset returns group index and asset index if found and (-1, -1) otherwise.
	// If a matching group found but the group is not loaded yet, it returns (groupIdx, -1)
	FindAsset(aidx basics.AssetIndex, startIdx int) (int, int)

	// dropGroup is similar to ReleaseGroup but does not modify GroupList
	// assuming it was changed by a caller
	dropGroup(gi int)
	// delete asset by index ai from group gi
	deleteByIndex(gi int, ai int)
	// prependNewGroup, prependNewGroup and insertNewGroupAfter create new group with one data element
	prependNewGroup(aidx basics.AssetIndex, data interface{})
	appendNewGroup(aidx basics.AssetIndex, data interface{})
	insertNewGroupAfter(gi int, aidx basics.AssetIndex, data interface{})
	// insertInto adds new asset data into group at index gi
	insertInto(gi int, aidx basics.AssetIndex, data interface{})
	// insertAfter inserts a group into position gi+1
	insertAfter(gi int, group interface{})
	// split group at index gi into two groups, and returns group index suitable for asset aidx insertion
	split(gi int, aidx basics.AssetIndex) int
}

type groupBuilder interface {
	newGroup(size int) groupBuilder
	newElement(offset basics.AssetIndex, data interface{}) groupBuilder
	build(desc AssetGroupDesc) interface{}
}

type flattener interface {
	Count() uint32
	Data(idx int) interface{}
	AssetIndex(idx int) basics.AssetIndex
}

// EncodedMaxAssetsPerAccount is a copy from basics package to resolve deps in msgp-generated file
var EncodedMaxAssetsPerAccount = basics.EncodedMaxAssetsPerAccount

// EncodedMaxAppLocalStates is a copy from basics package to resolve deps in msgp-generated file
var EncodedMaxAppLocalStates = basics.EncodedMaxAppLocalStates

// EncodedMaxAppParams is a copy from basics package to resolve deps in msgp-generated file
var EncodedMaxAppParams = basics.EncodedMaxAppParams

// NumAssetHoldings returns number of assets in the account
func (pad PersistedAccountData) NumAssetHoldings() int {
	if pad.ExtendedAssetHolding.Count > 0 {
		return int(pad.ExtendedAssetHolding.Count)
	}
	return len(pad.AccountData.Assets)
}

// NumAssetParams returns number of assets in the account
func (pad PersistedAccountData) NumAssetParams() int {
	if pad.ExtendedAssetParams.Count > 0 {
		return int(pad.ExtendedAssetParams.Count)
	}
	return len(pad.AccountData.AssetParams)
}

func (gd *AssetsHoldingGroupData) update(ai int, hodl basics.AssetHolding) {
	gd.Amounts[ai] = hodl.Amount
	gd.Frozens[ai] = hodl.Frozen
}

func (gd *AssetsParamsGroupData) update(ai int, params basics.AssetParams) {
	gd.Totals[ai] = params.Total
	gd.Decimals[ai] = params.Decimals
	gd.DefaultFrozens[ai] = params.DefaultFrozen
	gd.UnitNames[ai] = params.UnitName
	gd.AssetNames[ai] = params.AssetName
	gd.URLs[ai] = params.URL
	copy(gd.MetadataHash[ai][:], params.MetadataHash[:])
	copy(gd.Managers[ai][:], params.Manager[:])
	copy(gd.Reserves[ai][:], params.Reserve[:])
	copy(gd.Freezes[ai][:], params.Freeze[:])
	copy(gd.Clawbacks[ai][:], params.Clawback[:])
}

func (gd *AssetsHoldingGroupData) delete(ai int) {
	if ai == 0 {
		gd.AssetOffsets = gd.AssetOffsets[1:]
		gd.AssetOffsets[0] = 0
		gd.Amounts = gd.Amounts[1:]
		gd.Frozens = gd.Frozens[1:]
	} else if ai == len(gd.AssetOffsets)-1 {
		gd.AssetOffsets = gd.AssetOffsets[:len(gd.AssetOffsets)-1]
		gd.Amounts = gd.Amounts[:len(gd.Amounts)-1]
		gd.Frozens = gd.Frozens[:len(gd.Frozens)-1]
	} else {
		length := len(gd.AssetOffsets)
		gd.AssetOffsets[ai+1] += gd.AssetOffsets[ai]
		copy(gd.AssetOffsets[ai:], gd.AssetOffsets[ai+1:])
		gd.AssetOffsets = gd.AssetOffsets[:length-1]

		// copy all and then slice to remove the last element
		copy(gd.Amounts[ai:], gd.Amounts[ai+1:])
		copy(gd.Frozens[ai:], gd.Frozens[ai+1:])

		gd.slice(0, length-1)
	}
}

func (gd *AssetsParamsGroupData) delete(ai int) {
	length := len(gd.AssetOffsets)
	if ai == 0 {
		gd.AssetOffsets = gd.AssetOffsets[1:]
		gd.AssetOffsets[0] = 0
		gd.slice(1, length)
	} else if ai == len(gd.AssetOffsets)-1 {
		gd.AssetOffsets = gd.AssetOffsets[:len(gd.AssetOffsets)-1]
		gd.Totals = gd.Totals[:len(gd.Totals)-1]
		gd.slice(0, length-1)
	} else {

		gd.AssetOffsets[ai+1] += gd.AssetOffsets[ai]
		copy(gd.AssetOffsets[ai:], gd.AssetOffsets[ai+1:])
		gd.AssetOffsets = gd.AssetOffsets[:length-1]

		// copy all and then slice to remove the last element
		copy(gd.Totals[ai:], gd.Totals[ai+1:])
		copy(gd.Decimals[ai:], gd.Decimals[ai+1:])
		copy(gd.DefaultFrozens[ai:], gd.DefaultFrozens[ai+1:])
		copy(gd.UnitNames[ai:], gd.UnitNames[ai+1:])
		copy(gd.AssetNames[ai:], gd.AssetNames[ai+1:])
		copy(gd.URLs[ai:], gd.URLs[ai+1:])
		copy(gd.MetadataHash[ai:], gd.MetadataHash[ai+1:])
		copy(gd.Managers[ai:], gd.Managers[ai+1:])
		copy(gd.Reserves[ai:], gd.Reserves[ai+1:])
		copy(gd.Freezes[ai:], gd.Freezes[ai+1:])
		copy(gd.Clawbacks[ai:], gd.Clawbacks[ai+1:])

		gd.slice(0, length-1)
	}
}

func (gd *AssetsHoldingGroupData) slice(start, end int) {
	gd.Amounts = gd.Amounts[start:end]
	gd.Frozens = gd.Frozens[start:end]
}

func (gd *AssetsParamsGroupData) slice(start, end int) {
	gd.Totals = gd.Totals[start:end]
	gd.Decimals = gd.Decimals[start:end]
	gd.DefaultFrozens = gd.DefaultFrozens[start:end]
	gd.UnitNames = gd.UnitNames[start:end]
	gd.AssetNames = gd.AssetNames[start:end]
	gd.URLs = gd.URLs[start:end]
	gd.MetadataHash = gd.MetadataHash[start:end]
	gd.Managers = gd.Managers[start:end]
	gd.Reserves = gd.Reserves[start:end]
	gd.Freezes = gd.Freezes[start:end]
	gd.Clawbacks = gd.Clawbacks[start:end]
}

// GetHolding returns AssetHolding from group data by asset index ai
func (gd AssetsHoldingGroupData) GetHolding(ai int) basics.AssetHolding {
	return basics.AssetHolding{Amount: gd.Amounts[ai], Frozen: gd.Frozens[ai]}
}

// GetHolding returns AssetHolding from group data by asset index ai
func (g AssetsHoldingGroup) GetHolding(ai int) basics.AssetHolding {
	return g.groupData.GetHolding(ai)
}

// Encode returns msgp-encoded group data
func (g AssetsHoldingGroup) Encode() []byte {
	// TODO: use GetEncodingBuf/PutEncodingBuf
	return protocol.Encode(&g.groupData)
}

// Encode returns msgp-encoded group data
func (g AssetsParamsGroup) Encode() []byte {
	// TODO: use GetEncodingBuf/PutEncodingBuf
	return protocol.Encode(&g.groupData)
}

// Update an asset holding by index
func (g *AssetsHoldingGroup) update(ai int, holding basics.AssetHolding) {
	g.groupData.update(ai, holding)
}

// Loaded return a boolean flag indicated if the group loaded or not
func (g AssetsHoldingGroup) Loaded() bool {
	return g.loaded
}

// Load sets a group data value in the group
func (g *AssetsHoldingGroup) Load(gd AssetsHoldingGroupData) {
	g.groupData = gd
	g.loaded = true
}

// Load sets a group data value in the group
func (g *AssetsParamsGroup) Load(gd AssetsParamsGroupData) {
	g.groupData = gd
	g.loaded = true
}

// Delete removes asset by index ai from a group
func (g *AssetGroupDesc) Delete(ai int, ag AbstractAssetGroup) {
	// although a group with only one element is handled by a caller
	// add a safety check here
	if ag.AssetCount() == 1 {
		ag.Reset()
		return
	}

	agd := ag.GroupData()
	if ai == 0 {
		// when deleting the first element, update MinAssetIndex and DeltaMaxAssetIndex
		g.MinAssetIndex += agd.AssetDeltaValue(1)
		g.DeltaMaxAssetIndex -= uint64(agd.AssetDeltaValue(1))
	} else if uint32(ai) == g.Count-1 {
		// when deleting the last element, update DeltaMaxAssetIndex
		g.DeltaMaxAssetIndex -= uint64(agd.AssetDeltaValue(int(ag.AssetCount() - 1)))
	}

	ag.delete(ai)
	g.Count--
	return
}

func (g *AssetsHoldingGroup) delete(ai int) {
	g.groupData.delete(ai)
}

func (g *AssetsParamsGroup) delete(ai int) {
	g.groupData.delete(ai)
}

// GetParams returns AssetParams from group data by asset index ai
func (gd AssetsParamsGroupData) GetParams(ai int) basics.AssetParams {
	return basics.AssetParams{
		Total:         gd.Totals[ai],
		Decimals:      gd.Decimals[ai],
		DefaultFrozen: gd.DefaultFrozens[ai],
		UnitName:      gd.UnitNames[ai],
		AssetName:     gd.AssetNames[ai],
		URL:           gd.URLs[ai],
		MetadataHash:  gd.MetadataHash[ai],
		Manager:       gd.Managers[ai],
		Reserve:       gd.Reserves[ai],
		Freeze:        gd.Freezes[ai],
		Clawback:      gd.Clawbacks[ai],
	}
}

// GetParams returns AssetParams from group data by asset index ai
func (g AssetsParamsGroup) GetParams(ai int) basics.AssetParams {
	return g.groupData.GetParams(ai)
}

// insert asset aidx into current group. It should not exist in the group
func (g *AssetsHoldingGroup) insert(aidx basics.AssetIndex, holding basics.AssetHolding) {
	if aidx < g.MinAssetIndex {
		// prepend
		g.groupData.Amounts = append([]uint64{holding.Amount}, g.groupData.Amounts...)
		g.groupData.Frozens = append([]bool{holding.Frozen}, g.groupData.Frozens...)

		g.groupData.AssetOffsets[0] = g.MinAssetIndex - aidx
		g.groupData.AssetOffsets = append([]basics.AssetIndex{0}, g.groupData.AssetOffsets...)
		g.DeltaMaxAssetIndex += uint64(g.MinAssetIndex - aidx)
		g.MinAssetIndex = aidx
	} else if aidx > g.MinAssetIndex+basics.AssetIndex(g.DeltaMaxAssetIndex) {
		// append
		g.groupData.Amounts = append(g.groupData.Amounts, holding.Amount)
		g.groupData.Frozens = append(g.groupData.Frozens, holding.Frozen)

		lastAssetIndex := g.MinAssetIndex + basics.AssetIndex(g.DeltaMaxAssetIndex)
		delta := aidx - lastAssetIndex
		g.groupData.AssetOffsets = append(g.groupData.AssetOffsets, delta)
		g.DeltaMaxAssetIndex = uint64(aidx - g.MinAssetIndex)
	} else {
		// find position and insert
		cur := g.MinAssetIndex
		for ai, d := range g.groupData.AssetOffsets {
			cur += d
			if aidx < cur {
				g.groupData.AssetOffsets = append(g.groupData.AssetOffsets, 0)
				copy(g.groupData.AssetOffsets[ai:], g.groupData.AssetOffsets[ai-1:])
				prev := cur - d
				g.groupData.AssetOffsets[ai] = aidx - prev
				g.groupData.AssetOffsets[ai+1] = cur - aidx

				g.groupData.Amounts = append(g.groupData.Amounts, 0)
				copy(g.groupData.Amounts[ai:], g.groupData.Amounts[ai-1:])
				g.groupData.Amounts[ai] = holding.Amount

				g.groupData.Frozens = append(g.groupData.Frozens, false)
				copy(g.groupData.Frozens[ai:], g.groupData.Frozens[ai-1:])
				g.groupData.Frozens[ai] = holding.Frozen

				break
			}
		}
	}
	g.Count++
}

func (g *AssetsParamsGroup) insert(aidx basics.AssetIndex, params basics.AssetParams) {
	if aidx < g.MinAssetIndex {
		// prepend
		g.groupData.Totals = append([]uint64{params.Total}, g.groupData.Totals...)
		g.groupData.Decimals = append([]uint32{params.Decimals}, g.groupData.Decimals...)
		g.groupData.DefaultFrozens = append([]bool{params.DefaultFrozen}, g.groupData.DefaultFrozens...)
		g.groupData.UnitNames = append([]string{params.UnitName}, g.groupData.UnitNames...)
		g.groupData.AssetNames = append([]string{params.AssetName}, g.groupData.AssetNames...)
		g.groupData.URLs = append([]string{params.URL}, g.groupData.URLs...)
		g.groupData.MetadataHash = append([][32]byte{params.MetadataHash}, g.groupData.MetadataHash...)
		g.groupData.Managers = append([]basics.Address{params.Manager}, g.groupData.Managers...)
		g.groupData.Reserves = append([]basics.Address{params.Reserve}, g.groupData.Reserves...)
		g.groupData.Freezes = append([]basics.Address{params.Freeze}, g.groupData.Freezes...)
		g.groupData.Clawbacks = append([]basics.Address{params.Clawback}, g.groupData.Clawbacks...)

		g.groupData.AssetOffsets[0] = g.MinAssetIndex - aidx
		g.groupData.AssetOffsets = append([]basics.AssetIndex{0}, g.groupData.AssetOffsets...)
		g.DeltaMaxAssetIndex += uint64(g.MinAssetIndex - aidx)
		g.MinAssetIndex = aidx
	} else if aidx > g.MinAssetIndex+basics.AssetIndex(g.DeltaMaxAssetIndex) {
		// append
		g.groupData.Totals = append(g.groupData.Totals, params.Total)
		g.groupData.Decimals = append(g.groupData.Decimals, params.Decimals)
		g.groupData.DefaultFrozens = append(g.groupData.DefaultFrozens, params.DefaultFrozen)
		g.groupData.UnitNames = append(g.groupData.UnitNames, params.UnitName)
		g.groupData.AssetNames = append(g.groupData.AssetNames, params.AssetName)
		g.groupData.URLs = append(g.groupData.URLs, params.URL)
		g.groupData.MetadataHash = append(g.groupData.MetadataHash, params.MetadataHash)
		g.groupData.Managers = append(g.groupData.Managers, params.Manager)
		g.groupData.Reserves = append(g.groupData.Reserves, params.Reserve)
		g.groupData.Freezes = append(g.groupData.Freezes, params.Freeze)
		g.groupData.Clawbacks = append(g.groupData.Clawbacks, params.Clawback)

		lastAssetIndex := g.MinAssetIndex + basics.AssetIndex(g.DeltaMaxAssetIndex)
		delta := aidx - lastAssetIndex
		g.groupData.AssetOffsets = append(g.groupData.AssetOffsets, delta)
		g.DeltaMaxAssetIndex = uint64(aidx - g.MinAssetIndex)
	} else {
		// find position and insert
		cur := g.MinAssetIndex
		for ai, d := range g.groupData.AssetOffsets {
			cur += d
			if aidx < cur {
				g.groupData.AssetOffsets = append(g.groupData.AssetOffsets, 0)
				copy(g.groupData.AssetOffsets[ai:], g.groupData.AssetOffsets[ai-1:])
				prev := cur - d
				g.groupData.AssetOffsets[ai] = aidx - prev
				g.groupData.AssetOffsets[ai+1] = cur - aidx

				g.groupData.Totals = append(g.groupData.Totals, 0)
				copy(g.groupData.Totals[ai:], g.groupData.Totals[ai-1:])
				g.groupData.Totals[ai] = params.Total

				g.groupData.Decimals = append(g.groupData.Decimals, 0)
				copy(g.groupData.Decimals[ai:], g.groupData.Decimals[ai-1:])
				g.groupData.Decimals[ai] = params.Decimals

				g.groupData.DefaultFrozens = append(g.groupData.DefaultFrozens, false)
				copy(g.groupData.DefaultFrozens[ai:], g.groupData.DefaultFrozens[ai-1:])
				g.groupData.DefaultFrozens[ai] = params.DefaultFrozen

				g.groupData.UnitNames = append(g.groupData.UnitNames, "")
				copy(g.groupData.UnitNames[ai:], g.groupData.UnitNames[ai-1:])
				g.groupData.UnitNames[ai] = params.UnitName

				g.groupData.AssetNames = append(g.groupData.AssetNames, "")
				copy(g.groupData.AssetNames[ai:], g.groupData.AssetNames[ai-1:])
				g.groupData.AssetNames[ai] = params.AssetName

				g.groupData.URLs = append(g.groupData.URLs, "")
				copy(g.groupData.URLs[ai:], g.groupData.URLs[ai-1:])
				g.groupData.URLs[ai] = params.URL

				g.groupData.MetadataHash = append(g.groupData.MetadataHash, [32]byte{})
				copy(g.groupData.MetadataHash[ai:], g.groupData.MetadataHash[ai-1:])
				g.groupData.MetadataHash[ai] = params.MetadataHash

				g.groupData.Managers = append(g.groupData.Managers, basics.Address{})
				copy(g.groupData.Managers[ai:], g.groupData.Managers[ai-1:])
				g.groupData.Managers[ai] = params.Manager

				g.groupData.Reserves = append(g.groupData.Reserves, basics.Address{})
				copy(g.groupData.Reserves[ai:], g.groupData.Reserves[ai-1:])
				g.groupData.Reserves[ai] = params.Reserve

				g.groupData.Freezes = append(g.groupData.Freezes, basics.Address{})
				copy(g.groupData.Freezes[ai:], g.groupData.Freezes[ai-1:])
				g.groupData.Freezes[ai] = params.Freeze

				g.groupData.Clawbacks = append(g.groupData.Clawbacks, basics.Address{})
				copy(g.groupData.Clawbacks[ai:], g.groupData.Clawbacks[ai-1:])
				g.groupData.Clawbacks[ai] = params.Clawback

				break
			}
		}
	}
	g.Count++

}

func (g *AssetsHoldingGroup) mergeIn(other AbstractAssetGroup, pos uint32) (delta basics.AssetIndex) {
	groupDelta := other.MinAsset() - (g.MinAssetIndex + basics.AssetIndex(g.DeltaMaxAssetIndex))

	g.groupData.AssetOffsets = append(g.groupData.AssetOffsets, other.GroupData().AssetDeltaValue(0)+groupDelta)
	for j := 1; j < int(pos); j++ {
		offset := other.GroupData().AssetDeltaValue(j)
		g.groupData.AssetOffsets = append(g.groupData.AssetOffsets, offset)
		delta += offset
	}
	g.DeltaMaxAssetIndex += uint64(delta + groupDelta)
	gd := other.(*AssetsHoldingGroup).groupData
	g.groupData.Amounts = append(g.groupData.Amounts, gd.Amounts[:pos]...)
	g.groupData.Frozens = append(g.groupData.Frozens, gd.Frozens[:pos]...)
	g.Count += pos

	return delta
}

func (g *AssetsParamsGroup) mergeIn(other AbstractAssetGroup, pos uint32) (delta basics.AssetIndex) {
	groupDelta := other.MinAsset() - (g.MinAssetIndex + basics.AssetIndex(g.DeltaMaxAssetIndex))

	g.groupData.AssetOffsets = append(g.groupData.AssetOffsets, other.GroupData().AssetDeltaValue(0)+groupDelta)
	for j := 1; j < int(pos); j++ {
		offset := other.GroupData().AssetDeltaValue(j)
		g.groupData.AssetOffsets = append(g.groupData.AssetOffsets, offset)
		delta += offset
	}
	g.DeltaMaxAssetIndex += uint64(delta + groupDelta)
	gd := other.(*AssetsParamsGroup).groupData

	g.groupData.Totals = append(g.groupData.Totals, gd.Totals[:pos]...)
	g.groupData.Decimals = append(g.groupData.Decimals, gd.Decimals[:pos]...)
	g.groupData.DefaultFrozens = append(g.groupData.DefaultFrozens, gd.DefaultFrozens[:pos]...)
	g.groupData.UnitNames = append(g.groupData.UnitNames, gd.UnitNames[:pos]...)
	g.groupData.AssetNames = append(g.groupData.AssetNames, gd.AssetNames[:pos]...)
	g.groupData.URLs = append(g.groupData.URLs, gd.URLs[:pos]...)
	g.groupData.MetadataHash = append(g.groupData.MetadataHash, gd.MetadataHash[:pos]...)
	g.groupData.Managers = append(g.groupData.Managers, gd.Managers[:pos]...)
	g.groupData.Reserves = append(g.groupData.Reserves, gd.Reserves[:pos]...)
	g.groupData.Freezes = append(g.groupData.Freezes, gd.Freezes[:pos]...)
	g.groupData.Clawbacks = append(g.groupData.Clawbacks, gd.Clawbacks[:pos]...)
	g.Count += pos

	return delta
}

// Loaded return a boolean flag indicated if the group loaded or not
func (g AssetsParamsGroup) Loaded() bool {
	return g.loaded
}

func (g *AssetsParamsGroup) update(ai int, params basics.AssetParams) {
	g.groupData.update(ai, params)
}

// Find returns asset index in AssetOffsets by given AssetIndex and group base AssetIndex value
func (g *AssetsCommonGroupData) Find(aidx basics.AssetIndex, base basics.AssetIndex) int {
	// linear search because AssetOffsets is delta-encoded, not values
	cur := base
	for ai, d := range g.AssetOffsets {
		cur = d + cur
		if aidx == cur {
			return ai
		}
	}
	return -1
}

// AssetDeltaValue returns asset offset value at index ai.
// It does not check boundaries.
func (g *AssetsCommonGroupData) AssetDeltaValue(ai int) basics.AssetIndex {
	return g.AssetOffsets[ai]
}

// HasSpace returns true if this group has space to accommodate one more asset entry
func (g *AssetsHoldingGroup) HasSpace() bool {
	return g.Count < MaxHoldingGroupSize
}

// HasSpace returns true if this group has space to accommodate one more asset entry
func (g *AssetsParamsGroup) HasSpace() bool {
	return g.Count < MaxParamsGroupSize
}

// MinAsset returns min (base) AssetIndex value for this group
func (g *AssetGroupDesc) MinAsset() basics.AssetIndex {
	return g.MinAssetIndex
}

// MaxAsset returns max AssetIndex value in this group
func (g *AssetGroupDesc) MaxAsset() basics.AssetIndex {
	return g.MinAssetIndex + basics.AssetIndex(g.DeltaMaxAssetIndex)
}

// AssetCount returns number of assets in this group
func (g *AssetGroupDesc) AssetCount() uint32 {
	return g.Count
}

// SetKey sets id of a DB record containing actual this group data
func (g *AssetGroupDesc) SetKey(key int64) {
	g.AssetGroupKey = key
}

// Key returns id of a DB record containing actual this group data
func (g *AssetGroupDesc) Key() int64 {
	return g.AssetGroupKey
}

// AssetAt returns asset value at postion ai
func (g *AssetsHoldingGroup) AssetAt(ai int) basics.AssetIndex {
	asset := g.MinAssetIndex
	for i := 0; i <= int(ai); i++ {
		asset += g.groupData.AssetOffsets[i]
	}
	return asset
}

// AssetAt returns asset value at postion ai
func (g *AssetsParamsGroup) AssetAt(ai int) basics.AssetIndex {
	asset := g.MinAssetIndex
	for i := 0; i <= int(ai); i++ {
		asset += g.groupData.AssetOffsets[i]
	}
	return asset
}

// GroupData returns interface to AbstractAssetGroupData for this group data
func (g *AssetsHoldingGroup) GroupData() AbstractAssetGroupData {
	return &g.groupData.AssetsCommonGroupData
}

// GroupData returns interface to AbstractAssetGroupData for this group data
func (g *AssetsParamsGroup) GroupData() AbstractAssetGroupData {
	return &g.groupData.AssetsCommonGroupData
}

// Reset clears this group
func (g *AssetsHoldingGroup) Reset() {
	*g = AssetsHoldingGroup{}
}

// Reset clears this group
func (g *AssetsParamsGroup) Reset() {
	*g = AssetsParamsGroup{}
}

// Update sets group data by asset index
func (g *AssetsHoldingGroup) Update(ai int, data interface{}) {
	g.update(ai, data.(basics.AssetHolding))
}

// Update sets group data by asset index
func (g *AssetsParamsGroup) Update(ai int, data interface{}) {
	g.update(ai, data.(basics.AssetParams))
}

// Fetch loads group data using fetcher and returns all holdings
func (g *AssetsHoldingGroup) Fetch(fetcher func(int64) ([]byte, basics.Round, error), assets interface{}) (basics.Round, error) {
	var holdings map[basics.AssetIndex]basics.AssetHolding
	if assets != nil {
		holdings = assets.(map[basics.AssetIndex]basics.AssetHolding)
	}

	buf, rnd, err := fetcher(g.AssetGroupKey)
	if err != nil {
		return 0, err
	}

	var groupData AssetsHoldingGroupData
	err = protocol.Decode(buf, &groupData)
	if err != nil {
		return 0, err
	}

	if holdings != nil {
		aidx := g.MinAssetIndex
		for i := 0; i < len(groupData.AssetOffsets); i++ {
			aidx += groupData.AssetOffsets[i]
			holdings[aidx] = groupData.GetHolding(i)
		}
	}
	g.Load(groupData)
	return rnd, nil
}

// Fetch loads group data into  using fetcher
func (g *AssetsParamsGroup) Fetch(fetcher func(int64) ([]byte, basics.Round, error), assets interface{}) (basics.Round, error) {
	var params map[basics.AssetIndex]basics.AssetParams
	if assets != nil {
		params = assets.(map[basics.AssetIndex]basics.AssetParams)
	}

	buf, rnd, err := fetcher(g.AssetGroupKey)
	if err != nil {
		return 0, err
	}

	var groupData AssetsParamsGroupData
	err = protocol.Decode(buf, &groupData)
	if err != nil {
		return 0, err
	}

	if params != nil {
		aidx := g.MinAssetIndex
		for i := 0; i < len(groupData.AssetOffsets); i++ {
			aidx += groupData.AssetOffsets[i]
			params[aidx] = groupData.GetParams(i)
		}
	}
	g.Load(groupData)
	return rnd, nil
}

type assetDataGetter interface {
	get(aidx basics.AssetIndex) interface{}
}

type assetHoldingGetter struct {
	assets map[basics.AssetIndex]basics.AssetHolding
}

func (g assetHoldingGetter) get(aidx basics.AssetIndex) interface{} {
	return g.assets[aidx]
}

type assetParamsGetter struct {
	assets map[basics.AssetIndex]basics.AssetParams
}

func (g assetParamsGetter) get(aidx basics.AssetIndex) interface{} {
	return g.assets[aidx]
}

// Update an asset holding by asset index
func (e *ExtendedAssetHolding) Update(updated []basics.AssetIndex, assets map[basics.AssetIndex]basics.AssetHolding) error {
	g := assetHoldingGetter{assets}
	return update(updated, e, &g)
}

// Update an asset params by index
func (e *ExtendedAssetParams) Update(updated []basics.AssetIndex, assets map[basics.AssetIndex]basics.AssetParams) error {
	g := assetParamsGetter{assets}
	return update(updated, e, &g)
}

func update(updated []basics.AssetIndex, agl AbstractAssetGroupList, assets assetDataGetter) error {
	sort.SliceStable(updated, func(i, j int) bool { return updated[i] < updated[j] })
	gi, ai := 0, 0
	for _, aidx := range updated {
		gi, ai = findAsset(aidx, gi, agl)
		if gi == -1 || ai == -1 {
			return fmt.Errorf("failed to find asset group for updating %d: (%d, %d)", aidx, gi, ai)
		}
		agl.Get(gi).Update(ai, assets.get(aidx))
	}
	return nil
}

func deleteAssets(assets []basics.AssetIndex, agl AbstractAssetGroupList) (deleted []int64, err error) {
	// TODO: possible optimizations:
	// 1. pad.NumAssetHoldings() == len(deleted)
	// 2. deletion of entire group
	sort.SliceStable(assets, func(i, j int) bool { return assets[i] < assets[j] })
	gi, ai := 0, 0
	for _, aidx := range assets {
		gi, ai = findAsset(aidx, gi, agl)
		if gi == -1 || ai == -1 {
			err = fmt.Errorf("failed to find asset group for deleting %d: (%d, %d)", aidx, gi, ai)
			return
		}
		// group data is loaded in accountsLoadOld
		ag := agl.Get(gi)
		if ag.AssetCount() == 1 {
			key := ag.Key()
			agl.ReleaseGroup(gi)
			deleted = append(deleted, key)
		} else {
			agl.deleteByIndex(gi, ai)
		}
	}
	return
}

// Delete asset holdings identified by asset indexes in assets list
// Function returns list of group keys that needs to be removed from DB
func (e *ExtendedAssetHolding) Delete(assets []basics.AssetIndex) (deleted []int64, err error) {
	return deleteAssets(assets, e)
}

// Delete asset holdings identified by asset indexes in assets list
// Function returns list of group keys that needs to be removed from DB
func (e *ExtendedAssetParams) Delete(assets []basics.AssetIndex) (deleted []int64, err error) {
	return deleteAssets(assets, e)
}

func (e *ExtendedAssetHolding) dropGroup(gi int) {
	if gi < len(e.Groups)-1 {
		copy(e.Groups[gi:], e.Groups[gi+1:])
	}
	e.Groups[len(e.Groups)-1] = AssetsHoldingGroup{} // release AssetsHoldingGroup data
	e.Groups = e.Groups[:len(e.Groups)-1]
}

func (e *ExtendedAssetParams) dropGroup(gi int) {
	if gi < len(e.Groups)-1 {
		copy(e.Groups[gi:], e.Groups[gi+1:])
	}
	e.Groups[len(e.Groups)-1] = AssetsParamsGroup{} // release AssetsHoldingGroup data
	e.Groups = e.Groups[:len(e.Groups)-1]
}

// ReleaseGroup removes all assets in group gi and the group itself
func (e *ExtendedAssetHolding) ReleaseGroup(gi int) {
	count := e.Groups[gi].AssetCount()
	e.dropGroup(gi)
	e.Count -= count
}

// ReleaseGroup removes all assets in group gi and the group itself
func (e *ExtendedAssetParams) ReleaseGroup(gi int) {
	count := e.Groups[gi].AssetCount()
	e.dropGroup(gi)
	e.Count -= count
}

func (e *ExtendedAssetHolding) deleteByIndex(gi int, ai int) {
	e.Groups[gi].Delete(ai, &e.Groups[gi])
	e.Count--
}

func (e *ExtendedAssetParams) deleteByIndex(gi int, ai int) {
	e.Groups[gi].Delete(ai, &e.Groups[gi])
	e.Count--
}

// split Groups[i] in preparation to insertion of asset aidx.
// It returns group index where to insert.
func (e *ExtendedAssetHolding) split(gi int, aidx basics.AssetIndex) int {
	return split(gi, aidx, e)
}

func (e *ExtendedAssetParams) split(gi int, aidx basics.AssetIndex) int {
	return split(gi, aidx, e)
}

func split(gi int, aidx basics.AssetIndex, agl AbstractAssetGroupList) int {
	g := agl.Get(gi)
	pos := g.AssetCount() / 2
	asset := g.AssetAt(int(pos - 1))

	rgCount := g.AssetCount() - pos
	lgCount := pos
	rgMinAssetIndex := asset + g.GroupData().AssetDeltaValue(int(pos))
	lgMinAssetIndex := g.MinAsset()
	rgDeltaMaxIndex := g.MaxAsset() - rgMinAssetIndex
	lgDeltaMaxIndex := asset - g.MinAsset()

	rgCap := rgCount
	if aidx >= lgMinAssetIndex+lgDeltaMaxIndex {
		// if new asset goes into right group, reserve space
		rgCap++
	}

	// make a right group
	rightGroup := g.groupFromPosition(pos, rgCount, rgCap, rgMinAssetIndex, uint64(rgDeltaMaxIndex))

	// modify left group
	g.slice(lgCount, uint64(lgDeltaMaxIndex))

	// insert rightGroup after gi
	// slice reallocation may happen, so the left group needs to modifed before possible array reallocation in insertAfter
	agl.insertAfter(gi, rightGroup)

	if aidx < lgMinAssetIndex+lgDeltaMaxIndex {
		return gi
	}
	return gi + 1
}

func (g *AssetsHoldingGroup) slice(pos uint32, maxDelta uint64) {
	g.Count = pos
	g.DeltaMaxAssetIndex = maxDelta
	g.groupData = AssetsHoldingGroupData{
		Amounts: g.groupData.Amounts[:pos],
		Frozens: g.groupData.Frozens[:pos],
		AssetsCommonGroupData: AssetsCommonGroupData{
			AssetOffsets: g.groupData.AssetOffsets[:pos],
		},
	}
}

func (g *AssetsParamsGroup) slice(pos uint32, maxDelta uint64) {
	g.Count = pos
	g.DeltaMaxAssetIndex = maxDelta
	g.groupData = AssetsParamsGroupData{
		Totals:         g.groupData.Totals[:pos],
		Decimals:       g.groupData.Decimals[:pos],
		DefaultFrozens: g.groupData.DefaultFrozens[:pos],
		UnitNames:      g.groupData.UnitNames[:pos],
		AssetNames:     g.groupData.AssetNames[:pos],
		URLs:           g.groupData.URLs[:pos],
		MetadataHash:   g.groupData.MetadataHash[:pos],
		Managers:       g.groupData.Managers[:pos],
		Reserves:       g.groupData.Reserves[:pos],
		Freezes:        g.groupData.Freezes[:pos],
		Clawbacks:      g.groupData.Clawbacks[:pos],
		AssetsCommonGroupData: AssetsCommonGroupData{
			AssetOffsets: g.groupData.AssetOffsets[:pos],
		},
	}
}

// groupFromPosition creates a new group from the data at position [pos:]
func (g *AssetsHoldingGroup) sliceRight(pos uint32, delta basics.AssetIndex) {
	length := len(g.groupData.AssetOffsets)

	g.Count -= uint32(pos)
	g.groupData.AssetOffsets = g.groupData.AssetOffsets[pos:]
	delta += g.groupData.AssetOffsets[0]
	g.groupData.AssetOffsets[0] = 0

	g.groupData.slice(int(pos), length)
	g.MinAssetIndex += delta
	g.DeltaMaxAssetIndex -= uint64(delta)
}

// groupFromPosition creates a new group from the data at position [pos:]
func (g *AssetsParamsGroup) sliceRight(pos uint32, delta basics.AssetIndex) {
	length := len(g.groupData.AssetOffsets)

	g.Count -= uint32(pos)
	g.groupData.AssetOffsets = g.groupData.AssetOffsets[pos:]
	delta += g.groupData.AssetOffsets[0]
	g.groupData.AssetOffsets[0] = 0
	g.groupData.slice(int(pos), length)
	g.MinAssetIndex += delta
	g.DeltaMaxAssetIndex -= uint64(delta)
}

// groupFromPosition creates a new group from the data at position [pos:]
func (g *AssetsHoldingGroup) groupFromPosition(pos uint32, length, capacity uint32, minAssetIndex basics.AssetIndex, maxDelta uint64) interface{} {
	rgd := AssetsHoldingGroupData{
		Amounts:               make([]uint64, length, capacity),
		Frozens:               make([]bool, length, capacity),
		AssetsCommonGroupData: AssetsCommonGroupData{AssetOffsets: make([]basics.AssetIndex, length, capacity)},
	}
	copy(rgd.Amounts, g.groupData.Amounts[pos:])
	copy(rgd.Frozens, g.groupData.Frozens[pos:])
	copy(rgd.AssetOffsets, g.groupData.AssetOffsets[pos:])
	rightGroup := AssetsHoldingGroup{
		AssetGroupDesc: AssetGroupDesc{
			Count:              length,
			MinAssetIndex:      minAssetIndex,
			DeltaMaxAssetIndex: maxDelta,
		},
		groupData: rgd,
		loaded:    true,
	}
	rightGroup.groupData.AssetOffsets[0] = 0
	return rightGroup
}

func (g *AssetsParamsGroup) groupFromPosition(pos uint32, length, capacity uint32, minAssetIndex basics.AssetIndex, maxDelta uint64) interface{} {
	rgd := AssetsParamsGroupData{
		Totals:                make([]uint64, length, capacity),
		Decimals:              make([]uint32, length, capacity),
		DefaultFrozens:        make([]bool, length, capacity),
		UnitNames:             make([]string, length, capacity),
		AssetNames:            make([]string, length, capacity),
		URLs:                  make([]string, length, capacity),
		MetadataHash:          make([][32]byte, length, capacity),
		Managers:              make([]basics.Address, length, capacity),
		Reserves:              make([]basics.Address, length, capacity),
		Freezes:               make([]basics.Address, length, capacity),
		Clawbacks:             make([]basics.Address, length, capacity),
		AssetsCommonGroupData: AssetsCommonGroupData{AssetOffsets: make([]basics.AssetIndex, length, capacity)},
	}
	copy(rgd.Totals, g.groupData.Totals[pos:])
	copy(rgd.Decimals, g.groupData.Decimals[pos:])
	copy(rgd.DefaultFrozens, g.groupData.DefaultFrozens[pos:])
	copy(rgd.UnitNames, g.groupData.UnitNames[pos:])
	copy(rgd.AssetNames, g.groupData.AssetNames[pos:])
	copy(rgd.URLs, g.groupData.URLs[pos:])
	copy(rgd.MetadataHash, g.groupData.MetadataHash[pos:])
	copy(rgd.Managers, g.groupData.Managers[pos:])
	copy(rgd.Reserves, g.groupData.Reserves[pos:])
	copy(rgd.Freezes, g.groupData.Freezes[pos:])
	copy(rgd.Clawbacks, g.groupData.Clawbacks[pos:])
	copy(rgd.AssetOffsets, g.groupData.AssetOffsets[pos:])
	rightGroup := AssetsParamsGroup{
		AssetGroupDesc: AssetGroupDesc{
			Count:              length,
			MinAssetIndex:      minAssetIndex,
			DeltaMaxAssetIndex: maxDelta,
		},
		groupData: rgd,
		loaded:    true,
	}
	rightGroup.groupData.AssetOffsets[0] = 0
	return rightGroup
}

func makeAssetGroup(aidx basics.AssetIndex, data interface{}, b groupBuilder) interface{} {
	desc := AssetGroupDesc{
		Count:              1,
		MinAssetIndex:      aidx,
		DeltaMaxAssetIndex: 0,
		AssetGroupKey:      0,
	}
	return b.newGroup(1).newElement(0, data).build(desc)
}

func makeAssetHoldingGroup(aidx basics.AssetIndex, data interface{}) AssetsHoldingGroup {
	g := makeAssetGroup(aidx, data, &assetHoldingGroupBuilder{})
	return g.(AssetsHoldingGroup)
}

func makeAssetParamsGroup(aidx basics.AssetIndex, data interface{}) AssetsParamsGroup {
	g := makeAssetGroup(aidx, data, &assetParamsGroupBuilder{})
	return g.(AssetsParamsGroup)
}

func (e *ExtendedAssetHolding) prependNewGroup(aidx basics.AssetIndex, data interface{}) {
	g := makeAssetHoldingGroup(aidx, data)
	e.Groups = append([]AssetsHoldingGroup{g}, e.Groups...)
	e.Count++
}

func (e *ExtendedAssetHolding) appendNewGroup(aidx basics.AssetIndex, data interface{}) {
	g := makeAssetHoldingGroup(aidx, data)
	e.Groups = append(e.Groups, g)
	e.Count++
}

func (e *ExtendedAssetHolding) insertNewGroupAfter(gi int, aidx basics.AssetIndex, data interface{}) {
	g := makeAssetHoldingGroup(aidx, data)
	e.insertAfter(gi, g)
	e.Count++
}

// insertAfter adds a new group after idx (at newly allocated position idx+1)
func (e *ExtendedAssetHolding) insertAfter(gi int, group interface{}) {
	e.Groups = append(e.Groups, AssetsHoldingGroup{})
	copy(e.Groups[gi+1:], e.Groups[gi:])
	e.Groups[gi+1] = group.(AssetsHoldingGroup)
}

func (e *ExtendedAssetHolding) insertInto(idx int, aidx basics.AssetIndex, data interface{}) {
	e.Groups[idx].insert(aidx, data.(basics.AssetHolding))
	e.Count++
}

func (e *ExtendedAssetParams) prependNewGroup(aidx basics.AssetIndex, data interface{}) {
	g := makeAssetParamsGroup(aidx, data)
	e.Groups = append([]AssetsParamsGroup{g}, e.Groups...)
	e.Count++
}

func (e *ExtendedAssetParams) appendNewGroup(aidx basics.AssetIndex, data interface{}) {
	g := makeAssetParamsGroup(aidx, data)
	e.Groups = append(e.Groups, g)
	e.Count++
}

// insertAfter adds new group after idx (at newly allocated position idx+1)
func (e *ExtendedAssetParams) insertNewGroupAfter(gi int, aidx basics.AssetIndex, data interface{}) {
	g := makeAssetParamsGroup(aidx, data)
	e.insertAfter(gi, g)
	e.Count++
}

func (e *ExtendedAssetParams) insertAfter(gi int, group interface{}) {
	e.Groups = append(e.Groups, AssetsParamsGroup{})
	copy(e.Groups[gi+1:], e.Groups[gi:])
	e.Groups[gi+1] = group.(AssetsParamsGroup)
}

func (e *ExtendedAssetParams) insertInto(idx int, aidx basics.AssetIndex, data interface{}) {
	e.Groups[idx].insert(aidx, data.(basics.AssetParams))
	e.Count++
}

// Insert takes an array of asset holdings into ExtendedAssetHolding.
// The input sequence must be sorted.
func (e *ExtendedAssetHolding) Insert(input []basics.AssetIndex, data map[basics.AssetIndex]basics.AssetHolding) {
	flatten := make([]flattenAsset, len(input), len(input))
	for i, aidx := range input {
		flatten[i] = flattenAsset{aidx, data[aidx]}
	}
	sort.SliceStable(flatten, func(i, j int) bool { return flatten[i].aidx < flatten[j].aidx })
	insert(flatten, e)
}

// Insert takes an array of asset params into ExtendedAssetParams.
// The input sequence must be sorted.
func (e *ExtendedAssetParams) Insert(input []basics.AssetIndex, data map[basics.AssetIndex]basics.AssetParams) {
	flatten := make([]flattenAsset, len(input), len(input))
	for i, aidx := range input {
		flatten[i] = flattenAsset{aidx, data[aidx]}
	}
	sort.SliceStable(flatten, func(i, j int) bool { return flatten[i].aidx < flatten[j].aidx })
	insert(flatten, e)
}

func insert(assets []flattenAsset, agl AbstractAssetGroupList) {
	gi := 0
	for _, asset := range assets {
		result := findGroup(asset.aidx, gi, agl)
		if result.found {
			if result.split {
				pos := agl.split(result.gi, asset.aidx)
				agl.insertInto(pos, asset.aidx, asset.data)
			} else {
				agl.insertInto(result.gi, asset.aidx, asset.data)
			}
			gi = result.gi // advance group search offset (input is ordered, it is safe to search from the last match)
		} else {
			insertAfter := result.gi
			if insertAfter == -1 {
				agl.prependNewGroup(asset.aidx, asset.data)
			} else if insertAfter == agl.Len()-1 {
				agl.appendNewGroup(asset.aidx, asset.data)
			} else {
				agl.insertNewGroupAfter(result.gi, asset.aidx, asset.data)
			}
			gi = result.gi + 1
		}
	}
	return
}

// fgres structure describes result value of findGroup function
//
// +-------+-----------------------------+-------------------------------+
// | found | gi                          | split                         |
// |-------|-----------------------------|-------------------------------|
// | true  | target group index          | split the target group or not |
// | false | group index to insert after | not used                      |
// +-------+-----------------------------+-------------------------------+
type fgres struct {
	found bool
	gi    int
	split bool
}

// findGroup looks up for an appropriate group or position for insertion a new asset holding entry
// Examples:
//   groups of size 4
//   [2, 3, 5], [7, 10, 12, 15]
//   aidx = 0 -> group 0
//   aidx = 4 -> group 0
//   aidx = 6 -> group 0
//   aidx = 8 -> group 1 split
//   aidx = 16 -> new group after 1
//
//   groups of size 4
//   [1, 2, 3, 5], [7, 10, 15]
//   aidx = 0 -> new group after -1
//   aidx = 4 -> group 0 split
//   aidx = 6 -> group 1
//   aidx = 16 -> group 1
//
//   groups of size 4
//   [1, 2, 3, 5], [7, 10, 12, 15]
//   aidx = 6 -> new group after 0

// func (e ExtendedAssetHolding) findGroup(aidx basics.AssetIndex, startIdx int) fgres {
func findGroup(aidx basics.AssetIndex, startIdx int, agl AbstractAssetGroupList) fgres {
	if agl.Total() == 0 {
		return fgres{false, -1, false}
	}
	for i := startIdx; i < agl.Len(); i++ {
		g := agl.Get(i)
		// check exact boundaries
		if aidx >= g.MinAsset() && aidx <= g.MaxAsset() {
			// found a group that is a right place for the asset
			// if it has space, insert into it
			if g.HasSpace() {
				return fgres{found: true, gi: i, split: false}
			}
			// otherwise split into two groups
			return fgres{found: true, gi: i, split: true}
		}
		// check upper bound
		if aidx >= g.MinAsset() && aidx > g.MaxAsset() {
			// the asset still might fit into a group if it has space and does not break groups order
			if g.HasSpace() {
				// ensure next group starts with the asset greater than current one
				if i < agl.Len()-1 && aidx < agl.Get(i+1).MinAsset() {
					return fgres{found: true, gi: i, split: false}
				}
				// the last group, ok to add more
				if i == agl.Len()-1 {
					return fgres{found: true, gi: i, split: false}
				}
			}
		}

		// check bottom bound
		if aidx < g.MinAsset() {
			// found a group that is a right place for the asset
			// if it has space, insert into it
			if g.HasSpace() {
				return fgres{found: true, gi: i, split: false}
			}
			// otherwise insert group before the current one
			return fgres{found: false, gi: i - 1, split: false}
		}
	}

	// no matching groups then add a new group at the end
	return fgres{found: false, gi: agl.Len() - 1, split: false}
}

// FindGroup returns a group suitable for asset insertion
func (e ExtendedAssetHolding) FindGroup(aidx basics.AssetIndex, startIdx int) int {
	res := findGroup(aidx, startIdx, &e)
	if res.found {
		return res.gi
	}
	return -1
}

// FindAsset returns group index and asset index if found and (-1, -1) otherwise.
// If a matching group found but the group is not loaded yet, it returns (groupIdx, -1)
func (e ExtendedAssetHolding) FindAsset(aidx basics.AssetIndex, startIdx int) (int, int) {
	return findAsset(aidx, startIdx, &e)
}

// FindGroup returns a group suitable for asset insertion
func (e ExtendedAssetParams) FindGroup(aidx basics.AssetIndex, startIdx int) int {
	res := findGroup(aidx, startIdx, &e)
	if res.found {
		return res.gi
	}
	return -1
}

// FindAsset returns group index and asset index if found and (-1, -1) otherwise.
// If a matching group found but the group is not loaded yet, it returns (groupIdx, -1)
func (e ExtendedAssetParams) FindAsset(aidx basics.AssetIndex, startIdx int) (int, int) {
	return findAsset(aidx, startIdx, &e)
}

// findAsset returns group index and asset index if found and (-1, -1) otherwise.
// If a matching group found but the group is not loaded yet, it returns (groupIdx, -1).
// It is suitable for searchin within AbstractAssetGroupList that is either holding or params types.
func findAsset(aidx basics.AssetIndex, startIdx int, agl AbstractAssetGroupList) (int, int) {
	const notFound int = -1

	if agl.Total() == 0 {
		return notFound, notFound
	}

	// TODO: binary search
	for i := startIdx; i < agl.Len(); i++ {
		g := agl.Get(i)
		if aidx >= g.MinAsset() && aidx <= g.MaxAsset() {
			if !g.Loaded() {
				// groupData not loaded, but the group boundaries match
				// return group match and -1 as asset index indicating loading is need
				return i, notFound
			}

			if ai := g.GroupData().Find(aidx, g.MinAsset()); ai != -1 {
				return i, ai
			}

			// the group is loaded and the asset not found
			return notFound, notFound
		}
	}
	return notFound, notFound
}

type assetHoldingGroupBuilder struct {
	gd  AssetsHoldingGroupData
	idx int
}

func (b *assetHoldingGroupBuilder) newGroup(size int) groupBuilder {
	b.gd = AssetsHoldingGroupData{
		AssetsCommonGroupData: AssetsCommonGroupData{AssetOffsets: make([]basics.AssetIndex, size, size)},
		Amounts:               make([]uint64, size, size),
		Frozens:               make([]bool, size, size),
	}
	b.idx = 0
	return b
}

func (b *assetHoldingGroupBuilder) build(desc AssetGroupDesc) interface{} {
	defer func() {
		b.gd = AssetsHoldingGroupData{}
		b.idx = 0
	}()

	return AssetsHoldingGroup{
		AssetGroupDesc: desc,
		groupData:      b.gd,
		loaded:         true,
	}
}

func (b *assetHoldingGroupBuilder) newElement(offset basics.AssetIndex, data interface{}) groupBuilder {
	b.gd.AssetOffsets[b.idx] = offset
	holding := data.(basics.AssetHolding)
	b.gd.Amounts[b.idx] = holding.Amount
	b.gd.Frozens[b.idx] = holding.Frozen
	b.idx++
	return b
}

type assetParamsGroupBuilder struct {
	gd  AssetsParamsGroupData
	idx int
}

func (b *assetParamsGroupBuilder) newGroup(size int) groupBuilder {
	b.gd = AssetsParamsGroupData{
		AssetsCommonGroupData: AssetsCommonGroupData{AssetOffsets: make([]basics.AssetIndex, size, size)},
		Totals:                make([]uint64, size, size),
		Decimals:              make([]uint32, size, size),
		DefaultFrozens:        make([]bool, size, size),
		UnitNames:             make([]string, size, size),
		AssetNames:            make([]string, size, size),
		URLs:                  make([]string, size, size),
		MetadataHash:          make([][32]byte, size, size),
		Managers:              make([]basics.Address, size, size),
		Reserves:              make([]basics.Address, size, size),
		Freezes:               make([]basics.Address, size, size),
		Clawbacks:             make([]basics.Address, size, size),
	}
	b.idx = 0
	return b
}

func (b *assetParamsGroupBuilder) build(desc AssetGroupDesc) interface{} {
	defer func() {
		b.gd = AssetsParamsGroupData{}
		b.idx = 0
	}()

	return AssetsParamsGroup{
		AssetGroupDesc: desc,
		groupData:      b.gd,
		loaded:         true,
	}
}

func (b *assetParamsGroupBuilder) newElement(offset basics.AssetIndex, data interface{}) groupBuilder {
	b.gd.AssetOffsets[b.idx] = offset
	params := data.(basics.AssetParams)
	b.gd.Totals[b.idx] = params.Total
	b.gd.Decimals[b.idx] = params.Decimals
	b.gd.DefaultFrozens[b.idx] = params.DefaultFrozen
	b.gd.UnitNames[b.idx] = params.UnitName
	b.gd.AssetNames[b.idx] = params.AssetName
	b.gd.URLs[b.idx] = params.URL

	copy(b.gd.MetadataHash[b.idx][:], params.MetadataHash[:])
	copy(b.gd.Managers[b.idx][:], params.Manager[:])
	copy(b.gd.Reserves[b.idx][:], params.Reserve[:])
	copy(b.gd.Freezes[b.idx][:], params.Freeze[:])
	copy(b.gd.Clawbacks[b.idx][:], params.Clawback[:])
	b.idx++

	return b
}

type assetFlattener struct {
	assets []flattenAsset
}

type flattenAsset struct {
	aidx basics.AssetIndex
	data interface{}
}

func newAssetHoldingFlattener(assets map[basics.AssetIndex]basics.AssetHolding) *assetFlattener {
	flatten := make([]flattenAsset, len(assets), len(assets))
	i := 0
	for k, v := range assets {
		flatten[i] = flattenAsset{k, v}
		i++
	}
	sort.SliceStable(flatten, func(i, j int) bool { return flatten[i].aidx < flatten[j].aidx })
	return &assetFlattener{flatten}
}

func newAssetParamsFlattener(assets map[basics.AssetIndex]basics.AssetParams) *assetFlattener {
	flatten := make([]flattenAsset, len(assets), len(assets))
	i := 0
	for k, v := range assets {
		flatten[i] = flattenAsset{k, v}
		i++
	}
	sort.SliceStable(flatten, func(i, j int) bool { return flatten[i].aidx < flatten[j].aidx })
	return &assetFlattener{flatten}
}

func (f *assetFlattener) Count() uint32 {
	return uint32(len(f.assets))
}

func (f *assetFlattener) AssetIndex(idx int) basics.AssetIndex {
	return f.assets[idx].aidx
}

func (f *assetFlattener) Data(idx int) interface{} {
	return f.assets[idx].data
}

// ConvertToGroups converts map of basics.AssetHolding to asset holding groups
func (e *ExtendedAssetHolding) ConvertToGroups(assets map[basics.AssetIndex]basics.AssetHolding) {
	if len(assets) == 0 {
		return
	}
	b := assetHoldingGroupBuilder{}
	flt := newAssetHoldingFlattener(assets)
	convertToGroups(e, flt, &b, MaxHoldingGroupSize)
}

// ConvertToGroups converts map of basics.AssetHolding to asset params groups
func (e *ExtendedAssetParams) ConvertToGroups(assets map[basics.AssetIndex]basics.AssetParams) {
	if len(assets) == 0 {
		return
	}
	b := assetParamsGroupBuilder{}
	flt := newAssetParamsFlattener(assets)
	convertToGroups(e, flt, &b, MaxParamsGroupSize)
}

// convertToGroups converts data from Flattener into groups produced by GroupBuilder and assigns into AbstractAssetGroupList
func convertToGroups(agl AbstractAssetGroupList, flt flattener, builder groupBuilder, maxGroupSize int) {
	min := func(a, b int) int {
		if a < b {
			return a
		}
		return b
	}

	numGroups := (int(flt.Count()) + maxGroupSize - 1) / maxGroupSize
	agl.Reset(flt.Count(), numGroups)

	for i := 0; i < numGroups; i++ {
		start := i * maxGroupSize
		end := min((i+1)*maxGroupSize, int(flt.Count()))
		size := end - start
		builder.newGroup(size)

		first := flt.AssetIndex(start)
		prev := first
		for j, di := start, 0; j < end; j, di = j+1, di+1 {
			offset := flt.AssetIndex(j) - prev
			builder.newElement(offset, flt.Data(j))
			prev = flt.AssetIndex(j)
		}

		desc := AssetGroupDesc{
			Count:              uint32(size),
			MinAssetIndex:      first,
			DeltaMaxAssetIndex: uint64(prev - first),
		}
		agl.Assign(i, builder.build(desc))
	}
}

// continuosRange describes range of groups that can be merged
type continuosRange struct {
	start int // group start index
	size  int // number of groups
	count int // total holdings
}

func findLoadedSiblings(agl AbstractAssetGroupList) (loaded []int, crs []continuosRange) {
	// find candidates for merging
	loaded = make([]int, 0, agl.Len())
	for i := 0; i < agl.Len(); i++ {
		g := agl.Get(i)
		if !g.Loaded() {
			continue
		}
		if len(loaded) > 0 && loaded[len(loaded)-1] == i-1 {
			// found continuos range
			exists := false
			if len(crs) != 0 {
				last := &crs[len(crs)-1]
				if last.start+last.size == i {
					last.size++
					last.count += int(g.AssetCount())
					exists = true
				}
			}
			if !exists {
				pg := agl.Get(i - 1)
				count := int(pg.AssetCount() + g.AssetCount())
				crs = append(crs, continuosRange{i - 1, 2, count})
			}
		}
		loaded = append(loaded, i)
	}
	if len(loaded) == 0 {
		return nil, nil
	}

	return
}

// mergeInternal merges groups [start, start+size) and returns keys of deleted group data entries
func mergeInternal(agl AbstractAssetGroupList, start int, size int, hint int, assetThreshold uint32) (deleted []int64) {
	deleted = make([]int64, 0, hint)
	// process i and i + 1 groups at once => size-1 iterations
	i := 0
	for i < size-1 {
		li := start + i     // left group index, destination
		ri := start + i + 1 // right group index, source
		lg := agl.Get(li)
		rg := agl.Get(ri)

		num := assetThreshold - lg.AssetCount()
		if num == 0 { // group is full, skip
			i++
			continue
		}
		if num > rg.AssetCount() { // source group is shorter than dest capacity, adjust
			num = rg.AssetCount()
		}

		delta := lg.mergeIn(rg, num)
		if num != rg.AssetCount() {
			// src group survived, update it and repeat
			rg.sliceRight(num, delta)
			i++
		} else {
			// entire src group gone: save the key and delete from Groups
			deleted = append(deleted, rg.Key())
			agl.dropGroup(ri)
			// restart merging with the same index but decrease size
			size--
		}
	}
	return
}

// Merge attempts to re-merge loaded groups by squashing small loaded sibling groups together
// Returns:
// - loaded list group indices that are loaded and needs to flushed
// - deleted list of group data keys that needs to be deleted
func (e *ExtendedAssetHolding) Merge() (loaded []int, deleted []int64) {
	return merge(e, MaxHoldingGroupSize)
}

// Merge attempts to re-merge loaded groups by squashing small loaded sibling groups together
// Returns:
// - loaded list group indices that are loaded and needs to flushed
// - deleted list of group data keys that needs to be deleted
func (e *ExtendedAssetParams) Merge() (loaded []int, deleted []int64) {
	return merge(e, MaxParamsGroupSize)
}

func merge(agl AbstractAssetGroupList, assetThreshold uint32) (loaded []int, deleted []int64) {
	loaded, crs := findLoadedSiblings(agl)
	if len(crs) == 0 {
		return
	}

	someGroupDeleted := false
	offset := 0 // difference in group indexes that happens after deletion some groups from e.Groups array
	for _, cr := range crs {
		minGroupsRequired := (cr.count + int(assetThreshold) - 1) / int(assetThreshold)
		if minGroupsRequired == cr.size {
			// no gain in merging, skip
			continue
		}
		del := mergeInternal(agl, cr.start-offset, cr.size, cr.size-minGroupsRequired, assetThreshold)
		offset += len(del)
		for _, key := range del {
			someGroupDeleted = true
			if key != 0 { // 0 key means a new group that exist only in memory
				deleted = append(deleted, key)
			}
		}
	}

	if someGroupDeleted {
		// rebuild loaded list since indices changed after merging
		loaded = make([]int, 0, len(loaded)-len(deleted))
		for i := 0; i < agl.Len(); i++ {
			g := agl.Get(i)
			if g.Loaded() {
				loaded = append(loaded, i)
			}
		}
	}
	return
}

// Get returns AbstractAssetGroup interface by group index
func (e *ExtendedAssetHolding) Get(gi int) AbstractAssetGroup {
	return &(e.Groups[gi])
}

// Len returns number of groups
func (e *ExtendedAssetHolding) Len() int {
	return len(e.Groups)
}

// Total returns number or assets
func (e *ExtendedAssetHolding) Total() uint32 {
	return e.Count
}

// Reset sets count to a new value and re-allocates groups
func (e *ExtendedAssetHolding) Reset(count uint32, length int) {
	e.Count = count
	e.Groups = make([]AssetsHoldingGroup, length)
}

// Assign sets group at group index position
func (e *ExtendedAssetHolding) Assign(gi int, group interface{}) {
	e.Groups[gi] = group.(AssetsHoldingGroup)
}

// Get returns AbstractAssetGroup interface by group index
func (e *ExtendedAssetParams) Get(gi int) AbstractAssetGroup {
	return &(e.Groups[gi])
}

// Len returns number of groups
func (e *ExtendedAssetParams) Len() int {
	return len(e.Groups)
}

// Total returns number or assets
func (e *ExtendedAssetParams) Total() uint32 {
	return e.Count
}

// Reset sets count to a new value and re-allocates groups
func (e *ExtendedAssetParams) Reset(count uint32, length int) {
	e.Count = count
	e.Groups = make([]AssetsParamsGroup, length)
}

// Assign sets group at group index position
func (e *ExtendedAssetParams) Assign(gi int, group interface{}) {
	e.Groups[gi] = group.(AssetsParamsGroup)
}

// TestGetGroupData returns group data. Used in tests only
func (g AssetsHoldingGroup) TestGetGroupData() AssetsHoldingGroupData {
	return g.groupData
}

// TestGetGroupData returns group data. Used in tests only
func (g AssetsParamsGroup) TestGetGroupData() AssetsParamsGroupData {
	return g.groupData
}

// TestClearGroupData removes all the groups, used in tests only
func (e *ExtendedAssetHolding) TestClearGroupData() {
	for i := 0; i < len(e.Groups); i++ {
		// ignored on serialization
		e.Groups[i].groupData = AssetsHoldingGroupData{}
		e.Groups[i].loaded = false
	}
}
