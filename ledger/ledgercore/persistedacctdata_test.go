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
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
)

func TestAssetHoldingConvertToGroups(t *testing.T) {
	a := require.New(t)

	var e ExtendedAssetHolding

	e.ConvertToGroups(nil)
	a.Equal(uint32(0), e.Count)
	a.Equal(0, len(e.Groups))

	e.ConvertToGroups(map[basics.AssetIndex]basics.AssetHolding{})
	a.Equal(uint32(0), e.Count)
	a.Equal(0, len(e.Groups))

	var tests = []struct {
		size        int
		numGroups   int
		minAssets   []basics.AssetIndex
		deltaAssets []uint64
	}{
		{10, 1, []basics.AssetIndex{1}, []uint64{9}},
		{255, 1, []basics.AssetIndex{1}, []uint64{254}},
		{256, 1, []basics.AssetIndex{1}, []uint64{255}},
		{257, 2, []basics.AssetIndex{1, 257}, []uint64{255, 0}},
		{1024, 4, []basics.AssetIndex{1, 257, 513, 769}, []uint64{255, 255, 255, 255}},
		{1028, 5, []basics.AssetIndex{1, 257, 513, 769, 1025}, []uint64{255, 255, 255, 255, 3}},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%d-assets-convert", test.size), func(t *testing.T) {
			a := require.New(t)
			assets := make(map[basics.AssetIndex]basics.AssetHolding, test.size)
			for i := 0; i < test.size; i++ {
				assets[basics.AssetIndex(i+1)] = basics.AssetHolding{Amount: uint64(i), Frozen: i%2 != 0}
			}

			var e ExtendedAssetHolding
			e.ConvertToGroups(assets)
			a.Equal(uint32(test.size), e.Count)
			a.Equal(test.numGroups, len(e.Groups))
			total := 0
			for i := 0; i < len(e.Groups); i++ {
				total += int(e.Groups[i].Count)
				a.Equal(test.minAssets[i], e.Groups[i].MinAssetIndex)
				a.Equal(test.deltaAssets[i], e.Groups[i].DeltaMaxAssetIndex)
				a.Equal(int64(0), e.Groups[i].AssetGroupKey)
				a.True(e.Groups[i].loaded)

				a.Equal(int(e.Groups[i].Count), len(e.Groups[i].groupData.Amounts))
				a.Equal(len(e.Groups[i].groupData.Amounts), len(e.Groups[i].groupData.Frozens))
				a.Equal(len(e.Groups[i].groupData.Amounts), len(e.Groups[i].groupData.AssetOffsets))
				aidx := e.Groups[i].MinAssetIndex
				a.Equal(0, int(e.Groups[i].groupData.AssetOffsets[0]))
				for j := 0; j < len(e.Groups[i].groupData.AssetOffsets); j++ {
					aidx += e.Groups[i].groupData.AssetOffsets[j]
					a.Contains(assets, aidx)
					a.Equal(uint64(aidx)-1, e.Groups[i].groupData.Amounts[j])
				}
				a.Equal(e.Groups[i].MinAssetIndex+basics.AssetIndex(e.Groups[i].DeltaMaxAssetIndex), aidx)
			}
			a.Equal(int(e.Count), total)
		})
	}
}

func TestAssetHoldingFindAsset(t *testing.T) {
	a := require.New(t)

	var e ExtendedAssetHolding
	for aidx := 0; aidx < 2; aidx++ {
		for startIdx := 0; startIdx < 2; startIdx++ {
			gi, ai := e.FindAsset(basics.AssetIndex(aidx), startIdx)
			a.Equal(-1, gi)
			a.Equal(-1, ai)
		}
	}

	var tests = []struct {
		size      int
		numGroups int
		samples   []basics.AssetIndex
		groups    []int
		assets    []int
	}{
		{8, 1, []basics.AssetIndex{1, 5, 10, 12}, []int{0, 0, -1, -1}, []int{0, 4, -1, -1}},
		{10, 1, []basics.AssetIndex{1, 5, 10, 12}, []int{0, 0, 0, -1}, []int{0, 4, 9, -1}},
		{255, 1, []basics.AssetIndex{1, 255, 256, 257, 258}, []int{0, 0, -1, -1, -1}, []int{0, 254, -1, -1, -1}},
		{256, 1, []basics.AssetIndex{1, 255, 256, 257, 258}, []int{0, 0, 0, -1, -1}, []int{0, 254, 255, -1, -1}},
		{257, 2, []basics.AssetIndex{1, 255, 256, 257, 258}, []int{0, 0, 0, 1, -1}, []int{0, 254, 255, 0, -1}},
		{1024, 4, []basics.AssetIndex{1, 255, 1024, 1025}, []int{0, 0, 3, -1}, []int{0, 254, 255, -1}},
		{1028, 5, []basics.AssetIndex{1, 255, 1024, 1025}, []int{0, 0, 3, 4}, []int{0, 254, 255, 0}},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%d-find-asset", test.size), func(t *testing.T) {
			a := require.New(t)
			assets := make(map[basics.AssetIndex]basics.AssetHolding, test.size)
			for i := 0; i < test.size; i++ {
				assets[basics.AssetIndex(i+1)] = basics.AssetHolding{Amount: uint64(i), Frozen: i%2 != 0}
			}

			var e ExtendedAssetHolding
			e.ConvertToGroups(assets)

			for i := 0; i < len(test.samples); i++ {
				gi, ai := e.FindAsset(test.samples[i], 0)
				a.Equal(test.groups[i], gi)
				a.Equal(test.assets[i], ai)
			}

			goodIdx := 0
			for i := 0; i < len(test.samples); i++ {
				gi, ai := e.FindAsset(test.samples[i], goodIdx)
				expgi := test.groups[i]
				expai := test.assets[i]
				a.Equal(expgi, gi)
				a.Equal(expai, ai)
				if gi > 0 {
					goodIdx = gi
				}
			}
			if test.numGroups > 1 {
				a.Greater(goodIdx, 0)
			}
		})
	}
}

type groupSpec struct {
	start basics.AssetIndex
	end   basics.AssetIndex
	count int
}

func assetHoldingTestGroupMaker(desc AssetGroupDesc, ao []basics.AssetIndex, am []uint64) interface{} {
	g := AssetsHoldingGroup{
		AssetGroupDesc: desc,
		groupData: AssetsHoldingGroupData{
			AssetsCommonGroupData: AssetsCommonGroupData{AssetOffsets: ao},
			Amounts:               am,
			Frozens:               make([]bool, len(ao)),
		},
		loaded: true,
	}
	return g
}

func assetParamsTestGroupMaker(desc AssetGroupDesc, ao []basics.AssetIndex, am []uint64) interface{} {
	assetNames := make([]string, len(ao))
	for i, total := range am {
		assetNames[i] = fmt.Sprintf("a%d", total)
	}
	g := AssetsParamsGroup{
		AssetGroupDesc: desc,
		groupData: AssetsParamsGroupData{
			AssetsCommonGroupData: AssetsCommonGroupData{AssetOffsets: ao},
			Totals:                am,
			Decimals:              make([]uint32, len(ao)),
			DefaultFrozens:        make([]bool, len(ao)),
			UnitNames:             make([]string, len(ao)),
			AssetNames:            assetNames,
			URLs:                  make([]string, len(ao)),
			MetadataHash:          make([][32]byte, len(ao)),
			Managers:              make([]basics.Address, len(ao)),
			Reserves:              make([]basics.Address, len(ao)),
			Freezes:               make([]basics.Address, len(ao)),
			Clawbacks:             make([]basics.Address, len(ao)),
		},
		loaded: true,
	}
	return g
}

func genExtendedHolding(t testing.TB, spec []groupSpec) (e ExtendedAssetHolding) {
	e.Groups = make([]AssetsHoldingGroup, len(spec))
	count := genExtendedAsset(spec, &e, assetHoldingTestGroupMaker)
	e.Count = count

	a := require.New(t)
	for _, s := range spec {
		gi, ai := e.FindAsset(s.start, 0)
		a.NotEqual(-1, gi)
		a.NotEqual(-1, ai)
		a.Equal(uint64(s.start), e.Groups[gi].groupData.Amounts[ai])
		gi, ai = e.FindAsset(s.end, 0)
		a.NotEqual(-1, gi)
		a.NotEqual(-1, ai)
		a.Equal(uint64(s.end), e.Groups[gi].groupData.Amounts[ai])
	}

	return e
}

func genExtendedParams(t testing.TB, spec []groupSpec) (e ExtendedAssetParams) {
	e.Groups = make([]AssetsParamsGroup, len(spec))
	count := genExtendedAsset(spec, &e, assetParamsTestGroupMaker)
	e.Count = count

	a := require.New(t)
	for _, s := range spec {
		gi, ai := e.FindAsset(s.start, 0)
		a.NotEqual(-1, gi)
		a.NotEqual(-1, ai)
		a.Equal(uint64(s.start), e.Groups[gi].groupData.Totals[ai])
		a.Equal(fmt.Sprintf("a%d", e.Groups[gi].groupData.Totals[ai]), e.Groups[gi].groupData.AssetNames[ai])
		gi, ai = e.FindAsset(s.end, 0)
		a.NotEqual(-1, gi)
		a.NotEqual(-1, ai)
		a.Equal(uint64(s.end), e.Groups[gi].groupData.Totals[ai])
	}

	return e
}

func genExtendedAsset(spec []groupSpec, agl AbstractAssetGroupList, maker func(AssetGroupDesc, []basics.AssetIndex, []uint64) interface{}) (count uint32) {
	for i, s := range spec {
		desc := AssetGroupDesc{
			Count:              uint32(s.count),
			MinAssetIndex:      s.start,
			DeltaMaxAssetIndex: uint64(s.end - s.start),
		}
		ao := make([]basics.AssetIndex, s.count)
		am := make([]uint64, s.count)
		ao[0] = 0
		am[0] = uint64(s.start)
		gap := (s.end + 1 - s.start) / basics.AssetIndex(s.count)
		aidx := s.start
		for j := 1; j < s.count; j++ {
			ao[j] = gap
			aidx += gap
			am[j] = uint64(aidx)
		}
		if aidx != s.end {
			ao[s.count-1] = s.end - aidx + gap
			am[s.count-1] = uint64(s.end)
		}
		group := maker(desc, ao, am)
		agl.Assign(i, group)
		count += uint32(s.count)
	}
	return count
}

// test for AssetsHoldingGroup.insert
func TestAssetHoldingGroupInsert(t *testing.T) {
	a := require.New(t)

	spec := []groupSpec{
		{1001, 1060, 20},
	}

	e := genExtendedHolding(t, spec)
	e2 := genExtendedParams(t, spec)
	oldCount := e.Count
	oldDeltaMaxAssetIndex := e.Groups[0].DeltaMaxAssetIndex
	oldAssetOffsets := make([]basics.AssetIndex, spec[0].count)
	oldAssets := make(map[basics.AssetIndex]basics.AssetHolding, spec[0].count)
	aidx := e.Groups[0].MinAssetIndex
	for i := 0; i < spec[0].count; i++ {
		oldAssetOffsets[i] = e.Groups[0].groupData.AssetOffsets[i]
		aidx += e.Groups[0].groupData.AssetOffsets[i]
		oldAssets[aidx] = basics.AssetHolding{}
	}
	a.Equal(int(oldCount), len(oldAssets))
	a.Contains(oldAssets, spec[0].start)
	a.Contains(oldAssets, spec[0].end)

	checkAssetMap := func(newAsset basics.AssetIndex, g AssetsHoldingGroup) {
		newAssets := make(map[basics.AssetIndex]basics.AssetHolding, g.Count)
		aidx := g.MinAssetIndex
		for i := 0; i < int(g.Count); i++ {
			aidx += g.groupData.AssetOffsets[i]
			newAssets[aidx] = basics.AssetHolding{}
			a.Equal(uint64(aidx), g.groupData.Amounts[i])
		}
		a.Equal(int(g.Count), len(newAssets))
		a.Contains(newAssets, newAsset)
		delete(newAssets, newAsset)
		a.Equal(oldAssets, newAssets)
	}

	// prepend
	aidx = spec[0].start - 10
	e.Groups[0].insert(aidx, basics.AssetHolding{Amount: uint64(aidx)})
	a.Equal(oldCount+1, e.Groups[0].Count)
	a.Equal(aidx, e.Groups[0].MinAssetIndex)
	a.Equal(oldDeltaMaxAssetIndex+uint64((spec[0].start-aidx)), e.Groups[0].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.AssetOffsets))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Amounts))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Frozens))
	a.Equal(basics.AssetIndex(0), e.Groups[0].groupData.AssetOffsets[0])
	a.Equal(spec[0].start-aidx, e.Groups[0].groupData.AssetOffsets[1])
	a.Equal(oldAssetOffsets[1:], e.Groups[0].groupData.AssetOffsets[2:])
	checkAssetMap(aidx, e.Groups[0])

	e2.Groups[0].insert(aidx, basics.AssetParams{Total: uint64(aidx)})
	a.Equal(oldCount+1, e2.Groups[0].Count)
	a.Equal(aidx, e2.Groups[0].MinAssetIndex)
	a.Equal(oldDeltaMaxAssetIndex+uint64((spec[0].start-aidx)), e2.Groups[0].DeltaMaxAssetIndex)
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.AssetOffsets))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.Totals))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.Decimals))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.DefaultFrozens))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.Managers))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.MetadataHash))
	a.Equal(basics.AssetIndex(0), e2.Groups[0].groupData.AssetOffsets[0])
	a.Equal(spec[0].start-aidx, e2.Groups[0].groupData.AssetOffsets[1])
	a.Equal(oldAssetOffsets[1:], e2.Groups[0].groupData.AssetOffsets[2:])

	// append
	aidx = spec[0].end + 10
	e = genExtendedHolding(t, spec)
	e.Groups[0].insert(aidx, basics.AssetHolding{Amount: uint64(aidx)})
	a.Equal(oldCount+1, e.Groups[0].Count)
	a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
	a.Equal(uint64(aidx-spec[0].start), e.Groups[0].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.AssetOffsets))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Amounts))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Frozens))
	a.Equal(basics.AssetIndex(0), e.Groups[0].groupData.AssetOffsets[0])
	a.Equal(oldAssetOffsets, e.Groups[0].groupData.AssetOffsets[:e2.Groups[0].Count-1])
	a.Equal(aidx-spec[0].end, e.Groups[0].groupData.AssetOffsets[e2.Groups[0].Count-1])
	checkAssetMap(aidx, e.Groups[0])

	e2 = genExtendedParams(t, spec)
	e2.Groups[0].insert(aidx, basics.AssetParams{Total: uint64(aidx)})
	a.Equal(oldCount+1, e2.Groups[0].Count)
	a.Equal(spec[0].start, e2.Groups[0].MinAssetIndex)
	a.Equal(uint64(aidx-spec[0].start), e2.Groups[0].DeltaMaxAssetIndex)
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.Totals))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.Decimals))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.DefaultFrozens))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.Managers))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.MetadataHash))
	a.Equal(basics.AssetIndex(0), e2.Groups[0].groupData.AssetOffsets[0])
	a.Equal(oldAssetOffsets, e2.Groups[0].groupData.AssetOffsets[:e2.Groups[0].Count-1])
	a.Equal(aidx-spec[0].end, e2.Groups[0].groupData.AssetOffsets[e2.Groups[0].Count-1])

	// insert in the middle
	aidx = spec[0].end - 1
	delta := spec[0].end - aidx
	e = genExtendedHolding(t, spec)
	e.Groups[0].insert(aidx, basics.AssetHolding{Amount: uint64(aidx)})
	a.Equal(oldCount+1, e.Groups[0].Count)
	a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
	a.Equal(uint64(spec[0].end-spec[0].start), e.Groups[0].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.AssetOffsets))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Amounts))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Frozens))
	a.Equal(basics.AssetIndex(0), e.Groups[0].groupData.AssetOffsets[0])
	a.Equal(oldAssetOffsets[:len(oldAssetOffsets)-1], e.Groups[0].groupData.AssetOffsets[:e.Groups[0].Count-2])
	a.Equal(oldAssetOffsets[len(oldAssetOffsets)-1]-delta, e.Groups[0].groupData.AssetOffsets[e.Groups[0].Count-2])
	a.Equal(delta, e.Groups[0].groupData.AssetOffsets[e.Groups[0].Count-1])
	checkAssetMap(aidx, e.Groups[0])

	e2 = genExtendedParams(t, spec)
	e2.Groups[0].insert(aidx, basics.AssetParams{Total: uint64(aidx)})
	a.Equal(oldCount+1, e2.Groups[0].Count)
	a.Equal(spec[0].start, e2.Groups[0].MinAssetIndex)
	a.Equal(uint64(spec[0].end-spec[0].start), e2.Groups[0].DeltaMaxAssetIndex)
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.AssetOffsets))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.Totals))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.Decimals))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.DefaultFrozens))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.Managers))
	a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.MetadataHash))
	a.Equal(basics.AssetIndex(0), e2.Groups[0].groupData.AssetOffsets[0])
	a.Equal(oldAssetOffsets[:len(oldAssetOffsets)-1], e2.Groups[0].groupData.AssetOffsets[:e2.Groups[0].Count-2])
	a.Equal(oldAssetOffsets[len(oldAssetOffsets)-1]-delta, e2.Groups[0].groupData.AssetOffsets[e2.Groups[0].Count-2])
	a.Equal(delta, e2.Groups[0].groupData.AssetOffsets[e2.Groups[0].Count-1])

}

func checkGroup(t *testing.T, group interface{}) {
	if g, ok := group.(*AssetsHoldingGroup); ok {
		checkHoldings(t, *g)
	} else if g, ok := group.(*AssetsParamsGroup); ok {
		checkParams(t, *g)
	} else {
		t.Fatal(fmt.Sprintf("%T is not %T nor %T", group, &AssetsHoldingGroup{}, &AssetsParamsGroup{}))
	}
}

func checkHoldings(t *testing.T, g AssetsHoldingGroup) {
	a := require.New(t)
	aidx := g.MinAssetIndex
	for i := 0; i < int(g.Count); i++ {
		aidx += g.groupData.AssetOffsets[i]
		a.Equal(uint64(aidx), g.groupData.Amounts[i])
	}
}

func checkParams(t *testing.T, g AssetsParamsGroup) {
	a := require.New(t)
	aidx := g.MinAssetIndex
	for i := 0; i < int(g.Count); i++ {
		aidx += g.groupData.AssetOffsets[i]
		a.Equal(uint64(aidx), g.groupData.Totals[i])
		a.Equal(fmt.Sprintf("a%d", g.groupData.Totals[i]), g.groupData.AssetNames[i])
	}
}

// test for AssetsHoldingGroup.split + insertAfter
func TestAssetSplitInsertAfter(t *testing.T) {
	a := require.New(t)

	spec1 := []groupSpec{
		{10, 700, MaxHoldingGroupSize},
	}
	spec2 := []groupSpec{
		{10, 700, MaxHoldingGroupSize - 1},
	}

	var tests = []struct {
		spec  []groupSpec
		split [2]int
	}{
		{spec1, [2]int{spec1[0].count / 2, spec1[0].count / 2}},
		{spec2, [2]int{spec2[0].count / 2, spec2[0].count/2 + 1}},
	}

	for _, test := range tests {
		spec := test.spec
		lsize := test.split[0]
		rsize := test.split[1]
		t.Run(fmt.Sprintf("size=%d", spec[0].count), func(t *testing.T) {
			e := genExtendedHolding(t, spec)
			e2 := genExtendedParams(t, spec)

			// save original data for later comparison
			oldCount := e.Count
			a.Equal(uint32(spec[0].count), oldCount)
			oldAssetOffsets1 := make([]basics.AssetIndex, lsize)
			oldAssetOffsets2 := make([]basics.AssetIndex, rsize)
			for i := 0; i < lsize; i++ {
				oldAssetOffsets1[i] = e.Groups[0].groupData.AssetOffsets[i]
			}
			for i := 0; i < rsize; i++ {
				oldAssetOffsets2[i] = e.Groups[0].groupData.AssetOffsets[i+lsize]
			}
			// genExtendedHoldingfunction increments assets as (700-20)/256 = 2
			gap := int(spec[0].end-spec[0].start) / spec[0].count

			// split the group and insert left
			aidx := spec[0].start + 1
			pos := e.split(0, aidx)
			a.Equal(0, pos)
			e.insertInto(pos, aidx, basics.AssetHolding{Amount: uint64(aidx)})
			a.Equal(oldCount+1, e.Count)
			a.Equal(2, len(e.Groups))
			a.Equal(e.Count, e.Groups[0].Count+e.Groups[1].Count)

			pos = e2.split(0, aidx)
			a.Equal(0, pos)
			e2.insertInto(pos, aidx, basics.AssetParams{Total: uint64(aidx), AssetName: fmt.Sprintf("a%d", aidx)})
			a.Equal(oldCount+1, e2.Count)
			a.Equal(2, len(e2.Groups))
			a.Equal(e2.Count, e2.Groups[0].Count+e2.Groups[1].Count)

			a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
			a.Equal(uint32(lsize+1), e.Groups[0].Count)
			a.Equal(uint64((lsize-1)*gap), e.Groups[0].DeltaMaxAssetIndex)
			a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.AssetOffsets))

			a.Equal(spec[0].start, e2.Groups[0].MinAssetIndex)
			a.Equal(uint32(lsize+1), e2.Groups[0].Count)
			a.Equal(uint64((lsize-1)*gap), e2.Groups[0].DeltaMaxAssetIndex)
			a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.AssetOffsets))

			checkGroupDataArrays(a, int(e.Groups[0].Count), &e.Groups[0])
			checkGroupDataArrays(a, int(e2.Groups[0].Count), &e2.Groups[0])

			a.Equal(oldAssetOffsets1[0], e.Groups[0].groupData.AssetOffsets[0])
			a.Equal(basics.AssetIndex(1), e.Groups[0].groupData.AssetOffsets[1])
			a.Equal(basics.AssetIndex(1), e.Groups[0].groupData.AssetOffsets[2])
			a.Equal(oldAssetOffsets1[2:], e.Groups[0].groupData.AssetOffsets[3:])

			a.Equal(oldAssetOffsets1[0], e2.Groups[0].groupData.AssetOffsets[0])
			a.Equal(basics.AssetIndex(1), e2.Groups[0].groupData.AssetOffsets[1])
			a.Equal(basics.AssetIndex(1), e2.Groups[0].groupData.AssetOffsets[2])
			a.Equal(oldAssetOffsets1[2:], e2.Groups[0].groupData.AssetOffsets[3:])

			checkHoldings(t, e.Groups[0])
			checkParams(t, e2.Groups[0])

			a.Equal(spec[0].start+basics.AssetIndex(e.Groups[0].DeltaMaxAssetIndex+uint64(gap)), e.Groups[1].MinAssetIndex)
			a.Equal(uint32(rsize), e.Groups[1].Count)
			a.Equal(uint64(spec[0].end-e.Groups[1].MinAssetIndex), e.Groups[1].DeltaMaxAssetIndex)
			a.Equal(int(e.Groups[1].Count), len(e.Groups[1].groupData.AssetOffsets))
			a.Equal(basics.AssetIndex(0), e.Groups[1].groupData.AssetOffsets[0])
			a.Equal(oldAssetOffsets2[1:], e.Groups[1].groupData.AssetOffsets[1:])
			checkGroupDataArrays(a, int(e.Groups[1].Count), &e.Groups[1])
			checkHoldings(t, e.Groups[1])

			a.Equal(spec[0].start+basics.AssetIndex(e2.Groups[0].DeltaMaxAssetIndex+uint64(gap)), e2.Groups[1].MinAssetIndex)
			a.Equal(uint32(rsize), e2.Groups[1].Count)
			a.Equal(uint64(spec[0].end-e2.Groups[1].MinAssetIndex), e2.Groups[1].DeltaMaxAssetIndex)
			a.Equal(int(e2.Groups[1].Count), len(e2.Groups[1].groupData.AssetOffsets))
			a.Equal(basics.AssetIndex(0), e2.Groups[1].groupData.AssetOffsets[0])
			a.Equal(oldAssetOffsets2[1:], e2.Groups[1].groupData.AssetOffsets[1:])
			checkGroupDataArrays(a, int(e2.Groups[1].Count), &e2.Groups[1])
			checkParams(t, e2.Groups[1])

			e = genExtendedHolding(t, spec)
			e2 = genExtendedParams(t, spec)

			// split the group and insert right
			aidx = spec[0].end - 1
			pos = e.split(0, aidx)
			a.Equal(1, pos)
			e.insertInto(pos, aidx, basics.AssetHolding{Amount: uint64(aidx)})
			a.Equal(oldCount+1, e.Count)
			a.Equal(2, len(e.Groups))
			a.Equal(e.Count, e.Groups[0].Count+e.Groups[1].Count)

			pos = e2.split(0, aidx)
			a.Equal(1, pos)
			e2.insertInto(pos, aidx, basics.AssetParams{Total: uint64(aidx), AssetName: fmt.Sprintf("a%d", aidx)})
			a.Equal(oldCount+1, e2.Count)
			a.Equal(2, len(e2.Groups))
			a.Equal(e2.Count, e2.Groups[0].Count+e2.Groups[1].Count)

			a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
			a.Equal(uint32(lsize), e.Groups[0].Count)
			a.Equal(uint64((lsize-1)*gap), e.Groups[0].DeltaMaxAssetIndex)
			a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.AssetOffsets))
			a.Equal(oldAssetOffsets1, e.Groups[0].groupData.AssetOffsets)
			checkGroupDataArrays(a, int(e.Groups[0].Count), &e.Groups[0])
			checkHoldings(t, e.Groups[0])

			a.Equal(spec[0].start, e2.Groups[0].MinAssetIndex)
			a.Equal(uint32(lsize), e2.Groups[0].Count)
			a.Equal(uint64((lsize-1)*gap), e2.Groups[0].DeltaMaxAssetIndex)
			a.Equal(int(e2.Groups[0].Count), len(e2.Groups[0].groupData.AssetOffsets))
			a.Equal(oldAssetOffsets1, e2.Groups[0].groupData.AssetOffsets)
			checkGroupDataArrays(a, int(e2.Groups[0].Count), &e2.Groups[0])
			checkParams(t, e2.Groups[0])

			a.Equal(spec[0].start+basics.AssetIndex(e.Groups[0].DeltaMaxAssetIndex+uint64(gap)), e.Groups[1].MinAssetIndex)
			a.Equal(uint32(rsize+1), e.Groups[1].Count)
			a.Equal(uint64(spec[0].end-e.Groups[1].MinAssetIndex), e.Groups[1].DeltaMaxAssetIndex)
			a.Equal(int(e.Groups[1].Count), len(e.Groups[1].groupData.AssetOffsets))

			a.Equal(spec[0].start+basics.AssetIndex(e2.Groups[0].DeltaMaxAssetIndex+uint64(gap)), e2.Groups[1].MinAssetIndex)
			a.Equal(uint32(rsize+1), e2.Groups[1].Count)
			a.Equal(uint64(spec[0].end-e2.Groups[1].MinAssetIndex), e2.Groups[1].DeltaMaxAssetIndex)
			a.Equal(int(e2.Groups[1].Count), len(e2.Groups[1].groupData.AssetOffsets))

			checkGroupDataArrays(a, int(e.Groups[1].Count), &e.Groups[1])
			checkGroupDataArrays(a, int(e2.Groups[1].Count), &e2.Groups[1])

			a.Equal(basics.AssetIndex(0), e.Groups[1].groupData.AssetOffsets[0])
			a.Equal(oldAssetOffsets2[1:len(oldAssetOffsets2)-1], e.Groups[1].groupData.AssetOffsets[1:e.Groups[1].Count-2])
			a.Equal(oldAssetOffsets2[len(oldAssetOffsets2)-1]-1, e.Groups[1].groupData.AssetOffsets[e.Groups[1].Count-2])
			a.Equal(basics.AssetIndex(1), e.Groups[1].groupData.AssetOffsets[e.Groups[1].Count-1])

			a.Equal(basics.AssetIndex(0), e2.Groups[1].groupData.AssetOffsets[0])
			a.Equal(oldAssetOffsets2[1:len(oldAssetOffsets2)-1], e2.Groups[1].groupData.AssetOffsets[1:e2.Groups[1].Count-2])
			a.Equal(oldAssetOffsets2[len(oldAssetOffsets2)-1]-1, e2.Groups[1].groupData.AssetOffsets[e2.Groups[1].Count-2])
			a.Equal(basics.AssetIndex(1), e2.Groups[1].groupData.AssetOffsets[e2.Groups[1].Count-1])

			checkHoldings(t, e.Groups[1])
			checkParams(t, e2.Groups[1])
		})
	}
}

func checkGroupDataArrays(a *require.Assertions, count int, group interface{}) {
	if g, ok := group.(*AssetsHoldingGroup); ok {
		gd := g.groupData
		a.Equal(count, len(gd.AssetOffsets))
		a.Equal(count, len(gd.Amounts))
		a.Equal(count, len(gd.Frozens))
	} else if g, ok := group.(*AssetsParamsGroup); ok {
		gd := g.groupData
		a.Equal(count, len(gd.AssetOffsets))
		a.Equal(count, len(gd.Totals))
		a.Equal(count, len(gd.Decimals))
		a.Equal(count, len(gd.DefaultFrozens))
		a.Equal(count, len(gd.UnitNames))
		a.Equal(count, len(gd.AssetNames))
		a.Equal(count, len(gd.URLs))
		a.Equal(count, len(gd.MetadataHash))
		a.Equal(count, len(gd.Managers))
		a.Equal(count, len(gd.Reserves))
		a.Equal(count, len(gd.Freezes))
		a.Equal(count, len(gd.Clawbacks))
	} else {
		a.Fail(fmt.Sprintf("%T is not %T nor %T", group, &AssetsHoldingGroup{}, &AssetsParamsGroup{}))
	}
}

// test for ExtendedAssetHolding.insert and findGroup
func TestAssetHoldingInsertGroup(t *testing.T) {
	a := require.New(t)

	spec1 := []groupSpec{
		{10, 700, MaxHoldingGroupSize},
		{1001, 1060, 20},
		{2001, 3000, MaxHoldingGroupSize},
		{4001, 5000, MaxHoldingGroupSize},
	}

	e1 := genExtendedHolding(t, spec1)
	e2 := genExtendedParams(t, spec1)
	tests := []AbstractAssetGroupList{&e1, &e2}
	for _, e := range tests {
		t.Run(fmt.Sprintf("%T", e), func(t *testing.T) {

			// new group at the beginning
			aidx := basics.AssetIndex(1)
			res := findGroup(aidx, 0, e)
			a.False(res.found)
			a.False(res.split)
			a.Equal(-1, res.gi)

			// split group 0
			aidx = basics.AssetIndex(spec1[0].start + 1)
			res = findGroup(aidx, 0, e)
			a.True(res.found)
			a.True(res.split)
			a.Equal(0, res.gi)

			// insert into group 1 if skipping 0
			res = findGroup(aidx, 1, e)
			a.True(res.found)
			a.False(res.split)
			a.Equal(1, res.gi)

			// prepend into group 1
			aidx = basics.AssetIndex(spec1[0].end + 10)
			res = findGroup(aidx, 0, e)
			a.True(res.found)
			a.False(res.split)
			a.Equal(1, res.gi)

			// append into group 1
			aidx = basics.AssetIndex(spec1[1].end + 10)
			res = findGroup(aidx, 0, e)
			a.True(res.found)
			a.False(res.split)
			a.Equal(1, res.gi)

			// insert into group 1
			aidx = basics.AssetIndex(spec1[1].start + 1)
			res = findGroup(aidx, 0, e)
			a.True(res.found)
			a.False(res.split)
			a.Equal(1, res.gi)

			// split group 2
			aidx = basics.AssetIndex(spec1[2].start + 1)
			res = findGroup(aidx, 0, e)
			a.True(res.found)
			a.True(res.split)
			a.Equal(2, res.gi)

			// new group after group 2
			aidx = basics.AssetIndex(spec1[2].end + 100)
			res = findGroup(aidx, 0, e)
			a.False(res.found)
			a.False(res.split)
			a.Equal(2, res.gi)

			// new group after group 3
			aidx = basics.AssetIndex(spec1[3].end + 100)
			res = findGroup(aidx, 0, e)
			a.False(res.found)
			a.False(res.split)
			a.Equal(3, res.gi)
		})
	}

	// check insertion
	assets := []basics.AssetIndex{
		1,                  // create a new group at the beginning (new 0)
		spec1[0].start + 1, // split old group 0 and insert left
		spec1[0].end + 10,  // insert into new group 1
		spec1[1].start + 1, // insert into old group 1 (new 3)
		spec1[2].end + 100, // create a new after old group 2 (new 4)
		spec1[3].end + 100, // create a new group after old group 3 (new 7)
	}
	holdings := make(map[basics.AssetIndex]basics.AssetHolding, len(assets))
	for _, aidx := range assets {
		holdings[aidx] = basics.AssetHolding{Amount: uint64(aidx)}
	}
	params := make(map[basics.AssetIndex]basics.AssetParams, len(assets))
	for _, aidx := range assets {
		params[aidx] = basics.AssetParams{Total: uint64(aidx), AssetName: fmt.Sprintf("a%d", aidx)}
	}
	oldCount := e1.Count

	e1.Insert(assets, holdings)
	e2.Insert(assets, params)

	tests = []AbstractAssetGroupList{&e1, &e2}
	for _, e := range tests {
		t.Run(fmt.Sprintf("%T", e), func(t *testing.T) {

			a.Equal(oldCount+uint32(len(assets)), e.Total())
			a.Equal(4+len(spec1), e.Len())

			a.Equal(uint32(1), e.Get(0).AssetCount())
			a.Equal(assets[0], e.Get(0).MinAsset())
			a.Equal(e.Get(0).MinAsset()+0, e.Get(0).MaxAsset()) // MaxAsset returns min asset + delta, 0 emphasizes expected delta value
			checkGroupDataArrays(a, int(e.Get(0).AssetCount()), e.Get(0))
			a.Equal(basics.AssetIndex(0), e.Get(0).GroupData().AssetDeltaValue(0))
			checkGroup(t, e.Get(0))

			// two cases below checked in split + insertAfter test
			a.Equal(uint32(spec1[0].count/2+1), e.Get(1).AssetCount())
			checkGroupDataArrays(a, int(e.Get(1).AssetCount()), e.Get(1))
			checkGroup(t, e.Get(1))

			a.Equal(uint32(spec1[0].count/2+1), e.Get(2).AssetCount())
			checkGroupDataArrays(a, int(e.Get(2).AssetCount()), e.Get(2))
			checkGroup(t, e.Get(2))

			a.Equal(uint32(spec1[1].count+1), e.Get(3).AssetCount())
			a.Equal(spec1[1].start, e.Get(3).MinAsset())
			a.Equal(e.Get(3).MinAsset()+spec1[1].end-spec1[1].start, e.Get(3).MaxAsset())
			checkGroupDataArrays(a, int(e.Get(3).AssetCount()), e.Get(3))
			checkGroup(t, e.Get(3))

			// checked in group insert test
			a.Equal(uint32(spec1[2].count), e.Get(4).AssetCount())
			checkGroupDataArrays(a, int(e.Get(4).AssetCount()), e.Get(4))
			checkGroup(t, e.Get(4))

			a.Equal(uint32(1), e.Get(5).AssetCount())
			a.Equal(assets[4], e.Get(5).MinAsset())
			a.Equal(e.Get(5).MinAsset()+0, e.Get(5).MaxAsset())
			checkGroupDataArrays(a, int(e.Get(5).AssetCount()), e.Get(5))
			a.Equal(basics.AssetIndex(0), e.Get(5).GroupData().AssetDeltaValue(0))
			checkGroup(t, e.Get(5))

			a.Equal(uint32(1), e.Get(7).AssetCount())
			a.Equal(assets[5], e.Get(7).MinAsset())
			a.Equal(e.Get(7).MinAsset()+0, e.Get(7).MaxAsset())
			checkGroupDataArrays(a, int(e.Get(7).AssetCount()), e.Get(7))
			checkGroup(t, e.Get(7))
		})
	}

	spec2 := []groupSpec{
		{1001, 1060, 20},
		{2001, 3000, MaxHoldingGroupSize},
	}

	e1 = genExtendedHolding(t, spec2)
	e2 = genExtendedParams(t, spec2)
	tests = []AbstractAssetGroupList{&e1, &e2}
	for _, e := range tests {
		t.Run(fmt.Sprintf("%T", e), func(t *testing.T) {

			// insert into group 0
			aidx := basics.AssetIndex(1)
			res := findGroup(aidx, 0, e)
			a.True(res.found)
			a.False(res.split)
			a.Equal(0, res.gi)

			// insert into group 0
			aidx = basics.AssetIndex(spec2[0].start + 1)
			res = findGroup(aidx, 0, e)
			a.True(res.found)
			a.False(res.split)
			a.Equal(0, res.gi)

			// insert into group 0
			aidx = basics.AssetIndex(spec2[0].end + 1)
			res = findGroup(aidx, 0, e)
			a.True(res.found)
			a.False(res.split)
			a.Equal(0, res.gi)

			// split group 1
			aidx = basics.AssetIndex(spec2[1].start + 1)
			res = findGroup(aidx, 0, e)
			a.True(res.found)
			a.True(res.split)
			a.Equal(1, res.gi)

			// new group after group 1
			aidx = basics.AssetIndex(spec2[1].end + 1)
			res = findGroup(aidx, 0, e)
			a.False(res.found)
			a.False(res.split)
			a.Equal(1, res.gi)
		})
	}

	spec3 := []groupSpec{
		{2001, 3000, MaxHoldingGroupSize},
		{3002, 3062, 20},
	}

	e1 = genExtendedHolding(t, spec3)
	e2 = genExtendedParams(t, spec3)
	tests = []AbstractAssetGroupList{&e1, &e2}
	for _, e := range tests {
		t.Run(fmt.Sprintf("%T", e), func(t *testing.T) {

			// split group 0
			aidx := basics.AssetIndex(spec3[0].start + 1)
			res := findGroup(aidx, 0, e)
			a.True(res.found)
			a.True(res.split)
			a.Equal(0, res.gi)

			// insert into group 1
			aidx = basics.AssetIndex(spec3[1].start - 1)
			res = findGroup(aidx, 0, e)
			a.True(res.found)
			a.False(res.split)
			a.Equal(1, res.gi)

			// insert into group 1
			aidx = basics.AssetIndex(spec3[1].end + 1)
			res = findGroup(aidx, 0, e)
			a.True(res.found)
			a.False(res.split)
			a.Equal(1, res.gi)
		})
	}

	spec4 := []groupSpec{
		{2001, 3000, MaxHoldingGroupSize},
		{3002, 4000, MaxHoldingGroupSize},
	}

	e1 = genExtendedHolding(t, spec4)
	e2 = genExtendedParams(t, spec4)
	tests = []AbstractAssetGroupList{&e1, &e2}
	for _, e := range tests {
		t.Run(fmt.Sprintf("%T", e), func(t *testing.T) {

			// new group after 0
			aidx := basics.AssetIndex(spec4[0].end + 1)
			res := findGroup(aidx, 0, e)
			a.False(res.found)
			a.False(res.split)
			a.Equal(0, res.gi)
		})
	}
}

func TestAssetDelete(t *testing.T) {
	a := require.New(t)

	spec := []groupSpec{
		{10, 700, MaxHoldingGroupSize},
		{1001, 1001, 1},
		{2001, 3000, MaxHoldingGroupSize},
	}

	e := genExtendedHolding(t, spec)
	e2 := genExtendedParams(t, spec)
	oldCount := e.Count
	a.Equal(uint32(spec[0].count+spec[1].count+spec[2].count), e.Count)
	a.Equal(e.Count, e2.Count)
	a.Equal(uint32(spec[1].count), e.Groups[1].Count)
	a.Equal(e.Groups[1].Count, e2.Groups[1].Count)
	a.Equal(spec[1].start, e.Groups[1].MinAssetIndex)
	a.Equal(e.Groups[1].MinAssetIndex, e2.Groups[1].MinAssetIndex)
	a.Equal(uint64(0), e.Groups[1].DeltaMaxAssetIndex)
	a.Equal(e.Groups[1].DeltaMaxAssetIndex, e2.Groups[1].DeltaMaxAssetIndex)
	a.Equal(basics.AssetIndex(0), e.Groups[1].groupData.AssetOffsets[0])
	a.Equal(e.Groups[1].groupData.AssetOffsets[0], e2.Groups[1].groupData.AssetOffsets[0])

	oldAssetHoldings := make(map[basics.AssetIndex]basics.AssetHolding, spec[0].count)
	aidx := e.Groups[0].MinAssetIndex
	for i := 0; i < spec[0].count; i++ {
		aidx += e.Groups[0].groupData.AssetOffsets[i]
		oldAssetHoldings[aidx] = basics.AssetHolding{Amount: e.Groups[0].groupData.Amounts[i]}
	}

	oldAssetParams := make(map[basics.AssetIndex]basics.AssetParams, spec[0].count)
	aidx = e2.Groups[0].MinAssetIndex
	for i := 0; i < spec[0].count; i++ {
		aidx += e2.Groups[0].groupData.AssetOffsets[i]
		oldAssetParams[aidx] = basics.AssetParams{Total: e2.Groups[0].groupData.Totals[i], AssetName: e2.Groups[0].groupData.AssetNames[i]}
	}

	checkAssetHoldingsMap := func(delAsset basics.AssetIndex, g AssetsHoldingGroup) {
		newAssets := make(map[basics.AssetIndex]basics.AssetHolding, g.Count)
		aidx := g.MinAssetIndex
		for i := 0; i < int(g.Count); i++ {
			aidx += g.groupData.AssetOffsets[i]
			newAssets[aidx] = basics.AssetHolding{Amount: g.groupData.Amounts[i]}
			a.Equal(uint64(aidx), g.groupData.Amounts[i])
		}
		a.Equal(int(g.Count), len(newAssets))
		a.Contains(oldAssetHoldings, delAsset)

		oldAssetHoldingsCopy := make(map[basics.AssetIndex]basics.AssetHolding, len(oldAssetHoldings))
		for k, v := range oldAssetHoldings {
			oldAssetHoldingsCopy[k] = v
		}
		delete(oldAssetHoldingsCopy, delAsset)
		a.Equal(oldAssetHoldingsCopy, newAssets)
	}

	checkAssetParamsMap := func(delAsset basics.AssetIndex, g AssetsParamsGroup) {
		newAssets := make(map[basics.AssetIndex]basics.AssetParams, g.Count)
		aidx := g.MinAssetIndex
		for i := 0; i < int(g.Count); i++ {
			aidx += g.groupData.AssetOffsets[i]
			newAssets[aidx] = basics.AssetParams{Total: g.groupData.Totals[i], AssetName: g.groupData.AssetNames[i]}
			a.Equal(uint64(aidx), g.groupData.Totals[i])
		}
		a.Equal(int(g.Count), len(newAssets))
		a.Contains(oldAssetParams, delAsset)

		oldAssetParamsCopy := make(map[basics.AssetIndex]basics.AssetParams, len(oldAssetParams))
		for k, v := range oldAssetParams {
			oldAssetParamsCopy[k] = v
		}
		delete(oldAssetParamsCopy, delAsset)
		a.Equal(oldAssetParamsCopy, newAssets)
	}

	// delete a group with only one item
	e.Delete([]basics.AssetIndex{spec[1].start})
	a.Equal(oldCount-1, e.Count)
	a.Equal(len(spec)-1, len(e.Groups))

	e2.Delete([]basics.AssetIndex{spec[1].start})
	a.Equal(oldCount-1, e2.Count)
	a.Equal(len(spec)-1, len(e2.Groups))

	gap := int(spec[0].end-spec[0].start) / spec[0].count

	tests := []struct {
		gi       int
		ai       int
		minAsset basics.AssetIndex
		maxDelta uint64
	}{
		// delete first entry in a group
		{0, 0, spec[0].start + basics.AssetIndex(gap), uint64(spec[0].end - spec[0].start - basics.AssetIndex(gap))},
		// delete last entry in a group
		// assets are 10, 12, 14, ..., 700
		// the second last is 2 * (spec[0].count-2) + 10
		// so the delta = (spec[0].count-2)*gap + 10 -10
		{0, spec[0].count - 1, spec[0].start, uint64((spec[0].count - 2) * gap)},
		// delete some middle entry
		{0, 1, spec[0].start, uint64(spec[0].end - spec[0].start)},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("holding_%d", i+1), func(t *testing.T) {
			e := genExtendedHolding(t, spec)
			aidx := e.Get(test.gi).AssetAt(test.ai)
			e.deleteByIndex(test.gi, test.ai)
			a.Equal(oldCount-1, e.Count)
			a.Equal(len(spec), len(e.Groups))
			a.Equal(test.minAsset, e.Groups[0].MinAssetIndex)
			a.Equal(test.maxDelta, e.Groups[0].DeltaMaxAssetIndex)
			checkAssetHoldingsMap(aidx, e.Groups[0])
		})

		t.Run(fmt.Sprintf("params_%d", i+1), func(t *testing.T) {
			e := genExtendedParams(t, spec)
			aidx = e.Get(test.gi).AssetAt(test.ai)
			e.deleteByIndex(test.gi, test.ai)
			a.Equal(oldCount-1, e.Count)
			a.Equal(len(spec), len(e.Groups))
			a.Equal(test.minAsset, e.Groups[0].MinAssetIndex)
			a.Equal(test.maxDelta, e.Groups[0].DeltaMaxAssetIndex)
			checkAssetParamsMap(aidx, e.Groups[0])

		})
	}
}

func TestAssetHoldingDeleteRepeat(t *testing.T) {
	a := require.New(t)

	spec := []groupSpec{
		{1, 256, MaxHoldingGroupSize},
		{257, 512, MaxHoldingGroupSize},
	}

	e := genExtendedHolding(t, spec)
	a.Equal(uint32(spec[0].count+spec[1].count), e.Count)
	a.Equal(uint32(spec[0].count), e.Groups[0].Count)
	a.Equal(uint32(spec[1].count), e.Groups[1].Count)
	a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
	a.Equal(spec[0].end, e.Groups[0].MinAssetIndex+basics.AssetIndex(e.Groups[0].DeltaMaxAssetIndex))
	a.Equal(spec[1].start, e.Groups[1].MinAssetIndex)
	a.Equal(spec[1].end, e.Groups[1].MinAssetIndex+basics.AssetIndex(e.Groups[1].DeltaMaxAssetIndex))
	for i := 1; i < MaxHoldingGroupSize; i++ {
		e.Groups[0].groupData.AssetOffsets[i] = basics.AssetIndex(1)
		e.Groups[1].groupData.AssetOffsets[i] = basics.AssetIndex(1)
	}
	maxReps := rand.Intn(30)
	for c := 0; c < maxReps; c++ {
		maxIdx := rand.Intn(MaxHoldingGroupSize)
		if c%2 == 0 {
			delOrder := rand.Perm(maxIdx)
			for _, i := range delOrder {
				if i < int(e.Groups[0].Count) {
					e.deleteByIndex(0, i)
				}
			}
		} else {
			delOrder := make([]basics.AssetIndex, 0, maxIdx)
			for i := 1; i <= maxIdx; i++ {
				if i >= int(e.Groups[0].Count) {
					break
				}
				gi, ai := e.FindAsset(basics.AssetIndex(i), 0)
				if gi != -1 && ai != -1 {
					delOrder = append(delOrder, basics.AssetIndex(i))
				}
			}
			_, err := e.Delete(delOrder)
			a.NoError(err)
		}

		// validate the group after deletion
		g := e.Groups[0]
		maxAsset := g.MinAssetIndex + basics.AssetIndex(g.DeltaMaxAssetIndex)
		a.Less(uint64(maxAsset), uint64(e.Groups[1].MinAssetIndex))
		asset := g.MinAssetIndex
		for _, offset := range g.groupData.AssetOffsets {
			asset += offset
		}
		a.Equal(maxAsset, asset)

		e = genExtendedHolding(t, spec)
	}
}

type groupLayout struct {
	count  int
	loaded bool
}

func genExtendedHoldingGroups(spec []groupLayout) (e ExtendedAssetHolding) {
	if len(spec) == 0 {
		return
	}
	e.Groups = make([]AssetsHoldingGroup, len(spec), len(spec))
	for i, s := range spec {
		e.Groups[i] = AssetsHoldingGroup{
			AssetGroupDesc: AssetGroupDesc{Count: uint32(s.count)},
			loaded:         s.loaded}
	}
	return
}

func TestFindLoadedSiblings(t *testing.T) {
	type result struct {
		loaded []int
		crs    []continuosRange
	}
	type test struct {
		i    []groupLayout
		r    result
		seed int64
	}

	tests := []test{
		{i: []groupLayout{}, r: result{}},
		{i: []groupLayout{{1, false}}, r: result{}},
		{i: []groupLayout{{1, false}, {3, false}}, r: result{}},
		{i: []groupLayout{{1, true}, {3, true}}, r: result{[]int{0, 1}, []continuosRange{{0, 2, 4}}}},
		{i: []groupLayout{{1, true}, {3, false}}, r: result{[]int{0}, nil}},
		{i: []groupLayout{{1, false}, {3, true}}, r: result{[]int{1}, nil}},
		{i: []groupLayout{{1, false}, {3, true}, {5, true}}, r: result{[]int{1, 2}, []continuosRange{{1, 2, 8}}}},
		{i: []groupLayout{{1, false}, {3, true}, {5, true}, {7, false}}, r: result{[]int{1, 2}, []continuosRange{{1, 2, 8}}}},
		{i: []groupLayout{{1, false}, {3, true}, {5, true}, {7, true}}, r: result{[]int{1, 2, 3}, []continuosRange{{1, 3, 15}}}},
		{i: []groupLayout{{1, false}, {3, true}, {5, false}, {7, true}}, r: result{[]int{1, 3}, nil}},
		{
			i: []groupLayout{{1, false}, {3, true}, {5, true}, {7, false}, {9, true}},
			r: result{[]int{1, 2, 4}, []continuosRange{{1, 2, 8}}},
		},
		{
			i: []groupLayout{{1, false}, {3, true}, {5, true}, {7, false}, {9, true}, {11, true}},
			r: result{[]int{1, 2, 4, 5}, []continuosRange{{1, 2, 8}, {4, 2, 20}}},
		},
		{
			i: []groupLayout{{1, true}, {3, true}, {5, true}, {7, false}, {9, true}, {11, true}},
			r: result{[]int{0, 1, 2, 4, 5}, []continuosRange{{0, 3, 9}, {4, 2, 20}}},
		},
		{
			i: []groupLayout{{1, true}, {3, true}, {5, true}, {7, false}, {9, true}, {11, false}},
			r: result{[]int{0, 1, 2, 4}, []continuosRange{{0, 3, 9}}},
		},
		{
			i: []groupLayout{{1, true}, {3, true}, {5, true}, {7, true}, {9, true}, {11, true}},
			r: result{[]int{0, 1, 2, 3, 4, 5}, []continuosRange{{0, 6, 36}}},
		},
	}

	// random tests
	getRandTest := func(seed int64) test {
		rand.Seed(seed)
		num := rand.Intn(128)
		gl := make([]groupLayout, num, num)
		var r result
		lastLoaded := -1
		for i := 0; i < num; i++ {
			val := rand.Intn(256)
			gl[i] = groupLayout{val, val%2 == 0}
			if gl[i].loaded {
				r.loaded = append(r.loaded, i)
				if lastLoaded == -1 {
					lastLoaded = i
				}
			}
			if lastLoaded != -1 && (!gl[i].loaded || i == num-1) {
				if i-lastLoaded > 1 || i == num-1 && gl[i].loaded && i-lastLoaded >= 1 {
					count := 0
					lastIndex := i
					if gl[i].loaded && i == num-1 {
						lastIndex = num
					}
					for j := lastLoaded; j < lastIndex; j++ {
						count += gl[j].count
					}
					r.crs = append(r.crs, continuosRange{lastLoaded, lastIndex - lastLoaded, count})
				}
				// reset
				lastLoaded = -1
			}
		}
		return test{gl, r, seed}
	}

	// these seeds a know to produce intersting loaded combinations in the end
	seeds := []int64{1615596918, 1615597682, 1615609061, 1615824956, 1615940924}
	for _, seed := range seeds {
		rt := getRandTest(seed)
		tests = append(tests, rt)
	}
	rt := getRandTest(time.Now().Unix())
	tests = append(tests, rt)

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			e := genExtendedHoldingGroups(test.i)
			l, c := findLoadedSiblings(&e)
			if test.seed != 0 {
				fmt.Printf("seed = %d\n", test.seed)
			}
			require.Equal(t, test.r.loaded, l)
			require.Equal(t, test.r.crs, c)
		})
	}
}

func specFromSizes(t testing.TB, sizes []int, aidx basics.AssetIndex) []groupSpec {
	spec := make([]groupSpec, 0, len(sizes))
	for i, size := range sizes {
		increment := i + 1
		end := aidx + basics.AssetIndex(increment*(size-1))
		s := groupSpec{aidx, end, size}
		spec = append(spec, s)
		aidx = end + 1
	}
	return spec
}

// generate groups from sizes. group N increments each asset id by N
// i.e. Group[0] = [aidx, aidx+1, aidx+2,...]
func genExtendedHoldingGroupsFromSizes(t testing.TB, sizes []int, aidx basics.AssetIndex) (e ExtendedAssetHolding) {
	spec := specFromSizes(t, sizes, aidx)
	e = genExtendedHolding(t, spec)
	for i := 0; i < len(e.Groups); i++ {
		e.Groups[i].AssetGroupKey = int64(i + 1)
	}

	return
}

func genExtendedParamsGroupsFromSizes(t testing.TB, sizes []int, aidx basics.AssetIndex) (e ExtendedAssetParams) {
	spec := specFromSizes(t, sizes, aidx)
	e = genExtendedParams(t, spec)
	for i := 0; i < len(e.Groups); i++ {
		e.Groups[i].AssetGroupKey = int64(i + 1)
	}

	return
}

func getAllHoldings(e ExtendedAssetHolding) map[basics.AssetIndex]basics.AssetHolding {
	holdings := make(map[basics.AssetIndex]basics.AssetHolding, int(e.Count))
	for _, g := range e.Groups {
		aidx := g.MinAssetIndex
		for ai, offset := range g.groupData.AssetOffsets {
			aidx += offset
			holdings[aidx] = g.GetHolding(ai)
		}
	}
	return holdings
}

func getAllParams(e ExtendedAssetParams) map[basics.AssetIndex]basics.AssetParams {
	params := make(map[basics.AssetIndex]basics.AssetParams, int(e.Count))
	for _, g := range e.Groups {
		aidx := g.MinAssetIndex
		for ai, offset := range g.groupData.AssetOffsets {
			aidx += offset
			params[aidx] = g.GetParams(ai)
		}
	}
	return params
}

func TestGroupMergeInternal(t *testing.T) {
	estimate := func(sizes []int, assetThreshold int) (int, int, int) {
		sum := 0
		for _, size := range sizes {
			sum += size
		}
		groupsNeeded := (sum + assetThreshold - 1) / assetThreshold
		groupsToDelete := len(sizes) - groupsNeeded
		return groupsNeeded, groupsToDelete, sum
	}

	type test struct {
		sizes []int
	}

	tests := []test{
		{[]int{1, 2}},
		{[]int{1, 2, 3}},
		{[]int{1, 255, 3}},
		{[]int{1, 253, 1}},
		{[]int{256, 2, 3}},
		{[]int{256, 1, 256}},
		{[]int{254, 1, 1}},
		{[]int{256, 255, 1}},
		{[]int{256, 256, 1}},
		{[]int{256, 256, 256}},
		{[]int{128, 179, 128, 142, 128, 164, 128, 156, 147}},
		{[]int{128, 168, 242, 128, 144, 255, 232}},
	}

	// random test
	n := rand.Intn(100)
	sizes := make([]int, n, n)
	for i := 0; i < n; i++ {
		sizes[i] = rand.Intn(MaxHoldingGroupSize-1) + 1 // no zeroes please
	}
	tests = append(tests, test{sizes})

	for n, test := range tests {
		for _, size := range []uint32{MaxHoldingGroupSize, MaxParamsGroupSize} {
			t.Run(fmt.Sprintf("%d_%d", n, size), func(t *testing.T) {
				a := require.New(t)
				sizes := test.sizes
				groupsNeeded, groupsToDelete, totalAssets := estimate(sizes, int(size))
				a.Equal(len(sizes), groupsNeeded+groupsToDelete)
				e := genExtendedHoldingGroupsFromSizes(t, sizes, basics.AssetIndex(1))
				oldCount := e.Count

				oldHoldings := getAllHoldings(e)
				deleted := mergeInternal(&e, 0, len(sizes), groupsToDelete, size)
				a.Equal(groupsToDelete, len(deleted))
				a.Equal(groupsNeeded, len(e.Groups))
				a.Equal(oldCount, e.Count)
				for i := 0; i < groupsNeeded-1; i++ {
					a.Equal(uint32(size), e.Groups[i].Count)
				}
				a.Equal(uint32(totalAssets-(groupsNeeded-1)*int(size)), e.Groups[groupsNeeded-1].Count)
				newHoldings := getAllHoldings(e)
				a.Equal(oldHoldings, newHoldings)

			})
		}
	}
}

func TestGroupMerge(t *testing.T) {
	hdelgroup := func(e ExtendedAssetHolding, d []int) ExtendedAssetHolding {
		offset := 0
		for _, gi := range d {
			e.Count -= e.Groups[gi+offset].Count
			if gi == len(e.Groups)-1 {
				e.Groups = e.Groups[:len(e.Groups)-1]
			} else {
				e.Groups = append(e.Groups[:gi], e.Groups[gi+1:]...)
			}
		}
		return e
	}

	pdelgroup := func(e ExtendedAssetParams, d []int) ExtendedAssetParams {
		offset := 0
		for _, gi := range d {
			e.Count -= e.Groups[gi+offset].Count
			if gi == len(e.Groups)-1 {
				e.Groups = e.Groups[:len(e.Groups)-1]
			} else {
				e.Groups = append(e.Groups[:gi], e.Groups[gi+1:]...)
			}
		}
		return e
	}

	type result struct {
		l []int
		d []int64
	}
	type test struct {
		sizes  []int
		unload []int
		del    []int
		r      result
	}

	tests := []test{
		{[]int{1, 2, 3}, nil, nil, result{[]int{0}, []int64{2, 3}}},
		{[]int{1, 2, 3}, nil, []int{1}, result{[]int{0}, []int64{3}}},
		{[]int{1, 2, 3}, []int{1}, nil, result{[]int{0, 2}, nil}},
		{[]int{1, 2, 3}, []int{1}, []int{0}, result{[]int{1}, nil}}, // unload 1, del 0 => idx 1 left loaded
		{[]int{1, 2, 3, 4}, nil, []int{0}, result{[]int{0}, []int64{3, 4}}},
		{[]int{1, 2, 3, 4}, []int{3}, []int{0}, result{[]int{0}, []int64{3}}},
		{[]int{1, 2, 3, 4}, []int{0, 1}, nil, result{[]int{2}, []int64{4}}},
		{[]int{1, 2, 3, 4}, []int{1, 3}, nil, result{[]int{0, 2}, nil}},
		{[]int{1, 2, 3, 4}, []int{1, 2}, nil, result{[]int{0, 3}, nil}},
		{[]int{1, 2, 3, 4}, []int{3}, nil, result{[]int{0}, []int64{2, 3}}},
		{[]int{1, 2, 3, 4}, []int{0, 3}, nil, result{[]int{1}, []int64{3}}},
		{[]int{255, 5, 255}, nil, nil, result{[]int{0, 1, 2}, nil}},
		{[]int{250, 5, 255}, nil, nil, result{[]int{0, 1}, []int64{2}}},
		{[]int{250, 5, 255}, []int{1}, nil, result{[]int{0, 2}, nil}},
		{[]int{250, 5, 255}, []int{2}, nil, result{[]int{0}, []int64{2}}},
	}

	for n, test := range tests {
		t.Run(fmt.Sprintf("holding_%d", n), func(t *testing.T) {
			a := require.New(t)
			sizes := test.sizes
			e := genExtendedHoldingGroupsFromSizes(t, sizes, basics.AssetIndex(1))
			for _, gi := range test.unload {
				e.Groups[gi].loaded = false
			}
			e = hdelgroup(e, test.del)
			oldCount := e.Count
			oldHoldings := getAllHoldings(e)

			loaded, deleted := e.Merge()
			a.Equal(test.r.l, loaded)
			a.Equal(test.r.d, deleted)
			a.Equal(oldCount, e.Count)
			newHoldings := getAllHoldings(e)
			a.Equal(oldHoldings, newHoldings)
			var count uint32
			for _, g := range e.Groups {
				count += g.Count
			}
			a.Equal(count, e.Count)
		})

		t.Run(fmt.Sprintf("params_%d", n), func(t *testing.T) {
			a := require.New(t)
			sizes := test.sizes
			e := genExtendedParamsGroupsFromSizes(t, sizes, basics.AssetIndex(1))
			for _, gi := range test.unload {
				e.Groups[gi].loaded = false
			}
			e = pdelgroup(e, test.del)
			oldCount := e.Count
			oldParams := getAllParams(e)

			loaded, deleted := e.Merge()
			a.Equal(test.r.l, loaded)
			a.Equal(test.r.d, deleted)
			a.Equal(oldCount, e.Count)
			newParams := getAllParams(e)
			a.Equal(oldParams, newParams)
			var count uint32
			for _, g := range e.Groups {
				count += g.Count
			}
			a.Equal(count, e.Count)
		})
	}

	// simulate new in-mem group
	a := require.New(t)
	e := genExtendedHoldingGroupsFromSizes(t, []int{250, 5, 255}, basics.AssetIndex(1))
	e.Groups[1].AssetGroupKey = 0
	oldCount := e.Count
	oldHoldings := getAllHoldings(e)
	loaded, deleted := e.Merge()
	a.Equal([]int{0, 1}, loaded)
	a.Equal([]int64(nil), deleted)
	a.Equal(oldCount, e.Count)
	newHoldings := getAllHoldings(e)
	a.Equal(oldHoldings, newHoldings)

}

func viaInterface(agl AbstractAssetGroupList) (total int64) {
	for i := 0; i < agl.Len(); i++ {
		total += int64(len(agl.Get(i).Encode()))
		agl.Get(i).SetKey(total)
	}
	return total
}

func viaType(a *ExtendedAssetHolding) (total int64) {
	for i := 0; i < len(a.Groups); i++ {
		total += int64(len(a.Groups[i].Encode()))
		a.Groups[i].SetKey(total)
	}
	return total
}

var result int64

func BenchmarkSliceVsInterface(b *testing.B) {
	tests := []bool{false, true}
	sizes := []int{128, 179, 128, 142, 128, 164, 128, 156, 147}
	e := genExtendedHoldingGroupsFromSizes(b, sizes, basics.AssetIndex(1))
	for _, isSlice := range tests {
		b.Run(fmt.Sprintf("slice=%v", isSlice), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if isSlice {
					result += viaType(&e)
				} else {
					result += viaInterface(&e)
				}
			}
		})
	}
}
