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

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
)

func TestAssetHoldingConvertToGroups(t *testing.T) {
	a := require.New(t)

	var e ExtendedAssetHolding

	e.ConvertToGroups(nil)
	a.Equal(uint32(0), e.Count)
	a.Equal(0, len(e.Groups))
	a.False(e.loaded)

	e.ConvertToGroups(map[basics.AssetIndex]basics.AssetHolding{})
	a.Equal(uint32(0), e.Count)
	a.Equal(0, len(e.Groups))
	a.False(e.loaded)

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
			a.True(e.loaded)
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

func genExtendedHolding(t *testing.T, spec []groupSpec) (e ExtendedAssetHolding) {
	e.Groups = make([]AssetsHoldingGroup, len(spec))
	for i, s := range spec {
		e.Groups[i].Count = uint32(s.count)
		e.Groups[i].MinAssetIndex = s.start
		e.Groups[i].DeltaMaxAssetIndex = uint64(s.end - s.start)
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
		e.Groups[i].groupData = AssetsHoldingGroupData{AssetOffsets: ao, Amounts: am, Frozens: make([]bool, len(ao))}
		e.Groups[i].loaded = true
		e.Count += uint32(s.count)
	}
	e.loaded = true

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

// test for AssetsHoldingGroup.insert
func TestAssetHoldingGroupInsert(t *testing.T) {
	a := require.New(t)

	spec := []groupSpec{
		{1001, 1060, 20},
	}

	e := genExtendedHolding(t, spec)
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

	// append
	e = genExtendedHolding(t, spec)
	aidx = spec[0].end + 10
	e.Groups[0].insert(aidx, basics.AssetHolding{Amount: uint64(aidx)})
	a.Equal(oldCount+1, e.Groups[0].Count)
	a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
	a.Equal(uint64(aidx-spec[0].start), e.Groups[0].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.AssetOffsets))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Amounts))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Frozens))
	a.Equal(basics.AssetIndex(0), e.Groups[0].groupData.AssetOffsets[0])
	a.Equal(oldAssetOffsets, e.Groups[0].groupData.AssetOffsets[:e.Groups[0].Count-1])
	a.Equal(aidx-spec[0].end, e.Groups[0].groupData.AssetOffsets[e.Groups[0].Count-1])
	checkAssetMap(aidx, e.Groups[0])

	// insert in the middle
	e = genExtendedHolding(t, spec)
	aidx = spec[0].end - 1
	delta := spec[0].end - aidx
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
}

func checkHoldings(t *testing.T, g AssetsHoldingGroup) {
	a := require.New(t)
	aidx := g.MinAssetIndex
	for i := 0; i < int(g.Count); i++ {
		aidx += g.groupData.AssetOffsets[i]
		a.Equal(uint64(aidx), g.groupData.Amounts[i])
	}
}

// test for AssetsHoldingGroup.splitInsert
func TestAssetHoldingSplitInsertGroup(t *testing.T) {
	a := require.New(t)

	spec := []groupSpec{
		{10, 700, MaxHoldingGroupSize},
	}

	e := genExtendedHolding(t, spec)
	// save original data for later comparison
	oldCount := e.Count
	a.Equal(uint32(spec[0].count), oldCount)
	oldAssetOffsets1 := make([]basics.AssetIndex, spec[0].count/2)
	oldAssetOffsets2 := make([]basics.AssetIndex, spec[0].count/2)
	for i := 0; i < spec[0].count/2; i++ {
		oldAssetOffsets1[i] = e.Groups[0].groupData.AssetOffsets[i]
		oldAssetOffsets2[i] = e.Groups[0].groupData.AssetOffsets[i+spec[0].count/2]
	}
	num := spec[0].count / 2
	// genExtendedHoldingfunction increments assets as (700-20)/256 = 2
	gap := int(spec[0].end-spec[0].start) / spec[0].count

	// split the group and insert left
	aidx := spec[0].start + 1
	e.splitInsert(0, aidx, basics.AssetHolding{Amount: uint64(aidx)})
	a.Equal(oldCount+1, e.Count)
	a.Equal(2, len(e.Groups))
	a.Equal(e.Count, e.Groups[0].Count+e.Groups[1].Count)

	a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
	a.Equal(uint32(MaxHoldingGroupSize/2+1), e.Groups[0].Count)
	a.Equal(uint64((num-1)*gap), e.Groups[0].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.AssetOffsets))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Amounts))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Frozens))
	a.Equal(oldAssetOffsets1[0], e.Groups[0].groupData.AssetOffsets[0])
	a.Equal(basics.AssetIndex(1), e.Groups[0].groupData.AssetOffsets[1])
	a.Equal(basics.AssetIndex(1), e.Groups[0].groupData.AssetOffsets[2])
	a.Equal(oldAssetOffsets1[2:], e.Groups[0].groupData.AssetOffsets[3:])
	checkHoldings(t, e.Groups[0])

	a.Equal(spec[0].start+basics.AssetIndex(e.Groups[0].DeltaMaxAssetIndex+uint64(gap)), e.Groups[1].MinAssetIndex)
	a.Equal(uint32(MaxHoldingGroupSize/2), e.Groups[1].Count)
	a.Equal(uint64(spec[0].end-e.Groups[1].MinAssetIndex), e.Groups[1].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[1].Count), len(e.Groups[1].groupData.AssetOffsets))
	a.Equal(int(e.Groups[1].Count), len(e.Groups[1].groupData.Amounts))
	a.Equal(int(e.Groups[1].Count), len(e.Groups[1].groupData.Frozens))
	a.Equal(basics.AssetIndex(0), e.Groups[1].groupData.AssetOffsets[0])
	a.Equal(oldAssetOffsets2[1:], e.Groups[1].groupData.AssetOffsets[1:])
	checkHoldings(t, e.Groups[1])

	e = genExtendedHolding(t, spec)

	// split the group and insert right
	aidx = spec[0].end - 1
	e.splitInsert(0, aidx, basics.AssetHolding{Amount: uint64(aidx)})
	a.Equal(oldCount+1, e.Count)
	a.Equal(2, len(e.Groups))
	a.Equal(e.Count, e.Groups[0].Count+e.Groups[1].Count)

	a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
	a.Equal(uint32(MaxHoldingGroupSize/2), e.Groups[0].Count)
	a.Equal(uint64((num-1)*gap), e.Groups[0].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.AssetOffsets))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Amounts))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Frozens))
	a.Equal(oldAssetOffsets1, e.Groups[0].groupData.AssetOffsets)
	checkHoldings(t, e.Groups[0])

	a.Equal(spec[0].start+basics.AssetIndex(e.Groups[0].DeltaMaxAssetIndex+uint64(gap)), e.Groups[1].MinAssetIndex)
	a.Equal(uint32(MaxHoldingGroupSize/2+1), e.Groups[1].Count)
	a.Equal(uint64(spec[0].end-e.Groups[1].MinAssetIndex), e.Groups[1].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[1].Count), len(e.Groups[1].groupData.AssetOffsets))
	a.Equal(int(e.Groups[1].Count), len(e.Groups[1].groupData.Amounts))
	a.Equal(int(e.Groups[1].Count), len(e.Groups[1].groupData.Frozens))
	a.Equal(basics.AssetIndex(0), e.Groups[1].groupData.AssetOffsets[0])
	a.Equal(oldAssetOffsets2[1:len(oldAssetOffsets2)-1], e.Groups[1].groupData.AssetOffsets[1:e.Groups[1].Count-2])
	a.Equal(oldAssetOffsets2[len(oldAssetOffsets2)-1]-1, e.Groups[1].groupData.AssetOffsets[e.Groups[1].Count-2])
	a.Equal(basics.AssetIndex(1), e.Groups[1].groupData.AssetOffsets[e.Groups[1].Count-1])
	checkHoldings(t, e.Groups[1])
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

	e := genExtendedHolding(t, spec1)

	// new group at the beginning
	aidx := basics.AssetIndex(1)
	res := e.findGroup(aidx, 0)
	a.False(res.found)
	a.False(res.split)
	a.Equal(-1, res.gi)

	// split group 0
	aidx = basics.AssetIndex(spec1[0].start + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.True(res.split)
	a.Equal(0, res.gi)

	// insert into group 1 if skipping 0
	res = e.findGroup(aidx, 1)
	a.True(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	// prepend into group 1
	aidx = basics.AssetIndex(spec1[0].end + 10)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	// append into group 1
	aidx = basics.AssetIndex(spec1[1].end + 10)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	// insert into group 1
	aidx = basics.AssetIndex(spec1[1].start + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	// split group 2
	aidx = basics.AssetIndex(spec1[2].start + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.True(res.split)
	a.Equal(2, res.gi)

	// new group after group 2
	aidx = basics.AssetIndex(spec1[2].end + 100)
	res = e.findGroup(aidx, 0)
	a.False(res.found)
	a.False(res.split)
	a.Equal(2, res.gi)

	// new group after group 3
	aidx = basics.AssetIndex(spec1[3].end + 100)
	res = e.findGroup(aidx, 0)
	a.False(res.found)
	a.False(res.split)
	a.Equal(3, res.gi)

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
	oldCount := e.Count

	e.Insert(assets, holdings)

	a.Equal(oldCount+uint32(len(assets)), e.Count)
	a.Equal(4+len(spec1), len(e.Groups))

	a.Equal(uint32(1), e.Groups[0].Count)
	a.Equal(assets[0], e.Groups[0].MinAssetIndex)
	a.Equal(uint64(0), e.Groups[0].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.AssetOffsets))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Amounts))
	a.Equal(int(e.Groups[0].Count), len(e.Groups[0].groupData.Frozens))
	a.Equal(basics.AssetIndex(0), e.Groups[0].groupData.AssetOffsets[0])
	checkHoldings(t, e.Groups[0])

	// two cases below checked in splitInsert test
	a.Equal(uint32(spec1[0].count/2+1), e.Groups[1].Count)
	a.Equal(int(e.Groups[1].Count), len(e.Groups[1].groupData.AssetOffsets))
	checkHoldings(t, e.Groups[1])

	a.Equal(uint32(spec1[0].count/2+1), e.Groups[2].Count)
	a.Equal(int(e.Groups[2].Count), len(e.Groups[2].groupData.AssetOffsets))
	checkHoldings(t, e.Groups[2])

	a.Equal(uint32(spec1[1].count+1), e.Groups[3].Count)
	a.Equal(spec1[1].start, e.Groups[3].MinAssetIndex)
	a.Equal(uint64(spec1[1].end-spec1[1].start), e.Groups[3].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[3].Count), len(e.Groups[3].groupData.AssetOffsets))
	a.Equal(int(e.Groups[3].Count), len(e.Groups[3].groupData.Amounts))
	a.Equal(int(e.Groups[3].Count), len(e.Groups[3].groupData.Frozens))
	checkHoldings(t, e.Groups[3])

	// checked in group insert test
	a.Equal(uint32(spec1[2].count), e.Groups[4].Count)
	a.Equal(int(e.Groups[4].Count), len(e.Groups[4].groupData.AssetOffsets))
	checkHoldings(t, e.Groups[4])

	a.Equal(uint32(1), e.Groups[5].Count)
	a.Equal(assets[4], e.Groups[5].MinAssetIndex)
	a.Equal(uint64(0), e.Groups[5].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[5].Count), len(e.Groups[5].groupData.AssetOffsets))
	a.Equal(int(e.Groups[5].Count), len(e.Groups[5].groupData.Amounts))
	a.Equal(int(e.Groups[5].Count), len(e.Groups[5].groupData.Frozens))
	a.Equal(basics.AssetIndex(0), e.Groups[5].groupData.AssetOffsets[0])
	checkHoldings(t, e.Groups[5])

	a.Equal(uint32(1), e.Groups[7].Count)
	a.Equal(assets[5], e.Groups[7].MinAssetIndex)
	a.Equal(uint64(0), e.Groups[7].DeltaMaxAssetIndex)
	a.Equal(int(e.Groups[7].Count), len(e.Groups[7].groupData.AssetOffsets))
	a.Equal(int(e.Groups[7].Count), len(e.Groups[7].groupData.Amounts))
	a.Equal(int(e.Groups[7].Count), len(e.Groups[7].groupData.Frozens))
	a.Equal(basics.AssetIndex(0), e.Groups[7].groupData.AssetOffsets[0])
	checkHoldings(t, e.Groups[7])

	spec2 := []groupSpec{
		{1001, 1060, 20},
		{2001, 3000, MaxHoldingGroupSize},
	}

	e = genExtendedHolding(t, spec2)

	// insert into group 0
	aidx = basics.AssetIndex(1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(0, res.gi)

	// insert into group 0
	aidx = basics.AssetIndex(spec2[0].start + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(0, res.gi)

	// insert into group 0
	aidx = basics.AssetIndex(spec2[0].end + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(0, res.gi)

	// split group 1
	aidx = basics.AssetIndex(spec2[1].start + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.True(res.split)
	a.Equal(1, res.gi)

	// new group after group 1
	aidx = basics.AssetIndex(spec2[1].end + 1)
	res = e.findGroup(aidx, 0)
	a.False(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	spec3 := []groupSpec{
		{2001, 3000, MaxHoldingGroupSize},
		{3002, 3062, 20},
	}

	e = genExtendedHolding(t, spec3)

	// split group 0
	aidx = basics.AssetIndex(spec3[0].start + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.True(res.split)
	a.Equal(0, res.gi)

	// insert into group 1
	aidx = basics.AssetIndex(spec3[1].start - 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	// insert into group 1
	aidx = basics.AssetIndex(spec3[1].end + 1)
	res = e.findGroup(aidx, 0)
	a.True(res.found)
	a.False(res.split)
	a.Equal(1, res.gi)

	spec4 := []groupSpec{
		{2001, 3000, MaxHoldingGroupSize},
		{3002, 4000, MaxHoldingGroupSize},
	}

	e = genExtendedHolding(t, spec4)

	// new group after 0
	aidx = basics.AssetIndex(spec4[0].end + 1)
	res = e.findGroup(aidx, 0)
	a.False(res.found)
	a.False(res.split)
	a.Equal(0, res.gi)
}

func TestAssetHoldingDelete(t *testing.T) {
	a := require.New(t)

	spec := []groupSpec{
		{10, 700, MaxHoldingGroupSize},
		{1001, 1001, 1},
		{2001, 3000, MaxHoldingGroupSize},
	}

	e := genExtendedHolding(t, spec)
	oldCount := e.Count
	a.Equal(uint32(spec[0].count+spec[1].count+spec[2].count), e.Count)
	a.Equal(uint32(spec[1].count), e.Groups[1].Count)
	a.Equal(spec[1].start, e.Groups[1].MinAssetIndex)
	a.Equal(uint64(0), e.Groups[1].DeltaMaxAssetIndex)
	a.Equal(basics.AssetIndex(0), e.Groups[1].groupData.AssetOffsets[0])

	oldAssets := make(map[basics.AssetIndex]basics.AssetHolding, spec[0].count)
	aidx := e.Groups[0].MinAssetIndex
	for i := 0; i < spec[0].count; i++ {
		aidx += e.Groups[0].groupData.AssetOffsets[i]
		oldAssets[aidx] = basics.AssetHolding{Amount: e.Groups[0].groupData.Amounts[i]}
	}

	checkAssetMap := func(delAsset basics.AssetIndex, g AssetsHoldingGroup) {
		newAssets := make(map[basics.AssetIndex]basics.AssetHolding, g.Count)
		aidx := g.MinAssetIndex
		for i := 0; i < int(g.Count); i++ {
			aidx += g.groupData.AssetOffsets[i]
			newAssets[aidx] = basics.AssetHolding{Amount: e.Groups[0].groupData.Amounts[i]}
			a.Equal(uint64(aidx), g.groupData.Amounts[i])
		}
		a.Equal(int(g.Count), len(newAssets))
		a.Contains(oldAssets, delAsset)

		oldAssetsCopy := make(map[basics.AssetIndex]basics.AssetHolding, len(oldAssets))
		for k, v := range oldAssets {
			oldAssetsCopy[k] = v
		}
		delete(oldAssetsCopy, delAsset)
		a.Equal(oldAssetsCopy, newAssets)
	}

	assetByIndex := func(gi, ai int, e ExtendedAssetHolding) basics.AssetIndex {
		aidx := e.Groups[gi].MinAssetIndex
		for i := 0; i <= ai; i++ {
			aidx += e.Groups[gi].groupData.AssetOffsets[i]
		}
		return aidx
	}

	// delete a group with only one item
	e.Delete(1, 0)
	a.Equal(oldCount-1, e.Count)
	a.Equal(len(spec)-1, len(e.Groups))

	gap := int(spec[0].end-spec[0].start) / spec[0].count

	// delete first entry in a group
	e = genExtendedHolding(t, spec)
	aidx = assetByIndex(0, 0, e)
	e.Delete(0, 0)
	a.Equal(oldCount-1, e.Count)
	a.Equal(len(spec), len(e.Groups))
	a.Equal(spec[0].start+basics.AssetIndex(gap), e.Groups[0].MinAssetIndex)
	a.Equal(uint64(spec[0].end-spec[0].start-basics.AssetIndex(gap)), e.Groups[0].DeltaMaxAssetIndex)
	checkAssetMap(aidx, e.Groups[0])

	// delete last entry in a group
	e = genExtendedHolding(t, spec)
	aidx = assetByIndex(0, spec[0].count-1, e)
	e.Delete(0, spec[0].count-1)
	a.Equal(oldCount-1, e.Count)
	a.Equal(len(spec), len(e.Groups))
	a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
	// assets are 10, 12, 14, ..., 700
	// the second last is 2 * (spec[0].count-2) + 10
	// so the delta = (spec[0].count-2)*gap + 10 -10
	a.Equal(uint64((spec[0].count-2)*gap), e.Groups[0].DeltaMaxAssetIndex)
	checkAssetMap(aidx, e.Groups[0])

	// delete some middle entry
	e = genExtendedHolding(t, spec)
	aidx = assetByIndex(0, 1, e)
	e.Delete(0, 1)
	a.Equal(oldCount-1, e.Count)
	a.Equal(len(spec), len(e.Groups))
	a.Equal(spec[0].start, e.Groups[0].MinAssetIndex)
	a.Equal(uint64(spec[0].end-spec[0].start), e.Groups[0].DeltaMaxAssetIndex)
	checkAssetMap(aidx, e.Groups[0])
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
		delOrder := rand.Perm(maxIdx)
		for _, i := range delOrder {
			if i < int(e.Groups[0].Count) {
				e.Delete(0, i)
			}
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
