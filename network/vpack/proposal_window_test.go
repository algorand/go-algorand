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

package vpack

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func makeTestPropBundle(seed byte) proposalEntry {
	var p proposalEntry
	for i := range p.dig {
		p.dig[i] = seed
	}
	p.operLen = 1
	p.operEnc[0] = seed
	p.mask = bitDig | bitOper
	return p
}

func TestPropWindowHPACK(t *testing.T) {
	partitiontest.PartitionTest(t)
	var w propWindow

	// 1. Insert seven unique entries (fills the window).
	for i := 0; i < proposalWindowSize; i++ {
		pb := makeTestPropBundle(byte(i))
		w.insertNew(pb)
		require.Equal(t, i+1, w.size, "size incorrect after insertNew")
		// Newly inserted entry should always be HPACK index 1 (MRU).
		require.Equal(t, 1, w.lookup(pb), "lookup did not return 1")
	}

	// 2. Verify byRef/lookup mapping for current content.
	for idx := 1; idx <= proposalWindowSize; idx++ {
		prop, ok := w.byRef(idx)
		require.True(t, ok)
		expectedSeed := byte(proposalWindowSize - idx) // newest (idx==1) == seed 6, oldest (idx==7) == seed 0
		want := makeTestPropBundle(expectedSeed)
		require.Equal(t, want, prop)
	}

	// 3. Insert an eighth entry – should evict the oldest (seed 0).
	evicted := makeTestPropBundle(0)
	newEntry := makeTestPropBundle(7)
	w.insertNew(newEntry)
	require.Equal(t, proposalWindowSize, w.size, "size after eviction incorrect")

	// Oldest should now be former seed 1, and evicted one should not be found.
	require.Equal(t, 0, w.lookup(evicted), "evicted entry still found")

	// New entry must be at HPACK index 1.
	require.Equal(t, 1, w.lookup(newEntry), "newest entry lookup not 1")

	// Verify byRef again: idx 1 == seed 7, idx 7 == seed 1
	prop, ok := w.byRef(1)
	require.True(t, ok)
	require.Equal(t, newEntry, prop)

	prop, ok = w.byRef(proposalWindowSize)
	require.True(t, ok)
	require.Equal(t, makeTestPropBundle(1), prop)
}
