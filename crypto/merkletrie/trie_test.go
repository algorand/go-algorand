// Copyright (C) 2019-2020 Algorand, Inc.
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

package merkletrie

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
)

const (
	defaultTestEvictSize = 10000
)

func TestAddingAndRemoving(t *testing.T) {
	mt, _ := MakeTrie(nil, defaultTestEvictSize)
	// create 10000 hashes.
	hashes := make([]crypto.Digest, 10000)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte(i / 256)})
	}

	rootsWhileAdding := make([]crypto.Digest, len(hashes))
	for i := 0; i < len(hashes); i++ {
		addResult, _ := mt.Add(hashes[i][:])
		require.Equal(t, true, addResult)
		rootsWhileAdding[i], _ = mt.RootHash()
		stats, _ := mt.GetStats()
		require.Equal(t, i+1, int(stats.leafCount))
	}

	stats, _ := mt.GetStats()
	require.Equal(t, len(hashes), int(stats.leafCount))
	require.Equal(t, 4, int(stats.depth))
	require.Equal(t, 10915, int(stats.nodesCount))
	require.Equal(t, 2490656, int(stats.size))
	require.True(t, int(stats.nodesCount) > len(hashes))
	require.True(t, int(stats.nodesCount) < 2*len(hashes))

	allHashesAddedRoot, _ := mt.RootHash()

	for i := len(hashes) - 1; i >= 0; i-- {
		roothash, _ := mt.RootHash()
		require.Equalf(t, rootsWhileAdding[i], roothash, "i=%d", i)
		deleteResult, _ := mt.Delete(hashes[i][:])
		require.Equalf(t, true, deleteResult, "number %d", i)

	}

	roothash, _ := mt.RootHash()
	require.Equal(t, crypto.Digest{}, roothash)
	stats, _ = mt.GetStats()
	require.Equal(t, 0, int(stats.leafCount))
	require.Equal(t, 0, int(stats.depth))

	// add the items in a different order.
	hashesOrder := rand.New(rand.NewSource(1234567)).Perm(len(hashes))
	for i := 0; i < len(hashes); i++ {
		addResult, _ := mt.Add(hashes[hashesOrder[i]][:])
		require.Equal(t, true, addResult)
	}

	randomOrderedHashesRoot, _ := mt.RootHash()
	require.Equal(t, randomOrderedHashesRoot, allHashesAddedRoot)
}
