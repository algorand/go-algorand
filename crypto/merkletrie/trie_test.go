// Copyright (C) 2019-2023 Algorand, Inc.
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
	"github.com/algorand/go-algorand/test/partitiontest"
)

const (
	defaultTestEvictSize = 10000
)

func TestAddingAndRemoving(t *testing.T) {
	partitiontest.PartitionTest(t)

	mt, _ := MakeTrie(nil, defaultTestMemoryConfig)
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
		require.Equal(t, i+1, int(stats.LeafCount))
	}

	stats, _ := mt.GetStats()
	require.Equal(t, len(hashes), int(stats.LeafCount))
	require.Equal(t, 4, int(stats.Depth))
	require.Equal(t, 10915, int(stats.NodesCount))
	require.Equal(t, 1135745, int(stats.Size))
	require.True(t, int(stats.NodesCount) > len(hashes))
	require.True(t, int(stats.NodesCount) < 2*len(hashes))

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
	require.Equal(t, 0, int(stats.LeafCount))
	require.Equal(t, 0, int(stats.Depth))

	// add the items in a different order.
	hashesOrder := rand.New(rand.NewSource(1234567)).Perm(len(hashes))
	for i := 0; i < len(hashes); i++ {
		addResult, _ := mt.Add(hashes[hashesOrder[i]][:])
		require.Equal(t, true, addResult)
	}

	randomOrderedHashesRoot, _ := mt.RootHash()
	require.Equal(t, randomOrderedHashesRoot, allHashesAddedRoot)
}

func TestRandomAddingAndRemoving(t *testing.T) {
	partitiontest.PartitionTest(t)

	mt, err := MakeTrie(nil, defaultTestMemoryConfig)
	require.NoError(t, err)

	// create 10000 hashes.
	toAddHashes := make([][]byte, 10000)
	for i := 0; i < len(toAddHashes); i++ {
		hash := crypto.Hash([]byte{byte(i % 256), byte(i / 256)})
		toAddHashes[i] = hash[:]
	}
	toRemoveHashes := make([][]byte, 0, 10000)

	nextOperation := 0 // 0 is for adding, 1 is for removing.
	for i := 0; i < 100000; i++ {
		if nextOperation == 0 && len(toAddHashes) == 0 {
			nextOperation = 1
		}
		if nextOperation == 1 && len(toRemoveHashes) == 0 {
			nextOperation = 0
		}
		var processesHash []byte
		if nextOperation == 0 {
			// pick an item to add:
			semiRandomIdx := int(toAddHashes[0][0]) + int(toAddHashes[0][1])*256 + int(toAddHashes[0][3])*65536 + i
			semiRandomIdx %= len(toAddHashes)
			processesHash = toAddHashes[semiRandomIdx]
			addResult, err := mt.Add(processesHash)
			require.NoError(t, err)
			require.Equal(t, true, addResult)

			toRemoveHashes = append(toRemoveHashes, toAddHashes[semiRandomIdx])
			toAddHashes = append(toAddHashes[:semiRandomIdx], toAddHashes[semiRandomIdx+1:]...)
		} else {
			// pick an item to remove:
			semiRandomIdx := int(toRemoveHashes[0][0]) + int(toRemoveHashes[0][1])*256 + int(toRemoveHashes[0][3])*65536 + i
			semiRandomIdx %= len(toRemoveHashes)
			processesHash = toRemoveHashes[semiRandomIdx]
			deleteResult, err := mt.Delete(processesHash)
			require.NoError(t, err)
			require.Equal(t, true, deleteResult)

			toAddHashes = append(toAddHashes, toRemoveHashes[semiRandomIdx])
			toRemoveHashes = append(toRemoveHashes[:semiRandomIdx], toRemoveHashes[semiRandomIdx+1:]...)
		}
		if processesHash[0] > 128 {
			nextOperation = 0
		} else {
			nextOperation = 1
		}
		if (i % (1 + int(processesHash[0]))) == 42 {
			_, err := mt.Commit()
			require.NoError(t, err)
			verifyCacheNodeCount(t, mt)
		}
	}
}
