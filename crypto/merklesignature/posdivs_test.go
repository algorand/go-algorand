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

package merklesignature

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestRoundToIndex(t *testing.T) {
	partitiontest.PartitionTest(t)

	count := uint64(200)

	// firstValid <= keyLifetime
	firstValid := uint64(100)
	keyLifetime := uint64(101)
	ic := uint64(1)
	checkRoundToIndex(count, ic, firstValid, keyLifetime, t)

	// firstValid > keyLifetime
	firstValid = uint64(100)
	keyLifetime = uint64(99)
	ic = uint64(2)
	checkRoundToIndex(count, ic, firstValid, keyLifetime, t)

	// firstValid >> keyLifetime
	firstValid = uint64(100)
	keyLifetime = uint64(20)
	ic = uint64(5)
	checkRoundToIndex(count, ic, firstValid, keyLifetime, t)
}

func TestIndexToRoundToIndex(t *testing.T) {
	partitiontest.PartitionTest(t)

	count := uint64(200)
	firstValid := uint64(100)
	keyLifetime := uint64(101)
	checkIndexToRoundToIndex(count, firstValid, keyLifetime, t)

	firstValid = uint64(100)
	keyLifetime = uint64(99)
	checkIndexToRoundToIndex(count, firstValid, keyLifetime, t)

	firstValid = uint64(100)
	keyLifetime = uint64(20)
	checkIndexToRoundToIndex(count, firstValid, keyLifetime, t)
}

func TestErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	firstValid := uint64(101)
	round := firstValid - 1
	keyLifetime := round / 2
	require.Equal(t, errRoundFirstValid, checkMerkleSignatureSchemeParams(firstValid, round, keyLifetime))

	keyLifetime = 0
	require.Equal(t, ErrKeyLifetimeIsZero, checkMerkleSignatureSchemeParams(firstValid, round, keyLifetime))

	keyLifetime = 107
	round = 107
	firstValid = 107
	require.NoError(t, checkMerkleSignatureSchemeParams(firstValid, round, keyLifetime))
}

func checkIndexToRoundToIndex(count, firstValid, keyLifetime uint64, t *testing.T) {
	for pos := uint64(0); pos < count; pos++ {
		round := indexToRound(firstValid, keyLifetime, uint64(pos))
		index := roundToIndex(firstValid, round, keyLifetime)
		require.Equal(t, uint64(pos), index)
	}

}

func checkRoundToIndex(count, initC, firstValid, keyLifetime uint64, t *testing.T) {
	expIndex := uint64(0)
	for c := initC; c < count; c++ {
		round := keyLifetime * c
		index := roundToIndex(firstValid, round, keyLifetime)
		require.Equal(t, expIndex, index)
		expIndex++
		round2 := indexToRound(firstValid, keyLifetime, index)
		require.Equal(t, round, round2)
	}

}
