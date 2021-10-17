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

package merklekeystore

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoundToIndex(t *testing.T) {

	// firstValid <= interval
	firstValid := uint64(100)
	interval := uint64(101)

	// round == firstValid (< 101) will fail
	for round := uint64(101); round < 5*interval; round += interval {
		index := roundToIndex(firstValid, uint64(round), interval)
		round2 := indexToRound(firstValid, interval, uint64(index))
		require.Equal(t, round, round2)
		index2 := roundToIndex(firstValid, uint64(round+interval-1), interval)
		require.Equal(t, index, index2)
		if round == uint64(101) {
			round = firstValid
		}
	}

	// firstValid <= interval
	firstValid = uint64(100)
	interval = uint64(99)

	for round := firstValid; round < 5*interval; round += interval {
		index := roundToIndex(firstValid, uint64(round), interval)
		round2 := indexToRound(firstValid, interval, uint64(index))
		require.Equal(t, round, round2)
		index2 := roundToIndex(firstValid, uint64(round+interval-1), interval)
		require.Equal(t, index, index2)
	}

	// firstValid <= interval
	firstValid = uint64(100)
	interval = uint64(20)

	for round := firstValid; round < 5*interval; round += interval {
		index := roundToIndex(firstValid, uint64(round), interval)
		round2 := indexToRound(firstValid, interval, uint64(index))
		require.Equal(t, round, round2)
		index2 := roundToIndex(firstValid, uint64(round+interval-1), interval)
		require.Equal(t, index, index2)
	}
}

func TestIndexToRoundToIndex(t *testing.T) {

	count := 2

	// firstValid <= interval
	for pos := 0; pos < count; pos++ {
		firstValid := uint64(100)
		interval := uint64(101)

		round := indexToRound(firstValid, interval, uint64(pos))
		index := roundToIndex(firstValid, round, interval)
		fmt.Printf("firstValid %d interval %d pos: %d round: %d  index: %d \n", firstValid, interval, pos, round, index)
		require.Equal(t, uint64(pos), index)
	}
	fmt.Println()

	//firstValid > interval
	for pos := 0; pos < count; pos++ {
		firstValid := uint64(100)
		interval := uint64(99)

		round := indexToRound(firstValid, interval, uint64(pos))
		index := roundToIndex(firstValid, round, interval)
		fmt.Printf("firstValid %d interval %d pos: %d round: %d  index: %d \n", firstValid, interval, pos, round, index)
		require.Equal(t, uint64(pos), index)
	}
	fmt.Println()

	//firstValid >>> interval
	for pos := 0; pos < count; pos++ {
		firstValid := uint64(100)
		interval := uint64(20)

		round := indexToRound(firstValid, interval, uint64(pos))
		index := roundToIndex(firstValid, round, interval)
		fmt.Printf("firstValid %d interval %d pos: %d round: %d  index: %d \n", firstValid, interval, pos, round, index)
		require.Equal(t, uint64(pos), index)
	}

}
