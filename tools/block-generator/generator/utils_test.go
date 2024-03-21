// Copyright (C) 2019-2024 Algorand, Inc.
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

package generator

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWeightedSelectionInternalBadInput(t *testing.T) {
	partitiontest.PartitionTest(t)
	weights := []float32{0.10, 0.30}
	options := []interface{}{"10"}
	_, err := weightedSelectionInternal(0, weights, options, nil)
	require.EqualError(t, err, "number of weights must equal number of options: 2 != 1")
}

func TestWeightedSelectionInternal(t *testing.T) {
	partitiontest.PartitionTest(t)
	weights := []float32{0.10, 0.30, 0.60}
	options := []interface{}{"10", "30", "60"}

	testcases := []struct {
		selectionNum float32
		expected     interface{}
	}{
		{
			selectionNum: 0.0,
			expected:     options[0],
		},
		{
			selectionNum: 0.099,
			expected:     options[0],
		},
		{
			selectionNum: 0.1,
			expected:     options[1],
		},
		{
			selectionNum: 0.399,
			expected:     options[1],
		},
		{
			selectionNum: 0.4,
			expected:     options[2],
		},
		{
			selectionNum: 0.999,
			expected:     options[2],
		},
	}

	for _, test := range testcases {
		name := fmt.Sprintf("selectionNum %f - expected %v", test.selectionNum, test.expected)
		t.Run(name, func(t *testing.T) {
			actual, err := weightedSelectionInternal(test.selectionNum, weights, options, nil)
			require.NoError(t, err)
			require.Equal(t, test.expected, actual)
		})
	}
}

func TestWeightedSelection(t *testing.T) {
	partitiontest.PartitionTest(t)
	weights := []float32{0.10, 0.30, 0.60}
	options := []interface{}{"10", "30", "60"}
	selections := make(map[interface{}]int)

	for i := 0; i < 100; i++ {
		selected, err := weightedSelection(weights, options, nil)
		require.NoError(t, err)
		selections[selected]++
	}

	assert.Less(t, selections[options[0]], selections[options[1]])
	assert.Less(t, selections[options[1]], selections[options[2]])
}

func TestWeightedSelectionOutOfRange(t *testing.T) {
	partitiontest.PartitionTest(t)
	weights := []float32{0.1}
	options := []interface{}{"1"}
	defaultOption := "DEFAULT!"

	for i := 0; i < 10000; i++ {
		selection, err := weightedSelection(weights, options, defaultOption)
		require.NoError(t, err)
		if selection == defaultOption {
			return
		}
	}
	assert.Fail(t, "Expected an out of range error by this point.")
}

func TestConvertToGenesisBalance(t *testing.T) {
	partitiontest.PartitionTest(t)
	balance := []uint64{100, 200, 300}
	genesisBalances := convertToGenesisBalances(balance)
	require.Equal(t, 3, len(genesisBalances))
	for i, bal := range balance {
		require.Equal(t, bal, genesisBalances[indexToAccount(uint64(i))].MicroAlgos.Raw)
	}
}

func TestIndexToAccountAndAccountToIndex(t *testing.T) {
	partitiontest.PartitionTest(t)
	account := indexToAccount(1)
	fmt.Printf("account: %v\n", account)
	for i := uint64(0); i < uint64(100000); i++ {
		acct := indexToAccount(i)
		result := accountToIndex(acct)
		require.Equal(t, i, result)
	}
}
