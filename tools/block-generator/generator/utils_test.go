package generator

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWeightedSelectionInternalBadInput(t *testing.T) {
	weights := []float32{0.10, 0.30}
	options := []interface{}{"10"}
	_, err := weightedSelectionInternal(0, weights, options, nil)
	require.EqualError(t, err, "number of weights must equal number of options: 2 != 1")
}

func TestWeightedSelectionInternal(t *testing.T) {
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
