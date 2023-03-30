package generator

import (
	"fmt"
	"math/rand"
)

func weightedSelection(weights []float32, options []interface{}, defaultOption interface{}) (selection interface{}, err error) {
	return weightedSelectionInternal(rand.Float32(), weights, options, defaultOption)
}

func weightedSelectionInternal(selectionNumber float32, weights []float32, options []interface{}, defaultOption interface{}) (selection interface{}, err error) {
	if len(weights) != len(options) {
		err = fmt.Errorf("number of weights must equal number of options: %d != %d", len(weights), len(options))
		return
	}

	total := float32(0)
	for i := 0; i < len(weights); i++ {
		if selectionNumber-total < weights[i] {
			selection = options[i]
			return
		}
		total += weights[i]
	}

	selection = defaultOption
	return
}
