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
