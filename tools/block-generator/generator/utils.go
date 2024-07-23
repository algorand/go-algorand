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
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-codec/codec"
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

func indexToAccount(i uint64) (addr basics.Address) {
	// Make sure we don't generate a zero address by adding 1 to i
	binary.LittleEndian.PutUint64(addr[:], i+1)
	return
}

func accountToIndex(a basics.Address) (addr uint64) {
	// Make sure we don't generate a zero address by adding 1 to i
	return binary.LittleEndian.Uint64(a[:]) - 1
}

func convertToGenesisBalances(balances []uint64) map[basics.Address]basics.AccountData {
	genesisBalances := make(map[basics.Address]basics.AccountData)
	for i, balance := range balances {
		genesisBalances[indexToAccount(uint64(i))] = basics.AccountData{
			MicroAlgos: basics.MicroAlgos{Raw: balance},
		}
	}
	return genesisBalances
}

func encode(handle codec.Handle, obj interface{}) ([]byte, error) {
	var output []byte
	enc := codec.NewEncoderBytes(&output, handle)

	err := enc.Encode(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to encode object: %w", err)
	}
	return output, nil
}
