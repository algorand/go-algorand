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
	"github.com/algorand/go-algorand/crypto"
	"runtime"
	"sync"
)

// KeyStoreBuilder Responsible for generate slice of keys in a specific AlgorithmType.
// this function trys to optimize this process by using Goroutines.
func KeyStoreBuilder(numberOfKeys uint64, sigAlgoType crypto.AlgorithmType) ([]crypto.GenericSigningKey, error) {
	keys := make([]crypto.GenericSigningKey, numberOfKeys)

	var numberOfWorkers uint64
	numOfCores := uint64(runtime.NumCPU() * 2)

	if numberOfKeys > numOfCores {
		numberOfWorkers = numberOfKeys / numOfCores
	} else {
		numberOfWorkers = numberOfKeys
	}

	var wg sync.WaitGroup
	var endIdx uint64
	for i := uint64(0); i < numberOfKeys; i = endIdx {
		endIdx = i + numberOfWorkers
		// in case the next iteration will pass the number of keys.
		// we add this section to the last worker.
		if endIdx+numberOfWorkers > numberOfKeys {
			endIdx = numberOfKeys
		}

		wg.Add(1)
		go func(starIdx, endIdx uint64) {
			for k := starIdx; k < endIdx; k++ {
				sigAlgo, err := crypto.NewSigner(sigAlgoType)
				if err != nil {

				}
				keys[k] = *sigAlgo
			}
			wg.Done()
		}(i, endIdx)
	}
	wg.Wait()
	return keys, nil
}
