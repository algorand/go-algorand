// Copyright (C) 2019-2022 Algorand, Inc.
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
	"runtime"
	"sync"

	"github.com/algorand/go-algorand/crypto"
)

// KeyStoreBuilder Responsible for generate slice of keys in a specific AlgorithmType.
func KeyStoreBuilder(numberOfKeys uint64, sigAlgoType crypto.AlgorithmType) ([]crypto.GenericSigningKey, error) {
	numOfKeysPerRoutine, numOfRoutines := calculateRanges(numberOfKeys)

	terminate := make(chan struct{})
	defer func() {
		if !isChannelClosed(terminate) {
			close(terminate)
		}
	}()

	errors := make(chan error, numOfRoutines)
	defer close(errors)

	var wg sync.WaitGroup
	var endIdx uint64
	keys := make([]crypto.GenericSigningKey, numberOfKeys)

	for i := uint64(0); i < numberOfKeys; i = endIdx {
		endIdx = i + numOfKeysPerRoutine
		// in case the number of workers is not equally divides the number of keys
		// we want the last worker take care of them.
		if endIdx+numOfKeysPerRoutine > numberOfKeys {
			endIdx = numberOfKeys
		}

		wg.Add(1)
		go func(startIdx, endIdx uint64, errChan chan error, terminate chan struct{}, sigAlgoType crypto.AlgorithmType, keys []crypto.GenericSigningKey) {
			defer wg.Done()
			generateKeysForRange(startIdx, endIdx, errChan, terminate, sigAlgoType, keys)
		}(i, endIdx, errors, terminate, sigAlgoType, keys)
	}
	wg.Wait()

	select {
	case err := <-errors:
		return []crypto.GenericSigningKey{}, err
	default:
	}
	return keys, nil
}

func calculateRanges(numberOfKeys uint64) (numOfKeysPerRoutine uint64, numOfRoutines uint64) {
	numOfRoutines = uint64(runtime.NumCPU() * 2)

	if numberOfKeys > numOfRoutines {
		numOfKeysPerRoutine = numberOfKeys / numOfRoutines
	} else {
		numOfKeysPerRoutine = 1
	}
	return
}

func generateKeysForRange(startIdx uint64, endIdx uint64, errChan chan error, terminate chan struct{}, sigAlgoType crypto.AlgorithmType, keys []crypto.GenericSigningKey) {
	for k := startIdx; k < endIdx; k++ {
		if isChannelClosed(terminate) {
			return
		}
		sigAlgo, err := crypto.NewSigner(sigAlgoType)
		if err != nil {
			errChan <- err
			close(terminate)
			return
		}
		keys[k] = *sigAlgo
	}
}

func isChannelClosed(terminate chan struct{}) bool {
	select {
	case <-terminate:
		return true
	default:
	}
	return false
}
