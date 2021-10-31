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

	keysPerWorker := numberOfKeys / uint64(runtime.NumCPU()*2)

	var wg sync.WaitGroup
	for i, j := uint64(0), keysPerWorker; i < numberOfKeys; i, j = j, j+keysPerWorker {
		if j > numberOfKeys {
			j = numberOfKeys
		}
		// These goroutines share memory, but only for reading.
		wg.Add(1)
		go func(i, j uint64) {
			for k := i; k < j; k++ {
				sigAlgo, err := crypto.NewSigner(sigAlgoType)
				if err != nil {

				}
				keys[k] = *sigAlgo
			}
			wg.Done()
		}(i, j)
	}
	wg.Wait()

	return keys, nil
}

func LinerKeyStore(numberOfKeys uint64, sigAlgoType crypto.AlgorithmType) ([]crypto.GenericSigningKey, error) {
	keys := make([]crypto.GenericSigningKey, numberOfKeys)
	for i := range keys {
		sigAlgo, err := crypto.NewSigner(sigAlgoType)
		if err != nil {
			return nil, err
		}
		keys[i] = *sigAlgo
	}
	return keys, nil
}
