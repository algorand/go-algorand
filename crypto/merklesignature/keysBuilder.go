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
	"context"
	"runtime"
	"sync"

	"github.com/algorand/go-algorand/crypto"
)

// KeysBuilder Responsible for generate slice of falcon keys
func KeysBuilder(numberOfKeys uint64) ([]crypto.FalconSigner, error) {
	numOfKeysPerRoutine, _ := calculateRanges(numberOfKeys)

	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	errors := make(chan error, 1)
	defer close(errors)

	var wg sync.WaitGroup
	var endIdx uint64
	keys := make([]crypto.FalconSigner, numberOfKeys)

	for i := uint64(0); i < numberOfKeys; i = endIdx {
		endIdx = i + numOfKeysPerRoutine
		// in case the number of workers is not equally divides the number of keys
		// we want the last worker take care of them.
		if endIdx+numOfKeysPerRoutine > numberOfKeys {
			endIdx = numberOfKeys
		}

		wg.Add(1)
		go func(startIdx, endIdx uint64, keys []crypto.FalconSigner) {
			defer wg.Done()
			if err := generateKeysForRange(ctx, startIdx, endIdx, keys); err != nil {
				// write to the error channel, if it's not full already.
				select {
				case errors <- err:
				default:
				}
				ctxCancel()
			}
		}(i, endIdx, keys)
	}
	// wait until all the go-routines are over.
	wg.Wait()

	select {
	case err := <-errors:
		return []crypto.FalconSigner{}, err
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

func generateKeysForRange(ctx context.Context, startIdx uint64, endIdx uint64, keys []crypto.FalconSigner) error {
	for k := startIdx; k < endIdx; k++ {
		if ctx.Err() != nil {
			return nil //nolint:nilerr // we don't need to return the ctx error, since the other goroutine will report it.
		}
		sigAlgo, err := crypto.NewFalconSigner()
		if err != nil {
			return err
		}
		keys[k] = *sigAlgo
	}
	return nil
}
