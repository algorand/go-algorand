// Copyright (C) 2019-2020 Algorand, Inc.
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

package ledger

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
)

type emptyLedger struct {
}

func (ml *emptyLedger) lookup(addr basics.Address) (basics.AccountData, error) {
	return basics.AccountData{}, nil
}

func (ml *emptyLedger) isDup(firstValid, lastValid basics.Round, txn transactions.Txid, txl txlease) (bool, error) {
	return false, nil
}

func (ml *emptyLedger) getAssetCreator(assetIdx basics.AssetIndex) (basics.Address, bool, error) {
	return basics.Address{}, false, nil
}

func (ml *emptyLedger) getAppCreator(appIdx basics.AppIndex) (basics.Address, bool, error) {
	return basics.Address{}, false, nil
}

func (ml *emptyLedger) getCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return basics.Address{}, false, nil
}

func (ml *emptyLedger) getStorageCounts(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	return basics.StateSchema{}, nil
}

func (ml *emptyLedger) Allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error) {
	return false, nil
}

func (ml *emptyLedger) GetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) (basics.TealValue, bool, error) {
	return basics.TealValue{}, false, nil
}

func (ml *emptyLedger) txnCounter() uint64 {
	return 0
}

// stateTracker tracks the expected state of an account's storage after a
// series of allocs, dallocs, reads, writes, and deletes
type stateTracker struct {
	// Expected keys/values for addrApp
	storage map[addrApp]basics.TealKeyValue

	// Expected allocation state for addrApp
	allocState map[addrApp]bool

	// max StateSchema for addrApp
	schemas map[addrApp]basics.StateSchema
}

func makeStateTracker() stateTracker {
	return stateTracker{
		storage:    make(map[addrApp]basics.TealKeyValue),
		allocState: make(map[addrApp]bool),
		schemas:    make(map[addrApp]basics.StateSchema),
	}
}

func (st *stateTracker) alloc(aapp addrApp, schema basics.StateSchema) error {
	if st.allocated(aapp) {
		return fmt.Errorf("already allocated")
	}
	st.allocState[aapp] = true
	st.schemas[aapp] = schema
	st.storage[aapp] = make(basics.TealKeyValue)
	return nil
}

func (st *stateTracker) dealloc(aapp addrApp) error {
	if !st.allocated(aapp) {
		return fmt.Errorf("not allocated")
	}
	delete(st.allocState, aapp)
	delete(st.schemas, aapp)
	delete(st.storage, aapp)
	return nil
}

func (st *stateTracker) allocated(aapp addrApp) bool {
	return st.allocState[aapp]
}

func (st *stateTracker) get(aapp addrApp, key string) (basics.TealValue, bool, error) {
	if !st.allocated(aapp) {
		return basics.TealValue{}, false, fmt.Errorf("not allocated")
	}
	val, ok := st.storage[aapp][key]
	return val, ok, nil
}

func (st *stateTracker) set(aapp addrApp, key string, val basics.TealValue) error {
	if !st.allocated(aapp) {
		return fmt.Errorf("not allocated")
	}
	st.storage[aapp][key] = val
	return nil
}

func (st *stateTracker) del(aapp addrApp, key string) error {
	if !st.allocated(aapp) {
		return fmt.Errorf("not allocated")
	}
	delete(st.storage[aapp], key)
	return nil
}

func randomAddrApps(n int) []addrApp {
	out := make([]addrApp, n)
	for i := 0; i < n; i++ {
		out[i] = addrApp{
			addr:   randomAddress(),
			aidx:   basics.AppIndex(rand.Intn(100000) + 1),
			global: rand.Intn(2) == 0,
		}
	}
	return out
}

func TestCowStorage(t *testing.T) {
	ml := emptyLedger{}
	cow := makeRoundCowState(&ml, bookkeeping.BlockHeader{}, 0)
	allAapps := randomAddrApps(10)

	st := makeStateTracker()

	var lastParent *roundCowState
	const maxChildDepth = 10
	childDepth := 0

	allKeys := make([]string, 10)
	for i := 0; i < len(allKeys); i++ {
		allKeys[i] = fmt.Sprintf("%d", i)
	}

	allValues := make([]basics.TealValue, 100)
	for i := 0; i < len(allValues); i++ {
		allValues[i] = basics.TealValue{
			Type:  basics.TealBytesType,
			Bytes: fmt.Sprintf("%d", i),
		}
	}

	for i := 0; i < 1000; i++ {
		// Pick a random aapp
		aapp := allAapps[rand.Intn(len(allAapps))]

		// Do some random, valid actions and check that the behavior is
		// what we expect

		// Allocate
		if rand.Float32() < 0.25 {
			actuallyAllocated := st.allocated(aapp)
			err := cow.Allocate(aapp.addr, aapp.aidx, aapp.global)
			if actuallyAllocated {
				require.Error(t, err)
				require.Contains(t, err.Error(), "cannot allocate")
			} else {
				require.NoError(t, err)
				rschema := basics.StateSchema{
					NumUint:      rand.Uint64(),
					NumByteSlice: rand.Uint64(),
				}
				err = st.alloc(aapp, rschema)
				require.NoError(t, err)
			}
		}

		// Deallocate
		if rand.Float32() < 0.25 {
			actuallyAllocated := st.allocated(aapp)
			err := cow.Deallocate(aapp.addr, aapp.aidx, aapp.global)
			if actuallyAllocated {
				require.NoError(t, err)
				err := st.dealloc(aapp)
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), "cannot deallocate")
			}
		}

		// Write a random key/value
		if rand.Float32() < 0.25 {
			actuallyAllocated := st.allocated(aapp)
			rkey := allKeys[rand.Intn(len(allKeys))]
			rval := allValues[rand.Intn(len(allValues))]
			err := cow.SetKey(aapp.addr, aapp.aidx, aapp.global, rkey, rval)
			if actuallyAllocated {
				require.NoError(t, err)
				err = st.set(aapp, rkey, rval)
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), "cannot set")
			}
		}

		// Delete a random key/value
		if rand.Float32() < 0.25 {
			actuallyAllocated := st.allocated(aapp)
			rkey := allKeys[rand.Intn(len(allKeys))]
			err := cow.DelKey(aapp.addr, aapp.aidx, aapp.global, rkey)
			if actuallyAllocated {
				require.NoError(t, err)
				err = st.del(aapp, rkey)
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), "cannot del")
			}
		}

		// Collapse a child
		if childDepth > 0 && rand.Float32() < 0.1 {
			cow.commitToParent()
			cow = lastParent
			childDepth--
		}

		// Make a child
		if childDepth < maxChildDepth && rand.Float32() < 0.1 {
			lastParent = cow
			cow = cow.child()
			childDepth++
		}

		// Check that cow matches our computed state
		for _, aapp := range allAapps {
			// Allocations should match
			actuallyAllocated := st.allocated(aapp)
			cowAllocated, err := cow.Allocated(aapp.addr, aapp.aidx, aapp.global)
			require.NoError(t, err)
			require.Equal(t, actuallyAllocated, cowAllocated)

			// All storage should match
			if actuallyAllocated {
				for _, key := range allKeys {
					tval, tok, err := st.get(aapp, key)
					require.NoError(t, err)

					cval, cok, err := cow.GetKey(aapp.addr, aapp.aidx, aapp.global, key)
					require.NoError(t, err)
					require.Equal(t, tok, cok)
					require.Equal(t, tval, cval)
				}

				tcounts := basics.StateSchema{
					NumByteSlice: uint64(len(st.storage[aapp])),
				}
				ccounts, err := cow.getStorageCounts(aapp.addr, aapp.aidx, aapp.global)
				require.NoError(t, err)
				require.Equal(t, tcounts, ccounts)
			}
		}
	}
}
