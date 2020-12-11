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
	"github.com/algorand/go-algorand/protocol"
)

type emptyLedger struct {
}

func (ml *emptyLedger) lookup(addr basics.Address) (basics.AccountData, error) {
	return basics.AccountData{}, nil
}

func (ml *emptyLedger) checkDup(firstValid, lastValid basics.Round, txn transactions.Txid, txl txlease) error {
	return nil
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

func (ml *emptyLedger) getStorageLimits(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	return basics.StateSchema{}, nil
}

func (ml *emptyLedger) allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error) {
	return false, nil
}

func (ml *emptyLedger) getKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) (basics.TealValue, bool, error) {
	return basics.TealValue{}, false, nil
}

func (ml *emptyLedger) txnCounter() uint64 {
	return 0
}

func (ml *emptyLedger) blockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{}, nil
}

func (ml *emptyLedger) compactCertLast() basics.Round {
	return basics.Round(0)
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

func randomAddrApps(n int) ([]storagePtr, []basics.Address) {
	out := make([]storagePtr, n)
	outa := make([]basics.Address, n)
	for i := 0; i < n; i++ {
		out[i] = storagePtr{
			aidx:   basics.AppIndex(rand.Intn(100000) + 1),
			global: rand.Intn(2) == 0,
		}
		outa[i] = randomAddress()
	}
	return out, outa
}

func TestCowStorage(t *testing.T) {
	ml := emptyLedger{}
	var bh bookkeeping.BlockHeader
	bh.CurrentProtocol = protocol.ConsensusCurrentVersion
	cow := makeRoundCowState(&ml, bh, 0)
	allSptrs, allAddrs := randomAddrApps(10)

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
		if i%2 == 0 {
			allValues[i] = basics.TealValue{
				Type:  basics.TealBytesType,
				Bytes: fmt.Sprintf("%d", i),
			}
		} else {
			allValues[i] = basics.TealValue{
				Type: basics.TealUintType,
				Uint: uint64(i),
			}
		}
	}

	iters := 1000
	for i := 0; i < iters; i++ {
		// Pick a random sptr
		r := rand.Intn(len(allSptrs))
		sptr := allSptrs[r]
		addr := allAddrs[r]
		aapp := addrApp{addr: addr, aidx: sptr.aidx, global: sptr.global}

		// Do some random, valid actions and check that the behavior is
		// what we expect

		// Allocate
		if rand.Float32() < 0.25 {
			actuallyAllocated := st.allocated(aapp)
			rschema := basics.StateSchema{
				NumUint:      rand.Uint64(),
				NumByteSlice: rand.Uint64(),
			}
			err := cow.Allocate(addr, sptr.aidx, sptr.global, rschema)
			if actuallyAllocated {
				require.Error(t, err)
				require.Contains(t, err.Error(), "cannot allocate")
			} else {
				require.NoError(t, err)
				err = st.alloc(aapp, rschema)
				require.NoError(t, err)
			}
		}

		// Deallocate
		if rand.Float32() < 0.25 {
			actuallyAllocated := st.allocated(aapp)
			err := cow.Deallocate(addr, sptr.aidx, sptr.global)
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
			err := cow.SetKey(addr, sptr.aidx, sptr.global, rkey, rval)
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
			err := cow.DelKey(addr, sptr.aidx, sptr.global, rkey)
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
		for i := range allSptrs {
			sptr = allSptrs[i]
			addr = allAddrs[i]
			aapp = addrApp{addr: addr, aidx: sptr.aidx, global: sptr.global}
			// Allocations should match
			actuallyAllocated := st.allocated(aapp)
			cowAllocated, err := cow.allocated(addr, sptr.aidx, sptr.global)
			require.NoError(t, err)
			require.Equal(t, actuallyAllocated, cowAllocated, fmt.Sprintf("%d, %v, %s", sptr.aidx, sptr.global, addr.String()))

			// All storage should match
			if actuallyAllocated {
				for _, key := range allKeys {
					tval, tok, err := st.get(aapp, key)
					require.NoError(t, err)

					cval, cok, err := cow.GetKey(addr, sptr.aidx, sptr.global, key)
					require.NoError(t, err)
					require.Equal(t, tok, cok)
					require.Equal(t, tval, cval)
				}

				var numByteSlices uint64
				var numUints uint64
				for _, v := range st.storage[aapp] {
					if v.Type == basics.TealBytesType {
						numByteSlices++
					} else {
						numUints++
					}
				}
				tcounts := basics.StateSchema{
					NumByteSlice: numByteSlices,
					NumUint:      numUints,
				}
				ccounts, err := cow.getStorageCounts(addr, sptr.aidx, sptr.global)
				require.NoError(t, err)
				require.Equal(t, tcounts, ccounts)
			}
		}
	}
}

func TestCowBuildDelta(t *testing.T) {
	a := require.New(t)

	creator := randomAddress()
	sender := randomAddress()
	aidx := basics.AppIndex(2)

	cow := roundCowState{}
	cow.sdeltas = make(map[basics.Address]map[storagePtr]*storageDelta)
	txn := transactions.Transaction{}
	ed, err := cow.BuildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Empty(ed)

	cow.sdeltas[creator] = make(map[storagePtr]*storageDelta)
	ed, err = cow.BuildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Empty(ed)

	// check global delta
	cow.sdeltas[creator][storagePtr{aidx, true}] = &storageDelta{}
	ed, err = cow.BuildEvalDelta(1, &txn)
	a.Error(err)
	a.Contains(err.Error(), "found storage delta for different app")
	a.Empty(ed)

	cow.sdeltas[creator][storagePtr{aidx, true}] = &storageDelta{}
	ed, err = cow.BuildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(basics.EvalDelta{GlobalDelta: basics.StateDelta{}}, ed)

	cow.sdeltas[creator][storagePtr{aidx + 1, true}] = &storageDelta{}
	ed, err = cow.BuildEvalDelta(aidx, &txn)
	a.Error(err)
	a.Contains(err.Error(), "found storage delta for different app")
	a.Empty(ed)

	delete(cow.sdeltas[creator], storagePtr{aidx + 1, true})
	cow.sdeltas[sender] = make(map[storagePtr]*storageDelta)
	cow.sdeltas[sender][storagePtr{aidx, true}] = &storageDelta{}
	ed, err = cow.BuildEvalDelta(aidx, &txn)
	a.Error(err)
	a.Contains(err.Error(), "found more than one global delta")
	a.Empty(ed)

	// check local delta
	delete(cow.sdeltas[sender], storagePtr{aidx, true})
	cow.sdeltas[sender][storagePtr{aidx, false}] = &storageDelta{}

	ed, err = cow.BuildEvalDelta(aidx, &txn)
	a.Error(err)
	a.Contains(err.Error(), "could not find offset")
	a.Empty(ed)

	txn.Sender = sender
	ed, err = cow.BuildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(
		basics.EvalDelta{
			GlobalDelta: basics.StateDelta{},
			LocalDeltas: map[uint64]basics.StateDelta{0: {}},
		},
		ed,
	)

	// check actual serialization
	delete(cow.sdeltas[creator], storagePtr{aidx, true})
	cow.sdeltas[sender][storagePtr{aidx, false}] = &storageDelta{
		action: remainAllocAction,
		kvCow: stateDelta{
			"key1": valueDelta{
				old:       basics.TealValue{Type: basics.TealUintType, Uint: 1},
				new:       basics.TealValue{Type: basics.TealUintType, Uint: 2},
				oldExists: true,
				newExists: true,
			},
		},
	}
	ed, err = cow.BuildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(
		basics.EvalDelta{
			GlobalDelta: basics.StateDelta(nil),
			LocalDeltas: map[uint64]basics.StateDelta{
				0: {
					"key1": basics.ValueDelta{Action: basics.SetUintAction, Uint: 2},
				},
			},
		},
		ed,
	)
}

func TestCowDeltaSerialize(t *testing.T) {
	a := require.New(t)

	d := stateDelta{
		"key1": valueDelta{
			old:       basics.TealValue{Type: basics.TealUintType, Uint: 1},
			new:       basics.TealValue{Type: basics.TealUintType, Uint: 2},
			oldExists: true,
			newExists: true,
		},
	}
	sd := d.serialize()
	a.Equal(
		basics.StateDelta{
			"key1": basics.ValueDelta{Action: basics.SetUintAction, Uint: 2},
		},
		sd,
	)

	d = stateDelta{
		"key2": valueDelta{
			old:       basics.TealValue{Type: basics.TealUintType, Uint: 1},
			new:       basics.TealValue{Type: basics.TealBytesType, Bytes: "test"},
			oldExists: true,
			newExists: false,
		},
	}
	sd = d.serialize()
	a.Equal(
		basics.StateDelta{
			"key2": basics.ValueDelta{Action: basics.DeleteAction},
		},
		sd,
	)

	d = stateDelta{
		"key3": valueDelta{
			old:       basics.TealValue{Type: basics.TealUintType, Uint: 1},
			new:       basics.TealValue{Type: basics.TealBytesType, Bytes: "test"},
			oldExists: false,
			newExists: true,
		},
	}
	sd = d.serialize()
	a.Equal(
		basics.StateDelta{
			"key3": basics.ValueDelta{Action: basics.SetBytesAction, Bytes: "test"},
		},
		sd,
	)

	d = stateDelta{
		"key4": valueDelta{
			old:       basics.TealValue{Type: basics.TealUintType, Uint: 1},
			new:       basics.TealValue{Type: basics.TealUintType, Uint: 1},
			oldExists: true,
			newExists: true,
		},
	}
	sd = d.serialize()
	a.Equal(
		basics.StateDelta{},
		sd,
	)

}
