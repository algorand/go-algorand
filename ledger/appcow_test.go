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

package ledger

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

type addrApp struct {
	addr   basics.Address
	aidx   basics.AppIndex
	global bool
}

type emptyLedger struct {
}

func (ml *emptyLedger) lookup(addr basics.Address) (basics.AccountData, error) {
	return basics.AccountData{}, nil
}

func (ml *emptyLedger) checkDup(firstValid, lastValid basics.Round, txn transactions.Txid, txl ledgercore.Txlease) error {
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

func (ml *emptyLedger) getKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) (basics.TealValue, bool, error) {
	return basics.TealValue{}, false, nil
}

func (ml *emptyLedger) txnCounter() uint64 {
	return 0
}

func (ml *emptyLedger) blockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{}, nil
}

func (ml *emptyLedger) compactCertNext() basics.Round {
	return basics.Round(0)
}

type modsData struct {
	addr  basics.Address
	cidx  basics.CreatableIndex
	ctype basics.CreatableType
}

func getCow(creatables []modsData) *roundCowState {
	cs := &roundCowState{
		mods:  ledgercore.MakeStateDelta(&bookkeeping.BlockHeader{}, 0, 2, 0),
		proto: config.Consensus[protocol.ConsensusCurrentVersion],
	}
	for _, e := range creatables {
		cs.mods.Creatables[e.cidx] = ledgercore.ModifiedCreatable{Ctype: e.ctype, Creator: e.addr, Created: true}
	}
	return cs
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
	cow := makeRoundCowState(&ml, bh, 0, 0)
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
			err := cow.SetKey(addr, sptr.aidx, sptr.global, rkey, rval, 0)
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
			err := cow.DelKey(addr, sptr.aidx, sptr.global, rkey, 0)
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
			cow = cow.child(1)
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

					cval, cok, err := cow.GetKey(addr, sptr.aidx, sptr.global, key, 0)
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
	a.Contains(err.Error(), "invalid Account reference ")
	a.Empty(ed)

	// check v26 behavior for empty deltas
	txn.Sender = sender
	cow.mods.Hdr = &bookkeeping.BlockHeader{
		UpgradeState: bookkeeping.UpgradeState{CurrentProtocol: protocol.ConsensusV25},
	}
	ed, err = cow.BuildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(
		basics.EvalDelta{
			GlobalDelta: basics.StateDelta{},
			LocalDeltas: map[uint64]basics.StateDelta{0: {}},
		},
		ed,
	)

	// check v27 behavior for empty deltas
	cow.mods.Hdr = nil
	cow.proto = config.Consensus[protocol.ConsensusCurrentVersion]
	ed, err = cow.BuildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(
		basics.EvalDelta{
			GlobalDelta: basics.StateDelta{},
			LocalDeltas: map[uint64]basics.StateDelta{},
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

	// check empty sender delta (same key update) and non-empty others
	delete(cow.sdeltas[sender], storagePtr{aidx, false})
	cow.sdeltas[sender][storagePtr{aidx, false}] = &storageDelta{
		action: remainAllocAction,
		kvCow: stateDelta{
			"key1": valueDelta{
				old:       basics.TealValue{Type: basics.TealUintType, Uint: 1},
				new:       basics.TealValue{Type: basics.TealUintType, Uint: 1},
				oldExists: true,
				newExists: true,
			},
		},
	}
	txn.Accounts = append(txn.Accounts, creator)
	cow.sdeltas[creator][storagePtr{aidx, false}] = &storageDelta{
		action: remainAllocAction,
		kvCow: stateDelta{
			"key2": valueDelta{
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
				1: {
					"key2": basics.ValueDelta{Action: basics.SetUintAction, Uint: 2},
				},
			},
		},
		ed,
	)

	// check two keys: empty change and value update
	delete(cow.sdeltas[sender], storagePtr{aidx, false})
	delete(cow.sdeltas[creator], storagePtr{aidx, false})
	cow.sdeltas[sender][storagePtr{aidx, false}] = &storageDelta{
		action: remainAllocAction,
		kvCow: stateDelta{
			"key1": valueDelta{
				old:       basics.TealValue{Type: basics.TealUintType, Uint: 1},
				new:       basics.TealValue{Type: basics.TealUintType, Uint: 1},
				oldExists: true,
				newExists: true,
			},
			"key2": valueDelta{
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
					"key2": basics.ValueDelta{Action: basics.SetUintAction, Uint: 2},
				},
			},
		},
		ed,
	)

	// check pre v26 behavior for account index ordering
	txn.Sender = sender
	txn.Accounts = append(txn.Accounts, sender)
	cow.compatibilityMode = true
	cow.compatibilityGetKeyCache = make(map[basics.Address]map[storagePtr]uint64)
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
		accountIdx: 1,
	}
	ed, err = cow.BuildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(
		basics.EvalDelta{
			GlobalDelta: basics.StateDelta(nil),
			LocalDeltas: map[uint64]basics.StateDelta{
				1: {
					"key1": basics.ValueDelta{Action: basics.SetUintAction, Uint: 2},
				},
			},
		},
		ed,
	)

	// check v27 behavior for account ordering
	cow.compatibilityMode = false
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
		accountIdx: 1,
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

	// check logDelta is added
	cow.logdeltas = make(map[basics.AppIndex][]string)
	cow.logdeltas[aidx] = append(cow.logdeltas[aidx], "hello,world")
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
		accountIdx: 1,
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
			LogDelta: []string{"hello,world"},
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

func TestApplyChild(t *testing.T) {
	a := require.New(t)

	emptyStorageDelta := func(action storageAction) storageDelta {
		return storageDelta{
			action:    action,
			kvCow:     make(stateDelta),
			counts:    &basics.StateSchema{},
			maxCounts: &basics.StateSchema{},
		}
	}
	getSchema := func(u, b int) basics.StateSchema {
		return basics.StateSchema{NumUint: uint64(u), NumByteSlice: uint64(b)}
	}

	parent := emptyStorageDelta(0)
	child := emptyStorageDelta(0)

	chkEmpty := func(delta *storageDelta) {
		a.Empty(delta.action)
		a.Empty(*delta.counts)
		a.Empty(*delta.maxCounts)
		a.Equal(0, len(delta.kvCow))
	}

	parent.applyChild(&child)
	chkEmpty(&parent)
	chkEmpty(&child)

	child.action = deallocAction
	child.kvCow["key1"] = valueDelta{}
	a.Panics(func() { parent.applyChild(&child) })

	// check child overwrites values
	child.action = allocAction
	s1 := getSchema(1, 2)
	s2 := getSchema(3, 4)
	child.counts = &s1
	child.maxCounts = &s2
	parent.applyChild(&child)
	a.Equal(allocAction, parent.action)
	a.Equal(1, len(parent.kvCow))
	a.Equal(getSchema(1, 2), *parent.counts)
	a.Equal(getSchema(3, 4), *parent.maxCounts)

	// check child is correctly merged into parent
	empty := func() valueDelta {
		return valueDelta{
			old:       basics.TealValue{},
			new:       basics.TealValue{},
			oldExists: false, newExists: false,
		}
	}
	created := func(v uint64) valueDelta {
		return valueDelta{
			old:       basics.TealValue{},
			new:       basics.TealValue{Type: basics.TealUintType, Uint: v},
			oldExists: false, newExists: true,
		}
	}
	updated := func(v1, v2 uint64) valueDelta {
		return valueDelta{
			old:       basics.TealValue{Type: basics.TealUintType, Uint: v1},
			new:       basics.TealValue{Type: basics.TealUintType, Uint: v2},
			oldExists: true, newExists: true,
		}
	}
	deleted := func(v uint64) valueDelta {
		return valueDelta{
			old:       basics.TealValue{Type: basics.TealUintType, Uint: v},
			new:       basics.TealValue{},
			oldExists: true, newExists: false,
		}
	}

	var tests = []struct {
		name   string
		pkv    stateDelta
		ckv    stateDelta
		result stateDelta
	}{
		{
			// parent and child have unique keys
			name:   "unique-keys",
			pkv:    map[string]valueDelta{"key1": created(1), "key2": updated(1, 2), "key3": deleted(3)},
			ckv:    map[string]valueDelta{"key4": created(4), "key5": updated(4, 5), "key6": deleted(6)},
			result: map[string]valueDelta{"key1": created(1), "key2": updated(1, 2), "key3": deleted(3), "key4": created(4), "key5": updated(4, 5), "key6": deleted(6)},
		},
		{
			// child updates all parent keys
			name:   "update-keys",
			pkv:    map[string]valueDelta{"key1": created(1), "key2": updated(1, 2), "key3": deleted(3)},
			ckv:    map[string]valueDelta{"key1": updated(1, 2), "key2": updated(2, 3), "key3": updated(0, 4)},
			result: map[string]valueDelta{"key1": created(2), "key2": updated(1, 3), "key3": updated(3, 4)},
		},
		{
			// child deletes all parent keys
			name:   "delete-keys",
			pkv:    map[string]valueDelta{"key1": created(1), "key2": updated(1, 2), "key3": deleted(3)},
			ckv:    map[string]valueDelta{"key1": deleted(1), "key2": deleted(2), "key3": deleted(4)},
			result: map[string]valueDelta{"key1": empty(), "key2": deleted(1), "key3": deleted(3)},
		},
		{
			// child re-creates all parent keys
			name:   "delete-keys",
			pkv:    map[string]valueDelta{"key1": created(1), "key2": updated(1, 2), "key3": deleted(3)},
			ckv:    map[string]valueDelta{"key1": created(2), "key2": created(3), "key3": created(4)},
			result: map[string]valueDelta{"key1": created(2), "key2": updated(1, 3), "key3": updated(3, 4)},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parent := emptyStorageDelta(0)
			ps := getSchema(len(test.pkv), 0)
			parent.counts = &ps
			parent.kvCow = test.pkv

			child := emptyStorageDelta(remainAllocAction)
			cs := getSchema(len(test.ckv)+len(test.pkv), 0)
			child.counts = &cs
			child.kvCow = test.ckv

			parent.applyChild(&child)
			a.Equal(test.result, parent.kvCow)
			a.Equal(cs, *parent.counts)
		})
	}
}

func TestApplyStorageDelta(t *testing.T) {
	a := require.New(t)

	created := valueDelta{
		old:       basics.TealValue{},
		new:       basics.TealValue{Type: basics.TealUintType, Uint: 11},
		oldExists: false, newExists: true,
	}
	updated := valueDelta{
		old:       basics.TealValue{Type: basics.TealUintType, Uint: 22},
		new:       basics.TealValue{Type: basics.TealUintType, Uint: 33},
		oldExists: true, newExists: true,
	}
	deleted := valueDelta{
		old:       basics.TealValue{Type: basics.TealUintType, Uint: 44},
		new:       basics.TealValue{},
		oldExists: true, newExists: false,
	}

	freshAD := func(kv basics.TealKeyValue) basics.AccountData {
		ad := basics.AccountData{}
		ad.AppParams = map[basics.AppIndex]basics.AppParams{
			1: {GlobalState: make(basics.TealKeyValue)},
			2: {GlobalState: kv},
		}
		ad.AppLocalStates = map[basics.AppIndex]basics.AppLocalState{
			1: {KeyValue: make(basics.TealKeyValue)},
			2: {KeyValue: kv},
		}
		return ad
	}

	applyAll := func(kv basics.TealKeyValue, sd *storageDelta) basics.AccountData {
		data, err := applyStorageDelta(freshAD(kv), storagePtr{1, true}, sd)
		a.NoError(err)
		data, err = applyStorageDelta(data, storagePtr{2, true}, sd)
		a.NoError(err)
		data, err = applyStorageDelta(data, storagePtr{1, false}, sd)
		a.NoError(err)
		data, err = applyStorageDelta(data, storagePtr{2, false}, sd)
		a.NoError(err)
		return data
	}

	kv := basics.TealKeyValue{
		"key1": basics.TealValue{Type: basics.TealUintType, Uint: 1},
		"key2": basics.TealValue{Type: basics.TealUintType, Uint: 2},
		"key3": basics.TealValue{Type: basics.TealUintType, Uint: 3},
	}
	sdu := storageDelta{kvCow: map[string]valueDelta{"key4": created, "key5": updated, "key6": deleted}}
	sdd := storageDelta{kvCow: map[string]valueDelta{"key1": created, "key2": updated, "key3": deleted}}

	// check no action
	// no op
	data := applyAll(kv, &sdu)
	a.Equal(0, len(data.AppParams[1].GlobalState))
	a.Equal(len(kv), len(data.AppParams[2].GlobalState))
	a.Equal(0, len(data.AppLocalStates[1].KeyValue))
	a.Equal(len(kv), len(data.AppLocalStates[2].KeyValue))

	// check dealloc action
	// delete all
	sdu.action = deallocAction
	data = applyAll(kv, &sdu)
	a.Equal(0, len(data.AppParams[1].GlobalState))
	a.Equal(0, len(data.AppParams[2].GlobalState))
	a.Equal(0, len(data.AppLocalStates[1].KeyValue))
	a.Equal(0, len(data.AppLocalStates[2].KeyValue))

	// check alloc action
	// re-alloc storage and apply delta
	sdu.action = allocAction
	data = applyAll(kv, &sdu)
	a.Equal(2, len(data.AppParams[1].GlobalState))
	a.Equal(2, len(data.AppParams[2].GlobalState))
	a.Equal(2, len(data.AppLocalStates[1].KeyValue))
	a.Equal(2, len(data.AppLocalStates[2].KeyValue))

	// check remain action
	// unique keys: merge storage and deltas
	testUniqueKeys := func(state1 basics.TealKeyValue, state2 basics.TealKeyValue) {
		a.Equal(2, len(state1))
		a.Equal(created.new.Uint, state1["key4"].Uint)
		a.Equal(updated.new.Uint, state1["key5"].Uint)

		a.Equal(5, len(state2))
		a.Equal(uint64(1), state2["key1"].Uint)
		a.Equal(uint64(2), state2["key2"].Uint)
		a.Equal(uint64(3), state2["key3"].Uint)
		a.Equal(created.new.Uint, state2["key4"].Uint)
		a.Equal(updated.new.Uint, state2["key5"].Uint)
	}

	sdu.action = remainAllocAction
	data = applyAll(kv, &sdu)
	testUniqueKeys(data.AppParams[1].GlobalState, data.AppParams[2].GlobalState)
	testUniqueKeys(data.AppLocalStates[1].KeyValue, data.AppLocalStates[2].KeyValue)

	// check remain action
	// duplicate keys: merge storage and deltas
	testDuplicateKeys := func(state1 basics.TealKeyValue, state2 basics.TealKeyValue) {
		a.Equal(2, len(state1))
		a.Equal(created.new.Uint, state1["key1"].Uint)
		a.Equal(updated.new.Uint, state1["key2"].Uint)

		a.Equal(2, len(state2))
		a.Equal(created.new.Uint, state1["key1"].Uint)
		a.Equal(updated.new.Uint, state1["key2"].Uint)
	}

	sdd.action = remainAllocAction
	data = applyAll(kv, &sdd)
	testDuplicateKeys(data.AppParams[1].GlobalState, data.AppParams[2].GlobalState)
	testDuplicateKeys(data.AppLocalStates[1].KeyValue, data.AppLocalStates[2].KeyValue)

	sd := storageDelta{action: deallocAction, kvCow: map[string]valueDelta{}}
	data, err := applyStorageDelta(basics.AccountData{}, storagePtr{1, true}, &sd)
	a.NoError(err)
	a.Nil(data.AppParams)
	a.Nil(data.AppLocalStates)
	a.True(data.IsZero())
	data, err = applyStorageDelta(basics.AccountData{}, storagePtr{1, false}, &sd)
	a.NoError(err)
	a.Nil(data.AppParams)
	a.Nil(data.AppLocalStates)
	a.True(data.IsZero())
}

func TestCowAllocated(t *testing.T) {
	a := require.New(t)

	aidx := basics.AppIndex(1)
	c := getCow([]modsData{})

	addr1 := getRandomAddress(a)
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr1: {storagePtr{aidx, false}: &storageDelta{action: allocAction}},
	}

	a.True(c.allocated(addr1, aidx, false))

	// ensure other requests go down to roundCowParent
	a.Panics(func() { c.allocated(addr1, aidx+1, false) })
	a.Panics(func() { c.allocated(getRandomAddress(a), aidx, false) })

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr1: {storagePtr{aidx, true}: &storageDelta{action: allocAction}},
	}
	a.True(c.allocated(addr1, aidx, true))

	// ensure other requests go down to roundCowParent
	a.Panics(func() { c.allocated(addr1, aidx+1, true) })
	a.Panics(func() { c.allocated(getRandomAddress(a), aidx, true) })
}

func TestCowGetCreator(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})

	creator, found, err := c.GetCreator(basics.CreatableIndex(aidx), basics.AssetCreatable)
	a.NoError(err)
	a.False(found)
	a.Equal(creator, basics.Address{})

	creator, found, err = c.GetCreator(basics.CreatableIndex(aidx), basics.AppCreatable)
	a.NoError(err)
	a.True(found)
	a.Equal(addr, creator)

	// ensure other requests go down to roundCowParent
	a.Panics(func() { c.GetCreator(basics.CreatableIndex(aidx+1), basics.AppCreatable) })
}

func TestCowGetters(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})

	round := basics.Round(1234)
	c.mods.Hdr.Round = round
	ts := int64(11223344)
	c.mods.PrevTimestamp = ts

	a.Equal(round, c.round())
	a.Equal(ts, c.prevTimestamp())
}

func TestCowGet(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})

	addr1 := getRandomAddress(a)
	bre := basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 100}}
	c.mods.Accts.Upsert(addr1, bre)

	bra, err := c.Get(addr1, true)
	a.NoError(err)
	a.Equal(bre, bra)

	bra, err = c.Get(addr1, false)
	a.NoError(err)
	a.Equal(bre, bra)

	// ensure other requests go down to roundCowParent
	a.Panics(func() { c.Get(getRandomAddress(a), true) })
}

func TestCowGetKey(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {storagePtr{aidx, true}: &storageDelta{action: deallocAction}},
	}
	_, ok, err := c.GetKey(addr, aidx, true, "gkey", 0)
	a.Error(err)
	a.False(ok)
	a.Contains(err.Error(), "cannot fetch key")

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {storagePtr{aidx, true}: &storageDelta{action: allocAction}},
	}
	_, ok, err = c.GetKey(addr, aidx, true, "gkey", 0)
	a.NoError(err)
	a.False(ok)
	_, ok, err = c.GetKey(addr, aidx, true, "gkey", 0)
	a.NoError(err)
	a.False(ok)

	tv := basics.TealValue{Type: basics.TealUintType, Uint: 1}
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action: allocAction,
				kvCow:  stateDelta{"gkey": valueDelta{new: tv, newExists: false}},
			},
		},
	}
	_, ok, err = c.GetKey(addr, aidx, true, "gkey", 0)
	a.NoError(err)
	a.False(ok)

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action: allocAction,
				kvCow:  stateDelta{"gkey": valueDelta{new: tv, newExists: true}},
			},
		},
	}
	val, ok, err := c.GetKey(addr, aidx, true, "gkey", 0)
	a.NoError(err)
	a.True(ok)
	a.Equal(tv, val)

	// check local
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, false}: &storageDelta{
				action: allocAction,
				kvCow:  stateDelta{"lkey": valueDelta{new: tv, newExists: true}},
			},
		},
	}

	val, ok, err = c.GetKey(addr, aidx, false, "lkey", 0)
	a.NoError(err)
	a.True(ok)
	a.Equal(tv, val)

	// ensure other requests go down to roundCowParent
	a.Panics(func() { c.GetKey(getRandomAddress(a), aidx, false, "lkey", 0) })
	a.Panics(func() { c.GetKey(addr, aidx+1, false, "lkey", 0) })
}

func TestCowSetKey(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})

	key := strings.Repeat("key", 100)
	val := "val"
	tv := basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	err := c.SetKey(addr, aidx, true, key, tv, 0)
	a.Error(err)
	a.Contains(err.Error(), "key too long")

	key = "key"
	val = strings.Repeat("val", 100)
	tv = basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	err = c.SetKey(addr, aidx, true, key, tv, 0)
	a.Error(err)
	a.Contains(err.Error(), "value too long")

	val = "val"
	tv = basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {storagePtr{aidx, true}: &storageDelta{action: deallocAction}},
	}
	err = c.SetKey(addr, aidx, true, key, tv, 0)
	a.Error(err)
	a.Contains(err.Error(), "cannot set key")

	counts := basics.StateSchema{}
	maxCounts := basics.StateSchema{}
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action:    allocAction,
				kvCow:     make(stateDelta),
				counts:    &counts,
				maxCounts: &maxCounts,
			},
		},
	}
	err = c.SetKey(addr, aidx, true, key, tv, 0)
	a.Error(err)
	a.Contains(err.Error(), "exceeds schema bytes")

	counts = basics.StateSchema{NumUint: 1}
	maxCounts = basics.StateSchema{NumByteSlice: 1}
	err = c.SetKey(addr, aidx, true, key, tv, 0)
	a.Error(err)
	a.Contains(err.Error(), "exceeds schema integer")

	tv2 := basics.TealValue{Type: basics.TealUintType, Uint: 1}
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action:    allocAction,
				kvCow:     stateDelta{key: valueDelta{new: tv2, newExists: true}},
				counts:    &counts,
				maxCounts: &maxCounts,
			},
		},
	}
	err = c.SetKey(addr, aidx, true, key, tv, 0)
	a.NoError(err)

	counts = basics.StateSchema{NumUint: 1}
	maxCounts = basics.StateSchema{NumByteSlice: 1, NumUint: 1}
	err = c.SetKey(addr, aidx, true, key, tv, 0)
	a.NoError(err)

	// check local
	addr1 := getRandomAddress(a)
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr1: {
			storagePtr{aidx, false}: &storageDelta{
				action:    allocAction,
				kvCow:     stateDelta{key: valueDelta{new: tv2, newExists: true}},
				counts:    &counts,
				maxCounts: &maxCounts,
			},
		},
	}
	err = c.SetKey(addr1, aidx, false, key, tv, 0)
	a.NoError(err)

	// ensure other requests go down to roundCowParent
	a.Panics(func() { c.SetKey(getRandomAddress(a), aidx, false, key, tv, 0) })
	a.Panics(func() { c.SetKey(addr, aidx+1, false, key, tv, 0) })
}

func TestCowSetKeyVFuture(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})
	protoF := config.Consensus[protocol.ConsensusFuture]
	c.proto = protoF

	key := strings.Repeat("key", 100)
	val := "val"
	tv := basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	err := c.SetKey(addr, aidx, true, key, tv, 0)
	a.Error(err)
	a.Contains(err.Error(), "key too long")

	key = "key"
	val = strings.Repeat("val", 100)
	tv = basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	err = c.SetKey(addr, aidx, true, key, tv, 0)
	a.Error(err)
	a.Contains(err.Error(), "value too long")

	key = strings.Repeat("k", protoF.MaxAppKeyLen)
	val = strings.Repeat("v", protoF.MaxAppSumKeyValueLens-len(key)+1)
	tv = basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	err = c.SetKey(addr, aidx, true, key, tv, 0)
	a.Error(err)
	a.Contains(err.Error(), "key/value total too long")
}

func TestCowAccountIdx(t *testing.T) {
	a := require.New(t)

	l := emptyLedger{}
	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})
	c.lookupParent = &l
	c.compatibilityMode = true

	key := "key"
	val := "val"

	c.sdeltas = make(map[basics.Address]map[storagePtr]*storageDelta)
	tv := basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	sd, err := c.ensureStorageDelta(addr, aidx, true, remainAllocAction, 123)
	a.NoError(err)
	a.Equal(uint64(0), sd.accountIdx)

	c.sdeltas = make(map[basics.Address]map[storagePtr]*storageDelta)
	sd, err = c.ensureStorageDelta(addr, aidx, false, remainAllocAction, 123)
	a.NoError(err)
	a.Equal(uint64(123), sd.accountIdx)

	counts := basics.StateSchema{}
	maxCounts := basics.StateSchema{}
	for _, global := range []bool{false, true} {
		c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
			addr: {
				storagePtr{aidx, global}: &storageDelta{
					action:     allocAction,
					kvCow:      stateDelta{key: valueDelta{new: tv, newExists: true}},
					counts:     &counts,
					maxCounts:  &maxCounts,
					accountIdx: 123,
				},
			},
		}
		sd, err = c.ensureStorageDelta(addr, aidx, global, remainAllocAction, 456)
		a.NoError(err)
		a.Equal(uint64(123), sd.accountIdx)
	}
}

func TestCowDelKey(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})

	key := "key"
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {storagePtr{aidx, true}: &storageDelta{action: deallocAction}},
	}
	err := c.DelKey(addr, aidx, true, key, 0)
	a.Error(err)
	a.Contains(err.Error(), "cannot del key")

	counts := basics.StateSchema{}
	maxCounts := basics.StateSchema{}
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action:    allocAction,
				kvCow:     make(stateDelta),
				counts:    &counts,
				maxCounts: &maxCounts,
			},
		},
	}
	err = c.DelKey(addr, aidx, true, key, 0)
	a.NoError(err)

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, false}: &storageDelta{
				action:    allocAction,
				kvCow:     make(stateDelta),
				counts:    &counts,
				maxCounts: &maxCounts,
			},
		},
	}
	err = c.DelKey(addr, aidx, false, key, 0)
	a.NoError(err)

	// ensure other requests go down to roundCowParent
	a.Panics(func() { c.DelKey(getRandomAddress(a), aidx, false, key, 0) })
	a.Panics(func() { c.DelKey(addr, aidx+1, false, key, 0) })
}
func TestCowAppendLog(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})

	val := strings.Repeat("val", 100)
	tv := basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	err := c.AppendLog(aidx, tv)
	a.Error(err)
	a.Contains(err.Error(), "value too long")

	val = "val"
	tv = basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	c.logdeltas = map[basics.AppIndex][]string{}
	err = c.AppendLog(aidx, tv)
	a.NoError(err)
}
