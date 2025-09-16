// Copyright (C) 2019-2025 Algorand, Inc.
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

package eval

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type addrApp struct {
	addr   basics.Address
	aidx   basics.AppIndex
	global bool
}

type emptyLedger struct {
}

func (ml *emptyLedger) lookup(addr basics.Address) (ledgercore.AccountData, error) {
	return ledgercore.AccountData{}, nil
}

func (ml *emptyLedger) lookupAgreement(addr basics.Address) (basics.OnlineAccountData, error) {
	return basics.OnlineAccountData{}, nil
}

func (ml *emptyLedger) onlineStake() (basics.MicroAlgos, error) {
	return basics.MicroAlgos{}, nil
}

func (ml *emptyLedger) lookupAppParams(addr basics.Address, aidx basics.AppIndex, cacheOnly bool) (ledgercore.AppParamsDelta, bool, error) {
	return ledgercore.AppParamsDelta{}, true, nil
}

func (ml *emptyLedger) lookupAssetParams(addr basics.Address, aidx basics.AssetIndex, cacheOnly bool) (ledgercore.AssetParamsDelta, bool, error) {
	return ledgercore.AssetParamsDelta{}, true, nil
}

func (ml *emptyLedger) lookupAppLocalState(addr basics.Address, aidx basics.AppIndex, cacheOnly bool) (ledgercore.AppLocalStateDelta, bool, error) {
	return ledgercore.AppLocalStateDelta{}, true, nil
}

func (ml *emptyLedger) lookupAssetHolding(addr basics.Address, aidx basics.AssetIndex, cacheOnly bool) (ledgercore.AssetHoldingDelta, bool, error) {
	return ledgercore.AssetHoldingDelta{}, true, nil
}

func (ml *emptyLedger) checkDup(firstValid, lastValid basics.Round, txn transactions.Txid, txl ledgercore.Txlease) error {
	return nil
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

func (ml *emptyLedger) kvGet(key string) ([]byte, bool, error) {
	return nil, false, nil
}

func (ml *emptyLedger) Counter() uint64 {
	return 0
}

func (ml *emptyLedger) BlockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{}, nil
}

func (ml *emptyLedger) GenesisHash() crypto.Digest {
	return crypto.Digest{}
}

func (ml *emptyLedger) GetStateProofNextRound() basics.Round {
	return basics.Round(0)
}

func (ml *emptyLedger) GetStateProofVerificationContext(_ basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	return nil, fmt.Errorf("emptyLedger does not implement GetStateProofVerificationContext")
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
		cs.mods.AddCreatable(e.cidx, ledgercore.ModifiedCreatable{Ctype: e.ctype, Creator: e.addr, Created: true})
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
		outa[i] = ledgertesting.RandomAddress()
	}
	return out, outa
}

func TestCowStorage(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml := emptyLedger{}
	var bh bookkeeping.BlockHeader
	bh.CurrentProtocol = protocol.ConsensusCurrentVersion
	proto, ok := config.Consensus[bh.CurrentProtocol]
	require.True(t, ok)
	cow := makeRoundCowState(&ml, bh, proto, 0, ledgercore.AccountTotals{}, 0)
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
			err := cow.AllocateApp(addr, sptr.aidx, sptr.global, rschema)
			if actuallyAllocated {
				require.ErrorContains(t, err, "cannot allocate")
			} else {
				require.NoError(t, err)
				err = st.alloc(aapp, rschema)
				require.NoError(t, err)
			}
		}

		// Deallocate
		if rand.Float32() < 0.25 {
			actuallyAllocated := st.allocated(aapp)
			err := cow.DeallocateApp(addr, sptr.aidx, sptr.global)
			if actuallyAllocated {
				require.NoError(t, err)
				err := st.dealloc(aapp)
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "cannot deallocate")
			}
		}

		// Write a random key/value
		if rand.Float32() < 0.25 {
			actuallyAllocated := st.allocated(aapp)
			rkey := allKeys[rand.Intn(len(allKeys))]
			rval := allValues[rand.Intn(len(allValues))]
			err := cow.setKey(addr, sptr.aidx, sptr.global, rkey, rval, 0)
			if actuallyAllocated {
				require.NoError(t, err)
				err = st.set(aapp, rkey, rval)
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "cannot set")
			}
		}

		// Delete a random key/value
		if rand.Float32() < 0.25 {
			actuallyAllocated := st.allocated(aapp)
			rkey := allKeys[rand.Intn(len(allKeys))]
			err := cow.delKey(addr, sptr.aidx, sptr.global, rkey, 0)
			if actuallyAllocated {
				require.NoError(t, err)
				err = st.del(aapp, rkey)
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "cannot del")
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

					cval, cok, err := cow.getKey(addr, sptr.aidx, sptr.global, key, 0)
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
	partitiontest.PartitionTest(t)

	a := require.New(t)

	creator := ledgertesting.RandomAddress()
	sender := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(2)

	cow := roundCowState{}
	cow.sdeltas = make(map[basics.Address]map[storagePtr]*storageDelta)
	txn := transactions.Transaction{}
	ed, err := cow.buildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Empty(ed)

	cow.sdeltas[creator] = make(map[storagePtr]*storageDelta)
	ed, err = cow.buildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Empty(ed)

	// check global delta
	cow.sdeltas[creator][storagePtr{aidx, true}] = &storageDelta{}
	ed, err = cow.buildEvalDelta(1, &txn)
	a.ErrorContains(err, "found storage delta for different app")
	a.Empty(ed)

	cow.sdeltas[creator][storagePtr{aidx, true}] = &storageDelta{}
	ed, err = cow.buildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(transactions.EvalDelta{GlobalDelta: basics.StateDelta{}}, ed)

	cow.sdeltas[creator][storagePtr{aidx + 1, true}] = &storageDelta{}
	ed, err = cow.buildEvalDelta(aidx, &txn)
	a.ErrorContains(err, "found storage delta for different app")
	a.Empty(ed)

	delete(cow.sdeltas[creator], storagePtr{aidx + 1, true})
	cow.sdeltas[sender] = make(map[storagePtr]*storageDelta)
	cow.sdeltas[sender][storagePtr{aidx, true}] = &storageDelta{}
	ed, err = cow.buildEvalDelta(aidx, &txn)
	a.ErrorContains(err, "found more than one global delta")
	a.Empty(ed)

	// check local delta
	delete(cow.sdeltas[sender], storagePtr{aidx, true})
	cow.sdeltas[sender][storagePtr{aidx, false}] = &storageDelta{}

	ed, err = cow.buildEvalDelta(aidx, &txn)
	a.ErrorContains(err, "invalid Account reference ")
	a.Empty(ed)

	// check v26 behavior for empty deltas
	txn.Sender = sender
	cow.mods.Hdr = &bookkeeping.BlockHeader{
		UpgradeState: bookkeeping.UpgradeState{CurrentProtocol: protocol.ConsensusV25},
	}
	ed, err = cow.buildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(
		transactions.EvalDelta{
			GlobalDelta: basics.StateDelta{},
			LocalDeltas: map[uint64]basics.StateDelta{0: {}},
		},
		ed,
	)

	// check v27 behavior for empty deltas
	cow.mods.Hdr = nil
	cow.proto = config.Consensus[protocol.ConsensusCurrentVersion]
	ed, err = cow.buildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(
		transactions.EvalDelta{
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
	ed, err = cow.buildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(
		transactions.EvalDelta{
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

	ed, err = cow.buildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(
		transactions.EvalDelta{
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
	ed, err = cow.buildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(
		transactions.EvalDelta{
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
	ed, err = cow.buildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(
		transactions.EvalDelta{
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
	ed, err = cow.buildEvalDelta(aidx, &txn)
	a.NoError(err)
	a.Equal(
		transactions.EvalDelta{
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
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

	a := require.New(t)

	emptyStorageDelta := func(action storageAction) storageDelta {
		return storageDelta{
			action: action,
			kvCow:  make(stateDelta),
		}
	}
	getSchema := func(u, b int) basics.StateSchema {
		return basics.StateSchema{NumUint: uint64(u), NumByteSlice: uint64(b)}
	}

	parent := emptyStorageDelta(0)
	child := emptyStorageDelta(0)

	chkEmpty := func(delta *storageDelta) {
		a.Zero(delta.action)
		a.Zero(delta.counts)
		a.Zero(delta.maxCounts)
		a.Zero(len(delta.kvCow))
	}

	parent.applyChild(&child)
	chkEmpty(&parent)
	chkEmpty(&child)

	child.action = deallocAction
	child.kvCow["key1"] = valueDelta{}
	a.Panics(func() { parent.applyChild(&child) })

	// check child overwrites values
	child.action = allocAction
	child.counts = getSchema(1, 2)
	child.maxCounts = getSchema(3, 4)
	parent.applyChild(&child)
	a.Equal(allocAction, parent.action)
	a.Equal(1, len(parent.kvCow))
	a.Equal(getSchema(1, 2), parent.counts)
	a.Equal(getSchema(3, 4), parent.maxCounts)

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
			parent.counts = getSchema(len(test.pkv), 0)
			parent.kvCow = test.pkv

			child := emptyStorageDelta(remainAllocAction)
			cs := getSchema(len(test.ckv)+len(test.pkv), 0)
			child.counts = cs
			child.kvCow = test.ckv

			parent.applyChild(&child)
			a.Equal(test.result, parent.kvCow)
			a.Equal(cs, parent.counts)
		})
	}
}

func TestApplyStorageDelta(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	addr := ledgertesting.RandomAddress()

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

	freshCow := func(addr basics.Address, kv basics.TealKeyValue) *roundCowState {
		cow := makeRoundCowState(
			nil, bookkeeping.BlockHeader{}, config.Consensus[protocol.ConsensusCurrentVersion],
			0, ledgercore.AccountTotals{}, 0)
		cow.mods.Accts.Upsert(
			addr,
			ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{
				TotalAppParams:      2,
				TotalAppLocalStates: 2,
			}},
		)

		params1 := basics.AppParams{GlobalState: make(basics.TealKeyValue)}
		params2 := basics.AppParams{GlobalState: kv}

		state1 := basics.AppLocalState{KeyValue: make(basics.TealKeyValue)}
		state2 := basics.AppLocalState{KeyValue: kv}

		cow.mods.Accts.UpsertAppResource(addr, 1, ledgercore.AppParamsDelta{Params: &params1}, ledgercore.AppLocalStateDelta{LocalState: &state1})
		cow.mods.Accts.UpsertAppResource(addr, 2, ledgercore.AppParamsDelta{Params: &params2}, ledgercore.AppLocalStateDelta{LocalState: &state2})

		return cow
	}

	applyAll := func(kv basics.TealKeyValue, sd *storageDelta) *roundCowState {
		cow := freshCow(addr, kv)
		err := applyStorageDelta(cow, addr, storagePtr{1, true}, sd)
		a.NoError(err)
		err = applyStorageDelta(cow, addr, storagePtr{2, true}, sd)
		a.NoError(err)
		err = applyStorageDelta(cow, addr, storagePtr{1, false}, sd)
		a.NoError(err)
		err = applyStorageDelta(cow, addr, storagePtr{2, false}, sd)
		a.NoError(err)
		return cow
	}

	getAllFromCow := func(cow *roundCowState) (*basics.AppParams, *basics.AppParams, *basics.AppLocalState, *basics.AppLocalState) {
		params1, ok := cow.mods.Accts.GetAppParams(addr, 1)
		a.True(ok)
		params2, ok := cow.mods.Accts.GetAppParams(addr, 2)
		a.True(ok)
		state1, ok := cow.mods.Accts.GetAppLocalState(addr, 1)
		a.True(ok)
		state2, ok := cow.mods.Accts.GetAppLocalState(addr, 2)
		a.True(ok)
		return params1.Params, params2.Params, state1.LocalState, state2.LocalState
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
	cow := applyAll(kv, &sdu)
	params1, params2, state1, state2 := getAllFromCow(cow)
	a.Zero(len(params1.GlobalState))
	a.Equal(len(kv), len(params2.GlobalState))
	a.Zero(len(state1.KeyValue))
	a.Equal(len(kv), len(state2.KeyValue))

	// check dealloc action
	// delete all
	sdu.action = deallocAction
	cow = applyAll(kv, &sdu)
	params1, params2, state1, state2 = getAllFromCow(cow)
	a.Nil(params1)
	a.Nil(params2)
	a.Nil(state1)
	a.Nil(state2)

	// check alloc action
	// re-alloc storage and apply delta
	sdu.action = allocAction
	cow = applyAll(kv, &sdu)
	params1, params2, state1, state2 = getAllFromCow(cow)
	a.Equal(2, len(params1.GlobalState))
	a.Equal(2, len(params2.GlobalState))
	a.Equal(2, len(state1.KeyValue))
	a.Equal(2, len(state2.KeyValue))

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
	cow = applyAll(kv, &sdu)
	params1, params2, state1, state2 = getAllFromCow(cow)
	testUniqueKeys(params1.GlobalState, params2.GlobalState)
	testUniqueKeys(state1.KeyValue, state2.KeyValue)

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
	cow = applyAll(kv, &sdd)
	params1, params2, state1, state2 = getAllFromCow(cow)
	testDuplicateKeys(params1.GlobalState, params2.GlobalState)
	testDuplicateKeys(state1.KeyValue, state2.KeyValue)

	sd := storageDelta{action: deallocAction, kvCow: map[string]valueDelta{}}
	cow = makeRoundCowState(
		nil, bookkeeping.BlockHeader{}, config.Consensus[protocol.ConsensusCurrentVersion],
		0, ledgercore.AccountTotals{}, 0)
	cow.mods.Accts.Upsert(
		addr,
		ledgercore.AccountData{AccountBaseData: ledgercore.AccountBaseData{
			TotalAppParams:      1,
			TotalAppLocalStates: 1,
		}},
	)
	baseCow := makeRoundCowBase(nil, 0, 0, 0, config.ConsensusParams{})
	baseCow.updateAppResourceCache(ledgercore.AccountApp{Address: addr, App: 1}, ledgercore.AppResource{})
	cow.lookupParent = baseCow

	err := applyStorageDelta(cow, addr, storagePtr{1, true}, &sd)
	a.NoError(err)
	params1d, ok := cow.mods.Accts.GetAppParams(addr, 1)
	params1 = params1d.Params
	a.True(ok)
	state1d, ok := cow.mods.Accts.GetAppLocalState(addr, 1)
	state1 = state1d.LocalState
	a.False(ok)
	a.Nil(params1)
	a.Nil(state1)

	err = applyStorageDelta(cow, addr, storagePtr{1, false}, &sd)
	a.NoError(err)
	params1d, ok = cow.mods.Accts.GetAppParams(addr, 1)
	params1 = params1d.Params
	a.True(ok)
	state1d, ok = cow.mods.Accts.GetAppLocalState(addr, 1)
	state1 = state1d.LocalState
	a.True(ok)
	a.Nil(params1)
	a.Nil(state1)
}

func TestCowAllocated(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	aidx := basics.AppIndex(1)
	c := getCow([]modsData{})

	addr1 := ledgertesting.RandomAddress()
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr1: {storagePtr{aidx, false}: &storageDelta{action: allocAction}},
	}

	a.True(c.allocated(addr1, aidx, false))

	// ensure other requests go down to roundCowParent
	a.Panics(func() { c.allocated(addr1, aidx+1, false) })
	a.Panics(func() { c.allocated(ledgertesting.RandomAddress(), aidx, false) })

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr1: {storagePtr{aidx, true}: &storageDelta{action: allocAction}},
	}
	a.True(c.allocated(addr1, aidx, true))

	// ensure other requests go down to roundCowParent
	a.Panics(func() { c.allocated(addr1, aidx+1, true) })
	a.Panics(func() { c.allocated(ledgertesting.RandomAddress(), aidx, true) })
}

func TestCowGetCreator(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	addr := ledgertesting.RandomAddress()
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
	partitiontest.PartitionTest(t)

	a := require.New(t)

	addr := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})

	round := basics.Round(1234)
	c.mods.Hdr.Round = round
	ts := int64(11223344)
	c.mods.PrevTimestamp = ts

	a.Equal(round, c.Round())
	a.Equal(ts, c.PrevTimestamp())
}

func TestCowGet(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	addr := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})

	addr1 := ledgertesting.RandomAddress()
	bre := basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 100}}
	c.mods.Accts.Upsert(addr1, ledgercore.ToAccountData(bre))

	bra, err := c.Get(addr1, true)
	a.NoError(err)
	a.Equal(ledgercore.ToAccountData(bre), bra)

	bra, err = c.Get(addr1, false)
	a.NoError(err)
	a.Equal(ledgercore.ToAccountData(bre), bra)

	// ensure other requests go down to roundCowParent
	a.Panics(func() { c.Get(ledgertesting.RandomAddress(), true) })
}

func TestCowGetKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	addr := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {storagePtr{aidx, true}: &storageDelta{action: deallocAction}},
	}
	_, ok, err := c.getKey(addr, aidx, true, "gkey", 0)
	a.False(ok)
	a.ErrorContains(err, "cannot fetch key")

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {storagePtr{aidx, true}: &storageDelta{action: allocAction}},
	}
	_, ok, err = c.getKey(addr, aidx, true, "gkey", 0)
	a.NoError(err)
	a.False(ok)
	_, ok, err = c.getKey(addr, aidx, true, "gkey", 0)
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
	_, ok, err = c.getKey(addr, aidx, true, "gkey", 0)
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
	val, ok, err := c.getKey(addr, aidx, true, "gkey", 0)
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

	val, ok, err = c.getKey(addr, aidx, false, "lkey", 0)
	a.NoError(err)
	a.True(ok)
	a.Equal(tv, val)

	// ensure other requests go down to roundCowParent
	a.Panics(func() { c.getKey(ledgertesting.RandomAddress(), aidx, false, "lkey", 0) })
	a.Panics(func() { c.getKey(addr, aidx+1, false, "lkey", 0) })
}

func TestCowSetKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	addr := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})

	key := strings.Repeat("key", 100)
	val := "val"
	tv := basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	err := c.setKey(addr, aidx, true, key, tv, 0)
	a.ErrorContains(err, "key too long")

	key = "key"
	val = strings.Repeat("val", 100)
	tv = basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	err = c.setKey(addr, aidx, true, key, tv, 0)
	a.ErrorContains(err, "value too long")

	val = "val"
	tv = basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {storagePtr{aidx, true}: &storageDelta{action: deallocAction}},
	}
	err = c.setKey(addr, aidx, true, key, tv, 0)
	a.ErrorContains(err, "cannot set key")

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action: allocAction,
				kvCow:  make(stateDelta),
			},
		},
	}
	err = c.setKey(addr, aidx, true, key, tv, 0)
	a.ErrorContains(err, "exceeds schema bytes")

	err = c.setKey(addr, aidx, true, key, basics.TealValue{Type: basics.TealUintType}, 0)
	a.ErrorContains(err, "exceeds schema integer")

	tv2 := basics.TealValue{Type: basics.TealUintType, Uint: 1}
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action:    allocAction,
				kvCow:     stateDelta{key: valueDelta{new: tv2, newExists: true}},
				counts:    basics.StateSchema{NumUint: 1},
				maxCounts: basics.StateSchema{NumByteSlice: 1},
			},
		},
	}
	err = c.setKey(addr, aidx, true, key, tv, 0)
	a.NoError(err)

	err = c.setKey(addr, aidx, true, key, tv, 0)
	a.NoError(err)

	// check local
	addr1 := ledgertesting.RandomAddress()
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr1: {
			storagePtr{aidx, false}: &storageDelta{
				action:    allocAction,
				kvCow:     stateDelta{key: valueDelta{new: tv2, newExists: true}},
				counts:    basics.StateSchema{NumUint: 1},
				maxCounts: basics.StateSchema{NumByteSlice: 1, NumUint: 1},
			},
		},
	}
	err = c.setKey(addr1, aidx, false, key, tv, 0)
	a.NoError(err)

	// ensure other requests go down to roundCowParent
	a.Panics(func() { c.setKey(ledgertesting.RandomAddress(), aidx, false, key, tv, 0) })
	a.Panics(func() { c.setKey(addr, aidx+1, false, key, tv, 0) })
}

func TestCowSetKeyVFuture(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	addr := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})
	protoF := config.Consensus[protocol.ConsensusFuture]
	c.proto = protoF

	key := strings.Repeat("key", 100)
	val := "val"
	tv := basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	err := c.setKey(addr, aidx, true, key, tv, 0)
	a.ErrorContains(err, "key too long")

	key = "key"
	val = strings.Repeat("val", 100)
	tv = basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	err = c.setKey(addr, aidx, true, key, tv, 0)
	a.ErrorContains(err, "value too long")

	key = strings.Repeat("k", protoF.MaxAppKeyLen)
	val = strings.Repeat("v", protoF.MaxAppSumKeyValueLens-len(key)+1)
	tv = basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	err = c.setKey(addr, aidx, true, key, tv, 0)
	a.ErrorContains(err, "key/value total too long")
}

func TestCowAccountIdx(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	l := emptyLedger{}
	addr := ledgertesting.RandomAddress()
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

	for _, global := range []bool{false, true} {
		c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
			addr: {
				storagePtr{aidx, global}: &storageDelta{
					action:     allocAction,
					kvCow:      stateDelta{key: valueDelta{new: tv, newExists: true}},
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
	partitiontest.PartitionTest(t)

	a := require.New(t)

	addr := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})

	key := "key"
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {storagePtr{aidx, true}: &storageDelta{action: deallocAction}},
	}
	err := c.delKey(addr, aidx, true, key, 0)
	a.ErrorContains(err, "cannot del key")

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action: allocAction,
				kvCow:  make(stateDelta),
			},
		},
	}
	err = c.delKey(addr, aidx, true, key, 0)
	a.NoError(err)

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, false}: &storageDelta{
				action: allocAction,
				kvCow:  make(stateDelta),
			},
		},
	}
	err = c.delKey(addr, aidx, false, key, 0)
	a.NoError(err)

	// ensure other requests go down to roundCowParent
	a.Panics(func() { c.delKey(ledgertesting.RandomAddress(), aidx, false, key, 0) })
	a.Panics(func() { c.delKey(addr, aidx+1, false, key, 0) })
}
