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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

type storageAction uint64

const (
	remainAllocAction storageAction = 1
	allocAction       storageAction = 2
	deallocAction     storageAction = 3
)

type valueDelta struct {
	old, new basics.TealValue

	oldExists, newExists bool
}

type storagePtr struct {
	aidx   basics.AppIndex
	global bool
}

// ok is false if the provided valueDelta is redundant,
// which means that it encodes no update.
func (vd valueDelta) serialize() (vdelta basics.ValueDelta, ok bool) {
	if !vd.newExists {
		if vd.oldExists {
			vdelta.Action = basics.DeleteAction
			ok = true
		}
		return
	}
	if vd.oldExists && vd.old == vd.new {
		return
	}
	ok = true
	if vd.new.Type == basics.TealBytesType {
		vdelta.Action = basics.SetBytesAction
		vdelta.Bytes = vd.new.Bytes
	} else {
		vdelta.Action = basics.SetUintAction
		vdelta.Uint = vd.new.Uint
	}
	return
}

// stateDelta is similar to basics.StateDelta but stores both values before and after change
//msgp:ignore stateDelta
type stateDelta map[string]valueDelta

func (sd stateDelta) serialize() basics.StateDelta {
	delta := make(basics.StateDelta)
	for key, vd := range sd {
		vdelta, ok := vd.serialize()
		if ok {
			delta[key] = vdelta
		}
	}
	return delta
}

type storageDelta struct {
	action storageAction
	kvCow  stateDelta

	counts, maxCounts *basics.StateSchema
}

// ensureStorageDelta finds existing or allocate a new storageDelta for given {addr, aidx, global}
func (cb *roundCowState) ensureStorageDelta(addr basics.Address, aidx basics.AppIndex, global bool, defaultAction storageAction) (*storageDelta, error) {
	// If we already have a storageDelta, return it
	aapp := storagePtr{aidx, global}
	lsd, ok := cb.sdeltas[addr][aapp]
	if ok {
		return lsd, nil
	}

	// Otherwise, create a new one, looking up how much storage we are
	// currently using in order to populate `counts` correctly
	counts, err := cb.getStorageCounts(addr, aidx, global)
	if err != nil {
		return nil, err
	}

	maxCounts, err := cb.getStorageLimits(addr, aidx, global)
	if err != nil {
		return nil, err
	}

	lsd = &storageDelta{
		action:    defaultAction,
		kvCow:     make(stateDelta),
		counts:    &counts,
		maxCounts: &maxCounts,
	}

	_, ok = cb.sdeltas[addr]
	if !ok {
		cb.sdeltas[addr] = make(map[storagePtr]*storageDelta)
	}
	cb.sdeltas[addr][aapp] = lsd
	return lsd, nil
}

// getStorageCounts returns current storage usage for a given {addr, aidx, global} as basics.StateSchema
func (cb *roundCowState) getStorageCounts(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	// If we haven't allocated storage, then our used storage count is zero
	allocated, err := cb.allocated(addr, aidx, global)
	if err != nil {
		return basics.StateSchema{}, err
	}
	if !allocated {
		return basics.StateSchema{}, nil
	}

	// If we already have a storageDelta, return the counts from it
	aapp := storagePtr{aidx, global}
	lsd, ok := cb.sdeltas[addr][aapp]
	if ok {
		return *lsd.counts, nil
	}

	// Otherwise, check our parent
	return cb.lookupParent.getStorageCounts(addr, aidx, global)
}

// getStorageLimits returns storage schema limits for a given storage identified by {addr, aidx, global}
func (cb *roundCowState) getStorageLimits(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	// If we haven't allocated storage, then our storage limit is zero
	allocated, err := cb.allocated(addr, aidx, global)
	if err != nil {
		return basics.StateSchema{}, err
	}
	if !allocated {
		return basics.StateSchema{}, nil
	}

	// If we already have a storageDelta, return the counts from it
	aapp := storagePtr{aidx, global}
	lsd, ok := cb.sdeltas[addr][aapp]
	if ok {
		return *lsd.maxCounts, nil
	}

	// Otherwise, check our parent
	return cb.lookupParent.getStorageLimits(addr, aidx, global)
}

// allocated checks if a storage for {addr, aidx, global} has been already allocated
func (cb *roundCowState) allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error) {
	// Check if we've allocated or deallocate within this very cow
	aapp := storagePtr{aidx, global}
	lsd, ok := cb.sdeltas[addr][aapp]
	if ok {
		if lsd.action == allocAction {
			return true, nil
		} else if lsd.action == deallocAction {
			return false, nil
		}
	}

	// Otherwise, check our parent
	return cb.lookupParent.allocated(addr, aidx, global)
}

func errNoStorage(addr basics.Address, aidx basics.AppIndex, global bool) error {
	if global {
		return fmt.Errorf("app %d does not exist", aidx)
	}
	return fmt.Errorf("%v has not opted in to app %d", addr, aidx)
}

func errAlreadyStorage(addr basics.Address, aidx basics.AppIndex, global bool) error {
	if global {
		return fmt.Errorf("app %d already exists", aidx)
	}
	return fmt.Errorf("%v has already opted in to app %d", addr, aidx)
}

// Allocate creates kv storage for a given {addr, aidx, global}. It is called on app creation (global) or opting in (local)
func (cb *roundCowState) Allocate(addr basics.Address, cidx basics.CreatableIndex, ctype basics.CreatableType, global bool, space basics.StateSchema) error {
	if ctype == basics.AppCreatable {
		// Check that account is not already opted in
		aidx := basics.AppIndex(cidx)
		allocated, err := cb.allocated(addr, aidx, global)
		if err != nil {
			return err
		}
		if allocated {
			err = fmt.Errorf("cannot allocate storage, %v", errAlreadyStorage(addr, aidx, global))
			return err
		}

		lsd, err := cb.ensureStorageDelta(addr, aidx, global, allocAction)
		if err != nil {
			return err
		}

		lsd.action = allocAction
		lsd.maxCounts = &space

		return nil
	}

	return fmt.Errorf("not supported creatable type %v", ctype)
}

// Deallocate clears storage for {addr, aidx, global}. It happens on app deletion (global) or closing out (local)
func (cb *roundCowState) Deallocate(addr basics.Address, cidx basics.CreatableIndex, ctype basics.CreatableType, global bool) error {
	if ctype == basics.AppCreatable {
		// Check that account has allocated storage
		aidx := basics.AppIndex(cidx)
		allocated, err := cb.allocated(addr, aidx, global)
		if err != nil {
			return err
		}
		if !allocated {
			err = fmt.Errorf("cannot deallocate storage, %v", errNoStorage(addr, aidx, global))
			return err
		}

		lsd, err := cb.ensureStorageDelta(addr, aidx, global, deallocAction)
		if err != nil {
			return err
		}

		lsd.action = deallocAction
		lsd.counts = &basics.StateSchema{}
		lsd.maxCounts = &basics.StateSchema{}
		lsd.kvCow = make(stateDelta)
		return nil
	}

	return fmt.Errorf("not supported creatable type %v", ctype)
}

// GetKey looks for a key in {addr, aidx, global} storage
func (cb *roundCowState) GetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) (basics.TealValue, bool, error) {
	return cb.getKey(addr, aidx, global, key)
}

// getKey looks for a key in {addr, aidx, global} storage
// This is hierarchical lookup: if the key not in this cow cache, then request parent and all way down to ledger
func (cb *roundCowState) getKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) (basics.TealValue, bool, error) {
	// Check that account has allocated storage
	allocated, err := cb.allocated(addr, aidx, global)
	if err != nil {
		return basics.TealValue{}, false, err
	}
	if !allocated {
		err = fmt.Errorf("cannot fetch key, %v", errNoStorage(addr, aidx, global))
		return basics.TealValue{}, false, err
	}

	// Check if key is in a storage delta, if so return it (the "hasDelta"
	// boolean will be true if the kvCow holds _any_ delta for the key,
	// including if that delta is a "delete" delta)
	lsd, ok := cb.sdeltas[addr][storagePtr{aidx, global}]
	if ok {
		vdelta, hasDelta := lsd.kvCow[key]
		if hasDelta {
			return vdelta.new, vdelta.newExists, nil
		}

		// If this storage delta is remainAllocAction, then check our
		// parent. Otherwise, the key does not exist.
		if lsd.action != remainAllocAction {
			return basics.TealValue{}, false, nil
		}
	}

	// At this point, we know we're allocated, and we don't have a delta,
	// so we should check our parent.
	return cb.lookupParent.getKey(addr, aidx, global, key)
}

// SetKey creates a new key-value in {addr, aidx, global} storage
func (cb *roundCowState) SetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, value basics.TealValue) error {
	// Enforce maximum key length
	if len(key) > cb.proto.MaxAppKeyLen {
		return fmt.Errorf("key too long: length was %d, maximum is %d", len(key), cb.proto.MaxAppKeyLen)
	}

	// Enforce maximum value length
	if value.Type == basics.TealBytesType && len(value.Bytes) > cb.proto.MaxAppBytesValueLen {
		return fmt.Errorf("value too long for key 0x%x: length was %d, maximum is %d", key, len(value.Bytes), cb.proto.MaxAppBytesValueLen)
	}

	// Check that account has allocated storage
	allocated, err := cb.allocated(addr, aidx, global)
	if err != nil {
		return err
	}

	if !allocated {
		err = fmt.Errorf("cannot set key, %v", errNoStorage(addr, aidx, global))
		return err
	}

	// Fetch the old value + presence so we know how to update
	oldValue, oldOk, err := cb.GetKey(addr, aidx, global, key)
	if err != nil {
		return err
	}

	// Write the value delta associated with this key/value
	lsd, err := cb.ensureStorageDelta(addr, aidx, global, remainAllocAction)
	if err != nil {
		return err
	}

	vdelta, ok := lsd.kvCow[key]
	if !ok {
		vdelta = valueDelta{old: oldValue, oldExists: oldOk}
	}
	vdelta.new = value
	vdelta.newExists = true
	lsd.kvCow[key] = vdelta

	newValue, newOk := vdelta.new, vdelta.newExists

	// Update counts
	err = updateCounts(lsd, oldValue, oldOk, newValue, newOk)
	if err != nil {
		return err
	}

	return lsd.checkCounts()
}

// DelKey removes a key from {addr, aidx, global} storage
func (cb *roundCowState) DelKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) error {
	// Check that account has allocated storage
	allocated, err := cb.allocated(addr, aidx, global)
	if err != nil {
		return err
	}
	if !allocated {
		err = fmt.Errorf("cannot del key, %v", errNoStorage(addr, aidx, global))
		return err
	}

	// Fetch the old value + presence so we know how to update counts
	oldValue, oldOk, err := cb.GetKey(addr, aidx, global, key)
	if err != nil {
		return err
	}

	// Write the value delta associated with deleting this key
	lsd, err := cb.ensureStorageDelta(addr, aidx, global, remainAllocAction)
	if err != nil {
		return nil
	}

	vdelta, ok := lsd.kvCow[key]
	if !ok {
		vdelta = valueDelta{old: oldValue, oldExists: oldOk}
	}
	vdelta.new = basics.TealValue{}
	vdelta.newExists = false
	lsd.kvCow[key] = vdelta

	newValue, newOk := vdelta.new, vdelta.newExists

	// Update counts
	err = updateCounts(lsd, oldValue, oldOk, newValue, newOk)
	if err != nil {
		return err
	}

	return nil // note: deletion cannot cause us to violate maxCount
}

// StatefulEval runs application.
// Execution happens in a child cow and all modifications are merged into parent if the program passes
func (cb *roundCowState) StatefulEval(params logic.EvalParams, aidx basics.AppIndex, program []byte) (pass bool, evalDelta basics.EvalDelta, err error) {
	// Make a child cow to eval our program in
	calf := cb.child()
	params.Ledger, err = newLogicLedger(calf, aidx)
	if err != nil {
		return false, basics.EvalDelta{}, err
	}

	// Eval the program
	pass, err = logic.EvalStateful(program, params)
	if err != nil {
		return false, basics.EvalDelta{}, err
	}

	// If program passed, build our eval delta, and commit to state changes
	if pass {
		evalDelta, err = calf.BuildEvalDelta(aidx, &params.Txn.Txn)
		if err != nil {
			return false, basics.EvalDelta{}, err
		}
		calf.commitToParent()
	}

	return pass, evalDelta, nil
}

// BuildEvalDelta converts internal sdeltas into basics.EvalDelta
func (cb *roundCowState) BuildEvalDelta(aidx basics.AppIndex, txn *transactions.Transaction) (evalDelta basics.EvalDelta, err error) {
	foundGlobal := false
	for addr, smod := range cb.sdeltas {
		for aapp, sdelta := range smod {
			// Check that all of these deltas are for the correct app
			if aapp.aidx != aidx {
				err = fmt.Errorf("found storage delta for different app during StatefulEval/BuildDelta: %d != %d", aapp.aidx, aidx)
				return basics.EvalDelta{}, err
			}
			if aapp.global {
				// Check that there is at most one global delta
				if foundGlobal {
					err = fmt.Errorf("found more than one global delta during StatefulEval/BuildDelta: %d", aapp.aidx)
					return basics.EvalDelta{}, err
				}
				evalDelta.GlobalDelta = sdelta.kvCow.serialize()
				foundGlobal = true
			} else {
				if evalDelta.LocalDeltas == nil {
					evalDelta.LocalDeltas = make(map[uint64]basics.StateDelta)
				}
				// It is impossible for there to be more than one local delta for
				// a particular (address, app ID) in sdeltas, because the appAddr
				// type consists only of (address, appID, global=false). So if
				// IndexByAddress is deterministic (and it is), there is no need
				// to check for duplicates here.
				var addrOffset uint64
				addrOffset, err = txn.IndexByAddress(addr, txn.Sender)
				if err != nil {
					return basics.EvalDelta{}, err
				}
				evalDelta.LocalDeltas[addrOffset] = sdelta.kvCow.serialize()
			}
		}
	}
	return
}

// updateCounts updates usage counters
func updateCounts(lsd *storageDelta, bv basics.TealValue, bok bool, av basics.TealValue, aok bool) error {
	// If the value existed before, decrement the count of the old type.
	if bok {
		switch bv.Type {
		case basics.TealBytesType:
			lsd.counts.NumByteSlice--
		case basics.TealUintType:
			lsd.counts.NumUint--
		default:
			return fmt.Errorf("unknown before type: %v", bv.Type)
		}
	}

	// If the value exists now, increment the count of the new type.
	if aok {
		switch av.Type {
		case basics.TealBytesType:
			lsd.counts.NumByteSlice++
		case basics.TealUintType:
			lsd.counts.NumUint++
		default:
			return fmt.Errorf("unknown after type: %v", av.Type)
		}
	}
	return nil
}

// checkCounts ensures usage does not exceeds schema limits
func (lsd *storageDelta) checkCounts() error {
	// Check against the max schema
	if lsd.counts.NumUint > lsd.maxCounts.NumUint {
		return fmt.Errorf("store integer count %d exceeds schema integer count %d", lsd.counts.NumUint, lsd.maxCounts.NumUint)
	}
	if lsd.counts.NumByteSlice > lsd.maxCounts.NumByteSlice {
		return fmt.Errorf("store bytes count %d exceeds schema bytes count %d", lsd.counts.NumByteSlice, lsd.maxCounts.NumByteSlice)
	}
	return nil
}

// applyChild merges child storageDelta into this storageDelta
func (lsd *storageDelta) applyChild(child *storageDelta) {
	if child.action != remainAllocAction {
		// If child state allocated or deallocated, then its deltas
		// completely overwrite those of the parent.
		lsd.action = child.action
		lsd.kvCow = child.kvCow
		lsd.counts = child.counts
		lsd.maxCounts = child.maxCounts
	} else {
		// Otherwise, the child's deltas get merged with those of the
		// parent, and we keep whatever the parent's state was.
		for key := range child.kvCow {
			delta, ok := lsd.kvCow[key]
			if !ok {
				lsd.kvCow[key] = child.kvCow[key]
				continue
			}

			delta.new = child.kvCow[key].new
			delta.newExists = child.kvCow[key].newExists
			lsd.kvCow[key] = delta
		}

		// counts can just get overwritten because they are absolute
		// see ensureStorageDelta: child.counts is initialized from parent cow
		lsd.counts = child.counts
	}

	// sanity checks
	if lsd.action == deallocAction {
		if len(lsd.kvCow) > 0 {
			panic("dealloc state delta, but nonzero kv change")
		}
	}
}

// applyStorageDelta saves in-mem storageDelta into AccountData
// cow stores app data separately from AccountData to minimize potentially large AccountData copying/reallocations.
// When cow is done applyStorageDelta offloads app stores into AccountData
func applyStorageDelta(data basics.AccountData, aapp storagePtr, store *storageDelta) (basics.AccountData, error) {
	// duplicate code in branches is proven to be a bit faster than
	// having basics.AppParams and basics.AppLocalState under a common interface with additional loops and type assertions
	if aapp.global {
		owned := make(map[basics.AppIndex]basics.AppParams, len(data.AppParams))
		for k, v := range data.AppParams {
			owned[k] = v
		}

		switch store.action {
		case deallocAction:
			delete(owned, aapp.aidx)
		case allocAction, remainAllocAction:
			// TODO verify this assertion
			// note: these should always exist because they were
			// at least preceded by a call to PutWithCreatable?
			params, ok := owned[aapp.aidx]
			if !ok {
				return basics.AccountData{}, fmt.Errorf("could not find existing params for %v", aapp.aidx)
			}
			params = params.Clone()
			if store.action == allocAction {
				// TODO does this ever accidentally clobber?
				params.GlobalState = make(basics.TealKeyValue)
			}
			// note: if this is an allocAction, there will be no
			// DeleteActions below
			for k, v := range store.kvCow {
				if !v.newExists {
					delete(params.GlobalState, k)
				} else {
					params.GlobalState[k] = v.new
				}
			}
			owned[aapp.aidx] = params
		}

		data.AppParams = owned

	} else {
		owned := make(map[basics.AppIndex]basics.AppLocalState, len(data.AppLocalStates))
		for k, v := range data.AppLocalStates {
			owned[k] = v
		}

		switch store.action {
		case deallocAction:
			delete(owned, aapp.aidx)
		case allocAction, remainAllocAction:
			// TODO verify this assertion
			// note: these should always exist because they were
			// at least preceded by a call to Put?
			states, ok := owned[aapp.aidx]
			if !ok {
				return basics.AccountData{}, fmt.Errorf("could not find existing states for %v", aapp.aidx)
			}
			states = states.Clone()
			if store.action == allocAction {
				// TODO does this ever accidentally clobber?
				states.KeyValue = make(basics.TealKeyValue)
			}
			// note: if this is an allocAction, there will be no
			// DeleteActions below
			for k, v := range store.kvCow {
				if !v.newExists {
					delete(states.KeyValue, k)
				} else {
					states.KeyValue[k] = v.new
				}
			}
			owned[aapp.aidx] = states
		}

		data.AppLocalStates = owned
	}
	return data, nil
}
