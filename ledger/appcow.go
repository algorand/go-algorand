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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

type storageAction uint64

const (
	remainAllocAction storageAction = 1
	allocAction       storageAction = 2
	deallocAction     storageAction = 3
)

type storageDelta struct {
	action storageAction
	kvCow  basics.StateDelta
	counts *basics.StateSchema
}

func (lsd *storageDelta) merge(osd *storageDelta) {
	if osd.action != remainAllocAction {
		// If child state allocated or deallocated, then its deltas
		// completely overwrite those of the parent.
		lsd.action = osd.action
		lsd.kvCow = osd.kvCow
		lsd.counts = osd.counts
	} else {
		// Otherwise, the child's deltas get merged with those of the
		// parent, and we keep whatever the parent's state was.
		for key, delta := range osd.kvCow {
			lsd.kvCow[key] = delta
		}

		// counts can just get overwritten because they are absolute
		lsd.counts = osd.counts
	}

	// sanity checks
	if lsd.action == deallocAction {
		if len(lsd.kvCow) > 0 {
			panic("dealloc state delta, but nonzero kv change")
		}
	}
}

func (cb *roundCowState) ensureStorageDelta(addr basics.Address, aidx basics.AppIndex, global bool, defaultAction storageAction) (*storageDelta, error) {
	// If we already have a storageDelta, return it
	aapp := addrApp{addr, aidx, global}
	lsd, ok := cb.mods.sdeltas[aapp]
	if ok {
		return lsd, nil
	}

	// Otherwise, create a new one, looking up how much storage we are
	// currently using in order to populate `counts` correctly
	counts, err := cb.getStorageCounts(addr, aidx, global)
	if err != nil {
		return nil, err
	}

	lsd = &storageDelta{
		action: defaultAction,
		kvCow:  make(basics.StateDelta),
		counts: &counts,
	}

	cb.mods.sdeltas[aapp] = lsd
	return lsd, nil
}

func (cb *roundCowState) getStorageCounts(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	// If we haven't allocated storage, then our used storage count is zero
	allocated, err := cb.Allocated(addr, aidx, global)
	if err != nil {
		return basics.StateSchema{}, err
	}
	if !allocated {
		return basics.StateSchema{}, nil
	}

	// If we already have a storageDelta, return the counts from it
	aapp := addrApp{addr, aidx, global}
	lsd, ok := cb.mods.sdeltas[aapp]
	if ok {
		return *lsd.counts, nil
	}

	// Otherwise, check our parent
	return cb.lookupParent.getStorageCounts(addr, aidx, global)
}

func (cb *roundCowState) Allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error) {
	// Check if we've allocated or deallocate within this very cow
	aapp := addrApp{addr, aidx, global}
	lsd, ok := cb.mods.sdeltas[aapp]
	if ok {
		if lsd.action == allocAction {
			return true, nil
		} else if lsd.action == deallocAction {
			return false, nil
		}
	}

	// Otherwise, check our parent
	return cb.lookupParent.Allocated(addr, aidx, global)
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

func (cb *roundCowState) Allocate(addr basics.Address, aidx basics.AppIndex, global bool) error {
	// Check that account is not already opted in
	allocated, err := cb.Allocated(addr, aidx, global)
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
	return nil
}

func (cb *roundCowState) Deallocate(addr basics.Address, aidx basics.AppIndex, global bool) error {
	// Check that account has allocated storage
	allocated, err := cb.Allocated(addr, aidx, global)
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
	lsd.kvCow = make(basics.StateDelta)
	return nil
}

func (cb *roundCowState) GetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) (basics.TealValue, bool, error) {
	// Check that account has allocated storage
	allocated, err := cb.Allocated(addr, aidx, global)
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
	lsd, ok := cb.mods.sdeltas[addrApp{addr, aidx, global}]
	if ok {
		delta, hasDelta := lsd.kvCow[key]
		if hasDelta {
			val, ok := delta.ToTealValue()
			return val, ok, nil
		}

		// If this storage delta is remainAllocAction, then check our
		// parent. Otherwise, the key does not exist.
		if lsd.action == remainAllocAction {
			// Check our parent
			return cb.lookupParent.GetKey(addr, aidx, global, key)
		}

		return basics.TealValue{}, false, nil
	}

	// At this point, we know we're allocated, and we don't have a delta,
	// so we should check our parent.
	return cb.lookupParent.GetKey(addr, aidx, global, key)
}

func (cb *roundCowState) SetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, value basics.TealValue) error {
	// Check that account has allocated storage
	allocated, err := cb.Allocated(addr, aidx, global)
	if err != nil {
		return err
	}
	if !allocated {
		err = fmt.Errorf("cannot set key, %v", errNoStorage(addr, aidx, global))
		return err
	}

	// Fetch the old value + presence so we know how to update counts
	oldValue, oldOk, err := cb.GetKey(addr, aidx, global, key)
	if err != nil {
		return err
	}

	// Write the value delta associated with this key/value
	lsd, err := cb.ensureStorageDelta(addr, aidx, global, remainAllocAction)
	if err != nil {
		return err
	}
	lsd.kvCow[key] = value.ToValueDelta()

	// Fetch the new value + presence so we know how to update counts
	newValue, newOk, err := cb.GetKey(addr, aidx, global, key)
	if err != nil {
		return err
	}

	// Update counts
	err = updateCounts(lsd, oldValue, oldOk, newValue, newOk)
	if err != nil {
		return err
	}

	return nil
}

func (cb *roundCowState) DelKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) error {
	// Check that account has allocated storage
	allocated, err := cb.Allocated(addr, aidx, global)
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

	lsd.kvCow[key] = basics.ValueDelta{
		Action: basics.DeleteAction,
	}

	// Fetch the new value + presence so we know how to update counts
	newValue, newOk, err := cb.GetKey(addr, aidx, global, key)
	if err != nil {
		return err
	}

	// Update counts
	err = updateCounts(lsd, oldValue, oldOk, newValue, newOk)
	if err != nil {
		return err
	}

	return nil
}

func (cb *roundCowState) StatefulEval(params logic.EvalParams, aidx basics.AppIndex, program []byte) (pass bool, evalDelta basics.EvalDelta, err error) {
	// Make a child cow to eval our program in
	calf := cb.child()
	params.Ledger, err = makeLogicLedger(calf, aidx)
	if err != nil {
		return false, basics.EvalDelta{}, err
	}

	// Eval the program
	pass, err = logic.EvalStateful(program, params)
	if err != nil {
		return false, basics.EvalDelta{}, err
	}

	// If program passed, build our eval delta and commit to state changes
	if pass {
		foundGlobal := false
		for aapp, sdelta := range calf.mods.sdeltas {
			// Check that all of these deltas are for the correct app
			if aapp.aidx != aidx {
				err = fmt.Errorf("found storage delta for different app during StatefulEval: %d != %d", aapp.aidx, aidx)
				return false, basics.EvalDelta{}, err
			}
			if aapp.global {
				// Check that there is at most one global delta
				if foundGlobal {
					err = fmt.Errorf("found more than one global delta during StatefulEval: %d", aapp.aidx)
					return false, basics.EvalDelta{}, err
				}
				evalDelta.GlobalDelta = sdelta.kvCow.Clone()
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
				//
				// TODO(app refactor): minimize eval deltas
				var addrOffset uint64
				sender := params.Txn.Txn.Sender
				addrOffset, err = params.Txn.Txn.IndexByAddress(aapp.addr, sender)
				if err != nil {
					return false, basics.EvalDelta{}, err
				}
				evalDelta.LocalDeltas[addrOffset] = sdelta.kvCow.Clone()
			}
		}
		calf.commitToParent()
	}

	return pass, evalDelta, nil
}

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
