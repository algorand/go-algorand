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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

//msgp:ignore storageAction
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
//
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

	// counts represents the number of each value type currently used
	counts basics.StateSchema
	// maxCounts is the maximum allowed counts (it comes from the app's schema)
	maxCounts basics.StateSchema

	// account index for an address that was first referenced as in app_local_get/app_local_put/app_local_del
	// this is for backward compatibility with original implementation of applications
	// it is set only once on storageDelta creation and used only for local delta generation
	accountIdx uint64
}

// ensureStorageDelta finds existing or allocate a new storageDelta for given {addr, aidx, global}
func (cb *roundCowState) ensureStorageDelta(addr basics.Address, aidx basics.AppIndex, global bool, defaultAction storageAction, accountIdx uint64) (*storageDelta, error) {
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
		counts:    counts,
		maxCounts: maxCounts,
	}

	if cb.compatibilityMode && !global {
		lsd.accountIdx = accountIdx

		// if there was previous getKey call for this app and address, use that index instead
		if s, ok := cb.compatibilityGetKeyCache[addr]; ok {
			if idx, ok := s[aapp]; ok {
				lsd.accountIdx = idx
			}
		}
	}

	_, ok = cb.sdeltas[addr]
	if !ok {
		cb.sdeltas[addr] = make(map[storagePtr]*storageDelta)
	}
	cb.sdeltas[addr][aapp] = lsd
	return lsd, nil
}

// SetAppGlobalSchema sets the maximum allowed counts for app globals. It can
// be changed during evaluation by an app update.
func (cb *roundCowState) SetAppGlobalSchema(addr basics.Address, aidx basics.AppIndex, limits basics.StateSchema) error {
	// Obtain a storageDelta to record the schema change
	lsd, err := cb.ensureStorageDelta(addr, aidx, true, remainAllocAction, 0)
	if err != nil {
		return err
	}

	lsd.maxCounts = limits
	return lsd.checkCounts()
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
		return lsd.counts, nil
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
		return lsd.maxCounts, nil
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
func (cb *roundCowState) AllocateApp(addr basics.Address, aidx basics.AppIndex, global bool, space basics.StateSchema) error {
	// Check that account is not already opted in
	allocated, err := cb.allocated(addr, aidx, global)
	if err != nil {
		return err
	}
	if allocated {
		err = fmt.Errorf("cannot allocate storage, %v", errAlreadyStorage(addr, aidx, global))
		return err
	}

	lsd, err := cb.ensureStorageDelta(addr, aidx, global, allocAction, 0)
	if err != nil {
		return err
	}

	lsd.action = allocAction
	lsd.maxCounts = space

	if global {
		cb.mods.AddCreatable(basics.CreatableIndex(aidx), ledgercore.ModifiedCreatable{
			Ctype:   basics.AppCreatable,
			Creator: addr,
			Created: true,
		})
	}
	return nil
}

// Deallocate clears storage for {addr, aidx, global}. It happens on app deletion (global) or closing out (local)
func (cb *roundCowState) DeallocateApp(addr basics.Address, aidx basics.AppIndex, global bool) error {
	// Check that account has allocated storage
	allocated, err := cb.allocated(addr, aidx, global)
	if err != nil {
		return err
	}
	if !allocated {
		err = fmt.Errorf("cannot deallocate storage, %v", errNoStorage(addr, aidx, global))
		return err
	}

	lsd, err := cb.ensureStorageDelta(addr, aidx, global, deallocAction, 0)
	if err != nil {
		return err
	}

	lsd.action = deallocAction
	lsd.counts = basics.StateSchema{}
	lsd.maxCounts = basics.StateSchema{}
	lsd.kvCow = make(stateDelta)

	if global {
		cb.mods.AddCreatable(basics.CreatableIndex(aidx), ledgercore.ModifiedCreatable{
			Ctype:   basics.AppCreatable,
			Creator: addr,
			Created: false,
		})
	}
	return nil
}

// getKey looks for a key in {addr, aidx, global} storage
// This is hierarchical lookup: if the key not in this cow cache, then request parent and all way down to ledger
func (cb *roundCowState) getKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) (basics.TealValue, bool, error) {
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

	if cb.compatibilityMode && !global {
		// if fetching a key first time for this app,
		// cache account index, and use it later on lsd allocation
		s, ok := cb.compatibilityGetKeyCache[addr]
		if !ok {
			s = map[storagePtr]uint64{{aidx, global}: accountIdx}
			cb.compatibilityGetKeyCache[addr] = s
		} else {
			if _, ok := s[storagePtr{aidx, global}]; !ok {
				s[storagePtr{aidx, global}] = accountIdx
				cb.compatibilityGetKeyCache[addr] = s
			}
		}
	}

	// At this point, we know we're allocated, and we don't have a delta,
	// so we should check our parent.
	return cb.lookupParent.getKey(addr, aidx, global, key, accountIdx)
}

// setKey creates a new key-value in {addr, aidx, global} storage
func (cb *roundCowState) setKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, value basics.TealValue, accountIdx uint64) error {
	// Enforce maximum key length
	if len(key) > cb.proto.MaxAppKeyLen {
		return fmt.Errorf("key too long: length was %d, maximum is %d", len(key), cb.proto.MaxAppKeyLen)
	}

	// Enforce maximum value length
	if value.Type == basics.TealBytesType {
		if len(value.Bytes) > cb.proto.MaxAppBytesValueLen {
			return fmt.Errorf("value too long for key 0x%x: length was %d", key, len(value.Bytes))
		}
		if sum := len(key) + len(value.Bytes); sum > cb.proto.MaxAppSumKeyValueLens {
			return fmt.Errorf("key/value total too long for key 0x%x: sum was %d", key, sum)
		}
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
	oldValue, oldOk, err := cb.getKey(addr, aidx, global, key, accountIdx)
	if err != nil {
		return err
	}

	// Write the value delta associated with this key/value
	lsd, err := cb.ensureStorageDelta(addr, aidx, global, remainAllocAction, accountIdx)
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

// delKey removes a key from {addr, aidx, global} storage
func (cb *roundCowState) delKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) error {
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
	oldValue, oldOk, err := cb.getKey(addr, aidx, global, key, accountIdx)
	if err != nil {
		return err
	}

	// Write the value delta associated with deleting this key
	lsd, err := cb.ensureStorageDelta(addr, aidx, global, remainAllocAction, accountIdx)
	if err != nil {
		return err
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

// MakeDebugBalances creates a ledger suitable for dryrun and debugger
func MakeDebugBalances(l LedgerForCowBase, round basics.Round, proto protocol.ConsensusVersion, prevTimestamp int64) apply.Balances {
	base := makeRoundCowBase(l, round-1, 0, basics.Round(0), config.Consensus[proto])

	hdr := bookkeeping.BlockHeader{
		Round:        round,
		UpgradeState: bookkeeping.UpgradeState{CurrentProtocol: proto},
	}
	hint := 2
	// passing an empty AccountTotals here is fine since it's only being used by the top level cow state object.
	cb := makeRoundCowState(base, hdr, config.Consensus[proto], prevTimestamp, ledgercore.AccountTotals{}, hint)
	return cb
}

// StatefulEval runs application.  Execution happens in a child cow and all
// modifications are merged into parent and the ApplyData in params[gi] is
// filled if the program passes.
func (cb *roundCowState) StatefulEval(gi int, params *logic.EvalParams, aidx basics.AppIndex, program []byte) (pass bool, evalDelta transactions.EvalDelta, err error) {
	// Make a child cow to eval our program in
	calf := cb.child(1)
	defer func() {
		// get rid of references to the object that is about to be recycled
		params.Ledger = nil
		params.SigLedger = nil
		calf.recycle()
	}()

	params.Ledger = calf
	params.SigLedger = calf

	pass, err = logic.EvalApp(program, gi, aidx, params)
	if err != nil {
		return false, transactions.EvalDelta{}, err
	}

	// If program passed, build our eval delta, and commit to state changes
	if pass {
		// Before Contract to Contract calls, use BuildEvalDelta because it has
		// hairy code to maintain compatibility over some buggy old versions
		// that created EvalDeltas differently.  But after introducing c2c, it's
		// "too late" to build the EvalDelta here, since the ledger includes
		// changes from this app and any inner called apps. Instead, we now keep
		// the EvalDelta built as we go, in app evaluation.  So just use it.
		if cb.proto.LogicSigVersion < 6 {
			evalDelta, err = calf.buildEvalDelta(aidx, &params.TxnGroup[gi].Txn)
			if err != nil {
				return false, transactions.EvalDelta{}, err
			}
			evalDelta.Logs = params.TxnGroup[gi].EvalDelta.Logs
			evalDelta.InnerTxns = params.TxnGroup[gi].EvalDelta.InnerTxns
		} else {
			evalDelta = params.TxnGroup[gi].EvalDelta
		}
		calf.commitToParent()
	}

	return pass, evalDelta, nil
}

// buildEvalDelta creates an EvalDelta by converting internal sdeltas
// into the (Global|Local)Delta fields.
func (cb *roundCowState) buildEvalDelta(aidx basics.AppIndex, txn *transactions.Transaction) (evalDelta transactions.EvalDelta, err error) {
	// sdeltas
	foundGlobal := false
	for addr, smod := range cb.sdeltas {
		for aapp, sdelta := range smod {
			// Check that all of these deltas are for the correct app
			if aapp.aidx != aidx {
				err = fmt.Errorf("found storage delta for different app during StatefulEval/BuildDelta: %d != %d", aapp.aidx, aidx)
				return transactions.EvalDelta{}, err
			}
			if aapp.global {
				// Check that there is at most one global delta
				if foundGlobal {
					err = fmt.Errorf("found more than one global delta during StatefulEval/BuildDelta: %d", aapp.aidx)
					return transactions.EvalDelta{}, err
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
				if cb.compatibilityMode {
					addrOffset = sdelta.accountIdx
				} else {
					addrOffset, err = txn.IndexByAddress(addr, txn.Sender)
					if err != nil {
						return transactions.EvalDelta{}, err
					}
				}

				d := sdelta.kvCow.serialize()
				// noEmptyDeltas restricts producing empty local deltas in general
				// but allows it for a period of time when a buggy version was live
				noEmptyDeltas := cb.proto.NoEmptyLocalDeltas || (cb.mods.Hdr.CurrentProtocol == protocol.ConsensusV24) && (cb.mods.Hdr.NextProtocol != protocol.ConsensusV26)
				if !noEmptyDeltas || len(d) != 0 {
					evalDelta.LocalDeltas[addrOffset] = d
				}
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
	} else {
		// Otherwise, the child's new values get merged into the delta of the
		// parent, but we keep the parent's old/oldExists values.
		for key, childVal := range child.kvCow {
			delta, ok := lsd.kvCow[key]
			if !ok {
				lsd.kvCow[key] = childVal
				continue
			}

			delta.new = childVal.new
			delta.newExists = childVal.newExists
			lsd.kvCow[key] = delta
		}
	}
	// counts can just get overwritten because they are absolute
	// see ensureStorageDelta: counts are initialized from parent cow
	lsd.counts = child.counts       // propagate addition/deletion of globals
	lsd.maxCounts = child.maxCounts // propagate updates to global schema

	// sanity checks
	if lsd.action == deallocAction && len(lsd.kvCow) > 0 {
		panic("dealloc state delta, but nonzero kv change")
	}
}

// applyStorageDelta saves in-mem storageDelta into AccountData
// cow stores app data separately from AccountData to minimize potentially large AccountData copying/reallocations.
// When cow is done applyStorageDelta offloads app stores into AccountData
func applyStorageDelta(cb *roundCowState, addr basics.Address, aapp storagePtr, storeDelta *storageDelta) error {
	// duplicate code in branches is proven to be a bit faster than
	// having basics.AppParams and basics.AppLocalState under a common interface with additional loops and type assertions
	if aapp.global {
		switch storeDelta.action {
		case deallocAction:
			// app params and app local states might be accessed without touching base account record
			// from TEAL by writing into KV store.
			// This is OK although KV deletion and allocation must be preceded by updating counters in base account record,
			// so ensure the base record was updated and placed into deltas
			if _, ok := cb.mods.Accts.GetData(addr); !ok {
				return fmt.Errorf("dealloc consistency check (global=%v) failed for (%s, %d)", aapp.global, addr.String(), aapp.aidx)
			}
			// fetch AppLocalState to store along with deleted AppParams
			state, _, err := cb.lookupAppLocalState(addr, aapp.aidx, true)
			if err != nil {
				return fmt.Errorf("fetching storage (global=%v) failed for (%s, %d) AppLocalState: %w", aapp.global, addr.String(), aapp.aidx, err)
			}
			cb.mods.Accts.UpsertAppResource(addr, aapp.aidx, ledgercore.AppParamsDelta{Deleted: true}, state)
		case allocAction:
			if _, ok := cb.mods.Accts.GetData(addr); !ok {
				return fmt.Errorf("alloc consistency check (global=%v) failed for (%s, %d)", aapp.global, addr.String(), aapp.aidx)
			}
			fallthrough
		case remainAllocAction:
			// note: these should always exist because they were
			// at least preceded by a call to PutAppParams/PutAssetParams()
			params, exist, err := cb.lookupAppParams(addr, aapp.aidx, true)
			if err != nil {
				return fmt.Errorf("fetching storage (global=%v) failed for (%s, %d): %w", aapp.global, addr.String(), aapp.aidx, err)
			}
			if !exist {
				return fmt.Errorf("could not find existing params for %v", aapp.aidx)
			}
			paramsClone := params.Params.Clone()
			params.Params = &paramsClone
			if (storeDelta.action == allocAction && len(storeDelta.kvCow) > 0) ||
				(storeDelta.action == remainAllocAction && params.Params.GlobalState == nil) {
				// allocate KeyValue for
				// 1) app creation and global write in the same app call
				// 2) global state writing into empty global state
				params.Params.GlobalState = make(basics.TealKeyValue)
			}
			// note: if this is an allocAction, there will be no
			// DeleteActions below
			for k, v := range storeDelta.kvCow {
				if !v.newExists {
					delete(params.Params.GlobalState, k)
				} else {
					params.Params.GlobalState[k] = v.new
				}
			}
			// fetch AppLocalState to store along with updated AppParams
			state, _, err := cb.lookupAppLocalState(addr, aapp.aidx, true)
			if err != nil {
				return fmt.Errorf("fetching storage (global=%v) failed for (%s, %d) AppLocalState: %w", aapp.global, addr.String(), aapp.aidx, err)
			}
			cb.mods.Accts.UpsertAppResource(addr, aapp.aidx, params, state)
		}
	} else {
		switch storeDelta.action {
		case deallocAction:
			if _, ok := cb.mods.Accts.GetData(addr); !ok {
				return fmt.Errorf("dealloc consistency check (global=%v) failed for (%s, %d)", aapp.global, addr.String(), aapp.aidx)
			}
			// fetch AppParams to store along with deleted AppLocalState
			params, _, err := cb.lookupAppParams(addr, aapp.aidx, true)
			if err != nil {
				return fmt.Errorf("fetching storage (global=%v) failed for (%s, %d) AppLocalState: %w", aapp.global, addr.String(), aapp.aidx, err)
			}
			cb.mods.Accts.UpsertAppResource(addr, aapp.aidx, params, ledgercore.AppLocalStateDelta{Deleted: true})
		case allocAction:
			if _, ok := cb.mods.Accts.GetData(addr); !ok {
				return fmt.Errorf("alloc consistency check (global=%v) failed for (%s, %d)", aapp.global, addr.String(), aapp.aidx)
			}
			fallthrough
		case remainAllocAction:
			// note: these should always exist because they were
			// at least preceded by a call to PutAssetHolding/PutLocalState
			states, exist, err := cb.lookupAppLocalState(addr, aapp.aidx, true)
			if err != nil {
				return fmt.Errorf("fetching storage (global=%v) failed for (%s, %d): %w", aapp.global, addr.String(), aapp.aidx, err)
			}
			if !exist {
				return fmt.Errorf("could not find existing states for %v", aapp.aidx)
			}

			statesClone := states.LocalState.Clone()
			states.LocalState = &statesClone
			if (storeDelta.action == allocAction && len(storeDelta.kvCow) > 0) ||
				(storeDelta.action == remainAllocAction && states.LocalState.KeyValue == nil) {
				// allocate KeyValue for
				// 1) opting in and local state write in the same app call
				// 2) local state writing into empty local state (opted in)
				states.LocalState.KeyValue = make(basics.TealKeyValue)
			}
			// note: if this is an allocAction, there will be no
			// DeleteActions below
			for k, v := range storeDelta.kvCow {
				if !v.newExists {
					delete(states.LocalState.KeyValue, k)
				} else {
					states.LocalState.KeyValue[k] = v.new
				}
			}
			// fetch AppParams to store along with deleted AppLocalState
			params, _, err := cb.lookupAppParams(addr, aapp.aidx, true)
			if err != nil {
				return fmt.Errorf("fetching storage (global=%v) failed for (%s, %d) AppLocalState: %w", aapp.global, addr.String(), aapp.aidx, err)
			}
			cb.mods.Accts.UpsertAppResource(addr, aapp.aidx, params, states)
		}
	}
	return nil
}
