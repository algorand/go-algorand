// Copyright (C) 2019-2024 Algorand, Inc.
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

package logic

import "github.com/algorand/go-algorand/data/basics"

// debugStackExplain explains the effect of an opcode over the stack
// with 2 integers: deletions and additions, representing pops and inserts.
// An opcode may delete a few variables from stack, then add a few to stack.
type debugStackExplain func(*EvalContext) (int, int)

// AppStateOpEnum stands for the operation enum to app state, should be one of create, write, read, delete.
type AppStateOpEnum uint64

const (
	// AppStateWrite stands for writing to an app state.
	AppStateWrite AppStateOpEnum = iota + 1

	// AppStateDelete stands for deleting an app state.
	AppStateDelete

	// AppStateRead stands for reading from an app state.
	AppStateRead
)

// AppStateEnum stands for the enum of app state type, should be one of global/local/box.
type AppStateEnum uint64

const (
	// GlobalState stands for global state of an app.
	GlobalState AppStateEnum = iota + 1

	// LocalState stands for local state of an app.
	LocalState

	// BoxState stands for box storage of an app.
	BoxState
)

// stateChangeExplain explains how an opcode change the app's state with a quadruple:
// AppStateEnum stands for which app state: local/global/box,
// AppStateOpEnum stands for read/write/create/delete/check-existence,
// together with key for touched state
type stateChangeExplain func(ctx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string)

func opPushIntsStackChange(cx *EvalContext) (deletions, additions int) {
	// NOTE: WE ARE SWALLOWING THE ERROR HERE!
	// FOR EVENTUALLY IT WOULD ERROR IN ASSEMBLY
	intc, _, _ := parseIntImmArgs(cx.program, cx.pc+1)

	additions = len(intc)
	return
}

func opPushBytessStackChange(cx *EvalContext) (deletions, additions int) {
	// NOTE: WE ARE SWALLOWING THE ERROR HERE!
	// FOR EVENTUALLY IT WOULD ERROR IN ASSEMBLY
	cbytess, _, _ := parseByteImmArgs(cx.program, cx.pc+1)

	additions = len(cbytess)
	return
}

func opReturnStackChange(cx *EvalContext) (deletions, additions int) {
	deletions = len(cx.Stack)
	additions = 1
	return
}

func opBuryStackChange(cx *EvalContext) (deletions, additions int) {
	depth := int(cx.program[cx.pc+1])

	deletions = depth + 1
	additions = depth
	return
}

func opPopNStackChange(cx *EvalContext) (deletions, additions int) {
	n := int(cx.program[cx.pc+1])

	deletions = n
	return
}

func opDupNStackChange(cx *EvalContext) (deletions, additions int) {
	n := int(cx.program[cx.pc+1])

	deletions = 1
	additions = n + 1
	return
}

func opDigStackChange(cx *EvalContext) (deletions, additions int) {
	additions = 1
	return
}

func opFrameDigStackChange(cx *EvalContext) (deletions, additions int) {
	additions = 1
	return
}

func opCoverStackChange(cx *EvalContext) (deletions, additions int) {
	depth := int(cx.program[cx.pc+1])

	deletions = depth + 1
	additions = depth + 1
	return
}

func opUncoverStackChange(cx *EvalContext) (deletions, additions int) {
	depth := int(cx.program[cx.pc+1])

	deletions = depth + 1
	additions = depth + 1
	return
}

func opRetSubStackChange(cx *EvalContext) (deletions, additions int) {
	topFrame := cx.callstack[len(cx.callstack)-1]
	// fast path, no proto case
	if !topFrame.clear {
		return
	}

	argStart := topFrame.height - topFrame.args
	topStackIdx := len(cx.Stack) - 1

	diff := topStackIdx - argStart + 1

	deletions = diff
	additions = topFrame.returns
	return
}

func opFrameBuryStackChange(cx *EvalContext) (deletions, additions int) {
	topFrame := cx.callstack[len(cx.callstack)-1]

	immIndex := int8(cx.program[cx.pc+1])
	idx := topFrame.height + int(immIndex)
	topStackIdx := len(cx.Stack) - 1

	diff := topStackIdx - idx + 1

	deletions = diff
	additions = diff - 1
	return
}

func opMatchStackChange(cx *EvalContext) (deletions, additions int) {
	labelNum := int(cx.program[cx.pc+1])

	deletions = labelNum + 1
	return
}

func opBoxExtractStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // length
	prev := last - 1          // start
	pprev := prev - 1         // name

	return BoxState, AppStateRead, cx.appID, basics.Address{}, string(cx.Stack[pprev].Bytes)
}

func opBoxGetStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // name

	return BoxState, AppStateRead, cx.appID, basics.Address{}, string(cx.Stack[last].Bytes)
}

func opBoxCreateStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // size
	prev := last - 1          // name

	return BoxState, AppStateWrite, cx.appID, basics.Address{}, string(cx.Stack[prev].Bytes)
}

func opBoxReplaceStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // replacement
	prev := last - 1          // start
	pprev := prev - 1         // name

	return BoxState, AppStateWrite, cx.appID, basics.Address{}, string(cx.Stack[pprev].Bytes)
}

func opBoxSpliceStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	name := len(cx.Stack) - 4 // name, start, length, replacement

	return BoxState, AppStateWrite, cx.appID, basics.Address{}, string(cx.Stack[name].Bytes)
}

func opBoxDelStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // name

	return BoxState, AppStateDelete, cx.appID, basics.Address{}, string(cx.Stack[last].Bytes)
}

func opBoxPutStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // value
	prev := last - 1          // name

	return BoxState, AppStateWrite, cx.appID, basics.Address{}, string(cx.Stack[prev].Bytes)
}

func opBoxResizeStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	name := len(cx.Stack) - 2 // name, size

	return BoxState, AppStateWrite, cx.appID, basics.Address{}, string(cx.Stack[name].Bytes)
}

func opAppLocalGetStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // state key
	prev := last - 1          // account

	// NOTE: we swallow the error of finding account ref, for eventually it would error in execution time,
	// and we don't have to complain here.
	var addr basics.Address
	addr, _, _, _ = cx.localsReference(cx.Stack[prev], 0)

	return LocalState, AppStateRead, cx.appID, addr, string(cx.Stack[last].Bytes)
}

func opAppLocalGetExStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // state key
	prev := last - 1          // app id
	pprev := prev - 1         // account

	// NOTE: we swallow the error of finding account ref, for eventually it would error in execution time,
	// and we don't have to complain here.
	addr, appID, _, _ := cx.localsReference(cx.Stack[pprev], cx.Stack[prev].Uint)

	return LocalState, AppStateRead, appID, addr, string(cx.Stack[last].Bytes)
}

func opAppGlobalGetStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // state key

	return GlobalState, AppStateRead, cx.appID, basics.Address{}, string(cx.Stack[last].Bytes)
}

func opAppGlobalGetExStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // state key
	prev := last - 1          // app id

	// NOTE: we swallow the error of finding application ID, for eventually it would error in execution time,
	// and we don't have to complain here.
	appID, _ := cx.appReference(cx.Stack[prev].Uint, true)

	return GlobalState, AppStateRead, appID, basics.Address{}, string(cx.Stack[last].Bytes)
}

func opAppLocalPutStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // value
	prev := last - 1          // state key
	pprev := prev - 1         // account

	// NOTE: we swallow the error of finding account ref, for eventually it would error in execution time,
	// and we don't have to complain here.
	var addr basics.Address
	addr, _, _ = cx.mutableAccountReference(cx.Stack[pprev])

	return LocalState, AppStateWrite, cx.appID, addr, string(cx.Stack[prev].Bytes)
}

func opAppGlobalPutStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // value
	prev := last - 1          // state key

	return GlobalState, AppStateWrite, cx.appID, basics.Address{}, string(cx.Stack[prev].Bytes)
}

func opAppLocalDelStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // key
	prev := last - 1          // account

	// NOTE: we swallow the error of finding account ref, for eventually it would error in execution time,
	// and we don't have to complain here.
	var addr basics.Address
	addr, _, _ = cx.mutableAccountReference(cx.Stack[prev])

	return LocalState, AppStateDelete, cx.appID, addr, string(cx.Stack[last].Bytes)
}

func opAppGlobalDelStateChange(cx *EvalContext) (AppStateEnum, AppStateOpEnum, basics.AppIndex, basics.Address, string) {
	last := len(cx.Stack) - 1 // key

	return GlobalState, AppStateDelete, cx.appID, basics.Address{}, string(cx.Stack[last].Bytes)
}

// AppStateQuerying is used for simulation endpoint exec trace export:
// it reads *new* app state after opcode that writes to app-state.
// Since it is collecting new/updated app state, we don't have to error again here,
// and thus we omit the error or non-existence case, just returning empty TealValue.
// Otherwise, we find the updated new state value, and wrap up with new TealValue.
func AppStateQuerying(
	cx *EvalContext,
	appState AppStateEnum, stateOp AppStateOpEnum,
	appID basics.AppIndex, account basics.Address, key string) basics.TealValue {
	switch appState {
	case BoxState:
		boxBytes, exists, err := cx.Ledger.GetBox(appID, key)
		if !exists || err != nil {
			return basics.TealValue{}
		}
		return basics.TealValue{
			Type:  basics.TealBytesType,
			Bytes: string(boxBytes),
		}
	case GlobalState:
		globalValue, exists, err := cx.Ledger.GetGlobal(appID, key)
		if !exists || err != nil {
			return basics.TealValue{}
		}
		return globalValue
	case LocalState:
		var (
			addr   basics.Address
			acctID uint64
			err    error
		)
		switch stateOp {
		case AppStateWrite, AppStateDelete:
			addr, acctID, err = cx.mutableAccountReference(stackValue{Bytes: account[:]})
		default:
			addr, _, acctID, err = cx.localsReference(stackValue{Bytes: account[:]}, uint64(appID))
		}
		if err != nil {
			return basics.TealValue{}
		}
		localValue, exists, err := cx.Ledger.GetLocal(addr, appID, key, acctID)
		if !exists || err != nil {
			return basics.TealValue{}
		}
		return localValue
	default:
		return basics.TealValue{}
	}
}
