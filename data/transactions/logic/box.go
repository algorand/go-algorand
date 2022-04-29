// Copyright (C) 2019-2022 Algorand, Inc.
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

import (
	"errors"
	"fmt"
)

func opBoxCreate(cx *EvalContext) error {
	last := len(cx.stack) - 1 // name
	prev := last - 1          // size

	name := string(cx.stack[last].Bytes)
	size := cx.stack[prev].Uint

	// This is questionable! We need to think about how boxes can be made during
	// the txgroup that constructs the app.  The app won't be funded at create
	// time, but supposing someone uses the "trampoline" technique to fund it in
	// a later txn, if an even later txn invokes it, can it create any boxes?
	if !cx.availableBox(name) {
		return fmt.Errorf("invalid Box reference %v", name)
	}
	err := cx.Ledger.NewBox(cx.appID, name, size)
	if err != nil {
		return err
	}

	cx.stack = cx.stack[:prev]
	return nil
}

func (cx *EvalContext) availableBox(name string) bool {
	if available, ok := cx.available.boxes[cx.appID]; ok {
		for _, n := range available {
			if name == n {
				return true
			}
		}
	}
	return false
}

func opBoxExtract(cx *EvalContext) error {
	last := len(cx.stack) - 1 // length
	prev := last - 1          // start
	pprev := prev - 1         // name

	name := string(cx.stack[pprev].Bytes)
	start := cx.stack[prev].Uint
	length := cx.stack[last].Uint

	if !cx.availableBox(name) {
		return fmt.Errorf("invalid Box reference %v", name)
	}
	box, err := cx.Ledger.GetBox(cx.appID, name)
	if err != nil {
		return err
	}

	end := start + length
	if start > uint64(len(box)) || end > uint64(len(box)) {
		return errors.New("extract range beyond box")
	}

	cx.stack[pprev].Bytes = []byte(box[start:end])
	cx.stack = cx.stack[:prev]
	return nil
}

func opBoxReplace(cx *EvalContext) error {
	last := len(cx.stack) - 1 // replacement
	prev := last - 1          // start
	pprev := prev - 1         // name

	name := string(cx.stack[pprev].Bytes)
	start := cx.stack[prev].Uint
	replacement := cx.stack[last].Bytes

	if !cx.availableBox(name) {
		return fmt.Errorf("invalid Box reference %v", name)
	}
	box, err := cx.Ledger.GetBox(cx.appID, name)
	if err != nil {
		return err
	}

	end := start + uint64(len(replacement))
	if start > uint64(len(box)) || end > uint64(len(box)) {
		return errors.New("replace range beyond box")
	}
	clone := []byte(box)
	copy(clone[start:end], replacement)
	cx.stack = cx.stack[:pprev]
	return cx.Ledger.SetBox(cx.appID, name, string(clone))
}

func opBoxDel(cx *EvalContext) error {
	last := len(cx.stack) - 1 // name
	name := string(cx.stack[last].Bytes)

	if !cx.availableBox(name) {
		return fmt.Errorf("invalid Box reference %v", name)
	}
	cx.stack = cx.stack[:last]
	return cx.Ledger.DelBox(cx.appID, name)
}
