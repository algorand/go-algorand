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
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
)

const (
	boxCreate = iota
	boxRead
	boxWrite
	boxDelete
)

func (cx *EvalContext) availableBox(name string, operation int, createSize uint64) error {
	bt, ok := cx.available.boxes[boxRef{cx.appID, name}]
	if !ok {
		return fmt.Errorf("invalid Box reference %v", name)
	}
	switch operation {
	case boxCreate:
		bt.dirty = true
		bt.size = createSize
	case boxWrite:
		bt.dirty = true
	case boxDelete:
		bt.size = 0
	case boxRead:
		/* nothing to do */
	}
	cx.available.boxes[boxRef{cx.appID, name}] = bt
	return nil
}

func opBoxCreate(cx *EvalContext) error {
	last := len(cx.stack) - 1 // name
	prev := last - 1          // size

	name := string(cx.stack[last].Bytes)
	size := cx.stack[prev].Uint

	// Enforce maximums. Currently this is the same as enforced by ledger. If
	// these were ever to change in proto, we would need to isolate changes to
	// different program versions. (so a v7 app could not see a bigger box than
	// expected, for example)
	if len(name) > cx.Proto.MaxAppKeyLen {
		return fmt.Errorf("name too long: length was %d, maximum is %d", len(name), cx.Proto.MaxAppKeyLen)
	}
	if size > cx.Proto.MaxBoxSize {
		return fmt.Errorf("box size too large: %d, maximum is %d", size, cx.Proto.MaxBoxSize)
	}

	err := cx.availableBox(name, boxCreate, size)
	if err != nil {
		return err
	}
	err = cx.Ledger.NewBox(cx.appID, name, size)
	if err != nil {
		return err
	}

	cx.stack = cx.stack[:prev]
	return nil
}

func opBoxExtract(cx *EvalContext) error {
	last := len(cx.stack) - 1 // length
	prev := last - 1          // start
	pprev := prev - 1         // name

	name := string(cx.stack[pprev].Bytes)
	start := cx.stack[prev].Uint
	length := cx.stack[last].Uint

	err := cx.availableBox(name, boxRead, 0)
	if err != nil {
		return err
	}
	box, ok, err := cx.Ledger.GetBox(cx.appID, name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no such box %#v", name)
	}

	bytes, err := extractCarefully([]byte(box), start, length)
	cx.stack[pprev].Bytes = bytes
	cx.stack = cx.stack[:prev]
	return err
}

func opBoxReplace(cx *EvalContext) error {
	last := len(cx.stack) - 1 // replacement
	prev := last - 1          // start
	pprev := prev - 1         // name

	replacement := cx.stack[last].Bytes
	start := cx.stack[prev].Uint
	name := string(cx.stack[pprev].Bytes)

	err := cx.availableBox(name, boxWrite, 0 /* size is already known */)
	if err != nil {
		return err
	}
	box, ok, err := cx.Ledger.GetBox(cx.appID, name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no such box %#v", name)
	}

	bytes, err := replaceCarefully([]byte(box), replacement, start)
	if err != nil {
		return err
	}
	cx.stack[prev].Bytes = bytes
	cx.stack = cx.stack[:pprev]
	return cx.Ledger.SetBox(cx.appID, name, string(bytes))
}

func opBoxDel(cx *EvalContext) error {
	last := len(cx.stack) - 1 // name
	name := string(cx.stack[last].Bytes)

	err := cx.availableBox(name, boxDelete, 0)
	if err != nil {
		return err
	}
	cx.stack = cx.stack[:last]
	return cx.Ledger.DelBox(cx.appID, name)
}

// MakeBoxKey creates the key that a box named `name` under app `appIdx` should use.
func MakeBoxKey(appIdx basics.AppIndex, name string) string {
	// TODO: This format is WRONG! Printf does substitutions for non-unicode Be
	// sure to use an encoding that allows for prefixes. For example, msgpack is
	// a bad idea, because it encodes the string length ahead of the
	// string. "foo" would not be a prefix of "food".  A straightforward,
	// reasonable encoding might be: bx:[8 byte big endian appid]:[bytes of
	// name] The first colon seems important, so all future uses of kvstore have
	// an easy way to ensure uniqueness.  The second seems less important if the
	// appid is fixed length. But maybe the appID should be in ascii, then the
	// colon is important.
	return fmt.Sprintf("bx:%d:%s", appIdx, name)
}
