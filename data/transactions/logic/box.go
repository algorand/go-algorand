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
	"encoding/binary"
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

func createBox(cx *EvalContext, name string, value string, appAddr basics.Address) error {
	// Enforce length rules. Currently these are the same as enforced by
	// ledger. If these were ever to change in proto, we would need to isolate
	// changes to different program versions. (so a v7 app could not see a
	// bigger box than expected, for example)
	if len(name) == 0 {
		return fmt.Errorf("box names may not be zero length")
	}
	if len(name) > cx.Proto.MaxAppKeyLen {
		return fmt.Errorf("name too long: length was %d, maximum is %d", len(name), cx.Proto.MaxAppKeyLen)
	}
	size := uint64(len(value))
	if size > cx.Proto.MaxBoxSize {
		return fmt.Errorf("box size too large: %d, maximum is %d", size, cx.Proto.MaxBoxSize)
	}

	err := cx.availableBox(name, boxCreate, size) // annotate size for write budget check
	if err != nil {
		return err
	}

	return cx.Ledger.NewBox(cx.appID, name, value, appAddr)
}

func opBoxCreate(cx *EvalContext) error {
	last := len(cx.stack) - 1 // name
	prev := last - 1          // size

	name := string(cx.stack[last].Bytes)
	size := cx.stack[prev].Uint
	appAddr := cx.getApplicationAddress(cx.appID)

	cx.stack = cx.stack[:prev]
	return createBox(cx, name, string(make([]byte, size)), appAddr)
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
	appAddr := cx.getApplicationAddress(cx.appID)
	return cx.Ledger.DelBox(cx.appID, name, appAddr)
}

func opBoxLen(cx *EvalContext) error {
	last := len(cx.stack) - 1 // name
	name := string(cx.stack[last].Bytes)

	err := cx.availableBox(name, boxRead, 0)
	if err != nil {
		return err
	}
	box, ok, err := cx.Ledger.GetBox(cx.appID, name)
	if err != nil {
		return err
	}

	cx.stack[last] = stackValue{Uint: uint64(len(box))}
	cx.stack = append(cx.stack, stackValue{Uint: boolToUint(ok)})
	return nil
}

func opBoxGet(cx *EvalContext) error {
	last := len(cx.stack) - 1 // name
	name := string(cx.stack[last].Bytes)

	err := cx.availableBox(name, boxRead, 0)
	if err != nil {
		return err
	}
	box, ok, err := cx.Ledger.GetBox(cx.appID, name)
	if err != nil {
		return err
	}

	cx.stack[last].Bytes = []byte(box) // Will rightly panic if too big
	cx.stack = append(cx.stack, stackValue{Uint: boolToUint(ok)})
	return nil
}

func opBoxPut(cx *EvalContext) error {
	last := len(cx.stack) - 1 // value
	prev := last - 1          // name

	value := string(cx.stack[last].Bytes)
	name := string(cx.stack[prev].Bytes)

	err := cx.availableBox(name, boxWrite, 0 /* unused for write */)
	if err != nil {
		return err
	}
	box, ok, err := cx.Ledger.GetBox(cx.appID, name)
	if err != nil {
		return err
	}

	cx.stack = cx.stack[:prev]

	if ok {
		/* the box exists, so the replacement must match size */
		if len(box) != len(value) {
			return fmt.Errorf("attempt to box_put wrong size %d != %d", len(box), len(value))
		}

		cx.stack = cx.stack[:prev]
		return cx.Ledger.SetBox(cx.appID, name, value)
	}
	/* The box did not exist, so create it. */
	appAddr := cx.getApplicationAddress(cx.appID)

	return createBox(cx, name, value, appAddr)

}

const boxPrefix = "bx:"
const boxPrefixLength = len(boxPrefix)
const boxNameIndex = boxPrefixLength + 8 // len("bx:") + 8 (appIdx, big-endian)

// MakeBoxKey creates the key that a box named `name` under app `appIdx` should use.
func MakeBoxKey(appIdx basics.AppIndex, name string) string {
	/* This format is chosen so that a simple indexing scheme on the key would
	   allow for quick lookups of all the boxes of a certain app, or even all
	   the boxes of a certain app with a certain prefix.

	   The "bx:" prefix is so that the kvstore might be usable for things
	   besides boxes.
	*/
	key := make([]byte, boxNameIndex+len(name))
	copy(key, boxPrefix)
	binary.BigEndian.PutUint64(key[boxPrefixLength:], uint64(appIdx))
	copy(key[boxNameIndex:], name)
	return string(key)
}

// SplitBoxKey extracts an appid and box name from a string that was created by MakeBoxKey()
func SplitBoxKey(key string) (basics.AppIndex, string, error) {
	if len(key) < boxNameIndex {
		return 0, "", fmt.Errorf("SplitBoxKey() cannot extract AppIndex as key (%s) too short (length=%d)", key, len(key))
	}
	if key[:boxPrefixLength] != boxPrefix {
		return 0, "", fmt.Errorf("SplitBoxKey() illegal app box prefix in key (%s). Expected prefix '%s'", key, boxPrefix)
	}
	keyBytes := []byte(key)
	app := basics.AppIndex(binary.BigEndian.Uint64(keyBytes[boxPrefixLength:boxNameIndex]))
	return app, key[boxNameIndex:], nil
}
