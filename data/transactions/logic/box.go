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
	"github.com/algorand/go-algorand/data/transactions"
)

const (
	boxCreate = iota
	boxRead
	boxWrite
	boxDelete
)

func (cx *EvalContext) availableBox(name string, operation int, createSize uint64) ([]byte, bool, error) {
	if cx.txn.Txn.OnCompletion == transactions.ClearStateOC {
		return nil, false, fmt.Errorf("boxes may not be accessed from ClearState program")
	}

	dirty, ok := cx.available.boxes[boxRef{cx.appID, name}]
	if !ok {
		return nil, false, fmt.Errorf("invalid Box reference %v", name)
	}

	// Since the box is in cx.available, we know this GetBox call is cheap. It
	// will go (at most) to the cowRoundBase. Knowledge about existence
	// simplifies write budget tracking, then we return the info to avoid yet
	// another call to GetBox which most ops need anyway.
	content, exists, err := cx.Ledger.GetBox(cx.appID, name)
	if err != nil {
		return nil, false, err
	}

	switch operation {
	case boxCreate:
		if exists {
			if createSize != uint64(len(content)) {
				return nil, false, fmt.Errorf("box size mismatch %d %d", uint64(len(content)), createSize)
			}
			// Since it exists, we have no dirty work to do. The weird case of
			// box_put, which seems like a combination of create and write, is
			// properly handled because already used boxWrite to declare the
			// intent to write (and tracky dirtiness).
			return content, exists, nil
		}
		fallthrough // If it doesn't exist, a create is like write
	case boxWrite:
		writeSize := createSize
		if exists {
			writeSize = uint64(len(content))
		}
		if !dirty {
			cx.available.dirtyBytes += writeSize
		}
		dirty = true
	case boxDelete:
		if dirty {
			cx.available.dirtyBytes -= uint64(len(content))
		}
		dirty = false
	case boxRead:
		/* nothing to do */
	}
	cx.available.boxes[boxRef{cx.appID, name}] = dirty

	if cx.available.dirtyBytes > cx.ioBudget {
		return nil, false, fmt.Errorf("write budget (%d) exceeded %d", cx.ioBudget, cx.available.dirtyBytes)
	}
	return content, exists, nil
}

func argCheck(cx *EvalContext, name string, size uint64) error {
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
	if size > cx.Proto.MaxBoxSize {
		return fmt.Errorf("box size too large: %d, maximum is %d", size, cx.Proto.MaxBoxSize)
	}
	return nil
}

func opBoxCreate(cx *EvalContext) error {
	last := len(cx.stack) - 1 // size
	prev := last - 1          // name

	name := string(cx.stack[prev].Bytes)
	size := cx.stack[last].Uint

	err := argCheck(cx, name, size)
	if err != nil {
		return err
	}
	_, exists, err := cx.availableBox(name, boxCreate, size)
	if err != nil {
		return err
	}
	if !exists {
		appAddr := cx.getApplicationAddress(cx.appID)
		err = cx.Ledger.NewBox(cx.appID, name, make([]byte, size), appAddr)
		if err != nil {
			return err
		}
	}

	cx.stack[prev] = boolToSV(!exists)
	cx.stack = cx.stack[:last]
	return err
}

func opBoxExtract(cx *EvalContext) error {
	last := len(cx.stack) - 1 // length
	prev := last - 1          // start
	pprev := prev - 1         // name

	name := string(cx.stack[pprev].Bytes)
	start := cx.stack[prev].Uint
	length := cx.stack[last].Uint

	err := argCheck(cx, name, basics.AddSaturate(start, length))
	if err != nil {
		return err
	}
	contents, exists, err := cx.availableBox(name, boxRead, 0)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("no such box %#v", name)
	}

	bytes, err := extractCarefully(contents, start, length)
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

	err := argCheck(cx, name, basics.AddSaturate(start, uint64(len(replacement))))
	if err != nil {
		return err
	}

	contents, exists, err := cx.availableBox(name, boxWrite, 0 /* size is already known */)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("no such box %#v", name)
	}

	bytes, err := replaceCarefully(contents, replacement, start)
	if err != nil {
		return err
	}
	cx.stack = cx.stack[:pprev]
	return cx.Ledger.SetBox(cx.appID, name, bytes)
}

func opBoxDel(cx *EvalContext) error {
	last := len(cx.stack) - 1 // name
	name := string(cx.stack[last].Bytes)

	err := argCheck(cx, name, 0)
	if err != nil {
		return err
	}
	_, exists, err := cx.availableBox(name, boxDelete, 0)
	if err != nil {
		return err
	}
	if exists {
		appAddr := cx.getApplicationAddress(cx.appID)
		_, err := cx.Ledger.DelBox(cx.appID, name, appAddr)
		if err != nil {
			return err
		}
	}
	cx.stack[last] = boolToSV(exists)
	return nil
}

func opBoxLen(cx *EvalContext) error {
	last := len(cx.stack) - 1 // name
	name := string(cx.stack[last].Bytes)

	err := argCheck(cx, name, 0)
	if err != nil {
		return err
	}
	contents, exists, err := cx.availableBox(name, boxRead, 0)
	if err != nil {
		return err
	}

	cx.stack[last] = stackValue{Uint: uint64(len(contents))}
	cx.stack = append(cx.stack, boolToSV(exists))
	return nil
}

func opBoxGet(cx *EvalContext) error {
	last := len(cx.stack) - 1 // name
	name := string(cx.stack[last].Bytes)

	err := argCheck(cx, name, 0)
	if err != nil {
		return err
	}
	contents, exists, err := cx.availableBox(name, boxRead, 0)
	if err != nil {
		return err
	}
	if !exists {
		contents = []byte{}
	}
	cx.stack[last].Bytes = contents // Will rightly panic if too big
	cx.stack = append(cx.stack, boolToSV(exists))
	return nil
}

func opBoxPut(cx *EvalContext) error {
	last := len(cx.stack) - 1 // value
	prev := last - 1          // name

	value := cx.stack[last].Bytes
	name := string(cx.stack[prev].Bytes)

	err := argCheck(cx, name, uint64(len(value)))
	if err != nil {
		return err
	}

	// This boxWrite usage requires the size, because the box may not exist.
	contents, exists, err := cx.availableBox(name, boxWrite, uint64(len(value)))
	if err != nil {
		return err
	}

	cx.stack = cx.stack[:prev]

	if exists {
		/* the replacement must match existing size */
		if len(contents) != len(value) {
			return fmt.Errorf("attempt to box_put wrong size %d != %d", len(contents), len(value))
		}
		return cx.Ledger.SetBox(cx.appID, name, value)
	}

	/* The box did not exist, so create it. */
	appAddr := cx.getApplicationAddress(cx.appID)
	return cx.Ledger.NewBox(cx.appID, name, value, appAddr)
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
