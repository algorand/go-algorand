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

func opBoxCreate(cx *EvalContext) error {
	last := len(cx.stack) - 1 // name
	prev := last - 1          // size

	name := string(cx.stack[last].Bytes)
	size := cx.stack[prev].Uint

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

	err := cx.availableBox(name, boxCreate, size)
	if err != nil {
		return err
	}

	appAddr := cx.getApplicationAddress(cx.appID)
	err = cx.Ledger.NewBox(cx.appID, name, size, appAddr)
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
	appAddr := cx.getApplicationAddress(cx.appID)
	return cx.Ledger.DelBox(cx.appID, name, appAddr)
}

const boxPrefix = "bx:"
const boxPrefixLength = 3 // len("bx:")
const boxNameIndex = 11 // len("bx:") + 8 (appIdx, big-endian)

// MakeBoxKey creates the key that a box named `name` under app `appIdx` should use.
func MakeBoxKey(appIdx basics.AppIndex, name string) string {
	/* This format is chosen so that a simple indexing scheme on the key would
	   allow for quick lookups of all the boxes of a certain app, or even all
	   the boxes of a certain app with a certain prefix.

	   The "bx:" prefix is so that the kvstore might be usable for things
	   besides boxes.
	*/
	key := make([]byte, boxNameIndex + len(name))
	copy(key, boxPrefix)
	binary.BigEndian.PutUint64(key[boxPrefixLength:], uint64(appIdx))
	copy(key[boxNameIndex:], name)
	return string(key)
}

// GetAppAndNameFromKey extracts an appid and box name from a string that was created by MakeBoxKey()
func GetAppAndNameFromKey(key string) (basics.AppIndex, string, error) {
	// no assertion that prefix is "bx:"
	if len(key) < boxPrefixLength+8 {
		return 0, "", fmt.Errorf("GetAppNameFromKey() cannot extract AppIndex as key too short (length=%d)", len(key))
	}
	// WARNING: even junk such as "this is definitely NOT a box key" will return without error
	keyBytes := []byte(key)
	app := (basics.AppIndex)(binary.BigEndian.Uint64(keyBytes[boxPrefixLength:boxNameIndex]))
	return app, string(keyBytes[11:]), nil
}

// TODO: convert the following to a unit test
// func main() {
// 	var app AppIndex = 42
// 	fmt.Printf("Hello app %d\n", app)

// 	name := "yo yo mama"

// 	key := MakeBoxKey(app, name)
// 	fmt.Printf("app->%d\nname->%s\nkey=>%s", app, name, key)

// 	fmt.Println("\n\n\nNOW FOR GetAppNameFromkey()\n\n")

// 	testCases := []struct {
// 		app  AppIndex
// 		name string
// 	}{
// 		{42, "yo yo mother"}, {0, "stranger"}, {131231, "348-8uj"}, {0, ""},
// 	}
// 	fmt.Printf("TEST CASES: %+v\n\n", testCases)
// 	for i, testCase := range testCases {
// 		fmt.Printf("%d. %d + %s -->\n", i+1, testCase.app, testCase.name)
// 		key = MakeBoxKey(testCase.app, testCase.name)
// 		fmt.Printf("-->[%s] of length <%d>\n", key, len(key))
// 		app2, name2, _ := GetAppNameFromKey(key)
// 		fmt.Printf("BACK TO app=[%d] and box=<%s>\n", app2, name2)
// 	}

// 	errorCases := []string{"too short", "this is uttter nonsense"}
// OOPS - the second case doesn't actually error

// 	fmt.Printf("\n\n\nERRORING CASES: %#v\n\b\n", errorCases)
// 	for i, errorCase := range errorCases {
// 		fmt.Printf("%d. %s -->\n", i+1, errorCase)
// 		app, name, err := GetAppNameFromKey(errorCase)
// 		fmt.Printf("app=%d\nbox=%s\nerr=%v\n", app, name, err)
// 	}

// }