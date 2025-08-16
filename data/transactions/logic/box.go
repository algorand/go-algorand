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

package logic

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

// BoxOperation is an enum of box operation types
type BoxOperation int

const (
	// BoxCreateOperation creates a box
	BoxCreateOperation BoxOperation = iota
	// BoxReadOperation reads a box
	BoxReadOperation
	// BoxWriteOperation writes to a box
	BoxWriteOperation
	// BoxDeleteOperation deletes a box
	BoxDeleteOperation
	// BoxResizeOperation resizes a box
	BoxResizeOperation
)

func (cx *EvalContext) availableBox(name string, operation BoxOperation, createSize uint64) ([]byte, bool, error) {
	if cx.txn.Txn.OnCompletion == transactions.ClearStateOC {
		return nil, false, fmt.Errorf("boxes may not be accessed from ClearState program")
	}

	dirty, ok := cx.available.boxes[basics.BoxRef{App: cx.appID, Name: name}]

	newAppAccess := false
	// maybe allow it (and account for it) if a newly created app is accessing a
	// box. we allow this because we know the box is empty upon first touch, so
	// we don't have to go to the disk. but we only allow one such access for
	// each spare (empty) box ref. that way, we can't end up needing to write
	// many separate newly created boxes.
	if !ok && cx.Proto.EnableUnnamedBoxAccessInNewApps {
		if _, newAppAccess = cx.available.createdApps[cx.appID]; newAppAccess {
			if cx.available.unnamedAccess > 0 {
				ok = true                    // allow it
				cx.available.unnamedAccess-- // account for it
				dirty = false                // no-op, but for clarity

				// it will be marked dirty and dirtyBytes will be incremented
				// below, like any create. as a (good) side-effect it will go
				// into `cx.available` so that later uses will see it in
				// available.boxes, skipping this section
			}
		}
	}

	if !ok && cx.UnnamedResources != nil {
		ok = cx.UnnamedResources.AvailableBox(cx.appID, name, newAppAccess, createSize)
	}
	if !ok {
		return nil, false, fmt.Errorf("invalid Box reference %#x", name)
	}

	// If the box is in cx.available, GetBox() is cheap. It will go (at most) to
	// the cowRoundBase. But if we did a "newAppAccess", GetBox would go to disk
	// just to find the box is not there. So we skip it.
	content, exists := []byte(nil), false
	if !newAppAccess {
		var getErr error
		content, exists, getErr = cx.Ledger.GetBox(cx.appID, name)
		if getErr != nil {
			return nil, false, getErr
		}
	}

	switch operation {
	case BoxCreateOperation:
		if exists {
			if createSize != uint64(len(content)) {
				return nil, false, fmt.Errorf("box size mismatch %d %d", uint64(len(content)), createSize)
			}
			// Since it exists, we have no dirty work to do. The weird case of
			// box_put, which seems like a combination of create and write, is
			// properly handled because opBoxPut uses BoxWriteOperation to
			// declare the intent to write (and track dirtiness). opBoxPut
			// performs the length match check itself.
			return content, exists, nil
		}
		fallthrough // If it doesn't exist, a create is like write
	case BoxWriteOperation:
		writeSize := createSize
		if exists {
			writeSize = uint64(len(content))
		}
		if !dirty {
			cx.available.dirtyBytes += writeSize
		}
		dirty = true
	case BoxResizeOperation:
		newSize := createSize
		if dirty {
			cx.available.dirtyBytes -= uint64(len(content))
		}
		cx.available.dirtyBytes += newSize
		dirty = true
	case BoxDeleteOperation:
		if dirty {
			cx.available.dirtyBytes -= uint64(len(content))
		}
		dirty = false
	case BoxReadOperation:
		/* nothing to do */
	}
	cx.available.boxes[basics.BoxRef{App: cx.appID, Name: name}] = dirty

	if cx.available.dirtyBytes > cx.ioBudget {
		return nil, false, fmt.Errorf("write budget (%d) exceeded %d", cx.ioBudget, cx.available.dirtyBytes)
	}
	return content, exists, nil
}

func lengthChecks(cx *EvalContext, name string, size uint64) error {
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
	last := len(cx.Stack) - 1 // size
	prev := last - 1          // name

	name := string(cx.Stack[prev].Bytes)
	size := cx.Stack[last].Uint

	err := lengthChecks(cx, name, size)
	if err != nil {
		return err
	}
	_, exists, err := cx.availableBox(name, BoxCreateOperation, size)
	if err != nil {
		return err
	}
	if !exists {
		appAddr := cx.GetApplicationAddress(cx.appID)
		err = cx.Ledger.NewBox(cx.appID, name, make([]byte, size), appAddr)
		if err != nil {
			return err
		}
	}

	cx.Stack[prev] = boolToSV(!exists)
	cx.Stack = cx.Stack[:last]
	return err
}

func opBoxExtract(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // length
	prev := last - 1          // start
	pprev := prev - 1         // name

	name := string(cx.Stack[pprev].Bytes)
	start := cx.Stack[prev].Uint
	length := cx.Stack[last].Uint

	err := lengthChecks(cx, name, basics.AddSaturate(start, length))
	if err != nil {
		return err
	}
	contents, exists, err := cx.availableBox(name, BoxReadOperation, 0)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("no such box %#x", name)
	}

	bytes, err := extractCarefully(contents, start, length)
	cx.Stack[pprev].Bytes = bytes
	cx.Stack = cx.Stack[:prev]
	return err
}

func opBoxReplace(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // replacement
	prev := last - 1          // start
	pprev := prev - 1         // name

	replacement := cx.Stack[last].Bytes
	start := cx.Stack[prev].Uint
	name := string(cx.Stack[pprev].Bytes)

	err := lengthChecks(cx, name, basics.AddSaturate(start, uint64(len(replacement))))
	if err != nil {
		return err
	}

	contents, exists, err := cx.availableBox(name, BoxWriteOperation, 0 /* size is already known */)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("no such box %#x", name)
	}

	bytes, err := replaceCarefully(contents, replacement, start)
	if err != nil {
		return err
	}
	cx.Stack = cx.Stack[:pprev]
	return cx.Ledger.SetBox(cx.appID, name, bytes)
}

func opBoxSplice(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // replacement
	replacement := cx.Stack[last].Bytes
	length := cx.Stack[last-1].Uint
	start := cx.Stack[last-2].Uint
	name := string(cx.Stack[last-3].Bytes)

	err := lengthChecks(cx, name, 0)
	if err != nil {
		return err
	}

	contents, exists, err := cx.availableBox(name, BoxWriteOperation, 0 /* size is already known */)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("no such box %#x", name)
	}

	bytes, err := spliceCarefully(contents, replacement, start, length)
	if err != nil {
		return err
	}
	cx.Stack = cx.Stack[:last-3]
	return cx.Ledger.SetBox(cx.appID, name, bytes)
}

func opBoxDel(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // name
	name := string(cx.Stack[last].Bytes)

	err := lengthChecks(cx, name, 0)
	if err != nil {
		return err
	}
	_, exists, err := cx.availableBox(name, BoxDeleteOperation, 0)
	if err != nil {
		return err
	}
	if exists {
		appAddr := cx.GetApplicationAddress(cx.appID)
		_, err := cx.Ledger.DelBox(cx.appID, name, appAddr)
		if err != nil {
			return err
		}
	}
	cx.Stack[last] = boolToSV(exists)
	return nil
}

func opBoxResize(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // size
	prev := last - 1          // name

	name := string(cx.Stack[prev].Bytes)
	size := cx.Stack[last].Uint

	err := lengthChecks(cx, name, size)
	if err != nil {
		return err
	}

	contents, exists, err := cx.availableBox(name, BoxResizeOperation, size)
	if err != nil {
		return err
	}

	if !exists {
		return fmt.Errorf("no such box %#x", name)
	}
	appAddr := cx.GetApplicationAddress(cx.appID)
	_, err = cx.Ledger.DelBox(cx.appID, name, appAddr)
	if err != nil {
		return err
	}
	var resized []byte
	if size > uint64(len(contents)) {
		resized = make([]byte, size)
		copy(resized, contents)
	} else {
		resized = contents[:size]
	}
	err = cx.Ledger.NewBox(cx.appID, name, resized, appAddr)
	if err != nil {
		return err
	}

	cx.Stack = cx.Stack[:prev]
	return err

}

func opBoxLen(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // name
	name := string(cx.Stack[last].Bytes)

	err := lengthChecks(cx, name, 0)
	if err != nil {
		return err
	}
	contents, exists, err := cx.availableBox(name, BoxReadOperation, 0)
	if err != nil {
		return err
	}

	cx.Stack[last] = stackValue{Uint: uint64(len(contents))}
	cx.Stack = append(cx.Stack, boolToSV(exists))
	return nil
}

func opBoxGet(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // name
	name := string(cx.Stack[last].Bytes)

	err := lengthChecks(cx, name, 0)
	if err != nil {
		return err
	}
	contents, exists, err := cx.availableBox(name, BoxReadOperation, 0)
	if err != nil {
		return err
	}
	if !exists {
		contents = []byte{}
	}
	cx.Stack[last].Bytes = contents // Will rightly panic if too big
	cx.Stack = append(cx.Stack, boolToSV(exists))
	return nil
}

func opBoxPut(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // value
	prev := last - 1          // name

	value := cx.Stack[last].Bytes
	name := string(cx.Stack[prev].Bytes)

	err := lengthChecks(cx, name, uint64(len(value)))
	if err != nil {
		return err
	}

	// This boxWrite usage requires the size, because the box may not exist.
	contents, exists, err := cx.availableBox(name, BoxWriteOperation, uint64(len(value)))
	if err != nil {
		return err
	}

	cx.Stack = cx.Stack[:prev]

	if exists {
		/* the replacement must match existing size */
		if len(contents) != len(value) {
			return fmt.Errorf("attempt to box_put wrong size %d != %d", len(contents), len(value))
		}
		return cx.Ledger.SetBox(cx.appID, name, value)
	}

	/* The box did not exist, so create it. */
	appAddr := cx.GetApplicationAddress(cx.appID)
	return cx.Ledger.NewBox(cx.appID, name, value, appAddr)
}

// spliceCarefully is used to make a NEW byteslice copy of original, with
// replacement written over the bytes from start to start+length. Returned slice
// is always the same size as original. Zero bytes are "shifted in" or high
// bytes are "shifted out" as needed.
func spliceCarefully(original []byte, replacement []byte, start uint64, olen uint64) ([]byte, error) {
	if start > uint64(len(original)) {
		return nil, fmt.Errorf("replacement start %d beyond length: %d", start, len(original))
	}
	oend := start + olen
	if oend < start {
		return nil, fmt.Errorf("splice end exceeds uint64")
	}

	if oend > uint64(len(original)) {
		return nil, fmt.Errorf("splice end %d beyond original length: %d", oend, len(original))
	}

	// Do NOT use the append trick to make a copy here.
	// append(nil, []byte{}...) would return a nil, which means "not a bytearray" to AVM.
	clone := make([]byte, len(original))
	copy(clone[:start], original)
	copied := copy(clone[start:], replacement)
	if copied != len(replacement) {
		return nil, fmt.Errorf("splice inserted bytes too long")
	}
	// If original is "too short" we get zeros at the end. If original is "too
	// long" we lose some bytes. Fortunately, that's what we want.
	copy(clone[int(start)+copied:], original[oend:])
	return clone, nil
}
