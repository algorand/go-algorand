// Copyright (C) 2019-2026 Algorand, Inc.
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

// checkBoxPermission verifies that the current app may perform operation on
// another app's box. Reads require ForeignBoxReads or FamilyBoxAccess (with the
// same creator); writes require FamilyBoxAccess and the same creator.
func (cx *EvalContext) checkBoxPermission(appID basics.AppIndex, operation BoxOperation) error {
	params, targetCreator, err := cx.Ledger.AppParams(appID)
	if err != nil {
		return err
	}

	// Resolve whether the calling app shares a creator with the target app,
	// but only pay the cost of the lookup when FamilyBoxAccess is set.
	sameCreator := false
	if params.FamilyBoxAccess {
		_, callerCreator, err := cx.Ledger.AppParams(cx.appID)
		if err != nil {
			return err
		}
		sameCreator = callerCreator == targetCreator
	}

	isRead := operation == BoxReadOperation
	switch {
	case isRead && params.ForeignBoxReads:
		// any app with a box reference may read
	case sameCreator:
		// same-creator apps may read and write (FamilyBoxAccess already confirmed above)
	default:
		if isRead {
			return fmt.Errorf("app %d does not permit foreign reads of its boxes", appID)
		}
		return fmt.Errorf("app %d does not permit foreign writes to its boxes", appID)
	}
	return nil
}

// availableAppBox is like availableBox but accesses a box owned by appID rather
// than the current app. It enforces the ForeignBoxReads/FamilyBoxAccess permission
// checks in addition to the standard box-reference availability and write-budget checks.
// An app may always use app_box_* on its own boxes without a permission check.
func (cx *EvalContext) availableAppBox(appID basics.AppIndex, name string, operation BoxOperation, createSize uint64) ([]byte, bool, error) {
	if cx.txn.Txn.OnCompletion == transactions.ClearStateOC {
		return nil, false, fmt.Errorf("boxes may not be accessed from ClearState program")
	}

	dirty, ok := cx.available.boxes[basics.BoxRef{App: appID, Name: name}]

	newAppAccess := false
	// maybe allow it (and account for it) if a newly created app is accessing a
	// box. we allow this because we know the box is empty upon first touch, so
	// we don't have to go to the disk. but we only allow one such access for
	// each spare (empty) box ref. that way, we can't end up needing to write
	// many separate newly created boxes.
	if !ok {
		if _, newAppAccess = cx.available.createdApps[appID]; newAppAccess {
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
		ok = cx.UnnamedResources.AvailableBox(appID, name, newAppAccess, createSize)
	}
	if !ok {
		return nil, false, fmt.Errorf("invalid Box reference %#x", name)
	}

	if appID != cx.appID {
		if err := cx.checkBoxPermission(appID, operation); err != nil {
			return nil, false, err
		}
	}

	// If the box is in cx.available, GetBox() is cheap. It will go (at most) to
	// the cowRoundBase. But if we did a "newAppAccess", GetBox would go to disk
	// just to find the box is not there. So we skip it.
	content, exists := []byte(nil), false
	if !newAppAccess {
		var getErr error
		content, exists, getErr = cx.Ledger.GetBox(appID, name)
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
		fallthrough
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
	cx.available.boxes[basics.BoxRef{App: appID, Name: name}] = dirty

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

func boxCreateImpl(cx *EvalContext, appID basics.AppIndex) error {
	last := len(cx.Stack) - 1 // size
	prev := last - 1          // name

	name := string(cx.Stack[prev].Bytes)
	size := cx.Stack[last].Uint

	err := lengthChecks(cx, name, size)
	if err != nil {
		return err
	}
	_, exists, err := cx.availableAppBox(appID, name, BoxCreateOperation, size)
	if err != nil {
		return err
	}
	if !exists {
		appAddr := cx.GetApplicationAddress(appID)
		err = cx.Ledger.NewBox(appID, name, make([]byte, size), appAddr)
		if err != nil {
			return err
		}
	}
	cx.Stack[prev] = boolToSV(!exists)
	cx.Stack = cx.Stack[:last]
	return err
}

func opBoxCreate(cx *EvalContext) error {
	return boxCreateImpl(cx, cx.appID)
}

func opAppBoxCreate(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // appID
	appID := basics.AppIndex(cx.Stack[last].Uint)
	cx.Stack = cx.Stack[:last]
	return boxCreateImpl(cx, appID)
}

func boxExtractImpl(cx *EvalContext, appID basics.AppIndex) error {
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
	contents, exists, err := cx.availableAppBox(appID, name, BoxReadOperation, 0)
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

func opBoxExtract(cx *EvalContext) error {
	return boxExtractImpl(cx, cx.appID)
}

func opAppBoxExtract(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // appID
	appID := basics.AppIndex(cx.Stack[last].Uint)
	cx.Stack = cx.Stack[:last]
	return boxExtractImpl(cx, appID)
}

func boxReplaceImpl(cx *EvalContext, appID basics.AppIndex) error {
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
	contents, exists, err := cx.availableAppBox(appID, name, BoxWriteOperation, 0 /* size is already known */)
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
	return cx.Ledger.SetBox(appID, name, bytes)
}

func opBoxReplace(cx *EvalContext) error {
	return boxReplaceImpl(cx, cx.appID)
}

func opAppBoxReplace(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // appID
	appID := basics.AppIndex(cx.Stack[last].Uint)
	cx.Stack = cx.Stack[:last]
	return boxReplaceImpl(cx, appID)
}

func boxSpliceImpl(cx *EvalContext, appID basics.AppIndex) error {
	last := len(cx.Stack) - 1 // replacement
	replacement := cx.Stack[last].Bytes
	length := cx.Stack[last-1].Uint
	start := cx.Stack[last-2].Uint
	name := string(cx.Stack[last-3].Bytes)

	err := lengthChecks(cx, name, 0)
	if err != nil {
		return err
	}
	contents, exists, err := cx.availableAppBox(appID, name, BoxWriteOperation, 0 /* size is already known */)
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
	return cx.Ledger.SetBox(appID, name, bytes)
}

func opBoxSplice(cx *EvalContext) error {
	return boxSpliceImpl(cx, cx.appID)
}

func opAppBoxSplice(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // appID
	appID := basics.AppIndex(cx.Stack[last].Uint)
	cx.Stack = cx.Stack[:last]
	return boxSpliceImpl(cx, appID)
}

func boxDelImpl(cx *EvalContext, appID basics.AppIndex) error {
	last := len(cx.Stack) - 1 // name
	name := string(cx.Stack[last].Bytes)

	err := lengthChecks(cx, name, 0)
	if err != nil {
		return err
	}
	_, exists, err := cx.availableAppBox(appID, name, BoxDeleteOperation, 0)
	if err != nil {
		return err
	}
	if exists {
		appAddr := cx.GetApplicationAddress(appID)
		_, err := cx.Ledger.DelBox(appID, name, appAddr)
		if err != nil {
			return err
		}
	}
	cx.Stack[last] = boolToSV(exists)
	return nil
}

func opBoxDel(cx *EvalContext) error {
	return boxDelImpl(cx, cx.appID)
}

func opAppBoxDel(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // appID
	appID := basics.AppIndex(cx.Stack[last].Uint)
	cx.Stack = cx.Stack[:last]
	return boxDelImpl(cx, appID)
}

func boxResizeImpl(cx *EvalContext, appID basics.AppIndex) error {
	last := len(cx.Stack) - 1 // size
	prev := last - 1          // name

	name := string(cx.Stack[prev].Bytes)
	size := cx.Stack[last].Uint

	err := lengthChecks(cx, name, size)
	if err != nil {
		return err
	}
	contents, exists, err := cx.availableAppBox(appID, name, BoxResizeOperation, size)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("no such box %#x", name)
	}
	appAddr := cx.GetApplicationAddress(appID)
	_, err = cx.Ledger.DelBox(appID, name, appAddr)
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
	cx.Stack = cx.Stack[:prev]
	return cx.Ledger.NewBox(appID, name, resized, appAddr)
}

func opBoxResize(cx *EvalContext) error {
	return boxResizeImpl(cx, cx.appID)
}

func opAppBoxResize(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // appID
	appID := basics.AppIndex(cx.Stack[last].Uint)
	cx.Stack = cx.Stack[:last]
	return boxResizeImpl(cx, appID)
}

func boxLenImpl(cx *EvalContext, appID basics.AppIndex) error {
	last := len(cx.Stack) - 1 // name
	name := string(cx.Stack[last].Bytes)

	err := lengthChecks(cx, name, 0)
	if err != nil {
		return err
	}
	contents, exists, err := cx.availableAppBox(appID, name, BoxReadOperation, 0)
	if err != nil {
		return err
	}
	cx.Stack[last] = stackValue{Uint: uint64(len(contents))}
	cx.Stack = append(cx.Stack, boolToSV(exists))
	return nil
}

func opBoxLen(cx *EvalContext) error {
	return boxLenImpl(cx, cx.appID)
}

func opAppBoxLen(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // appID
	appID := basics.AppIndex(cx.Stack[last].Uint)
	cx.Stack = cx.Stack[:last]
	return boxLenImpl(cx, appID)
}

func boxGetImpl(cx *EvalContext, appID basics.AppIndex) error {
	last := len(cx.Stack) - 1 // name
	name := string(cx.Stack[last].Bytes)

	err := lengthChecks(cx, name, 0)
	if err != nil {
		return err
	}
	contents, exists, err := cx.availableAppBox(appID, name, BoxReadOperation, 0)
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

func opBoxGet(cx *EvalContext) error {
	return boxGetImpl(cx, cx.appID)
}

func opAppBoxGet(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // appID
	appID := basics.AppIndex(cx.Stack[last].Uint)
	cx.Stack = cx.Stack[:last]
	return boxGetImpl(cx, appID)
}

func boxPutImpl(cx *EvalContext, appID basics.AppIndex) error {
	last := len(cx.Stack) - 1 // value
	prev := last - 1          // name

	value := cx.Stack[last].Bytes
	name := string(cx.Stack[prev].Bytes)

	err := lengthChecks(cx, name, uint64(len(value)))
	if err != nil {
		return err
	}

	// This boxWrite usage requires the size, because the box may not exist.
	contents, exists, err := cx.availableAppBox(appID, name, BoxWriteOperation, uint64(len(value)))
	if err != nil {
		return err
	}

	cx.Stack = cx.Stack[:prev]

	if exists {
		/* the replacement must match existing size */
		if len(contents) != len(value) {
			return fmt.Errorf("attempt to box_put wrong size %d != %d", len(contents), len(value))
		}
		return cx.Ledger.SetBox(appID, name, value)
	}

	/* The box did not exist, so create it. */
	appAddr := cx.GetApplicationAddress(appID)
	return cx.Ledger.NewBox(appID, name, value, appAddr)
}

func opBoxPut(cx *EvalContext) error {
	return boxPutImpl(cx, cx.appID)
}

func opAppBoxPut(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // appID
	appID := basics.AppIndex(cx.Stack[last].Uint)
	cx.Stack = cx.Stack[:last]
	return boxPutImpl(cx, appID)
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
