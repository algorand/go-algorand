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

func opProto(cx *EvalContext) error {
	if !cx.fromCallsub {
		return fmt.Errorf("proto was executed without a callsub")
	}
	cx.fromCallsub = false
	nargs := int(cx.program[cx.pc+1])
	if nargs > len(cx.stack) {
		return fmt.Errorf("callsub to proto that requires %d args with stack height %d", nargs, len(cx.stack))
	}
	top := len(cx.callstack) - 1
	cx.callstack[top].clear = true
	cx.callstack[top].args = nargs
	cx.callstack[top].returns = int(cx.program[cx.pc+2])
	return nil
}

func opFrameDig(cx *EvalContext) error {
	i := int8(cx.program[cx.pc+1])

	top := len(cx.callstack) - 1
	if top < 0 {
		return errors.New("frame_dig with empty callstack")
	}

	frame := cx.callstack[top]
	// If proto was used, don't allow `frame_dig` to go below specified args
	if frame.clear && -int(i) > frame.args {
		return fmt.Errorf("frame_dig %d in sub with %d args", i, frame.args)
	}
	idx := frame.height + int(i)
	if idx >= len(cx.stack) {
		return errors.New("frame_dig above stack")
	}
	if idx < 0 {
		return errors.New("frame_dig below stack")
	}

	cx.stack = append(cx.stack, cx.stack[idx])
	return nil
}
func opFrameBury(cx *EvalContext) error {
	last := len(cx.stack) - 1 // value
	i := int8(cx.program[cx.pc+1])

	top := len(cx.callstack) - 1
	if top < 0 {
		return errors.New("frame_bury with empty callstack")
	}

	frame := cx.callstack[top]
	// If proto was used, don't allow `frame_bury` to go below specified args
	if frame.clear && -int(i) > frame.args {
		return fmt.Errorf("frame_bury %d in sub with %d args", i, frame.args)
	}
	idx := frame.height + int(i)
	if idx >= last {
		return errors.New("frame_bury above stack")
	}
	if idx < 0 {
		return errors.New("frame_bury below stack")
	}
	cx.stack[idx] = cx.stack[last]
	cx.stack = cx.stack[:last] // pop value
	return nil
}
func opBury(cx *EvalContext) error {
	last := len(cx.stack) - 1 // value
	i := int(cx.program[cx.pc+1])

	idx := last - i
	if idx < 0 || idx == last {
		return errors.New("bury outside stack")
	}
	cx.stack[idx] = cx.stack[last]
	cx.stack = cx.stack[:last] // pop value
	return nil
}

func opPushN(cx *EvalContext) error {
	n := cx.program[cx.pc+1]
	cx.stack = append(cx.stack, make([]stackValue, n)...)
	return nil
}
func opPopN(cx *EvalContext) error {
	n := cx.program[cx.pc+1]
	top := len(cx.stack) - int(n)
	if top < 0 {
		return fmt.Errorf("popn %d while stack contains %d", n, len(cx.stack))
	}
	cx.stack = cx.stack[:top] // pop value
	return nil
}
func opDupN(cx *EvalContext) error {
	last := len(cx.stack) - 1 // value

	n := int(cx.program[cx.pc+1])
	copies := make([]stackValue, n)
	for i := 0; i < n; i++ {
		copies[i] = cx.stack[last]
	}
	cx.stack = append(cx.stack, copies...)
	return nil
}
