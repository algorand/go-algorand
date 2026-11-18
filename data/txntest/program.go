// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package txntest

import (
	"fmt"

	"github.com/algorand/go-algorand/data/transactions/logic"
)

// GenerateUnsaltedProgramOfSize returns a TEAL bytecode of `size` bytes which always succeeds.
// `size` must be at least 5 bytes.
func GenerateUnsaltedProgramOfSize(size uint, pragma uint) ([]byte, error) {
	return GenerateUnsaltedArgReadingProgramOfSize(size, pragma, 0)
}

// GenerateUnsaltedArgReadingProgramOfSize returns a TEAL bytecode of `size`
// bytes which reads its first `args` LogicSig arguments and then succeeds. A
// LogicSig may carry no argument it does not read, so a test that wants a big
// LogicSig carrying arguments needs a program that consumes them.
//
// `args` may be at most 4, because arg_0 through arg_3 are the single-byte reads
// that let an "arg, pop" pair occupy exactly the two bytes the padding pair does.
// `size` must leave room for that many pairs.
func GenerateUnsaltedArgReadingProgramOfSize(size uint, pragma uint, args uint) ([]byte, error) {
	if size < 5 {
		return nil, fmt.Errorf("size must be at least 5 bytes; got %d", size)
	}
	if args > 4 {
		return nil, fmt.Errorf("at most 4 args can be read; got %d", args)
	}
	ls := fmt.Sprintf("#pragma version %d\n#pragma autosalt false\n", pragma)
	if size%2 == 0 {
		ls += "intcblock 1 1\n"
	} else {
		ls += "intcblock 1\n"
	}
	pairs := uint(0)
	for i := uint(7); i <= size; i += 2 {
		if pairs < args {
			ls += fmt.Sprintf("arg_%d\npop\n", pairs)
		} else {
			ls += "intc_0\npop\n"
		}
		pairs++
	}
	if pairs < args {
		return nil, fmt.Errorf("size %d leaves room for %d arg reads; wanted %d", size, pairs, args)
	}
	ls += "intc_0"
	code, err := logic.AssembleString(ls)
	if err != nil {
		return nil, err
	}
	// panic if the function is not working as expected and needs to be updated
	if len(code.Program) != int(size) {
		panic(fmt.Sprintf("wanted to create a program of size %d but got a program of size %d",
			size, len(code.Program)))
	}
	return code.Program, nil
}
