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
// `size` must be at least 9 bytes
// TODO: Replace with the helper from unmerged PR #6653 once this branch is rebased.
func GenerateUnsaltedProgramOfSize(size uint, pragma uint) ([]byte, error) {
	if size < 9 {
		return nil, fmt.Errorf("size must be at least 9 bytes; got %d", size)
	}
	if pragma == 0 || pragma > logic.LogicVersion {
		return nil, fmt.Errorf("unsupported logic version %d", pragma)
	}
	// Build bytecode directly so automatic off-curve salting in the assembler
	// cannot change the requested size.
	ops := logic.OpsByName[pragma]
	intcblock := ops["intcblock"].Opcode
	intc0 := ops["intc_0"].Opcode
	pop := ops["pop"].Opcode

	program := []byte{byte(pragma)}
	if size%2 == 0 {
		program = append(program, intcblock, 2, 1, 1)
	} else {
		program = append(program, intcblock, 1, 1)
	}
	for uint(len(program))+1 < size {
		program = append(program, intc0, pop)
	}
	program = append(program, intc0)
	if uint(len(program)) != size {
		panic(fmt.Sprintf("wanted to create a program of size %d but got a program of size %d",
			size, len(program)))
	}
	return program, nil
}
