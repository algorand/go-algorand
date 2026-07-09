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
	if size < 5 {
		return nil, fmt.Errorf("size must be at least 5 bytes; got %d", size)
	}
	ls := fmt.Sprintf("#pragma version %d\n#pragma autosalt false\n", pragma)
	if size%2 == 0 {
		ls += "intcblock 1 1\n"
	} else {
		ls += "intcblock 1\n"
	}
	for i := uint(7); i <= size; i += 2 {
		ls += "intc_0\npop\n"
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
