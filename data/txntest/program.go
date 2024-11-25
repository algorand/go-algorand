// Copyright (C) 2019-2024 Algorand, Inc.
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

// GenerateProgramOfSize return a TEAL bytecode of `size` bytes which always succeeds.
// `size` must be at least 9 bytes
func GenerateProgramOfSize(size uint, pragma uint) ([]byte, error) {
	if size < 9 {
		return nil, fmt.Errorf("size must be at least 9 bytes; got %d", size)
	}
	ls := fmt.Sprintf("#pragma version %d\n", pragma)
	if size%2 == 0 {
		ls += "int 10\npop\nint 1\npop\n"
	} else {
		ls += "int 1\npop\nint 1\npop\n"
	}
	for i := uint(11); i <= size; i += 2 {
		ls = ls + "int 1\npop\n"
	}
	ls = ls + "int 1"
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
