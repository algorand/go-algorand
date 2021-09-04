// Copyright (C) 2019-2021 Algorand, Inc.
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

// +build compare_purego_implementation

package crypto

import "fmt"

func init() {
	fmt.Println("purego: Compiled with comparison enabled for Verify() implementation.")
	validateGoVerify = func(pk VrfPubkey, p VrfProof, message Hashable, ok bool, out VrfOutput) {
		goOk, goOut := pk.verifyBytesGo(p, hashRep(message))
		if out != goOut {
			panic(fmt.Sprintf("Go and C implementations differ: %x %x %x %x %x\n", pk, p, message, out, goOut))
		}
		if ok != goOk {
			panic(fmt.Sprintf("Go and C implementations differ: %x %x %x\n", pk, p, message))
		}
	}
}
