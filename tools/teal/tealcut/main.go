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

package main

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

// Usage:
//
//   tealcut <filename> 0x<number separator>
//     Prints the program before and after the number separator,
//     as well as a hash of both these components in base 16.
//
//   tealcut <filename> 0x<number separator> b64
//     Like the above, but print in base 64 instead of base 16.
//
//   tealcut <filename> 0x<number separator> 0x<inserted number>
//     In addition to the program before and after the separator,
//     also print the program where the first occurrence of the
//     separator is replaced by the inserted number, along with
//     the program's hash.
//
// Note that all command-line number arguments are in base 16.

func main() {
	splitnum, err := strconv.ParseUint(os.Args[2], 0, 64)
	if err != nil {
		panic(err)
	}
	var splitbytes [8]byte
	binary.BigEndian.PutUint64(splitbytes[:], splitnum)
	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	substrings := strings.SplitN(string(data), string(splitbytes[:]), 2)
	fmt.Println(splitbytes[:])

	if len(substrings) == 1 {
		fmt.Println("split-string not found")
		return
	}

	hash0 := sha512.Sum512_256([]byte(substrings[0]))
	hash1 := sha512.Sum512_256([]byte(substrings[1]))

	encfn := func(str []byte) string {
		return "0x" + hex.EncodeToString(str)
	}
	if len(os.Args) > 3 {
		if os.Args[3] == "b64" {
			encfn = base64.StdEncoding.EncodeToString
		} else {
			writenum, err := strconv.ParseUint(os.Args[3], 0, 64)
			if err != nil {
				panic(err)
			}
			var writebytes [8]byte
			binary.BigEndian.PutUint64(writebytes[:], writenum)
			program := append([]byte(substrings[0]), writebytes[:]...)
			program = append(program, []byte(substrings[1])...)

			obj := logic.Program(program)
			lhash := crypto.HashObj(&obj)
			fmt.Println("addr:", basics.Address(lhash))
			fmt.Println("mod:", encfn(program))
		}
	}

	fmt.Println("hash0:", encfn(hash0[:]))
	fmt.Println("hash1:", encfn(hash1[:]))
	fmt.Println("sub0:", encfn([]byte(substrings[0])))
	fmt.Println("sub1:", encfn([]byte(substrings[1])))
	fmt.Println("data:", encfn(data))
}
