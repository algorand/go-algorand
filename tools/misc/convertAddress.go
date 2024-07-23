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

package main

import (
	"encoding/base64"
	"flag"
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
)

func main() {
	var addrInput string
	flag.StringVar(&addrInput, "addr", "", "base64/algorand address to convert to the other")
	flag.Parse()

	if addrInput == "" {
		fmt.Println("provide input with '-addr' flag.")
		return
	}

	addrBytes, err := base64.StdEncoding.DecodeString(addrInput)
	if err != nil {
		// Failed to base64 decode, check for Algorand address format.
		a, err := basics.UnmarshalChecksumAddress(addrInput)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(base64.StdEncoding.EncodeToString(a[:]))
		return
	}
	var addr basics.Address
	copy(addr[:], addrBytes)
	fmt.Println(addr.String())
}
