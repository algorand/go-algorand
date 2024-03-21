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
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/algorand/avm-abi/apps"
)

func main() {
	var name string
	var appIdx uint64
	flag.Uint64Var(&appIdx, "a", 0, "base64/algorand address to convert to the other")
	flag.StringVar(&name, "n", "", "base64 box name")
	flag.Parse()

	if appIdx == 0 && name == "" {
		fmt.Println("provide input with '-a' and '-k' flags.")
		return
	}

	nameBytes, err := base64.StdEncoding.DecodeString(name)
	if err != nil {
		fmt.Println("invalid key value")
		return
	}
	key := apps.MakeBoxKey(appIdx, string(nameBytes))
	fmt.Println(base64.StdEncoding.EncodeToString([]byte(key)))
	fmt.Println(hex.EncodeToString([]byte(key)))
}
