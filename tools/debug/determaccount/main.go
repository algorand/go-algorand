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
	"encoding/binary"
	"flag"
	"fmt"
	"os"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

var numAccounts = flag.Uint64("numaccounts", 0, "Use this many accounts")
var offset = flag.Uint64("offset", 0, "Start at this offset")

func main() {
	flag.Parse()
	if *numAccounts == 0 {
		flag.Usage()
		os.Exit(1)
	}
	for i := uint64(0); i < *numAccounts; i++ {
		acct := i + *offset
		var seed crypto.Seed
		binary.LittleEndian.PutUint64(seed[:], uint64(acct))
		secrets := crypto.GenerateSignatureSecrets(seed)
		fmt.Println(i, acct, basics.Address(secrets.SignatureVerifier).String())
	}
}
