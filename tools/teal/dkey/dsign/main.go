// Copyright (C) 2019 Algorand, Inc.
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

// dsign creates keys for signing data in LogicSig scripts.
//
// dsign creates signatures on data that will verify under
// the LogicSig ed25519verify opcode.
package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

func failFast(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <key-file> <lsig-file>", os.Args[0])
		os.Exit(-1)
	}

	keyfname := os.Args[1]
	lsigfname := os.Args[2]

	kdata, err := ioutil.ReadFile(keyfname)
	failFast(err)
	var seed crypto.Seed
	copy(seed[:], kdata)
	sec := crypto.GenerateSignatureSecrets(seed)

	pdata, err := ioutil.ReadFile(lsigfname)
	failFast(err)
	var lsig transactions.LogicSig
	err = protocol.Decode(pdata, &lsig)
	failFast(err)

	txdata, err := ioutil.ReadAll(os.Stdin)
	failFast(err)
	var txn transactions.SignedTxn
	err = protocol.Decode(txdata, &txn)
	failFast(err)

	txID := txn.ID()
	dsig := sec.Sign(logic.Msg{
		ProgramHash: crypto.HashObj(logic.Program(lsig.Logic)),
		Data:        txID[:],
	})
	lsig.Args = [][]byte{dsig[:]}

	var out transactions.SignedTxn
	out.Txn = txn.Txn
	out.Lsig = lsig
	protocol.EncodeStream(os.Stdout, out)
}
