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

package ledger

import (
	"fmt"
	"io"
	"log"
	"os/exec"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
)

type exeTail struct {
}
/*
func (t *txTail) loadFromDisk(l ledgerForTracker) error {
	return nil
}

func (t *txTail) close() {
}

func (au *accountUpdates) newBlock(blk bookkeeping.Block, delta StateDelta) {
	rnd := blk.Round()

	if rnd <= au.latest() {
		// Duplicate, ignore.
		return
	}
	if t.TxType != protocol.ExecTx {
		// Not executable, ignore.
		return
	}

	for txn := range blk.Payset {
		execTxn(txn)
	}
}
*/
// This is a stub for the execution protocol and code storage system.
//
// Currently the file name of the wasm code to exec is passed in the Code field rather than the code itself or a
// hash of code that is cached.  The code is simply spawned and the Input passed to stdin rather than being run by a
// consensus protocol
//
// The output is captured and placed back on the blockchain as another transaction
//
func execTxn(txn SignedTxnInBlock) {
	cmd := exec.Command("wavm", "run", "--abi=wasi", txn.Code)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, Input)
	}()

	out, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", out)
}
