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

package transactions

import (
	"bytes"
	"io/ioutil"
	"os/exec"
)

// This is part of a stub for the execution protocol, which I'll likely to need
// to move to a separate process along the lines of @algobolson's algobot.
// Saving here uncompleted until there is a place to move it to.

// The transaction is signed with Wasm code.  The code is simply spawned with the
// transaction's note passed to stdin.  The output is captured and placed back on
// the blockchain as a commit or fail transaction.
func execTxn(txn SignedTxn) error {

	// unpack transaction
	code := txn.Lsig.Logic
	execType := GetExecType(txn)
	input := GetExecData(txn)

	if execType != ExecRequest {
		sendResultTransaction(txn, ExecFail, input)
		return nil
	}

	// copy code to temp file
	temp, err := ioutil.TempFile("", "exec")
	if err != nil {
		sendResultTransaction(txn, ExecFail, input)
		return nil
	}
	defer temp.Close()
	_, err = temp.Write(code)
	if err != nil {
		sendResultTransaction(txn, ExecFail, input)
		return nil
	}

	// spawn WAVM to execute the wasm
	cmd := exec.Command("wavm", "run", "--abi=wasi", temp.Name())
	cmd.Stdin = bytes.NewBuffer(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		sendResultTransaction(txn, ExecFail, stderr.Bytes())
		return nil
	}
	sendResultTransaction(txn, ExecCommit, stdout.Bytes())
	return nil
}

func sendResultTransaction(txn SignedTxn, execType ExecType, output []byte) {
	SetExecType(txn, execType)
	SetExecData(txn, output)

	// TODO extend txn with output into atomic transfer

	// TODO whatever it takes to send a transaction
}
