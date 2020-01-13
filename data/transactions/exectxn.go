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

// ExecTxnSpawn spawns a VM to execute transaction code.
//
// The transaction is signed with Wasm code.  That code is copied and spawned with
// the transaction's note passed to stdin.  The output is captured and placed back on
// the blockchain as a commit or fail transaction.
func ExecTxnSpawn(txn SignedTxn, client RestClient) error {

	// unpack transaction
	code := txn.Lsig.Logic
	execType := txn.Txn.ExecType
	input := txn.Txn.Note

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
		sendTxn(client, txn, ExecFail, input)
		return nil
	}

	// Spawn WAVM to execute the wasm.  TODO Parameterize command.
	cmd := exec.Command("wavm", "run", "--abi=wasi", temp.Name())
	cmd.Stdin = bytes.NewBuffer(input)
	var stdin, stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		sendTxn(client, txn, ExecFail, stderr.Bytes())
		return nil
	}
	sendTxn(txn, ExecCommit, stdout.Bytes())
	return nil
}

func sendTxn(txn SignedTxn, execType ExecTxnPhase, output []byte, client RestClient) {
	txn.Txn.execType = execType
	txn.Txn.Note = output

	// TODO convert txn and output into atomic transfer
	_, err = client.SendRawTransaction(stx)
}
