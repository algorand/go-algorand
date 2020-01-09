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

// This is part of a stub for the execution protocol, which I'll likely to need
// to move to a separate process along the lines of @algobolson's algobot.
// Saving here uncompleted until there is a place to move it to.

// The transaction is signed with Wasm code.  The code is simply spawned with the
// transaction's note passed to stdin rather than being run by a consensus protocol.
// The output is captured and placed back on the blockchain as another transaction
func execTxn(txn SignedTxn) error {

	// unpack transaction
	code := txn.Lsig.Logic
	execType := ExecType(txn)
	input := GetExecData(txn)

	// temp file must be removed by spawned code
	temp, err := ioutil.TempFile("", "exec")
	if err != nil {
		return err
	}
	err = temp.write(code)

	// spawn WAVM to execute the wasm
	cmd := exec.Command("wavm", "run", "--abi=wasi", tempName(), input)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, input)
	}()

	output, err := cmd.Output()

	// reset transaction type
	if err == nil {
		SetExecTxType(signed_txn.Transaction.Note, ExecFailure)
	} else {
		SetExecTxType(signed_txn.Transaction.Note, ExecCommit)
	}
	txn.Transaction.Note[5:] = output

	// TODO send new transaction to network
}
