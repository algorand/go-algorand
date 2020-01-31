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
)

// Transactions for off-chain execution of code.
//
// We currently cannot carry ordinary signatures through the system,
// as the private keys disappear on the way from request to commit.
// We also cannot store code.  So we currently support only contract-
// controlled accounts, signed by a LogicSig, and addressed via a hash
// of their code.  Accounts are created by sending funds to that address.
// When we can store code indexed via hash the LogicSig can contain the
// hash rather than the code.

// ExecTxnPhase is type for phase lables.
type ExecTxnPhase string

// Labels for the phases of exec transactions.
const (
	ExecInit   ExecTxnPhase = "init"   // TODO store code indexed via hash
	ExecExec   ExecTxnPhase = "exec"   // request later execution
	ExecCommit ExecTxnPhase = "commit" // request commit of execution results
	ExecFail   ExecTxnPhase = "fail"   // failed execution or commit
)

// ExecTxnFields captures the fields used by exec transactions.
type ExecTxnFields struct {
	_struct   struct{}     `codec:",omitempty,omitemptyarray"`
	ExecPhase ExecTxnPhase `codec:"phase"`
	oldData   []byte       `codec:"old_data"`
	newData   []byte       `codec:"new_data"`
}

func (exec ExecTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData) error {

	account, err := balances.Get(header.Sender, false)
	if err != nil {
		return err
	}
	switch exec.ExecPhase {
	case ExecExec:

		// Save initial state of data.
		exec.oldData = account.Storage

	case ExecCommit:

		// If data is unchanged copy in new data.
		if bytes.Equal(account.Storage, exec.oldData) {
			account.Storage = exec.newData
			exec.newData = nil
		} else {

			// This transaction lost the race, mark phase as failed.
			exec.ExecPhase = ExecFail
		}
		exec.oldData = nil
	}
	return nil
}
