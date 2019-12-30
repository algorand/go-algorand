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
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
)

constant {
	ExecInit    = "INIT:"
	ExecRequest = "RQST:"
	ExecCommit  = "CMMT:"
	ExecFailure = "FAIL:"
}

// Currently using a PaymentTx whose Note field has a header indicating the type of
// transaction, followed by plain text for use by the executable as input and output.
// TODO use ExecTx and ExecTxnFields instead of header
// TODO decide how to structure input and output -- probably JSON

GetExecTxType(note []byte) string {
	if len(note) < 5 {
		return nil
	}
	return note[0:5]
}

SetExecTxType(note *[4]byte, string type) {
	*note = type
}

// ExecReqTxnFields captures the fields used by exec transactions.
type ExecTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	execType ExecType
}

// Apply changes the state according to this transaction.
func (exec ExecTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData) error {
	switch exec.execType {
	case ExecInit:    return nil // transfer of funds to hash of code creates account
	case ExecRequest: return nil // will be posted to blockchain for later execution
	case ExecCommit:  return nil // TODO attempt commitment to storage
	}
	return nil
}

