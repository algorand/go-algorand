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

type ExecType string

const (
	ExecInit    = "INIT:"
	ExecRequest = "RQST:"
	ExecCommit  = "CMMT:"
	ExecFailure = "FAIL:"
)

// Currently using a PaymentTx whose Note field has a header indicating the type of
// transaction, followed by plain text for use by the executable as input and output.
// TODO use ExecTx and ExecTxnFields instead of header (fields in header may be useful too)
// TODO decide how to structure input and output -- probably JSON

func IsExecLogic(txn SignedTransaction) bool {
	switch ExecType(txt) {
	case ExecInit:
		return true
	case ExecRequest:
		return true
	case ExecCommit:
		return true
	case ExecFail:
		return true
	default:
		return false
	}
}

func GetExecType(txn SignedTransaction) ExecType {
	if len(txn.Transaction.Note) < 5 {
		return nil
	}
	return txn.Transaction.Note[0:5]
}

func SetExecTxType(txn SignedTransaction, ExecType txType) {
	txn.Transaction.Note[0:5] = txType
}

func GetExecData(txn SignedTransaction) {
	return txn.Transaction.Note[5:]
}

// ExecReqTxnFields captures the fields used by exec transactions.
type ExecTxnFields struct {
	_struct  struct{} `codec:",omitempty,omitemptyarray"`
	execType ExecType
}

// Apply changes the state according to this transaction.
func (exec ExecTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData) error {
	switch exec.execType {
	case ExecInit:
		return nil // transfer of funds to hash of code creates account
	case ExecRequest:
		return nil // post to blockchain for later execution
	case ExecCommit:
		return nil // post to blockchain in case of succcessful commit
	case ExecFail:
		return nil // post to blockchain in case of failed comit
	}
	return nil
}
