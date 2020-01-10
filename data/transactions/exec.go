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

type ExecType string

const (
	ExecInit    ExecType = "INIT:"
	ExecRequest ExecType = "RQST:"
	ExecCommit  ExecType = "CMMT:"
	ExecFail    ExecType = "FAIL:"
	ExecNil     ExecType = ""
)

// Currently using a PaymentTx whose Note field has a header indicating the type of
// transaction, followed by plain text for use by the executable as input and output.
// TODO use ExecTx and ExecTxnFields instead of header (fields in header may be useful too)
// TODO decide how to structure input and output -- probably JSON

func IsExecLogic(txn SignedTxn) bool {
	return GetExecType(txn) != ExecNil
}

func GetExecType(txn SignedTxn) ExecType {
	if len(txn.Txn.Note) < 5 {
		return ExecNil
	}
	return ExecType(txn.Txn.Note[0:5])
}

func SetExecType(txn SignedTxn, txType ExecType) {
	copy(txn.Txn.Note[0:5], string(txType))
}

func GetExecData(txn SignedTxn) []byte {
	return txn.Txn.Note[5:]
}

func SetExecData(txn SignedTxn, data []byte) {
	copy(txn.Txn.Note[5:], data)
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
		return nil // store code indexed by hash -- transfer of funds to hash creates account
	case ExecRequest:
		return nil // post to blockchain to request later execution
	case ExecCommit:
		return nil // post to blockchain to request commit of execution results
	case ExecFail:
		return nil // post to blockchain in case of failed execution or commit
	}
	return nil
}
