// Copyright (C) 2019-2023 Algorand, Inc.
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

package simulation

import (
	"fmt"

	"github.com/algorand/go-algorand/data/transactions"
)

// TxnPath is a "transaction path": e.g. [0, 0, 1] means the second inner txn of the first inner txn of the first txn.
// You can use this transaction path to find the txn data in the `TxnResults` list.
type TxnPath []uint64

// ==============================
// > Transaction Results
// ==============================

type TxnResult struct {
	Txn              transactions.SignedTxnWithAD
	MissingSignature bool
}

type TxnGroupResult struct {
	Txns           []TxnResult
	FailureMessage string

	// FailedAt is the path to the txn that failed, instead of repeating the FailureMessage at every level
	FailedAt TxnPath
}

func MakeTxnGroupResult(txgroup []transactions.SignedTxn) TxnGroupResult {
	groupResult := TxnGroupResult{Txns: make([]TxnResult, len(txgroup))}
	for i, tx := range txgroup {
		groupResult.Txns[i] = TxnResult{Txn: transactions.SignedTxnWithAD{
			SignedTxn: tx,
		}}
	}
	return groupResult
}

const ResultCurrentVersion = uint64(1)

type Result struct {
	Version      uint64
	TxnGroups    []TxnGroupResult // txngroups is a list so that supporting multiple in the future is not breaking
	WouldSucceed bool             // true iff no failure message, no missing signatures, and the budget was not exceeded
}

func MakeSimulationResultWithVersion(txgroups [][]transactions.SignedTxn, version uint64) (Result, error) {
	if version != ResultCurrentVersion {
		return Result{}, fmt.Errorf("invalid SimulationResult version: %d", version)
	}

	groups := make([]TxnGroupResult, len(txgroups))

	for i, txgroup := range txgroups {
		groups[i] = MakeTxnGroupResult(txgroup)
	}

	return Result{Version: version, TxnGroups: groups, WouldSucceed: true}, nil
}

func MakeSimulationResult(txgroups [][]transactions.SignedTxn) Result {
	result, err := MakeSimulationResultWithVersion(txgroups, ResultCurrentVersion)
	if err != nil {
		// this should never happen, since we pass in ResultCurrentVersion
		panic(err)
	}
	return result
}
