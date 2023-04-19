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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// TxnPath is a "transaction path": e.g. [0, 0, 1] means the second inner txn of the first inner txn of the first txn.
// You can use this transaction path to find the txn data in the `TxnResults` list.
type TxnPath []uint64

// TxnResult contains the simulation result for a single transaction
type TxnResult struct {
	Txn                    transactions.SignedTxnWithAD
	MissingSignature       bool
	AppBudgetConsumed      uint64
	LogicSigBudgetConsumed uint64
}

// TxnGroupResult contains the simulation result for a single transaction group
type TxnGroupResult struct {
	Txns           []TxnResult
	FailureMessage string

	// FailedAt is the path to the txn that failed inside of this group
	FailedAt TxnPath

	// AppBudgetAdded is the total opcode budget for this group
	AppBudgetAdded uint64

	// AppBudgetConsumed is the total opcode cost used for this group
	AppBudgetConsumed uint64

	// FeeCredit is the fees left over after covering fees for this group
	FeeCredit uint64
}

func makeTxnGroupResult(txgroup []transactions.SignedTxn) TxnGroupResult {
	groupResult := TxnGroupResult{Txns: make([]TxnResult, len(txgroup))}
	for i, tx := range txgroup {
		groupResult.Txns[i] = TxnResult{Txn: transactions.SignedTxnWithAD{
			SignedTxn: tx,
		}}
	}
	return groupResult
}

// ResultLatestVersion is the latest version of the Result struct
const ResultLatestVersion = uint64(1)

// Result contains the result from a call to Simulator.Simulate
type Result struct {
	Version       uint64
	LastRound     basics.Round
	TxnGroups     []TxnGroupResult // this is a list so that supporting multiple in the future is not breaking
	WouldSucceed  bool             // true iff no failure message, no missing signatures, and the budget was not exceeded
	LiftLogLimits bool             // true iff we run simulation with `lift-log-limits` option
	MaxLogCalls   uint64
	MaxLogSize    uint64
	Block         *ledgercore.ValidatedBlock
}

func makeSimulationResultWithVersion(lastRound basics.Round, txgroups [][]transactions.SignedTxn, version uint64, liftLogLimits bool) (Result, error) {
	if version != ResultLatestVersion {
		return Result{}, fmt.Errorf("invalid SimulationResult version: %d", version)
	}

	groups := make([]TxnGroupResult, len(txgroups))

	for i, txgroup := range txgroups {
		groups[i] = makeTxnGroupResult(txgroup)
	}

	opCodeParam := logic.NewRuntimeEvalConstants()
	if liftLogLimits {
		opCodeParam = logic.NewSimulateEvalConstants()
	}

	return Result{
		Version:       version,
		LastRound:     lastRound,
		TxnGroups:     groups,
		LiftLogLimits: liftLogLimits,
		MaxLogCalls:   opCodeParam.MaxLogCalls,
		MaxLogSize:    opCodeParam.MaxLogSize,
		WouldSucceed:  true,
	}, nil
}

func makeSimulationResult(lastRound basics.Round, txgroups [][]transactions.SignedTxn, simConfig SimulatorConfig) Result {
	result, err := makeSimulationResultWithVersion(lastRound, txgroups, ResultLatestVersion, simConfig.LiftLogLimits)
	if err != nil {
		// this should never happen, since we pass in ResultLatestVersion
		panic(err)
	}
	return result
}
