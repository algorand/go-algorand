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

	"github.com/algorand/go-algorand/config"
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
const ResultLatestVersion = uint64(2)

// ResultEvalOverrides contains the limits and parameters during a call to Simulator.Simulate
type ResultEvalOverrides struct {
	AllowEmptySignatures bool
	MaxLogCalls          *uint64
	MaxLogSize           *uint64
	ExtraBudget          *uint64
}

// SimulateLogBytesLimit hardcode limit of how much bytes one can log per transaction during simulation (with AllowMoreLogging)
const SimulateLogBytesLimit = uint64(65536)

// AllowMoreLogging method modify the log limits from lift option:
// - if lift log limits, then overload result from local Config
// - otherwise, set `LogLimits` field to be nil
func (eo ResultEvalOverrides) AllowMoreLogging(allow bool) ResultEvalOverrides {
	if allow {
		maxLogCalls, maxLogSize := uint64(config.MaxLogCalls), SimulateLogBytesLimit
		eo.MaxLogCalls = &maxLogCalls
		eo.MaxLogSize = &maxLogSize
	}
	return eo
}

// LogicEvalConstants method infers the logic.EvalConstants from Result.EvalOverrides (*ResultEvalOverrides)
// and generate appropriate parameters to override during simulation runtime.
func (eo ResultEvalOverrides) LogicEvalConstants() logic.EvalConstants {
	logicEvalConstants := logic.RuntimeEvalConstants()
	if eo.MaxLogSize != nil {
		logicEvalConstants.MaxLogSize = *eo.MaxLogSize
	}
	if eo.MaxLogCalls != nil {
		logicEvalConstants.MaxLogCalls = *eo.MaxLogCalls
	}
	return logicEvalConstants
}

// Result contains the result from a call to Simulator.Simulate
type Result struct {
	Version       uint64
	LastRound     basics.Round
	TxnGroups     []TxnGroupResult // this is a list so that supporting multiple in the future is not breaking
	EvalOverrides ResultEvalOverrides
	Block         *ledgercore.ValidatedBlock
}

func makeSimulationResultWithVersion(lastRound basics.Round, request Request, version uint64) (Result, error) {
	if version != ResultLatestVersion {
		return Result{}, fmt.Errorf("invalid SimulationResult version: %d", version)
	}

	groups := make([]TxnGroupResult, len(request.TxnGroups))

	for i, txgroup := range request.TxnGroups {
		groups[i] = makeTxnGroupResult(txgroup)
	}

	resultEvalConstants := ResultEvalOverrides{
		AllowEmptySignatures: request.AllowEmptySignatures,
		ExtraBudget:          request.ExtraBudget,
	}.AllowMoreLogging(request.AllowMoreLogging)

	return Result{
		Version:       version,
		LastRound:     lastRound,
		TxnGroups:     groups,
		EvalOverrides: resultEvalConstants,
	}, nil
}

func makeSimulationResult(lastRound basics.Round, request Request) Result {
	result, err := makeSimulationResultWithVersion(lastRound, request, ResultLatestVersion)
	if err != nil {
		// this should never happen, since we pass in ResultLatestVersion
		panic(err)
	}
	return result
}
