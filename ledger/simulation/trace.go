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

// LogLimits contains the limits on log opcode during a call to Simulator.Simulate
type LogLimits struct {
	MaxLogCalls uint64
	MaxLogSize  uint64
}

// ResultEvalConstants contains the limits and parameters during a call to Simulator.Simulate
type ResultEvalConstants struct {
	LogLimits *LogLimits
}

// ResultEvalConstantsBuilder follows a builder pattern for ResultEvalConstants
type ResultEvalConstantsBuilder struct {
	Result ResultEvalConstants
}

// NewResultEvalConstantsBuilder constructs a builder for ResultEvalConstants
func NewResultEvalConstantsBuilder() *ResultEvalConstantsBuilder {
	return &ResultEvalConstantsBuilder{}
}

// LiftLogLimits method modify the log limits from lift option:
// - if lift log limits, then overload result from local config
// - otherwise, set `LogLimits` field to be nil
func (r *ResultEvalConstantsBuilder) LiftLogLimits(lift bool) *ResultEvalConstantsBuilder {
	if lift {
		localConfig := config.GetDefaultLocal()
		r.Result.LogLimits = &LogLimits{
			MaxLogCalls: uint64(config.MaxLogCalls),
			MaxLogSize:  localConfig.SimulateLogBytesLimit,
		}
	} else {
		r.Result.LogLimits = nil
	}
	return r
}

// Finalize method cleanup the *ResultEvalConstants if it is empty ResultEvalConstants{}, then return nil,
// otherwise it returns the pointer to ResultEvalConstants
func (r *ResultEvalConstantsBuilder) Finalize() *ResultEvalConstants {
	// Since ResultEvalConstants is omitempty, we want to check if it is actually empty
	if r.Result == (ResultEvalConstants{}) {
		return nil
	}
	return &r.Result
}

// LogicEvalConstants method infers the logic.EvalConstants from Result.EvalConstants (*ResultEvalConstants)
// and generate appropriate parameters to override during simulation runtime.
func (c *ResultEvalConstants) LogicEvalConstants() logic.EvalConstants {
	logicEvalConstants := logic.NewRuntimeEvalConstants()
	if c == nil {
		return logicEvalConstants
	}
	if c.LogLimits != nil {
		logicEvalConstants.MaxLogSize = c.LogLimits.MaxLogSize
		logicEvalConstants.MaxLogCalls = c.LogLimits.MaxLogCalls
	}
	return logicEvalConstants
}

// Result contains the result from a call to Simulator.Simulate
type Result struct {
	Version       uint64
	LastRound     basics.Round
	TxnGroups     []TxnGroupResult // this is a list so that supporting multiple in the future is not breaking
	WouldSucceed  bool             // true iff no failure message, no missing signatures, and the budget was not exceeded
	LiftLogLimits bool             // true iff we run simulation with `lift-log-limits` option
	EvalConstants *ResultEvalConstants
	Block         *ledgercore.ValidatedBlock
}

func makeSimulationResultWithVersion(lastRound basics.Round, txgroups [][]transactions.SignedTxn, version uint64, simConfig SimulatorConfig) (Result, error) {
	if version != ResultLatestVersion {
		return Result{}, fmt.Errorf("invalid SimulationResult version: %d", version)
	}

	groups := make([]TxnGroupResult, len(txgroups))

	for i, txgroup := range txgroups {
		groups[i] = makeTxnGroupResult(txgroup)
	}

	resultEvalConstants := NewResultEvalConstantsBuilder().LiftLogLimits(simConfig.LiftLogLimits).Finalize()

	return Result{
		Version:       version,
		LastRound:     lastRound,
		TxnGroups:     groups,
		LiftLogLimits: simConfig.LiftLogLimits,
		EvalConstants: resultEvalConstants,
		WouldSucceed:  true,
	}, nil
}

func makeSimulationResult(lastRound basics.Round, txgroups [][]transactions.SignedTxn, simConfig SimulatorConfig) Result {
	result, err := makeSimulationResultWithVersion(lastRound, txgroups, ResultLatestVersion, simConfig)
	if err != nil {
		// this should never happen, since we pass in ResultLatestVersion
		panic(err)
	}
	return result
}
