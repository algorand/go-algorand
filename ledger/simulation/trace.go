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
	Trace                  *TransactionTrace
}

// TxnGroupResult contains the simulation result for a single transaction group
type TxnGroupResult struct {
	Txns []TxnResult
	// FailureMessage will be the error message for the first transaction in the group which errors.
	// If the group succeeds, this will be empty.
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
	ExtraOpcodeBudget    uint64
}

// LogBytesLimit hardcode limit of how much bytes one can log per transaction during simulation (with AllowMoreLogging)
const LogBytesLimit = uint64(65536)

// MaxExtraOpcodeBudget hardcode limit of how much extra budget one can add to one transaction group (which is group-size * logic-sig-budget)
const MaxExtraOpcodeBudget = uint64(20000 * 16)

// AllowMoreLogging method modify the log limits from lift option:
// - if lift log limits, then overload result from local Config
// - otherwise, set `LogLimits` field to be nil
func (eo ResultEvalOverrides) AllowMoreLogging(allow bool) ResultEvalOverrides {
	if allow {
		maxLogCalls, maxLogSize := uint64(config.MaxLogCalls), LogBytesLimit
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

// ExecTraceConfig gathers all execution trace related configs for simulation result
type ExecTraceConfig struct {
	_struct struct{} `codec:",omitempty"`

	Enable  bool `codec:"enable"`
	Stack   bool `codec:"stack-change"`
	Scratch bool `codec:"scratch-change"`
}

// Result contains the result from a call to Simulator.Simulate
type Result struct {
	Version       uint64
	LastRound     basics.Round
	TxnGroups     []TxnGroupResult // this is a list so that supporting multiple in the future is not breaking
	EvalOverrides ResultEvalOverrides
	Block         *ledgercore.ValidatedBlock
	TraceConfig   ExecTraceConfig
}

// ReturnTrace reads from Result object and decides if simulation returns PC.
// It only reads Enable for any option combination must contain Enable field, or it won't make sense.
// The other invalid options would be eliminated in validateSimulateRequest early.
func (r Result) ReturnTrace() bool { return r.TraceConfig.Enable }

// ReturnStackChange reads from Result object and decides if simulation return stack changes.
func (r Result) ReturnStackChange() bool { return r.TraceConfig.Stack }

// ReturnScratchChange tells if the simulation runs with scratch-change enabled.
func (r Result) ReturnScratchChange() bool { return r.TraceConfig.Scratch }

// validateSimulateRequest first checks relation between request and config variables, including developerAPI:
// if `developerAPI` provided is turned off, this method would:
// - error on asking for exec trace
func validateSimulateRequest(request Request, developerAPI bool) error {
	if !developerAPI && request.TraceConfig.Enable {
		return InvalidRequestError{
			SimulatorError{
				err: fmt.Errorf("the local configuration of the node has `EnableDeveloperAPI` turned off, while requesting for execution trace"),
			},
		}
	}
	if !request.TraceConfig.Enable {
		if request.TraceConfig.Stack {
			return InvalidRequestError{
				SimulatorError{
					err: fmt.Errorf("basic trace must be enabled when enabling stack tracing"),
				},
			}
		}
		if request.TraceConfig.Scratch {
			return InvalidRequestError{
				SimulatorError{
					err: fmt.Errorf("basic trace must be enabled when enabling scratch slot change tracing"),
				},
			}
		}
	}
	return nil
}

func makeSimulationResult(lastRound basics.Round, request Request, developerAPI bool) (Result, error) {
	groups := make([]TxnGroupResult, len(request.TxnGroups))

	for i, txgroup := range request.TxnGroups {
		groups[i] = makeTxnGroupResult(txgroup)
	}

	resultEvalConstants := ResultEvalOverrides{
		AllowEmptySignatures: request.AllowEmptySignatures,
		ExtraOpcodeBudget:    request.ExtraOpcodeBudget,
	}.AllowMoreLogging(request.AllowMoreLogging)

	if err := validateSimulateRequest(request, developerAPI); err != nil {
		return Result{}, err
	}

	return Result{
		Version:       ResultLatestVersion,
		LastRound:     lastRound,
		TxnGroups:     groups,
		EvalOverrides: resultEvalConstants,
		TraceConfig:   request.TraceConfig,
	}, nil
}

// ScratchChange represents a write operation into a scratch slot
type ScratchChange struct {
	// Slot stands for the scratch slot id get written to
	Slot uint64

	// NewValue is the stack value written to scratch slot
	NewValue basics.TealValue
}

// OpcodeTraceUnit contains the trace effects of a single opcode evaluation.
type OpcodeTraceUnit struct {
	// The PC of the opcode being evaluated
	PC uint64

	// SpawnedInners contains the indexes of traces for inner transactions spawned by this opcode,
	// if any. These indexes refer to the InnerTraces array of the TransactionTrace object containing
	// this OpcodeTraceUnit.
	SpawnedInners []int

	// what has been added to stack
	StackAdded []basics.TealValue

	// deleted element number from stack
	StackPopCount uint64

	// ScratchSlotChanges stands for write operations into scratch slots
	ScratchSlotChanges []ScratchChange
}

// TransactionTrace contains the trace effects of a single transaction evaluation (including its inners)
type TransactionTrace struct {
	// ApprovalProgramTrace stands for a slice of OpcodeTraceUnit over application call on approval program
	ApprovalProgramTrace []OpcodeTraceUnit
	// ClearStateProgramTrace stands for a slice of OpcodeTraceUnit over application call on clear-state program
	ClearStateProgramTrace []OpcodeTraceUnit
	// LogicSigTrace contains the trace for a logicsig evaluation, if the transaction is approved by a logicsig.
	LogicSigTrace []OpcodeTraceUnit
	// programTraceRef points to one of ApprovalProgramTrace, ClearStateProgramTrace, and LogicSigTrace during simulation.
	programTraceRef *[]OpcodeTraceUnit
	// InnerTraces contains the traces for inner transactions, if this transaction spawned any. This
	// object only contains traces for inners that are immediate children of this transaction.
	// Grandchild traces will be present inside the TransactionTrace of their parent.
	InnerTraces []TransactionTrace
}
