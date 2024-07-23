// Copyright (C) 2019-2024 Algorand, Inc.
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
	"github.com/algorand/go-algorand/crypto"
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

	// UnnamedResourcesAccessed is present if all of the following are true:
	//  * AllowUnnamedResources is true
	//  * The transaction cannot use shared resources (pre-v9 program)
	//  * The transaction accessed unnamed resources.
	//
	// In that case, it will be populated with the unnamed resources accessed by this transaction.
	UnnamedResourcesAccessed *ResourceTracker

	// If the signer needed to be changed, this will be the address of the required signer
	// This will only be present if FixSigners is true in the EvalOverrides
	FixedSigner basics.Address
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

	// UnnamedResourcesAccessed will be present if AllowUnnamedResources is true. In that case, it
	// will be populated with the unnamed resources accessed by this transaction group from
	// transactions which can benefit from shared resources (v9 or higher programs).
	//
	// Any unnamed resources accessed from transactions which cannot benefit from shared resources
	// will be placed in the corresponding `UnnamedResourcesAccessed` field in the appropriate
	// TxnResult struct.
	UnnamedResourcesAccessed *ResourceTracker
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
	AllowEmptySignatures  bool
	AllowUnnamedResources bool
	MaxLogCalls           *uint64
	MaxLogSize            *uint64
	ExtraOpcodeBudget     uint64
	FixSigners            bool
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
	State   bool `codec:"state-change"`
}

// Result contains the result from a call to Simulator.Simulate
type Result struct {
	Version       uint64
	LastRound     basics.Round
	TxnGroups     []TxnGroupResult // this is a list so that supporting multiple in the future is not breaking
	EvalOverrides ResultEvalOverrides
	Block         *ledgercore.ValidatedBlock
	TraceConfig   ExecTraceConfig
	InitialStates *ResourcesInitialStates
}

// ReturnTrace reads from Result object and decides if simulation returns PC.
// It only reads Enable for any option combination must contain Enable field, or it won't make sense.
// The other invalid options would be eliminated in validateSimulateRequest early.
func (r Result) ReturnTrace() bool { return r.TraceConfig.Enable }

// ReturnStackChange reads from Result object and decides if simulation return stack changes.
func (r Result) ReturnStackChange() bool { return r.TraceConfig.Stack }

// ReturnScratchChange tells if the simulation runs with scratch-change enabled.
func (r Result) ReturnScratchChange() bool { return r.TraceConfig.Scratch }

// ReturnStateChange tells if the simulation runs with state-change enabled.
func (r Result) ReturnStateChange() bool { return r.TraceConfig.State }

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
		if request.TraceConfig.State {
			return InvalidRequestError{
				SimulatorError{
					err: fmt.Errorf("basic trace must be enabled when enabling app state change tracing"),
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
		AllowEmptySignatures:  request.AllowEmptySignatures,
		ExtraOpcodeBudget:     request.ExtraOpcodeBudget,
		AllowUnnamedResources: request.AllowUnnamedResources,
		FixSigners:            request.FixSigners,
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
		InitialStates: newResourcesInitialStates(request),
	}, nil
}

// ScratchChange represents a write operation into a scratch slot
type ScratchChange struct {
	// Slot stands for the scratch slot id get written to
	Slot uint64

	// NewValue is the stack value written to scratch slot
	NewValue basics.TealValue
}

// StateOperation represents an operation into an app local/global/box state
type StateOperation struct {
	// AppStateOp is one of logic.AppStateOpEnum, standing for either write or delete.
	AppStateOp logic.AppStateOpEnum

	// AppState is one of logic.AppStateEnum, standing for one of global/local/box.
	AppState logic.AppStateEnum

	// AppID is the current app's ID.
	AppID basics.AppIndex

	// Key is the app state kv-pair's key, directly casting byte slice to string.
	Key string

	// NewValue is the value write to the app's state.
	// NOTE: if the current app state operation is del, then this value is basics.TealValue{}.
	NewValue basics.TealValue

	// Account is the account associated to the local state an app writes to.
	// NOTE: if the current app state is not local, then this value is basics.Address{}.
	Account basics.Address
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

	// StateChanges stands for the creation/reading/writing/deletion operations to app's state
	StateChanges []StateOperation
}

// TransactionTrace contains the trace effects of a single transaction evaluation (including its inners)
type TransactionTrace struct {
	// ApprovalProgramTrace stands for a slice of OpcodeTraceUnit over application call on approval program
	ApprovalProgramTrace []OpcodeTraceUnit
	// ApprovalProgramHash stands for the hash digest of approval program bytecode executed during simulation
	ApprovalProgramHash crypto.Digest

	// ClearStateProgramTrace stands for a slice of OpcodeTraceUnit over application call on clear-state program
	ClearStateProgramTrace []OpcodeTraceUnit
	// ClearStateProgramHash stands for the hash digest of clear state program bytecode executed during simulation
	ClearStateProgramHash crypto.Digest
	// ClearStateRollback, if true, indicates that the clear state program failed and any persistent state changes
	// it produced should be reverted once the program exits.
	ClearStateRollback bool
	// ClearStateRollbackError contains the error message explaining why the clear state program failed. This
	// field will only be populated if ClearStateRollback is true and the failure was due to an execution error.
	ClearStateRollbackError string

	// LogicSigTrace contains the trace for a logicsig evaluation, if the transaction is approved by a logicsig.
	LogicSigTrace []OpcodeTraceUnit
	// LogicSigHash stands for the hash digest of logic sig bytecode executed during simulation
	LogicSigHash crypto.Digest

	// programTraceRef points to one of ApprovalProgramTrace, ClearStateProgramTrace, and LogicSigTrace during simulation.
	programTraceRef *[]OpcodeTraceUnit

	// InnerTraces contains the traces for inner transactions, if this transaction spawned any. This
	// object only contains traces for inners that are immediate children of this transaction.
	// Grandchild traces will be present inside the TransactionTrace of their parent.
	InnerTraces []TransactionTrace
}
