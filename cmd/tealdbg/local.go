// Copyright (C) 2019-2020 Algorand, Inc.
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

package main

import (
	"fmt"
	"io"
	"log"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

func protoFromString(protoString string) (name string, proto config.ConsensusParams, err error) {
	if len(protoString) == 0 || protoString == "current" {
		name = string(protocol.ConsensusCurrentVersion)
		proto = config.Consensus[protocol.ConsensusCurrentVersion]
	} else {
		var ok bool
		proto, ok = config.Consensus[protocol.ConsensusVersion(protoString)]
		if !ok {
			err = fmt.Errorf("Unknown protocol %s", protoString)
			return
		}
		name = protoString
	}

	return
}

// txnGroupFromParams validates DebugParams.TxnBlob
// DebugParams.TxnBlob parsed as JSON object, JSON array or MessagePack array of transactions.SignedTxn.
// The function returns ready to use txnGroup or an error
func txnGroupFromParams(dp *DebugParams) (txnGroup []transactions.SignedTxn, err error) {
	if len(dp.TxnBlob) == 0 {
		txnGroup = append(txnGroup, transactions.SignedTxn{})
		return
	}

	var data []byte = dp.TxnBlob

	// 1. Attempt json - a single transaction
	var txn transactions.SignedTxn
	err = protocol.DecodeJSON(data, &txn)
	if err == nil {
		txnGroup = append(txnGroup, txn)
		return
	}

	// 2. Attempt json - array of transactions
	err = protocol.DecodeJSON(data, &txnGroup)
	if err == nil {
		return
	}

	// 3. Attempt msgp - array of transactions
	dec := protocol.NewDecoderBytes(data)
	for {
		var txn transactions.SignedTxn
		err = dec.Decode(&txn)
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			break
		}
		txnGroup = append(txnGroup, txn)
	}

	return
}

// balanceRecordsFromParams attempts to parse DebugParams.BalanceBlob as
// JSON object, JSON array or MessagePack array of basics.BalanceRecord
func balanceRecordsFromParams(dp *DebugParams) (records []basics.BalanceRecord, err error) {
	if len(dp.BalanceBlob) == 0 {
		return
	}

	var data []byte = dp.BalanceBlob

	// 1. Attempt json - a single record
	var record basics.BalanceRecord
	err = protocol.DecodeJSON(data, &record)
	if err == nil {
		records = append(records, record)
		return
	}

	// 2. Attempt json - a array of records
	err = protocol.DecodeJSON(data, &records)
	if err == nil {
		return
	}

	// 2. Attempt msgp - a array of records
	dec := protocol.NewDecoderBytes(data)
	for {
		var record basics.BalanceRecord
		err = dec.Decode(&record)
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			break
		}
		records = append(records, record)
	}

	return
}

type evalResult struct {
	pass bool
	err  error
}

type evalFn func(program []byte, ep logic.EvalParams) (bool, error)

// AppState encapsulates information about execution of stateful teal program
type AppState struct {
	appIdx  basics.AppIndex
	schemas basics.StateSchemas
	global  map[basics.AppIndex]basics.TealKeyValue
	locals  map[basics.Address]map[basics.AppIndex]basics.TealKeyValue
}

func (a *AppState) clone() (b AppState) {
	b.appIdx = a.appIdx
	b.global = make(map[basics.AppIndex]basics.TealKeyValue, len(a.global))
	for aid, tkv := range a.global {
		b.global[aid] = tkv.Clone()
	}
	b.locals = make(map[basics.Address]map[basics.AppIndex]basics.TealKeyValue, len(a.locals))
	for addr, local := range a.locals {
		b.locals[addr] = make(map[basics.AppIndex]basics.TealKeyValue, len(local))
		for aid, tkv := range local {
			b.locals[addr][aid] = tkv.Clone()
		}
	}
	return
}

func (a *AppState) empty() bool {
	return a.appIdx == 0 && len(a.global) == 0 && len(a.locals) == 0
}

// evaluation is a description of a single debugger run
type evaluation struct {
	program      []byte
	source       string
	offsetToLine map[int]int
	name         string
	groupIndex   int
	eval         evalFn
	ledger       logic.LedgerForLogic
	result       evalResult
	states       AppState
}

// LocalRunner runs local eval
type LocalRunner struct {
	debugger  *Debugger
	proto     config.ConsensusParams
	protoName string
	txnGroup  []transactions.SignedTxn
	runs      []evaluation
}

func makeAppState() (states AppState) {
	states.global = make(map[basics.AppIndex]basics.TealKeyValue)
	states.locals = make(map[basics.Address]map[basics.AppIndex]basics.TealKeyValue)
	return
}

// MakeLocalRunner creates LocalRunner
func MakeLocalRunner(debugger *Debugger) *LocalRunner {
	r := new(LocalRunner)
	r.debugger = debugger
	return r
}

func determineEvalMode(program []byte, modeIn string) (eval evalFn, mode string, err error) {
	statefulEval := func(program []byte, ep logic.EvalParams) (bool, error) {
		pass, _, err := logic.EvalStateful(program, ep)
		return pass, err
	}
	mode = modeIn
	switch modeIn {
	case "signature":
		eval = logic.Eval
	case "application":
		eval = statefulEval
	case "auto":
		var hasStateful bool
		hasStateful, err = logic.HasStatefulOps(program)
		if err != nil {
			return
		}
		if hasStateful {
			eval = statefulEval
			mode = "application"
		} else {
			eval = logic.Eval
			mode = "signature"
		}
	default:
		err = fmt.Errorf("unknown run mode")
		return
	}
	return
}

// Setup validates input params and resolves inputs into canonical balance record structures.
// Programs for execution are discovered in the following way:
// - Sources from command line file names.
// - Programs mentioned in transaction group txnGroup.
// - if DryrunRequest present and no sources or transaction group set in command line then:
//   1. DryrunRequest.Sources are expanded to DryrunRequest.Apps or DryrunRequest.Txns.
//   2. DryrunRequest.Apps are expanded into DryrunRequest.Txns.
//   3. txnGroup is set to DryrunRequest.Txns
// Application search by id:
//  - Balance records from CLI or DryrunRequest.Accounts
//  - If no balance records set in CLI then DryrunRequest.Accounts and DryrunRequest.Apps are used.
//    In this case Accounts data is used as a base for balance records creation,
//    and Apps supply updates to AppParams field.
func (r *LocalRunner) Setup(dp *DebugParams) (err error) {
	ddr, err := ddrFromParams(dp)
	if err != nil {
		return
	}

	protoString := ddr.ProtocolVersion
	if len(dp.Proto) != 0 {
		protoString = dp.Proto
	}
	r.protoName, r.proto, err = protoFromString(protoString)
	if err != nil {
		return
	}

	log.Printf("Using proto: %s", r.protoName)

	r.txnGroup = ddr.Txns
	if len(dp.TxnBlob) != 0 || len(r.txnGroup) == 0 {
		r.txnGroup, err = txnGroupFromParams(dp)
		if err != nil {
			return
		}
	}

	// if no sources provided, check dryrun request object
	if len(dp.ProgramBlobs) == 0 && len(ddr.Sources) > 0 {
		err = ddr.ExpandSources()
		if err != nil {
			return
		}
	}

	var records []basics.BalanceRecord
	if len(dp.BalanceBlob) > 0 {
		records, err = balanceRecordsFromParams(dp)
	} else {
		records, err = balanceRecordsFromDdr(&ddr)
	}
	if err != nil {
		return
	}

	balances := make(map[basics.Address]basics.AccountData)
	for _, record := range records {
		balances[record.Addr] = record.AccountData
	}

	if dp.Round == 0 && ddr.Round != 0 {
		dp.Round = ddr.Round
	}

	if dp.LatestTimestamp == 0 && ddr.LatestTimestamp != 0 {
		dp.LatestTimestamp = int64(ddr.LatestTimestamp)
	}

	// if program(s) specified then run from it
	if len(dp.ProgramBlobs) > 0 {
		if len(r.txnGroup) == 1 && dp.GroupIndex != 0 {
			err = fmt.Errorf("invalid group index %d for a single transaction", dp.GroupIndex)
			return
		}
		if len(r.txnGroup) > 0 && dp.GroupIndex >= len(r.txnGroup) {
			err = fmt.Errorf("invalid group index %d for a txn in a transaction group of %d", dp.GroupIndex, len(r.txnGroup))
			return
		}

		r.runs = make([]evaluation, len(dp.ProgramBlobs))
		for i, data := range dp.ProgramBlobs {
			r.runs[i].program = data
			if IsTextFile(data) {
				source := string(data)
				ops, err := logic.AssembleStringWithVersion(source, r.proto.LogicSigVersion)
				if err != nil {
					return err
				}
				r.runs[i].program = ops.Program
				if !dp.DisableSourceMap {
					r.runs[i].offsetToLine = ops.OffsetToLine
					r.runs[i].source = source
				}
			}
			r.runs[i].groupIndex = dp.GroupIndex
			r.runs[i].name = dp.ProgramNames[i]

			var eval evalFn
			var mode string
			eval, mode, err = determineEvalMode(r.runs[i].program, dp.RunMode)
			if err != nil {
				return
			}
			r.runs[i].eval = eval

			log.Printf("Run mode: %s", mode)
			if mode == "application" {
				var ledger logic.LedgerForLogic
				var states AppState
				txn := r.txnGroup[dp.GroupIndex]
				appIdx := txn.Txn.ApplicationID
				if appIdx == 0 {
					appIdx = basics.AppIndex(dp.AppID)
				}

				ledger, states, err = makeAppLedger(
					balances, r.txnGroup, dp.GroupIndex,
					r.proto, dp.Round, dp.LatestTimestamp, appIdx,
					dp.Painless, dp.IndexerURL, dp.IndexerToken,
				)
				if err != nil {
					return
				}

				r.runs[i].ledger = ledger
				r.runs[i].states = states
			}
		}
		return nil
	}

	r.runs = nil
	// otherwise, if no program(s) set, check transactions for TEAL programs
	for gi, stxn := range r.txnGroup {
		// make a new ledger per possible execution since it requires a current group index
		if len(stxn.Lsig.Logic) > 0 {
			run := evaluation{
				program:    stxn.Lsig.Logic,
				groupIndex: gi,
				eval:       logic.Eval,
			}
			r.runs = append(r.runs, run)
		} else if stxn.Txn.Type == protocol.ApplicationCallTx {
			var ledger logic.LedgerForLogic
			var states AppState
			eval := func(program []byte, ep logic.EvalParams) (bool, error) {
				pass, _, err := logic.EvalStateful(program, ep)
				return pass, err
			}
			appIdx := stxn.Txn.ApplicationID
			if appIdx == 0 { // app create, use ApprovalProgram from the transaction
				if len(stxn.Txn.ApprovalProgram) > 0 {
					appIdx = basics.AppIndex(dp.AppID)
					ledger, states, err = makeAppLedger(
						balances, r.txnGroup, gi,
						r.proto, dp.Round, dp.LatestTimestamp,
						appIdx, dp.Painless, dp.IndexerURL, dp.IndexerToken,
					)
					if err != nil {
						return
					}
					run := evaluation{
						program:    stxn.Txn.ApprovalProgram,
						groupIndex: gi,
						eval:       eval,
						ledger:     ledger,
						states:     states,
					}
					r.runs = append(r.runs, run)
				}
			} else {
				// attempt to find this appIdx in balance records provided
				// and error if it is not there
				found := false
				for _, rec := range records {
					for a, ap := range rec.AppParams {
						if a == appIdx {
							var program []byte
							if stxn.Txn.OnCompletion == transactions.ClearStateOC {
								program = ap.ClearStateProgram
							} else {
								program = ap.ApprovalProgram
							}
							if len(program) == 0 {
								err = fmt.Errorf("empty program found for app idx %d", appIdx)
								return
							}
							ledger, states, err = makeAppLedger(
								balances, r.txnGroup, gi,
								r.proto, dp.Round, dp.LatestTimestamp,
								appIdx, dp.Painless, dp.IndexerURL, dp.IndexerToken,
							)
							if err != nil {
								return
							}
							run := evaluation{
								program:    program,
								groupIndex: gi,
								eval:       eval,
								ledger:     ledger,
								states:     states,
							}
							r.runs = append(r.runs, run)
							found = true
							break
						}
					}
				}
				if !found {
					err = fmt.Errorf("no program found for app idx %d", appIdx)
					return
				}
			}
		}
	}

	if len(r.runs) == 0 {
		err = fmt.Errorf("no programs found in transactions")
	}

	return
}

// RunAll runs all the programs
func (r *LocalRunner) RunAll() error {
	if len(r.runs) < 1 {
		return fmt.Errorf("no program to debug")
	}

	failed := 0
	start := time.Now()
	for _, run := range r.runs {
		r.debugger.SaveProgram(run.name, run.program, run.source, run.offsetToLine, run.states)

		ep := logic.EvalParams{
			Proto:      &r.proto,
			Debugger:   r.debugger,
			Txn:        &r.txnGroup[groupIndex],
			TxnGroup:   r.txnGroup,
			GroupIndex: run.groupIndex,
			Ledger:     run.ledger,
		}

		run.result.pass, run.result.err = run.eval(run.program, ep)
		if run.result.err != nil {
			failed++
		}
	}
	elapsed := time.Since(start)
	if failed == len(r.runs) && elapsed < time.Second {
		return fmt.Errorf("all %d program(s) failed in less than a second, invocation error?", failed)
	}
	return nil
}

// Run starts the first program in list
func (r *LocalRunner) Run() (bool, error) {
	if len(r.runs) < 1 {
		return false, fmt.Errorf("no program to debug")
	}

	run := r.runs[0]

	ep := logic.EvalParams{
		Proto:      &r.proto,
		Txn:        &r.txnGroup[groupIndex],
		TxnGroup:   r.txnGroup,
		GroupIndex: run.groupIndex,
		Ledger:     run.ledger,
	}

	// Workaround for Go's nil/empty interfaces nil check after nil assignment, i.e.
	// r.debugger = nil
	// ep.Debugger = r.debugger
	// if ep.Debugger != nil // FALSE
	if r.debugger != nil {
		r.debugger.SaveProgram(run.name, run.program, run.source, run.offsetToLine, run.states)
		ep.Debugger = r.debugger
	}

	return run.eval(run.program, ep)
}
