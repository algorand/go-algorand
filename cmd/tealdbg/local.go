// Copyright (C) 2019-2025 Algorand, Inc.
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
	"slices"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/apply"
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
			err = fmt.Errorf("unknown protocol %s", protoString)
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
	err1 := protocol.DecodeJSON(data, &txn)
	if err1 == nil {
		txnGroup = append(txnGroup, txn)
		return
	}

	// 2. Attempt json - array of transactions
	err2 := protocol.DecodeJSON(data, &txnGroup)
	if err2 == nil {
		return
	}

	// 3. Attempt msgp - array of transactions
	dec := protocol.NewMsgpDecoderBytes(data)
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

	// if conversion failed report all intermediate decoding errors
	if err != nil {
		log.Printf("Decoding as JSON txn failed: %v", err1)
		log.Printf("Decoding as JSON txn group failed: %v", err2)
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
	err1 := protocol.DecodeJSON(data, &record)
	if err1 == nil {
		records = append(records, record)
		return
	}

	// 2. Attempt json - a array of records
	err2 := protocol.DecodeJSON(data, &records)
	if err2 == nil {
		return
	}

	// 3. Attempt msgp - a array of records
	dec := protocol.NewMsgpDecoderBytes(data)
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

	// if conversion failed report all intermediate decoding errors
	if err != nil {
		log.Printf("Decoding as JSON record failed: %v", err1)
		log.Printf("Decoding as JSON array of records failed: %v", err2)
	}

	return
}

type evalResult struct {
	pass bool
	err  error
}

// AppState encapsulates information about execution of stateful teal program
type AppState struct {
	appIdx    basics.AppIndex
	schemas   basics.StateSchemas
	global    map[basics.AppIndex]basics.TealKeyValue
	locals    map[basics.Address]map[basics.AppIndex]basics.TealKeyValue
	logs      []string
	innerTxns []transactions.SignedTxnWithAD
}

func cloneInners(a []transactions.SignedTxnWithAD) (b []transactions.SignedTxnWithAD) {
	if a != nil {
		b = make([]transactions.SignedTxnWithAD, len(a))
		copy(b, a)
		for i, itxn := range a {
			b[i].EvalDelta.InnerTxns = cloneInners(itxn.EvalDelta.InnerTxns)
		}
	}
	return
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
	b.logs = slices.Clone(a.logs)
	b.innerTxns = cloneInners(a.innerTxns)
	return
}

func (a *AppState) empty() bool {
	return a.appIdx == 0 &&
		len(a.global) == 0 &&
		len(a.locals) == 0 &&
		len(a.logs) == 0 &&
		len(a.innerTxns) == 0
}

type modeType int

func (m modeType) String() string {
	switch m {
	case modeLogicsig:
		return "logicsig"
	case modeStateful:
		return "stateful"
	default:
		return "unknown"
	}
}

const (
	modeUnknown modeType = iota
	modeLogicsig
	modeStateful
)

// evaluation is a description of a single debugger run
type evaluation struct {
	program        []byte
	source         string
	offsetToSource map[int]logic.SourceLocation
	name           string
	groupIndex     uint64
	mode           modeType
	aidx           basics.AppIndex
	ba             apply.Balances
	result         evalResult
	states         AppState
}

func (e *evaluation) eval(gi int, sep *logic.EvalParams, aep *logic.EvalParams) (pass bool, err error) {
	if e.mode == modeStateful {
		pass, _, err = e.ba.StatefulEval(gi, aep, e.aidx, e.program)
		return
	}
	sep.TxnGroup[gi].Lsig.Logic = e.program
	return logic.EvalSignature(gi, sep)
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
	states.logs = make([]string, 0)
	states.innerTxns = make([]transactions.SignedTxnWithAD, 0)
	return
}

// MakeLocalRunner creates LocalRunner
func MakeLocalRunner(debugger *Debugger) *LocalRunner {
	r := new(LocalRunner)
	r.debugger = debugger
	return r
}

func determineEvalMode(program []byte, modeIn string) (mode modeType, err error) {
	switch modeIn {
	case "signature":
		mode = modeLogicsig
	case "application":
		mode = modeStateful
	case "auto":
		var hasStateful bool
		hasStateful, err = logic.HasStatefulOps(program)
		if err != nil {
			return
		}
		if hasStateful {
			mode = modeStateful
		} else {
			mode = modeLogicsig
		}
	default:
		err = fmt.Errorf("unknown run mode")
	}
	return
}

// Setup validates input params and resolves inputs into canonical balance record structures.
// Programs for execution are discovered in the following way:
// - Sources from command line file names.
// - Programs mentioned in transaction group txnGroup.
// - if DryrunRequest present and no sources or transaction group set in command line then:
//  1. DryrunRequest.Sources are expanded to DryrunRequest.Apps or DryrunRequest.Txns.
//  2. DryrunRequest.Apps are expanded into DryrunRequest.Txns.
//  3. txnGroup is set to DryrunRequest.Txns
//
// Application search by id:
//   - Balance records from CLI or DryrunRequest.Accounts
//   - If no balance records set in CLI then DryrunRequest.Accounts and DryrunRequest.Apps are used.
//     In this case Accounts data is used as a base for balance records creation,
//     and Apps supply updates to AppParams field.
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
				ops, err1 := logic.AssembleString(source)
				if ops.Version > r.proto.LogicSigVersion {
					return fmt.Errorf("program version (%d) is beyond the maximum supported protocol version (%d)", ops.Version, r.proto.LogicSigVersion)
				}
				if err1 != nil {
					errorLines := ""
					for _, lineError := range ops.Errors {
						errorLines = fmt.Sprintf("%s\n%s", errorLines, lineError.Error())
					}
					if errorLines != "" {
						return fmt.Errorf("%w:%s", err1, errorLines)
					}
					return err1
				}
				r.runs[i].program = ops.Program
				if !dp.DisableSourceMap {
					r.runs[i].offsetToSource = ops.OffsetToSource
					r.runs[i].source = source
				}
			}
			r.runs[i].groupIndex = uint64(dp.GroupIndex)
			r.runs[i].name = dp.ProgramNames[i]

			var mode modeType
			mode, err = determineEvalMode(r.runs[i].program, dp.RunMode)
			if err != nil {
				return
			}
			log.Printf("Run mode: %s", mode.String())
			r.runs[i].mode = mode
			if mode == modeStateful {
				var b apply.Balances
				var states AppState
				txn := r.txnGroup[dp.GroupIndex]
				appIdx := txn.Txn.ApplicationID
				if appIdx == 0 {
					appIdx = dp.AppID
				}

				b, states, err = makeBalancesAdapter(
					balances, r.txnGroup, dp.GroupIndex,
					r.protoName, dp.Round, dp.LatestTimestamp, appIdx,
					dp.Painless, dp.IndexerURL, dp.IndexerToken,
				)
				if err != nil {
					return
				}

				r.runs[i].aidx = appIdx
				r.runs[i].ba = b
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
				groupIndex: uint64(gi),
				mode:       modeLogicsig,
			}
			r.runs = append(r.runs, run)
		} else if stxn.Txn.Type == protocol.ApplicationCallTx {
			var b apply.Balances
			var states AppState
			appIdx := stxn.Txn.ApplicationID
			if appIdx == 0 { // app create, use ApprovalProgram from the transaction
				if len(stxn.Txn.ApprovalProgram) > 0 {
					appIdx = dp.AppID
					b, states, err = makeBalancesAdapter(
						balances, r.txnGroup, gi,
						r.protoName, dp.Round, dp.LatestTimestamp,
						appIdx, dp.Painless, dp.IndexerURL, dp.IndexerToken,
					)
					if err != nil {
						return
					}
					run := evaluation{
						program:    stxn.Txn.ApprovalProgram,
						groupIndex: uint64(gi),
						mode:       modeStateful,
						aidx:       appIdx,
						ba:         b,
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
							b, states, err = makeBalancesAdapter(
								balances, r.txnGroup, gi,
								r.protoName, dp.Round, dp.LatestTimestamp,
								appIdx, dp.Painless, dp.IndexerURL, dp.IndexerToken,
							)
							if err != nil {
								return
							}
							run := evaluation{
								program:    program,
								groupIndex: uint64(gi),
								mode:       modeStateful,
								aidx:       appIdx,
								ba:         b,
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

	txngroup := transactions.WrapSignedTxnsWithAD(r.txnGroup)
	failed := 0
	start := time.Now()

	sep := logic.NewSigEvalParams(r.txnGroup, &r.proto, &logic.NoHeaderLedger{})
	aep := logic.NewAppEvalParams(txngroup, &r.proto, &transactions.SpecialAddresses{})
	if r.debugger != nil {
		t := logic.MakeEvalTracerDebuggerAdaptor(r.debugger)
		sep.Tracer = t
		aep.Tracer = t
	}

	var last error
	for i := range r.runs {
		run := &r.runs[i]
		if r.debugger != nil {
			r.debugger.SaveProgram(run.name, run.program, run.source, run.offsetToSource, run.states)
		}

		run.result.pass, run.result.err = run.eval(int(run.groupIndex), sep, aep)
		if run.result.err != nil {
			failed++
			last = run.result.err
		}
	}
	elapsed := time.Since(start)
	if failed == len(r.runs) && elapsed < time.Second {
		return fmt.Errorf("all %d program(s) failed in less than a second, invocation error? %w", failed, last)
	}
	return nil
}
