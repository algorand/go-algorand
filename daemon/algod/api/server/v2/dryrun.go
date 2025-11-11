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

package v2

import (
	"fmt"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/ledger/ledgercore"

	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/protocol"
)

// DryrunRequest object uploaded to /v2/teal/dryrun
// It is the same as model.DryrunRequest but Txns deserialized properly.
// Given the Transactions and simulated ledger state upload, run TEAL scripts and return debugging information.
// This is also used for msgp-decoding
type DryrunRequest struct {
	// Txns is transactions to simulate
	Txns []transactions.SignedTxn `codec:"txns"` // not supposed to be serialized

	// Optional, useful for testing Application Call txns.
	Accounts []model.Account `codec:"accounts"`

	Apps []model.Application `codec:"apps"`

	// ProtocolVersion specifies a specific version string to operate under, otherwise whatever the current protocol of the network this algod is running in.
	ProtocolVersion string `codec:"protocol-version"`

	// Round is available to some TEAL scripts. Defaults to the current round on the network this algod is attached to.
	Round basics.Round `codec:"round"`

	// LatestTimestamp is available to some TEAL scripts. Defaults to the latest confirmed timestamp this algod is attached to.
	LatestTimestamp int64 `codec:"latest-timestamp"`

	Sources []model.DryrunSource `codec:"sources"`
}

// DryrunRequestFromGenerated converts model.DryrunRequest to DryrunRequest field by fields
// and re-types Txns []transactions.SignedTxn
func DryrunRequestFromGenerated(gdr *model.DryrunRequest) (dr DryrunRequest, err error) {
	dr.Txns = make([]transactions.SignedTxn, 0, len(gdr.Txns))
	for _, raw := range gdr.Txns {
		// no transactions.SignedTxn in OAS, map[string]interface{} is not good enough
		// json.RawMessage does the job
		var txn transactions.SignedTxn
		err = protocol.DecodeJSON(raw, &txn)
		if err != nil {
			return
		}
		dr.Txns = append(dr.Txns, txn)
	}
	dr.Accounts = gdr.Accounts
	dr.Apps = gdr.Apps
	dr.ProtocolVersion = gdr.ProtocolVersion
	dr.Round = gdr.Round
	dr.LatestTimestamp = int64(gdr.LatestTimestamp)
	dr.Sources = gdr.Sources
	return
}

// ExpandSources takes DryrunRequest.Source, compiles and
// puts into appropriate DryrunRequest.Apps entry
func (dr *DryrunRequest) ExpandSources() error {
	for i, s := range dr.Sources {
		ops, err := logic.AssembleString(s.Source)
		if err != nil {
			if len(ops.Errors) <= 1 {
				return fmt.Errorf("dryrun Source[%d]: %w", i, err)
			}
			var sb strings.Builder
			ops.ReportMultipleErrors("", &sb)
			return fmt.Errorf("dryrun Source[%d]: %d errors\n%s", i, len(ops.Errors), sb.String())
		}
		switch s.FieldName {
		case "lsig":
			dr.Txns[s.TxnIndex].Lsig.Logic = ops.Program
		case "approv", "clearp":
			for ai, app := range dr.Apps {
				if app.Id == s.AppIndex {
					switch s.FieldName {
					case "approv":
						dr.Apps[ai].Params.ApprovalProgram = ops.Program
					case "clearp":
						dr.Apps[ai].Params.ClearStateProgram = ops.Program
					}
				}
			}
		default:
			return fmt.Errorf("dryrun Source[%d]: bad field name %#v", i, s.FieldName)
		}
	}
	return nil
}

type dryrunDebugReceiver struct {
	disassembly   string
	lines         []string
	history       []model.DryrunState
	scratchActive []bool
}

func (ddr *dryrunDebugReceiver) updateScratch() {
	maxActive := -1
	lasti := len(ddr.history) - 1

	if ddr.history[lasti].Scratch == nil {
		return
	}

	if ddr.scratchActive == nil {
		ddr.scratchActive = make([]bool, 256)
	}

	for i, sv := range *ddr.history[lasti].Scratch {
		ddr.scratchActive[i] = false
		if sv.Type != uint64(basics.TealUintType) || sv.Uint != 0 {
			ddr.scratchActive[i] = true
			maxActive = i
		}
	}

	if maxActive == -1 {
		ddr.history[lasti].Scratch = nil
		return
	}

	*ddr.history[lasti].Scratch = (*ddr.history[lasti].Scratch)[:maxActive+1]
	for i := range *ddr.history[lasti].Scratch {
		if !ddr.scratchActive[i] {
			(*ddr.history[lasti].Scratch)[i].Type = 0
		}
	}
}

func (ddr *dryrunDebugReceiver) stateToState(state *logic.DebugState) model.DryrunState {
	st := model.DryrunState{
		Line: state.Line,
		Pc:   state.PC,
	}
	st.Stack = make([]model.TealValue, len(state.Stack))
	for i, v := range state.Stack {
		st.Stack[i] = model.TealValue{
			Uint:  v.Uint,
			Bytes: v.Bytes,
			Type:  uint64(v.Type),
		}
	}
	if len(state.Error) > 0 {
		st.Error = new(string)
		*st.Error = state.Error
	}

	scratch := make([]model.TealValue, len(state.Scratch))
	for i, v := range state.Scratch {
		scratch[i] = model.TealValue{
			Uint:  v.Uint,
			Bytes: v.Bytes,
			Type:  uint64(v.Type),
		}
	}
	st.Scratch = &scratch
	return st
}

// Register is fired on program creation (logic.Debugger interface)
func (ddr *dryrunDebugReceiver) Register(state *logic.DebugState) {
	ddr.disassembly = state.Disassembly
	ddr.lines = strings.Split(state.Disassembly, "\n")
}

// Update is fired on every step (logic.Debugger interface)
func (ddr *dryrunDebugReceiver) Update(state *logic.DebugState) {
	st := ddr.stateToState(state)
	ddr.history = append(ddr.history, st)
	ddr.updateScratch()
}

// Complete is called when the program exits (logic.Debugger interface)
func (ddr *dryrunDebugReceiver) Complete(state *logic.DebugState) {
	ddr.Update(state)
}

type dryrunLedger struct {
	// inputs:

	dr *DryrunRequest

	// intermediate state:

	// index into dr.Accounts[]
	accountsIn map[basics.Address]int
	// index into dr.Apps[]
	accountApps map[basics.Address]int
}

func (dl *dryrunLedger) init() error {
	dl.accountsIn = make(map[basics.Address]int)
	dl.accountApps = make(map[basics.Address]int)
	for i, acct := range dl.dr.Accounts {
		xaddr, err := basics.UnmarshalChecksumAddress(acct.Address)
		if err != nil {
			return err
		}
		dl.accountsIn[xaddr] = i
	}
	for i, app := range dl.dr.Apps {
		var addr basics.Address
		if app.Params.Creator != "" {
			var err error
			addr, err = basics.UnmarshalChecksumAddress(app.Params.Creator)
			if err != nil {
				return err
			}
		}
		dl.accountApps[addr] = i
	}
	return nil
}

func (dl *dryrunLedger) BlockHdr(basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{}, nil
}

func (dl *dryrunLedger) GenesisHash() crypto.Digest {
	return crypto.Digest{}
}

func (dl *dryrunLedger) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error {
	return nil
}

func (dl *dryrunLedger) GetStateProofVerificationContext(_ basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	return nil, fmt.Errorf("dryrunLedger: GetStateProofVerificationContext, needed for state proof verification, is not implemented in dryrun")
}

func (dl *dryrunLedger) lookup(rnd basics.Round, addr basics.Address) (basics.AccountData, basics.Round, error) {
	// check accounts from debug records uploaded
	out := basics.AccountData{}
	accti, ok := dl.accountsIn[addr]
	if ok {
		acct := dl.dr.Accounts[accti]
		var err error
		if out, err = AccountToAccountData(&acct); err != nil {
			return basics.AccountData{}, 0, err
		}
		out.MicroAlgos.Raw = acct.AmountWithoutPendingRewards
		// Clear RewardsBase since dryrun has no idea about rewards level so the underlying calculation with reward will fail.
		// The amount needed is known as acct.Amount but this method must return AmountWithoutPendingRewards
		out.RewardsBase = 0
	}
	appi, ok := dl.accountApps[addr]
	if ok {
		app := dl.dr.Apps[appi]
		params, err := ApplicationParamsToAppParams(&app.Params)
		if err != nil {
			return basics.AccountData{}, 0, err
		}
		if out.AppParams == nil {
			out.AppParams = make(map[basics.AppIndex]basics.AppParams)
			out.AppParams[app.Id] = params
		} else {
			ap, ok := out.AppParams[app.Id]
			if ok {
				MergeAppParams(&ap, &params)
				out.AppParams[app.Id] = ap
			} else {
				out.AppParams[app.Id] = params
			}
		}
	}
	// Returns a 0 account for account that wasn't supplied.  This is new as of
	// AVM 1.1 timeframe, but seems correct (allows using app accounts, and the
	// fee sink without supplying them)
	return out, rnd, nil
}

func (dl *dryrunLedger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, error) {
	ad, rnd, err := dl.lookup(rnd, addr)
	if err != nil {
		return ledgercore.AccountData{}, 0, err
	}
	return ledgercore.ToAccountData(ad), rnd, nil
}

func (dl *dryrunLedger) LookupAgreement(rnd basics.Round, addr basics.Address) (basics.OnlineAccountData, error) {
	// dryrun does not understand rewards, so we build the result without adding pending rewards.
	// we also have no history, so we return current values
	ad, _, err := dl.lookup(rnd, addr)
	if err != nil || ad.Status != basics.Online {
		return basics.OnlineAccountData{}, err
	}
	return basics.OnlineAccountData{
		MicroAlgosWithRewards: ad.MicroAlgos,
		VotingData: basics.VotingData{
			VoteID:          ad.VoteID,
			SelectionID:     ad.SelectionID,
			StateProofID:    ad.StateProofID,
			VoteFirstValid:  ad.VoteFirstValid,
			VoteLastValid:   ad.VoteLastValid,
			VoteKeyDilution: ad.VoteKeyDilution,
		},
		IncentiveEligible: ad.IncentiveEligible,
	}, nil
}

func (dl *dryrunLedger) GetKnockOfflineCandidates(basics.Round, config.ConsensusParams) (map[basics.Address]basics.OnlineAccountData, error) {
	return nil, nil
}

func (dl *dryrunLedger) OnlineCirculation(rnd basics.Round, voteRnd basics.Round) (basics.MicroAlgos, error) {
	// dryrun doesn't support setting the global online stake, so we'll just return a constant
	return basics.Algos(1_000_000_000), nil // 1B
}

func (dl *dryrunLedger) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	ad, _, err := dl.lookup(rnd, addr)
	if err != nil {
		return ledgercore.AppResource{}, err
	}
	var result ledgercore.AppResource
	if p, ok := ad.AppParams[aidx]; ok {
		result.AppParams = &p
	}
	if s, ok := ad.AppLocalStates[aidx]; ok {
		result.AppLocalState = &s
	}
	return result, nil
}

func (dl *dryrunLedger) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	ad, _, err := dl.lookup(rnd, addr)
	if err != nil {
		return ledgercore.AssetResource{}, err
	}
	var result ledgercore.AssetResource
	if p, ok := ad.AssetParams[aidx]; ok {
		result.AssetParams = &p
	}
	if p, ok := ad.Assets[aidx]; ok {
		result.AssetHolding = &p
	}
	return result, nil
}

func (dl *dryrunLedger) LookupKv(rnd basics.Round, key string) ([]byte, error) {
	return nil, fmt.Errorf("boxes not implemented in dry run")
}

func (dl *dryrunLedger) GetCreatorForRound(rnd basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	switch ctype {
	case basics.AssetCreatable:
		for _, acct := range dl.dr.Accounts {
			if acct.CreatedAssets == nil {
				continue
			}
			for _, asset := range *acct.CreatedAssets {
				if asset.Index == basics.AssetIndex(cidx) {
					addr, err := basics.UnmarshalChecksumAddress(acct.Address)
					return addr, true, err
				}
			}
		}
		return basics.Address{}, false, fmt.Errorf("no asset %d", cidx)
	case basics.AppCreatable:
		for _, app := range dl.dr.Apps {
			if app.Id == basics.AppIndex(cidx) {
				var addr basics.Address
				if app.Params.Creator != "" {
					var err error
					addr, err = basics.UnmarshalChecksumAddress(app.Params.Creator)
					if err != nil {
						return basics.Address{}, false, err
					}
				}
				return addr, true, nil
			}
		}
		return basics.Address{}, false, fmt.Errorf("no app %d", cidx)
	}
	return basics.Address{}, false, fmt.Errorf("unknown creatable type %d", ctype)
}

func makeBalancesAdapter(dl *dryrunLedger, txn *transactions.Transaction, appIdx basics.AppIndex) (ba apply.Balances, err error) {
	ba = ledger.MakeDebugBalances(dl, basics.Round(dl.dr.Round), protocol.ConsensusVersion(dl.dr.ProtocolVersion), dl.dr.LatestTimestamp)

	return ba, nil
}

// unit-testable core of dryrun handler
// programs for execution are discovered in the following way:
// - LogicSig: stxn.Lsig.Logic
// - Application: Apps[i].ClearStateProgram or Apps[i].ApprovalProgram for matched appIdx
// if dr.Sources is set it overrides appropriate entires in stxn.Lsig.Logic or Apps[i]
// important: dr.Accounts are not used for program lookup for application execution
// important: dr.ProtocolVersion is used by underlying ledger implementation so that it must exist in config.Consensus
func doDryrunRequest(dr *DryrunRequest, response *model.DryrunResponse) {
	err := dr.ExpandSources()
	if err != nil {
		response.Error = err.Error()
		return
	}

	dl := dryrunLedger{dr: dr}
	err = dl.init()
	if err != nil {
		response.Error = err.Error()
		return
	}
	proto := config.Consensus[protocol.ConsensusVersion(dr.ProtocolVersion)]
	txgroup := transactions.WrapSignedTxnsWithAD(dr.Txns)
	specials := transactions.SpecialAddresses{}
	ep := logic.NewAppEvalParams(txgroup, &proto, &specials)
	sep := logic.NewSigEvalParams(dr.Txns, &proto, &dl)

	origEnableAppCostPooling := proto.EnableAppCostPooling
	// Enable EnableAppCostPooling so that dryrun
	// 1) can determine cost 2) reports actual cost for large programs that fail
	proto.EnableAppCostPooling = true

	// allow a huge execution budget
	maxCurrentBudget := proto.MaxAppProgramCost * 100
	pooledAppBudget := maxCurrentBudget
	allowedBudget := 0
	cumulativeCost := 0
	for _, stxn := range dr.Txns {
		if stxn.Txn.Type == protocol.ApplicationCallTx {
			allowedBudget += proto.MaxAppProgramCost
		}
	}
	ep.PooledApplicationBudget = &pooledAppBudget

	response.Txns = make([]model.DryrunTxnResult, len(dr.Txns))
	for ti, stxn := range dr.Txns {
		var result model.DryrunTxnResult
		if !stxn.Lsig.Blank() {
			var debug dryrunDebugReceiver
			sep.Tracer = logic.MakeEvalTracerDebuggerAdaptor(&debug)
			pass, err := logic.EvalSignature(ti, sep)
			var messages []string
			result.Disassembly = debug.lines          // Keep backwards compat
			result.LogicSigDisassembly = &debug.lines // Also add to Lsig specific
			result.LogicSigTrace = &debug.history
			if pass {
				messages = append(messages, "PASS")
			} else {
				messages = append(messages, "REJECT")
			}
			if err != nil {
				messages = append(messages, err.Error())
			}
			result.LogicSigMessages = &messages
		}
		if stxn.Txn.Type == protocol.ApplicationCallTx {
			appIdx := stxn.Txn.ApplicationID
			if appIdx == 0 {
				creator := stxn.Txn.Sender.String()
				// check and use the first entry in dr.Apps
				if len(dr.Apps) > 0 && dr.Apps[0].Params.Creator == creator {
					appIdx = dr.Apps[0].Id
				}
			}
			if stxn.Txn.OnCompletion == transactions.OptInOC {
				if idx, ok := dl.accountsIn[stxn.Txn.Sender]; ok {
					acct := dl.dr.Accounts[idx]
					ls := model.ApplicationLocalState{
						Id:       appIdx,
						KeyValue: new(model.TealKeyValueStore),
					}
					for _, app := range dr.Apps {
						if app.Id == appIdx {
							if app.Params.LocalStateSchema != nil {
								ls.Schema = *app.Params.LocalStateSchema
							}
							break
						}
					}
					if acct.AppsLocalState == nil {
						lss := []model.ApplicationLocalState{ls}
						acct.AppsLocalState = &lss
					} else {
						found := false
						for _, apls := range *acct.AppsLocalState {
							if apls.Id == appIdx {
								// already opted in
								found = true
							}
						}
						if !found {
							*acct.AppsLocalState = append(*acct.AppsLocalState, ls)
						}
					}
					dl.dr.Accounts[idx] = acct
				}
			}

			ba, err := makeBalancesAdapter(&dl, &stxn.Txn, appIdx)
			if err != nil {
				response.Error = err.Error()
				return
			}
			var app basics.AppParams
			ok := false
			for _, appt := range dr.Apps {
				if appt.Id == appIdx {
					app, err = ApplicationParamsToAppParams(&appt.Params)
					if err != nil {
						response.Error = err.Error()
						return
					}
					ok = true
					break
				}
			}
			var messages []string
			if !ok {
				messages = make([]string, 1)
				messages[0] = fmt.Sprintf("uploaded state did not include app id %d referenced in txn[%d]", appIdx, ti)
			} else {
				var debug dryrunDebugReceiver
				ep.Tracer = logic.MakeEvalTracerDebuggerAdaptor(&debug)
				var program []byte
				messages = make([]string, 1)
				if stxn.Txn.OnCompletion == transactions.ClearStateOC {
					program = app.ClearStateProgram
					messages[0] = "ClearStateProgram"
				} else {
					program = app.ApprovalProgram
					messages[0] = "ApprovalProgram"
				}
				pass, delta, err := ba.StatefulEval(ti, ep, appIdx, program)
				if !pass {
					delta = ep.TxnGroup[ti].EvalDelta
				}
				result.Disassembly = debug.lines
				result.AppCallTrace = &debug.history
				result.GlobalDelta = sliceOrNil(globalDeltaToStateDelta(delta.GlobalDelta))
				result.LocalDeltas = sliceOrNil(localDeltasToLocalDeltas(delta, &stxn.Txn))

				// ensure the program has not exceeded execution budget
				cost := maxCurrentBudget - pooledAppBudget
				if pass {
					if !origEnableAppCostPooling {
						if cost > proto.MaxAppProgramCost {
							pass = false
							err = fmt.Errorf("cost budget exceeded: budget is %d but program cost was %d", proto.MaxAppProgramCost, cost)
						}
					} else if cumulativeCost+cost > allowedBudget {
						pass = false
						err = fmt.Errorf("cost budget exceeded: budget is %d but program cost was %d", allowedBudget-cumulativeCost, cost)
					}
				}
				// The cost is broken up into two fields: budgetAdded and budgetConsumed.
				// This is necessary because the fields can only be represented as unsigned
				// integers, so a negative cost would underflow. The two fields also provide
				// more information, which can be useful for testing purposes.
				budgetAdded := proto.MaxAppProgramCost * numInnerTxns(delta)
				budgetConsumed := cost + budgetAdded
				result.BudgetAdded = &budgetAdded
				result.BudgetConsumed = &budgetConsumed
				maxCurrentBudget = pooledAppBudget
				cumulativeCost += cost

				var err3 error
				result.Logs, err3 = DeltaLogToLog(delta.Logs)
				if err3 != nil {
					messages = append(messages, err3.Error())
				}

				if pass {
					messages = append(messages, "PASS")
				} else {
					messages = append(messages, "REJECT")
				}
				if err != nil {
					messages = append(messages, err.Error())
				}
			}
			result.AppCallMessages = &messages
		}
		response.Txns[ti] = result
	}
}

// DeltaLogToLog base64 encode the logs
func DeltaLogToLog(logs []string) (*[][]byte, error) {
	if len(logs) == 0 {
		return nil, nil
	}
	logsAsBytes := make([][]byte, len(logs))
	for i, log := range logs {
		logsAsBytes[i] = []byte(log)
	}
	return &logsAsBytes, nil
}

// MergeAppParams merges values, existing in "base" take priority over new in "update"
func MergeAppParams(base *basics.AppParams, update *basics.AppParams) {
	if len(base.ApprovalProgram) == 0 && len(update.ApprovalProgram) > 0 {
		base.ApprovalProgram = update.ApprovalProgram
	}
	if len(base.ClearStateProgram) == 0 && len(update.ClearStateProgram) > 0 {
		base.ClearStateProgram = update.ClearStateProgram
	}
	if len(base.GlobalState) == 0 && len(update.GlobalState) > 0 {
		base.GlobalState = update.GlobalState
	}
	if base.LocalStateSchema.Empty() && !update.LocalStateSchema.Empty() {
		base.LocalStateSchema = update.LocalStateSchema
	}
	if base.GlobalStateSchema.Empty() && !update.GlobalStateSchema.Empty() {
		base.GlobalStateSchema = update.GlobalStateSchema
	}
}

// count all inner transactions contained within the eval delta
func numInnerTxns(delta transactions.EvalDelta) (cnt int) {
	cnt = len(delta.InnerTxns)
	for _, itxn := range delta.InnerTxns {
		cnt += numInnerTxns(itxn.EvalDelta)
	}

	return
}
