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

package v2

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/protocol"
)

// DryrunRequest object uploaded to /v2/teal/dryrun
// It is the same as generated.DryrunRequest but Txns deserialized properly.
// Given the Transactions and simulated ledger state upload, run TEAL scripts and return debugging information.
// This is also used for msgp-decoding
type DryrunRequest struct {
	// Txns is transactions to simulate
	Txns []transactions.SignedTxn `codec:"txns"` // not supposed to be serialized

	// Optional, useful for testing Application Call txns.
	Accounts []generated.Account `codec:"accounts"`

	Apps []generated.Application `codec:"apps"`

	// ProtocolVersion specifies a specific version string to operate under, otherwise whatever the current protocol of the network this algod is running in.
	ProtocolVersion string `codec:"protocol-version"`

	// Round is available to some TEAL scripts. Defaults to the current round on the network this algod is attached to.
	Round uint64 `codec:"round"`

	// LatestTimestamp is available to some TEAL scripts. Defaults to the latest confirmed timestamp this algod is attached to.
	LatestTimestamp int64 `codec:"latest-timestamp"`

	Sources []generated.DryrunSource `codec:"sources"`
}

// DryrunRequestFromGenerated converts generated.DryrunRequest to DryrunRequest field by fields
// and re-types Txns []transactions.SignedTxn
func DryrunRequestFromGenerated(gdr *generated.DryrunRequest) (dr DryrunRequest, err error) {
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
			return fmt.Errorf("Dryrun Source[%d]: %v", i, err)
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
			return fmt.Errorf("Dryrun Source[%d]: bad field name %#v", i, s.FieldName)
		}
	}
	return nil
}

type dryrunDebugReceiver struct {
	disassembly   string
	lines         []string
	history       []generated.DryrunState
	scratchActive []bool
}

func (ddr *dryrunDebugReceiver) updateScratch() {
	any := false
	maxActive := -1
	lasti := len(ddr.history) - 1

	if ddr.history[lasti].Scratch == nil {
		return
	}

	for i, sv := range *ddr.history[lasti].Scratch {
		if sv.Type != uint64(basics.TealUintType) || sv.Uint != 0 {
			any = true
			maxActive = i
		}
	}

	if any {
		if ddr.scratchActive == nil {
			ddr.scratchActive = make([]bool, maxActive+1, 256)
		}
		for i := len(ddr.scratchActive); i <= maxActive; i++ {
			sv := (*ddr.history[lasti].Scratch)[i]
			active := sv.Type != uint64(basics.TealUintType) || sv.Uint != 0
			ddr.scratchActive = append(ddr.scratchActive, active)
		}
	} else {
		if ddr.scratchActive != nil {
			*ddr.history[lasti].Scratch = (*ddr.history[lasti].Scratch)[:len(ddr.scratchActive)]
		} else {
			ddr.history[lasti].Scratch = nil
			return
		}
	}

	scratchlen := maxActive + 1
	if len(ddr.scratchActive) > scratchlen {
		scratchlen = len(ddr.scratchActive)
	}

	*ddr.history[lasti].Scratch = (*ddr.history[lasti].Scratch)[:scratchlen]
	for i := range *ddr.history[lasti].Scratch {
		if !ddr.scratchActive[i] {
			(*ddr.history[lasti].Scratch)[i].Type = 0
		}
	}
}

func (ddr *dryrunDebugReceiver) stateToState(state *logic.DebugState) generated.DryrunState {
	st := generated.DryrunState{
		Line: uint64(state.Line),
		Pc:   uint64(state.PC),
	}
	st.Stack = make([]generated.TealValue, len(state.Stack))
	for i, v := range state.Stack {
		st.Stack[i] = generated.TealValue{
			Uint:  v.Uint,
			Bytes: v.Bytes,
			Type:  uint64(v.Type),
		}
	}
	if len(state.Error) > 0 {
		st.Error = new(string)
		*st.Error = state.Error
	}

	scratch := make([]generated.TealValue, len(state.Scratch))
	for i, v := range state.Scratch {
		scratch[i] = generated.TealValue{
			Uint:  v.Uint,
			Bytes: v.Bytes,
			Type:  uint64(v.Type),
		}
	}
	st.Scratch = &scratch
	return st
}

// Register is fired on program creation (DebuggerHook interface)
func (ddr *dryrunDebugReceiver) Register(state *logic.DebugState) error {
	ddr.disassembly = state.Disassembly
	ddr.lines = strings.Split(state.Disassembly, "\n")
	return nil
}

// Update is fired on every step (DebuggerHook interface)
func (ddr *dryrunDebugReceiver) Update(state *logic.DebugState) error {
	st := ddr.stateToState(state)
	ddr.history = append(ddr.history, st)
	ddr.updateScratch()
	return nil
}

// Complete is called when the program exits (DebuggerHook interface)
func (ddr *dryrunDebugReceiver) Complete(state *logic.DebugState) error {
	return ddr.Update(state)
}

type dryrunLedger struct {
	// inputs:

	dr    *DryrunRequest
	proto *config.ConsensusParams

	// intermediate state:

	// index into dr.Accounts[]
	accountsIn map[basics.Address]int

	// index into dr.Apps[]
	accountApps map[basics.Address]int

	// accounts that have been Put
	accounts map[basics.Address]basics.BalanceRecord
}

func (dl *dryrunLedger) init() error {
	dl.accounts = make(map[basics.Address]basics.BalanceRecord)
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

// apply.Balances interface
func (dl *dryrunLedger) Round() basics.Round {
	return basics.Round(dl.dr.Round)
}

// apply.Balances interface
func (dl *dryrunLedger) Get(addr basics.Address, withPendingRewards bool) (basics.BalanceRecord, error) {
	// first check accounts from a previous Put()
	br, ok := dl.accounts[addr]
	if ok {
		return br, nil
	}
	// check accounts from debug records uploaded
	any := false
	out := basics.BalanceRecord{
		Addr: addr,
	}
	accti, ok := dl.accountsIn[addr]
	if ok {
		any = true
		acct := dl.dr.Accounts[accti]
		var err error
		if out.AccountData, err = AccountToAccountData(&acct); err != nil {
			return basics.BalanceRecord{}, err
		}
		if withPendingRewards {
			out.MicroAlgos.Raw = acct.Amount
		} else {
			out.MicroAlgos.Raw = acct.AmountWithoutPendingRewards
		}
	}
	appi, ok := dl.accountApps[addr]
	if ok {
		any = true
		app := dl.dr.Apps[appi]
		params, err := ApplicationParamsToAppParams(&app.Params)
		if err != nil {
			return basics.BalanceRecord{}, err
		}
		if out.AppParams == nil {
			out.AppParams = make(map[basics.AppIndex]basics.AppParams)
			out.AppParams[basics.AppIndex(app.Id)] = params
		} else {
			ap, ok := out.AppParams[basics.AppIndex(app.Id)]
			if ok {
				MergeAppParams(&ap, &params)
				out.AppParams[basics.AppIndex(app.Id)] = ap
			} else {
				out.AppParams[basics.AppIndex(app.Id)] = params
			}
		}
	}
	if !any {
		return basics.BalanceRecord{}, fmt.Errorf("no account for addr %s", addr.String())
	}
	return out, nil
}

// apply.Balances interface
func (dl *dryrunLedger) Put(br basics.BalanceRecord) error {
	if dl.accounts == nil {
		dl.accounts = make(map[basics.Address]basics.BalanceRecord)
	}
	dl.accounts[br.Addr] = br
	return nil
}

// PutWithCreatable is like Put, but should be used when creating or deleting an asset or application.
func (dl *dryrunLedger) PutWithCreatable(record basics.BalanceRecord, newCreatable *basics.CreatableLocator, deletedCreatable *basics.CreatableLocator) error {
	return nil
}

// GetCreator gets the address of the creator of an app or asset
func (dl *dryrunLedger) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	switch ctype {
	case basics.AssetCreatable:
		for _, acct := range dl.dr.Accounts {
			if acct.CreatedAssets == nil {
				continue
			}
			for _, asset := range *acct.CreatedAssets {
				if asset.Index == uint64(cidx) {
					addr, err := basics.UnmarshalChecksumAddress(acct.Address)
					return addr, true, err
				}
			}
		}
		return basics.Address{}, false, fmt.Errorf("no asset %d", cidx)
	case basics.AppCreatable:
		for _, app := range dl.dr.Apps {
			if app.Id == uint64(cidx) {
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

// Move MicroAlgos from one account to another, doing all necessary overflow checking (convenience method)
// TODO: Does this need to be part of the balances interface, or can it just be implemented here as a function that calls Put and Get?
func (dl *dryrunLedger) Move(src, dst basics.Address, amount basics.MicroAlgos, srcRewards *basics.MicroAlgos, dstRewards *basics.MicroAlgos) error {
	return nil
}

// Balances correspond to a Round, which mean that they also correspond
// to a ConsensusParams.  This returns those parameters.
func (dl *dryrunLedger) ConsensusParams() config.ConsensusParams {
	return *dl.proto
}

func makeAppLedger(dl *dryrunLedger, txn *transactions.Transaction, appIdx basics.AppIndex) (l logic.LedgerForLogic, err error) {
	globals := ledger.AppTealGlobals{
		CurrentRound:    basics.Round(dl.dr.Round),
		LatestTimestamp: dl.dr.LatestTimestamp,
	}
	localSchema := basics.StateSchema{NumUint: 16, NumByteSlice: 16}
	globalSchema := basics.StateSchema{NumUint: 64, NumByteSlice: 64}
	schemas := basics.StateSchemas{LocalStateSchema: localSchema, GlobalStateSchema: globalSchema}
	return ledger.MakeDebugAppLedger(dl, appIdx, schemas, globals)
}

// unit-testable core of dryrun handler
// programs for execution are discovered in the following way:
// - LogicSig: stxn.Lsig.Logic
// - Application: Apps[i].ClearStateProgram or Apps[i].ApprovalProgram for matched appIdx
// if DryrunRequest.Sources is set it overrides appropriate entires in stxn.Lsig.Logic or Apps[i]
// important: Accounts are not used for program lookup for application execution
func doDryrunRequest(dr *DryrunRequest, proto *config.ConsensusParams, response *generated.DryrunResponse) {
	err := dr.ExpandSources()
	if err != nil {
		response.Error = err.Error()
		return
	}
	dl := dryrunLedger{dr: dr, proto: proto}
	err = dl.init()
	if err != nil {
		response.Error = err.Error()
		return
	}
	response.Txns = make([]generated.DryrunTxnResult, len(dr.Txns))
	for ti, stxn := range dr.Txns {
		ep := logic.EvalParams{
			Txn:        &stxn,
			Proto:      proto,
			TxnGroup:   dr.Txns,
			GroupIndex: ti,
			//Logger: nil, // TODO: capture logs, send them back
		}
		var result generated.DryrunTxnResult
		if len(stxn.Lsig.Logic) > 0 {
			var debug dryrunDebugReceiver
			ep.Debugger = &debug
			pass, err := logic.Eval(stxn.Lsig.Logic, ep)
			var messages []string
			result.Disassembly = debug.lines
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
					appIdx = basics.AppIndex(dr.Apps[0].Id)
				}
			}
			if stxn.Txn.OnCompletion == transactions.OptInOC {
				if idx, ok := dl.accountsIn[stxn.Txn.Sender]; ok {
					acct := dl.dr.Accounts[idx]
					var ad basics.AccountData
					if ad, err = AccountToAccountData(&acct); err != nil {
						response.Error = err.Error()
						return
					}
					if ad.AppLocalStates == nil {
						ad.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
					}
					ad.AppLocalStates[appIdx] = basics.AppLocalState{KeyValue: make(basics.TealKeyValue)}
					dl.accounts[stxn.Txn.Sender] = basics.BalanceRecord{Addr: stxn.Txn.Sender, AccountData: ad}
				}
			}

			l, err := makeAppLedger(&dl, &stxn.Txn, appIdx)
			if err != nil {
				response.Error = err.Error()
				return
			}
			ep.Ledger = l
			var app basics.AppParams
			ok := false
			for _, appt := range dr.Apps {
				if appt.Id == uint64(appIdx) {
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
				ep.Debugger = &debug
				var program []byte
				messages = make([]string, 1)
				if stxn.Txn.OnCompletion == transactions.ClearStateOC {
					program = app.ClearStateProgram
					messages[0] = "ClearStateProgram"
				} else {
					program = app.ApprovalProgram
					messages[0] = "ApprovalProgram"
				}
				pass, delta, err := logic.EvalStateful(program, ep)
				result.Disassembly = debug.lines
				result.AppCallTrace = &debug.history
				result.GlobalDelta = StateDeltaToStateDelta(delta.GlobalDelta)
				if len(delta.LocalDeltas) > 0 {
					localDeltas := make([]generated.AccountStateDelta, len(delta.LocalDeltas))
					for k, v := range delta.LocalDeltas {
						ldaddr, err := stxn.Txn.AddressByIndex(k, stxn.Txn.Sender)
						if err != nil {
							messages = append(messages, err.Error())
						}
						localDeltas = append(localDeltas, generated.AccountStateDelta{
							Address: ldaddr.String(),
							Delta:   *StateDeltaToStateDelta(v),
						})
					}
					result.LocalDeltas = &localDeltas
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

// StateDeltaToStateDelta converts basics.StateDelta to generated.StateDelta
func StateDeltaToStateDelta(sd basics.StateDelta) *generated.StateDelta {
	if len(sd) == 0 {
		return nil
	}

	gsd := make(generated.StateDelta, 0, len(sd))
	for k, v := range sd {
		value := generated.EvalDelta{Action: uint64(v.Action)}
		if v.Action == basics.SetBytesAction {
			bytesVal := base64.StdEncoding.EncodeToString([]byte(v.Bytes))
			value.Bytes = &bytesVal
		} else if v.Action == basics.SetUintAction {
			uintVal := v.Uint
			value.Uint = &uintVal
		}
		// basics.DeleteAction does not require Uint/Bytes
		kv := generated.EvalDeltaKeyValue{
			Key:   base64.StdEncoding.EncodeToString([]byte(k)),
			Value: value,
		}
		gsd = append(gsd, kv)
	}

	return &gsd
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
	if base.LocalStateSchema == (basics.StateSchema{}) && update.LocalStateSchema != (basics.StateSchema{}) {
		base.LocalStateSchema = update.LocalStateSchema
	}
	if base.GlobalStateSchema == (basics.StateSchema{}) && update.GlobalStateSchema != (basics.StateSchema{}) {
		base.GlobalStateSchema = update.GlobalStateSchema
	}
}
