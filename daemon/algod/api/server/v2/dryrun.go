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
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/protocol"
)

// DryrunApp holds global app state for a dryrun call.
// TODO: should become obsolete when app supported added to api v2?
type DryrunApp struct {
	Creator  basics.Address   `codec:"a"`
	AppIndex uint64           `codec:"i"`
	Params   basics.AppParams `codec:"p"`
}

// DryrunLocalAppState holds per-account app state for a dryrun call.
// TODO: should become obsolete when app supported added to api v2?
type DryrunLocalAppState struct {
	Account  basics.Address       `codec:"a"`
	AppIndex basics.AppIndex      `codec:"i"`
	State    basics.AppLocalState `codec:"s"`
}

// DryrunSource is TEAL source text that gets uploaded, compiled, and inserted into transactions or application state
type DryrunSource struct {
	// FieldName is what kind of sources this is.
	// If lsig then it goes into the transactions[this.TxnIndex].LogicSig
	// If approv or clearp it goes into the Approval Program or Clear State Program of application[this.AppIndex]
	FieldName string `codec:"f"` // "lsig", "approv", "clearp"
	Source    string `codec:"text"`
	TxnIndex  int    `codec:"ti,omitempty"`
	AppIndex  uint64 `codec:"ai,omitempty"`
}

// DryrunRequest is the JSON object uploaded to /v2/transactions/dryrun
// Given the Transactions and simulated ledger state upload, run TEAL scripts and return debugging information.
type DryrunRequest struct {
	// Txns is transactions to simulate
	Txns []transactions.SignedTxn `codec:"txns,omitempty"`

	// Accounts
	// Optional, useful for testing Application Call txns.
	Accounts []generated.Account `codec:"accounts,omitempty"`

	Apps []DryrunApp `codec:"apps,omitempty"`

	AccountAppStates []DryrunLocalAppState `codec:"applocal,omitempty"`

	// ProtocolVersion specifies a specific version string to operate under, otherwise whatever the current protocol of the network this algod is running in.
	ProtocolVersion string `codec:"proto,omitempty"`

	// Round is available to some TEAL scripts. Defaults to the current round on the network this algod is attached to.
	Round uint64 `codec:"round,omitempty"`

	Sources []DryrunSource
}

func (dr *DryrunRequest) expandSources() error {
	for i, s := range dr.Sources {
		program, err := logic.AssembleString(s.Source)
		if err != nil {
			return fmt.Errorf("Dryrun Source[%d]: %v", i, err)
		}
		switch s.FieldName {
		case "lsig":
			dr.Txns[s.TxnIndex].Lsig.Logic = program
		case "approv", "clearp":
			for ai, app := range dr.Apps {
				if app.AppIndex == s.AppIndex {
					switch s.FieldName {
					case "approv":
						dr.Apps[ai].Params.ApprovalProgram = program
					case "clearp":
						dr.Apps[ai].Params.ClearStateProgram = program
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
	history       []logic.DebugState
	scratchActive []bool
}

func (ddr *dryrunDebugReceiver) updateScratch() {
	any := false
	maxActive := -1
	lasti := len(ddr.history) - 1

	for i, sv := range ddr.history[lasti].Scratch {
		if sv.Type != "u" || sv.Uint != 0 {
			any = true
			maxActive = i
		}
	}
	if any {
		if ddr.scratchActive == nil {
			ddr.scratchActive = make([]bool, maxActive+1, 256)
		}
		for i := len(ddr.scratchActive); i <= maxActive; i++ {
			sv := ddr.history[lasti].Scratch[i]
			active := sv.Type != "u" || sv.Uint != 0
			ddr.scratchActive = append(ddr.scratchActive, active)
		}
	} else {
		if ddr.scratchActive != nil {
			ddr.history[lasti].Scratch = ddr.history[lasti].Scratch[:len(ddr.scratchActive)]
		} else {
			ddr.history[lasti].Scratch = nil
			return
		}
	}
	scratchlen := maxActive + 1
	if len(ddr.scratchActive) > scratchlen {
		scratchlen = len(ddr.scratchActive)
	}
	ddr.history[lasti].Scratch = ddr.history[lasti].Scratch[:scratchlen]
	for i := range ddr.history[lasti].Scratch {
		if !ddr.scratchActive[i] {
			ddr.history[lasti].Scratch[i].Type = ""
		}
	}
}

// Register is fired on program creation (DebuggerHook interface)
func (ddr *dryrunDebugReceiver) Register(state *logic.DebugState) error {
	ddr.history = append(ddr.history, *state)
	ddr.updateScratch()
	return nil
}

// Update is fired on every step (DebuggerHook interface)
func (ddr *dryrunDebugReceiver) Update(state *logic.DebugState) error {
	// see go-algorand/data/transactions/logic/debugger.go refreshDebugState() for which fields are updated
	ds := logic.DebugState{
		PC:      state.PC,
		Line:    state.Line,
		Error:   state.Error,
		Stack:   state.Stack,
		Scratch: state.Scratch,
	}
	ddr.history = append(ddr.history, ds)
	ddr.updateScratch()
	return nil
}

// Complete is called when the program exits (DebuggerHook interface)
func (ddr *dryrunDebugReceiver) Complete(state *logic.DebugState) error {
	return ddr.Update(state)
}

// LedgerForLogic
type dryrunLedger struct {
	// inputs:

	dr    *DryrunRequest
	proto *config.ConsensusParams

	// intermediate state:

	// index into dr.Accounts[]
	accountsIn map[basics.Address]int

	// index into dr.Apps[]
	accountApps map[basics.Address]int

	// index into dr.AccountAppStates[]
	accountAppStates map[basics.Address]int

	// accounts that have been Put
	accounts map[basics.Address]basics.BalanceRecord
}

func (dl *dryrunLedger) init() error {
	dl.accounts = make(map[basics.Address]basics.BalanceRecord)
	dl.accountsIn = make(map[basics.Address]int)
	dl.accountApps = make(map[basics.Address]int)
	dl.accountAppStates = make(map[basics.Address]int)
	for i, acct := range dl.dr.Accounts {
		xaddr, err := basics.UnmarshalChecksumAddress(acct.Address)
		if err != nil {
			return err
		}
		dl.accountsIn[xaddr] = i
	}
	for i, app := range dl.dr.Apps {
		dl.accountApps[app.Creator] = i
	}
	for i, appState := range dl.dr.AccountAppStates {
		dl.accountAppStates[appState.Account] = i
	}
	return nil
}

// LedgerForLogic
func (dl *dryrunLedger) Balance(addr basics.Address) (basics.MicroAlgos, error) {
	for _, acct := range dl.dr.Accounts {
		xaddr, err := basics.UnmarshalChecksumAddress(acct.Address)
		if err != nil {
			continue
		}
		if xaddr == addr {
			return basics.MicroAlgos{Raw: acct.Amount}, nil
		}
	}
	return basics.MicroAlgos{Raw: 0}, fmt.Errorf("no account %s", addr.String())
}

// LedgerForLogic interface
// transactions.Balances interface
func (dl *dryrunLedger) Round() basics.Round {
	return basics.Round(dl.dr.Round)
}

// LedgerForLogic interface
func (dl *dryrunLedger) AppGlobalState(appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	for _, app := range dl.dr.Apps {
		if app.AppIndex == uint64(appIdx) {
			return app.Params.GlobalState, nil
		}
	}
	return nil, nil
}

// LedgerForLogic interface
func (dl *dryrunLedger) AppLocalState(addr basics.Address, appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	for _, st := range dl.dr.AccountAppStates {
		if appIdx == st.AppIndex && addr == st.Account {
			return st.State.KeyValue, nil
		}
	}
	return nil, nil
}

// LedgerForLogic interface
func (dl *dryrunLedger) AssetHolding(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetHolding, error) {
	for _, acct := range dl.dr.Accounts {
		// TODO: check all address decodes when we first receive the dryrun request
		xaddr, err := basics.UnmarshalChecksumAddress(acct.Address)
		if err != nil {
			continue
		}
		if xaddr == addr {
			for _, ah := range *acct.Assets {
				if ah.AssetId == uint64(assetIdx) {
					return basics.AssetHolding{Amount: ah.Amount, Frozen: ah.IsFrozen}, nil
				}
			}
		}
	}
	return basics.AssetHolding{Amount: 0, Frozen: false}, fmt.Errorf("no account %s", addr.String())
}

// LedgerForLogic interface
func (dl *dryrunLedger) AssetParams(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetParams, error) {
	// TODO? maybe not needed for dryrun
	return basics.AssetParams{}, nil
}

// transactions.Balances interface
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
		if withPendingRewards {
			out.MicroAlgos.Raw = acct.Amount
		} else {
			out.MicroAlgos.Raw = acct.AmountWithoutPendingRewards
		}
		// TODO: more fields
	}
	appi, ok := dl.accountApps[addr]
	if ok {
		any = true
		app := dl.dr.Apps[appi]
		out.AppParams = make(map[basics.AppIndex]basics.AppParams)
		out.AppParams[basics.AppIndex(app.AppIndex)] = app.Params
	}
	appstatei, ok := dl.accountAppStates[addr]
	if ok {
		any = true
		appstate := dl.dr.AccountAppStates[appstatei]
		out.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
		out.AppLocalStates[basics.AppIndex(appstate.AppIndex)] = appstate.State
	}
	if !any {
		return basics.BalanceRecord{}, fmt.Errorf("no account for addr %s", addr.String())
	}
	return out, nil
}

// transactions.Balances interface
func (dl *dryrunLedger) Put(br basics.BalanceRecord) error {
	if dl.accounts == nil {
		dl.accounts = make(map[basics.Address]basics.BalanceRecord)
	}
	dl.accounts[br.Addr] = br
	return nil
}

// PutWithCreatables is like Put, but should be used when creating or deleting an asset or application.
func (dl *dryrunLedger) PutWithCreatables(record basics.BalanceRecord, newCreatables []basics.CreatableLocator, deletedCreatables []basics.CreatableLocator) error {
	return nil
}

// GetAssetCreator gets the address of the account whose balance record
// contains the asset params
func (dl *dryrunLedger) GetAssetCreator(aidx basics.AssetIndex) (basics.Address, bool, error) {
	for _, acct := range dl.dr.Accounts {
		if acct.CreatedAssets == nil {
			continue
		}
		for _, asset := range *acct.CreatedAssets {
			if asset.Index == uint64(aidx) {
				addr, err := basics.UnmarshalChecksumAddress(acct.Address)
				return addr, true, err
			}
		}
	}
	return basics.Address{}, false, fmt.Errorf("no asset %d", aidx)
}

// GetAppCreator gets the address of the account whose balance record
// contains the app params
func (dl *dryrunLedger) GetAppCreator(aidx basics.AppIndex) (basics.Address, bool, error) {
	for _, app := range dl.dr.Apps {
		if app.AppIndex == uint64(aidx) {
			return app.Creator, true, nil
		}
	}
	return basics.Address{}, false, fmt.Errorf("no app %d", aidx)
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

func makeAppLedger(dl *dryrunLedger, txnIndex int) (l logic.LedgerForLogic, err error) {
	dr := dl.dr
	accounts := make([]basics.Address, 1+len(dr.Txns[txnIndex].Txn.Accounts))
	accounts[0] = dr.Txns[txnIndex].Txn.Sender
	for i, addr := range dr.Txns[txnIndex].Txn.Accounts {
		accounts[i+1] = addr
	}
	apps := make([]basics.AppIndex, 1+len(dr.Txns[txnIndex].Txn.ForeignApps))
	apps[0] = dr.Txns[txnIndex].Txn.ApplicationID
	for i, appid := range dr.Txns[txnIndex].Txn.ForeignApps {
		apps[i+1] = appid
	}
	return ledger.MakeDebugAppLedger(dl, accounts, apps, dr.Txns[txnIndex].Txn.ApplicationID)
}

// DryrunTxnResult contains any LogicSig or ApplicationCall program debug information and state updates from a dryrun.
type DryrunTxnResult struct {
	LogicSigTrace    []logic.DebugState `json:"lsig,omitempty"`
	LogicSigMessages []string           `json:"lsigt,omitempty"`

	AppCallTrace    []logic.DebugState `json:"app,omitempty"`
	AppCallMessages []string           `json:"appt,omitempty"`

	// Open up the pieces of EvalDelta so we can replace map[uint64]{} with something JSON friendly.
	GlobalDelta basics.StateDelta            `json:"gd,omitempty"`
	LocalDeltas map[string]basics.StateDelta `json:"ld,omitempty"`
}

// DryrunResponse contains per-txn debug information from a dryrun.
type DryrunResponse struct {
	Txns  []*DryrunTxnResult `json:"txns,omitempty"`
	Error string             `json:"error,omitempty"`
}

// unit-testable core of dryrun handler
func doDryrunRequest(dr *DryrunRequest, proto *config.ConsensusParams, response *DryrunResponse) {
	err := dr.expandSources()
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
	response.Txns = make([]*DryrunTxnResult, len(dr.Txns))
	for ti, stxn := range dr.Txns {
		ep := logic.EvalParams{
			Txn:        &stxn,
			Proto:      proto,
			TxnGroup:   dr.Txns,
			GroupIndex: ti,
			//Logger: nil, // TODO: capture logs, send them back
			//Ledger: l,
		}
		var result *DryrunTxnResult
		if len(stxn.Lsig.Logic) > 0 {
			var debug dryrunDebugReceiver
			ep.Debugger = &debug
			pass, err := logic.Eval(stxn.Lsig.Logic, ep)
			result = new(DryrunTxnResult)
			var messages []string
			result.LogicSigTrace = debug.history
			if pass {
				messages = append(messages, "PASS")
			} else {
				messages = append(messages, "REJECT")
			}
			if err != nil {
				messages = append(messages, err.Error())
			}
			result.LogicSigMessages = messages
		}
		if stxn.Txn.Type == protocol.ApplicationCallTx {
			l, err := makeAppLedger(&dl, ti)
			if err != nil {
				response.Error = err.Error()
				return
			}
			ep.Ledger = l
			appid := stxn.Txn.ApplicationID
			var app basics.AppParams
			ok := false
			for _, appt := range dr.Apps {
				if appt.AppIndex == uint64(appid) {
					app = appt.Params
					ok = true
					break
				}
			}
			var messages []string
			if result == nil {
				result = new(DryrunTxnResult)
			}
			if !ok {
				messages = make([]string, 1)
				messages[0] = fmt.Sprintf("uploaded state did not include app id %d referenced in txn[%d]", appid, ti)
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
				result.AppCallTrace = debug.history
				result.GlobalDelta = delta.GlobalDelta
				if len(delta.LocalDeltas) > 0 {
					result.LocalDeltas = make(map[string]basics.StateDelta, len(delta.LocalDeltas))
					for k, v := range delta.LocalDeltas {
						ldaddr, err := stxn.Txn.AddressByIndex(k, stxn.Txn.Sender)
						if err != nil {
							messages = append(messages, err.Error())
						}
						result.LocalDeltas[ldaddr.String()] = v
					}
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
			result.AppCallMessages = messages
		}
		response.Txns[ti] = result
	}
}
