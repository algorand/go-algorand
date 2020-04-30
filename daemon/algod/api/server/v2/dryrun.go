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
	//"errors"
	//"fmt"
	//"io"
	//"net/http"
	//"time"

	//"github.com/labstack/echo/v4"

	//"github.com/algorand/go-algorand/config"
	//"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	//"github.com/algorand/go-algorand/logging"
	//"github.com/algorand/go-algorand/node"
	//"github.com/algorand/go-algorand/protocol"
	//"github.com/algorand/go-algorand/rpcs"
)

// DryrunApp holds global app state for a dryrun call.
// TODO: should become obsolete when app supported added to api v2?
type DryrunApp struct {
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
	dr *DryrunRequest
}

// LedgerForLogic
func (dl *dryrunLedger) Balance(addr basics.Address) (basics.MicroAlgos, error) {
	return basics.MicroAlgos{Raw: 0}, nil
}
func (dl *dryrunLedger) Round() basics.Round {
	return basics.Round(dl.dr.Round)
}
func (dl *dryrunLedger) AppGlobalState(appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	for _, app := range dl.dr.Apps {
		if app.AppIndex == uint64(appIdx) {
			return app.Params.GlobalState, nil
		}
	}
	return nil, nil
}
func (dl *dryrunLedger) AppLocalState(addr basics.Address, appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	for _, st := range dl.dr.AccountAppStates {
		if appIdx == st.AppIndex && addr == st.Account {
			return st.State.KeyValue, nil
		}
	}
	return nil, nil
}
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
	return basics.AssetHolding{Amount: 0, Frozen: false}, nil
}
func (dl *dryrunLedger) AssetParams(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetParams, error) {
	// TODO? maybe not needed for dryrun
	return basics.AssetParams{}, nil
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
	Txns []*DryrunTxnResult `json:"txns,omitempty"`
}
